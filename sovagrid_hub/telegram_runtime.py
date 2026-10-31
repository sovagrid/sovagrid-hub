# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Hot-swappable Telegram polling with a private, atomically stored token."""

from __future__ import annotations

import logging
import os
import re
import secrets
import stat
import threading
import time
import urllib.error
from pathlib import Path

from .telegram import TelegramBot


TOKEN_NAME = "telegram-bot-token"
TOKEN_PATTERN = re.compile(r"[0-9]{5,20}:[A-Za-z0-9_-]{30,80}\Z")
MAX_TOKEN_BYTES = 128


class TelegramModeError(RuntimeError):
    """A legacy externally mounted token cannot be changed through Hub."""


class TelegramStorageError(RuntimeError):
    """A secret-free filesystem failure."""


class TelegramActivationError(RuntimeError):
    """A safe-to-display BotFather verification failure."""

    def __init__(self, message: str, status: int = 503):
        super().__init__(message)
        self.status = status


def validate_token(value: object) -> str:
    if (not isinstance(value, str) or len(value.encode("utf-8")) > MAX_TOKEN_BYTES or
            not TOKEN_PATTERN.fullmatch(value)):
        raise ValueError("Invalid BotFather token format")
    return value


def _managed_path(db_path: str | Path) -> Path:
    return Path(os.path.abspath(db_path)).parent / TOKEN_NAME


def _read_token(path: Path, *, managed: bool) -> str:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            mode = stat.S_IMODE(info.st_mode)
            owner_ok = info.st_uid == os.geteuid() if managed else info.st_uid in (0, os.geteuid())
            mode_ok = mode == 0o600 if managed else not mode & 0o027
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                    not owner_ok or not mode_ok or info.st_size > MAX_TOKEN_BYTES + 1):
                raise TelegramStorageError("Telegram token file has unsafe permissions")
            raw = os.read(fd, MAX_TOKEN_BYTES + 2)
        finally:
            os.close(fd)
    except OSError as exc:
        raise TelegramStorageError("Telegram token file is unavailable") from exc
    try:
        return validate_token(raw.decode("ascii").rstrip("\n"))
    except (UnicodeError, ValueError) as exc:
        raise TelegramStorageError("Stored Telegram token is invalid") from exc


def _private_directory(path: Path) -> int:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        info = os.fstat(fd)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or
                stat.S_IMODE(info.st_mode) & 0o022):
            os.close(fd)
            raise TelegramStorageError("Telegram data directory is unsafe")
        return fd
    except OSError as exc:
        raise TelegramStorageError("Telegram data directory is unavailable") from exc


def _existing_managed_file(dir_fd: int) -> bool:
    try:
        fd = os.open(TOKEN_NAME, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dir_fd)
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise TelegramStorageError("Telegram token file is unsafe") from exc
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or
                info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600):
            raise TelegramStorageError("Telegram token file is unsafe")
    finally:
        os.close(fd)
    return True


def _write_token(path: Path, token: str) -> None:
    directory = _private_directory(path.parent)
    temporary = f".{TOKEN_NAME}.{secrets.token_hex(12)}"
    try:
        _existing_managed_file(directory)
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=directory)
        try:
            os.fchmod(fd, 0o600)
            payload = (token + "\n").encode("ascii")
            while payload:
                payload = payload[os.write(fd, payload):]
            os.fsync(fd)
        finally:
            os.close(fd)
        # The directory is owned by the Hub UID and not group/world writable.
        os.rename(temporary, TOKEN_NAME, src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
    except OSError as exc:
        raise TelegramStorageError("Could not save Telegram token") from exc
    finally:
        try:
            os.unlink(temporary, dir_fd=directory)
        except FileNotFoundError:
            pass
        os.close(directory)


def _remove_token(path: Path) -> None:
    directory = _private_directory(path.parent)
    try:
        if _existing_managed_file(directory):
            os.unlink(TOKEN_NAME, dir_fd=directory)
            os.fsync(directory)
    except OSError as exc:
        raise TelegramStorageError("Could not remove Telegram token") from exc
    finally:
        os.close(directory)


class TelegramRuntime:
    def __init__(self, store, db_path: str | Path, token_file: str | None = None,
                 *, poll: bool = True, bot_factory=TelegramBot, verifier=None):
        self.store = store
        self.managed_path = _managed_path(db_path)
        requested = Path(os.path.abspath(token_file)) if token_file else self.managed_path
        self.mode = "managed" if requested == self.managed_path else "managed_externally"
        self.token_path = requested
        self.poll = poll
        self.bot_factory = bot_factory
        self.verifier = verifier or self._verify_token
        self._bot = None
        self._bot_username: str | None = None
        self._started = False
        self._load_error: str | None = None
        self._lock = threading.RLock()

    def start(self) -> None:
        with self._lock:
            if self._started:
                return
            self._started = True
            try:
                token = _read_token(self.token_path, managed=self.mode == "managed")
            except TelegramStorageError:
                # A missing managed file means a fresh installation. Unsafe or
                # invalid files are left untouched for an administrator to fix.
                if self.mode == "managed" and not os.path.lexists(self.token_path):
                    return
                self._load_error = "Stored Telegram token could not be loaded"
                logging.error("Telegram token could not be loaded; polling disabled")
                return
            self._load_error = None
            self._bot_username = self.store.telegram_bot_username(token)
            bot = self.bot_factory(token, self.store)
            self._bot = bot
            bot.start(poll=self.poll)

    def _replace_bot(self, token: str | None) -> None:
        old = self._bot
        if old is not None:
            old.close()
        self._bot = self.bot_factory(token, self.store) if token else None
        if self._started and self._bot is not None:
            self._bot.start(poll=self.poll)

    def _verify_token(self, token: str) -> str | None:
        """Ask Telegram before persistence; never surface an exception URL."""
        try:
            response = TelegramBot(token, self.store)._call("getMe", {}, timeout=7)
            if not isinstance(response.get("result"), dict):
                raise TelegramActivationError("Telegram did not confirm the BotFather token", 422)
            username = response["result"].get("username")
            return username if isinstance(username, str) and re.fullmatch(r"[A-Za-z0-9_]{5,32}", username) else None
        except urllib.error.HTTPError as exc:
            if exc.code in (400, 401, 404):
                raise TelegramActivationError("BotFather token was rejected", 422) from None
            raise TelegramActivationError("Telegram validation is unavailable") from None
        except TelegramActivationError:
            raise
        except Exception:
            raise TelegramActivationError("Telegram validation is unavailable") from None

    def set_token(self, token: object, admin_session: str) -> dict:
        token = validate_token(token)
        with self._lock:
            if self.mode != "managed":
                raise TelegramModeError("Telegram token is managed externally")
        username = self.verifier(token)
        with self._lock:
            # getMe can take several seconds. Recheck the bearer token in a
            # SQLite write transaction immediately before changing the file;
            # logout and password change use that same write lock.
            with self.store.authorized_admin_session(admin_session):
                _write_token(self.managed_path, token)
            self._replace_bot(token)
            self._bot_username = username
            try:
                self.store.set_telegram_bot_info(token, username)
            except Exception:
                # Bot metadata is a convenience; token persistence and the
                # running bot must not be rolled back if SQLite is unavailable.
                logging.error("Telegram bot username could not be saved")
            self._load_error = None
        return self.status()

    def remove_token(self, admin_session: str) -> dict:
        with self._lock:
            if self.mode != "managed":
                raise TelegramModeError("Telegram token is managed externally")
            with self.store.authorized_admin_session(admin_session):
                _remove_token(self.managed_path)
            self._replace_bot(None)
            self._bot_username = None
            try:
                self.store.clear_telegram_bot_info()
            except Exception:
                logging.error("Telegram bot username could not be cleared")
            self._load_error = None
        return self.status()

    def status(self) -> dict:
        with self._lock:
            bot = self._bot
            last = getattr(bot, "last_success_at", None) if bot else None
            bot_error = getattr(bot, "last_error", None) if bot else None
            polling = bool(bot and self.poll and getattr(bot, "polling_started", False)
                           and not bot.stop.is_set())
            result = {"mode": self.mode, "configured": bot is not None,
                      "bot_username": self._bot_username if bot is not None else None,
                      "polling": polling,
                      "connected": bool(polling and not bot_error and isinstance(last, (int, float)) and
                                        0 <= time.time() - last <= 90),
                      "last_success_at": int(last) if isinstance(last, (int, float)) else None,
                      "error": self._load_error or bot_error}
        result["bindings"] = self.store.bot_bindings()
        result["pending_requests"] = self.store.pending_bot_pairings()
        result["pending_incident_notifications"] = self.store.incident_outbox_pending_count()
        result["pending_telegram_notices"] = self.store.telegram_notice_pending_count()
        return result

    def enqueue(self, events: list[dict]) -> None:
        with self._lock:
            if self._bot:
                self._bot.enqueue(events)

    def enqueue_job_result(self, job: dict) -> None:
        with self._lock:
            if self._bot:
                self._bot.enqueue_job_result(job)

    def notify_pairing_result(self, chat_id: int, role: str | None) -> None:
        with self._lock:
            if self._bot:
                self._bot.enqueue_pairing_result(chat_id, role)

    def close(self) -> None:
        with self._lock:
            if self._bot:
                self._bot.close()
                self._bot = None
