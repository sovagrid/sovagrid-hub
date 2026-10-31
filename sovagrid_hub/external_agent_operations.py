# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Durable, one-shot requests for the fixed external Agent updater unit."""

from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import time
import uuid

from .external_agent_control import valid_sha


ROOT = Path("/var/lib/sovagrid/external-agent-operations")
UNIT_FILE = Path("/etc/systemd/system/sovagrid-external-agent-apply@.service")
UNIT_MARKER = Path("/etc/sovagrid/.external-agent-apply-managed-by-run-sh")
MAX_OPERATIONS = 128
PHASES = frozenset(("accepted", "running", "complete", "failed", "uncertain"))
ERROR = re.compile(r"[A-Z][A-Z0-9_]{1,63}\Z")
REQUEST_FIELDS = frozenset(("format", "request_id", "archive_sha256",
                            "current_hub_manifest_sha256", "external_agent_manifest_sha256",
                            "review_sha256"))
STATUS_FIELDS = frozenset(("format", "request_id", "phase", "created_at",
                           "updated_at", "error"))


class ExternalOperationError(RuntimeError):
    pass


def canonical_id(value: object) -> bool:
    try:
        return isinstance(value, str) and str(uuid.UUID(value)) == value
    except (ValueError, AttributeError):
        return False


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ExternalOperationError("EXTERNAL_INVALID_STATE")
        result[key] = value
    return result


def _bytes(value: dict) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def valid_status(value: object, *, request_id: str | None = None) -> bool:
    return (isinstance(value, dict) and set(value) == STATUS_FIELDS and
            type(value["format"]) is int and value["format"] == 1 and
            canonical_id(value["request_id"]) and
            (request_id is None or value["request_id"] == request_id) and
            isinstance(value["phase"], str) and value["phase"] in PHASES and
            type(value["created_at"]) is int and 1 <= value["created_at"] <= 253402300799 and
            type(value["updated_at"]) is int and
            value["created_at"] <= value["updated_at"] <= 253402300799 and
            (value["error"] is None if value["phase"] in ("accepted", "running", "complete")
             else isinstance(value["error"], str) and ERROR.fullmatch(value["error"]) is not None))


class ExternalOperationStore:
    def __init__(self, *, root: Path = ROOT, unit_file: Path = UNIT_FILE,
                 unit_marker: Path = UNIT_MARKER,
                 uid: int = 0, gid: int = 0, run=subprocess.run):
        self.root, self.unit_file = Path(root), Path(unit_file)
        self.unit_marker = Path(unit_marker)
        self.uid, self.gid, self.run = uid, gid, run

    def _directory(self, path: Path, mode: int = 0o700) -> None:
        try:
            info = path.lstat()
        except FileNotFoundError:
            raise ExternalOperationError("EXTERNAL_INVALID_STATE") from None
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != self.uid or
                info.st_gid != self.gid or stat.S_IMODE(info.st_mode) != mode):
            raise ExternalOperationError("EXTERNAL_INVALID_STATE")

    def _base(self) -> None:
        parent = self.root.parent.lstat()
        if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != self.uid or
                parent.st_gid != self.gid or
                parent.st_mode & 0o022):
            raise ExternalOperationError("EXTERNAL_INVALID_STATE")
        # The installer creates this ledger alongside the fixed worker unit.
        # A metadata read must never create partial installation state.
        self._directory(self.root)

    def _regular(self, path: Path, limit: int) -> bytes:
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError as exc:
            raise ExternalOperationError("EXTERNAL_INVALID_STATE") from exc
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.uid or
                    info.st_gid != self.gid or info.st_nlink != 1 or
                    stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > limit):
                raise ExternalOperationError("EXTERNAL_INVALID_STATE")
            raw = os.read(fd, limit + 1)
            if not raw or len(raw) > limit:
                raise ExternalOperationError("EXTERNAL_INVALID_STATE")
            return raw
        finally:
            os.close(fd)

    def _json(self, path: Path, limit: int) -> dict:
        raw = self._regular(path, limit)
        try:
            value = json.loads(raw, object_pairs_hook=_unique)
        except (UnicodeError, ValueError) as exc:
            raise ExternalOperationError("EXTERNAL_INVALID_STATE") from exc
        if not isinstance(value, dict) or raw != _bytes(value):
            raise ExternalOperationError("EXTERNAL_INVALID_STATE")
        return value

    def _write_new(self, path: Path, value: dict) -> None:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW |
                     os.O_CLOEXEC, 0o600)
        try:
            with os.fdopen(fd, "wb") as output:
                output.write(_bytes(value))
                output.flush()
                os.fsync(output.fileno())
        except BaseException:
            path.unlink(missing_ok=True)
            raise

    @staticmethod
    def _write_lock_new(path: Path) -> None:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW |
                     os.O_CLOEXEC, 0o600)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    @staticmethod
    def _sync(directory: Path) -> None:
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def _lock(self, path: Path):
        fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.uid or
                info.st_gid != self.gid or info.st_nlink != 1 or
                stat.S_IMODE(info.st_mode) != 0o600 or info.st_size != 0):
            os.close(fd)
            raise ExternalOperationError("EXTERNAL_INVALID_STATE")
        fcntl.flock(fd, fcntl.LOCK_EX)
        return fd

    def _request(self, directory: Path, request_id: str) -> dict:
        value = self._json(directory / "request.json", 1024)
        if (set(value) != REQUEST_FIELDS or type(value["format"]) is not int or
                value["format"] != 1 or value["request_id"] != request_id or
                any(not valid_sha(value[key]) for key in REQUEST_FIELDS - {"format", "request_id"})):
            raise ExternalOperationError("EXTERNAL_INVALID_STATE")
        return value

    def _status(self, directory: Path, request_id: str) -> dict:
        value = self._json(directory / "status.json", 512)
        if not valid_status(value, request_id=request_id):
            raise ExternalOperationError("EXTERNAL_INVALID_STATE")
        return value

    def _change_status(self, directory: Path, request_id: str, *, error: str,
                       phase: str, from_phases: tuple[str, ...] = ("accepted",)) -> dict:
        fd = self._lock(directory / "status.lock")
        try:
            value = self._status(directory, request_id)
            if value["phase"] not in from_phases:
                return value
            next_value = {**value, "phase": phase, "error": error,
                          "updated_at": max(value["updated_at"], int(time.time()))}
            temporary = directory / (".status-" + secrets.token_hex(8))
            self._write_new(temporary, next_value)
            os.replace(temporary, directory / "status.json")
            self._sync(directory)
            return next_value
        finally:
            os.close(fd)

    def _unit(self) -> None:
        try:
            info = self.unit_file.lstat()
            marker = self.unit_marker.lstat()
        except OSError as exc:
            raise ExternalOperationError("EXTERNAL_UNAVAILABLE") from exc
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.uid or
                info.st_gid != self.gid or info.st_nlink != 1 or
                stat.S_IMODE(info.st_mode) != 0o644 or
                not stat.S_ISREG(marker.st_mode) or marker.st_uid != self.uid or
                marker.st_gid != self.gid or marker.st_nlink != 1 or
                stat.S_IMODE(marker.st_mode) != 0o600):
            raise ExternalOperationError("EXTERNAL_UNAVAILABLE")
        if self._regular(self.unit_marker, 64) != b"SOVAGRID_EXTERNAL_AGENT_APPLY_UNIT_V1\n":
            raise ExternalOperationError("EXTERNAL_UNAVAILABLE")

    def apply(self, request_id: str, archive_sha256: str, current_hub_manifest_sha256: str,
              external_agent_manifest_sha256: str, review_sha256: str) -> dict:
        if not canonical_id(request_id) or not all(valid_sha(value) for value in (
                archive_sha256, current_hub_manifest_sha256,
                external_agent_manifest_sha256, review_sha256)):
            raise ExternalOperationError("EXTERNAL_INVALID_REQUEST")
        requested = {"format": 1, "request_id": request_id,
                     "archive_sha256": archive_sha256,
                     "current_hub_manifest_sha256": current_hub_manifest_sha256,
                     "external_agent_manifest_sha256": external_agent_manifest_sha256,
                     "review_sha256": review_sha256}
        self._base()
        directory = self.root / request_id
        # The backup broker serves one connection at a time. A disk lock also
        # protects an interrupted/restarted broker and any recovery reader.
        lock_file = self.root / ".lock"
        if not lock_file.exists() and not lock_file.is_symlink():
            try:
                self._write_lock_new(lock_file)
            except FileExistsError:
                pass
        lock_fd = os.open(lock_file, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            lock_info = os.fstat(lock_fd)
            if (not stat.S_ISREG(lock_info.st_mode) or lock_info.st_uid != self.uid or
                    lock_info.st_gid != self.gid or lock_info.st_nlink != 1 or
                    stat.S_IMODE(lock_info.st_mode) != 0o600 or lock_info.st_size != 0):
                raise ExternalOperationError("EXTERNAL_INVALID_STATE")
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            if directory.exists() or directory.is_symlink():
                self._directory(directory)
                if self._request(directory, request_id) != requested:
                    raise ExternalOperationError("EXTERNAL_REQUEST_CONFLICT")
                return self.status(request_id)
            self._unit()
            operations = [item for item in self.root.iterdir() if canonical_id(item.name)]
            if len(operations) >= MAX_OPERATIONS:
                raise ExternalOperationError("EXTERNAL_OPERATION_LIMIT")
            for item in operations:
                self._directory(item)
                if self._status(item, item.name)["phase"] in ("accepted", "running") and \
                        self.status(item.name)["phase"] in ("accepted", "running"):
                    raise ExternalOperationError("EXTERNAL_BUSY")
            temporary = self.root / (".new-" + request_id)
            try:
                temporary.mkdir(mode=0o700)
            except OSError as exc:
                raise ExternalOperationError("EXTERNAL_INVALID_STATE") from exc
            try:
                now = int(time.time())
                self._write_new(temporary / "request.json", requested)
                accepted = {"format": 1, "request_id": request_id, "phase": "accepted",
                            "created_at": now, "updated_at": now, "error": None}
                self._write_new(temporary / "status.json", accepted)
                self._write_lock_new(temporary / "status.lock")
                self._sync(temporary)
                os.rename(temporary, directory)
                self._sync(self.root)
            except BaseException:
                if temporary.exists() and temporary.is_dir():
                    for child in temporary.iterdir():
                        child.unlink()
                    temporary.rmdir()
                raise
        finally:
            os.close(lock_fd)
        service = "sovagrid-external-agent-apply@" + request_id + ".service"
        try:
            result = self.run(["/usr/bin/systemctl", "start", "--no-block", service],
                              stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, timeout=15, check=False)
        except subprocess.TimeoutExpired:
            return self._change_status(directory, request_id, phase="uncertain",
                                       error="START_UNCERTAIN")
        except OSError:
            return self._change_status(directory, request_id, phase="failed",
                                       error="START_FAILED")
        if result.returncode != 0:
            return self._change_status(directory, request_id, phase="uncertain",
                                       error="START_UNCERTAIN")
        return self.status(request_id)

    def status(self, request_id: str) -> dict:
        if not canonical_id(request_id):
            raise ExternalOperationError("EXTERNAL_INVALID_REQUEST")
        self._base()
        directory = self.root / request_id
        if not directory.exists() and not directory.is_symlink():
            raise ExternalOperationError("EXTERNAL_NOT_FOUND")
        self._directory(directory)
        self._request(directory, request_id)
        value = self._status(directory, request_id)
        now = int(time.time())
        if value["phase"] in ("accepted", "running"):
            # A broker crash between durable rename and systemctl start leaves
            # an accepted request. A dead unit after reboot can leave running.
            # Read-only status never restarts the one-shot apply. Let --no-block
            # activation settle before declaring an accepted request uncertain.
            if value["phase"] == "accepted" and now - value["updated_at"] < 30:
                return value
            if now - value["created_at"] > 1200:
                return self._change_status(directory, request_id, phase="uncertain",
                                           error="RECOVERY_REQUIRED",
                                           from_phases=("accepted", "running"))
            service = "sovagrid-external-agent-apply@" + request_id + ".service"
            try:
                state = self.run(["/usr/bin/systemctl", "show", "-P", "ActiveState", service],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=subprocess.DEVNULL, timeout=5, check=False)
            except (OSError, subprocess.TimeoutExpired):
                return value
            if state.returncode == 0 and state.stdout in (b"inactive\n", b"failed\n"):
                return self._change_status(directory, request_id, phase="uncertain",
                                           error="RECOVERY_REQUIRED",
                                           from_phases=("accepted", "running"))
        return value

    def list(self) -> list[dict]:
        self._base()
        items = [item for item in self.root.iterdir() if canonical_id(item.name)]
        if len(items) > MAX_OPERATIONS:
            raise ExternalOperationError("EXTERNAL_OPERATION_LIMIT")
        records = [self.status(item.name) for item in items]
        return sorted(records, key=lambda value: (value["created_at"], value["request_id"]),
                      reverse=True)[:64]
