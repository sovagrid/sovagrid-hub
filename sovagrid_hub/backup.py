# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Root-private, consistent Hub-state snapshots for the Blueprint layout.

This is a Hub *data* backup, not a complete host restore.  The SQLite backup
itself runs with the Hub UID so a replaced database path cannot make a root
process read an unrelated host secret.  The root parent then publishes the
finished snapshot outside the Hub container's bind mount.
"""

from __future__ import annotations

from contextlib import closing
from contextlib import contextmanager
from dataclasses import dataclass
import ctypes
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import signal
import sqlite3
import stat
import subprocess
import sys
import threading
import time
from urllib.parse import quote
import uuid

from .amnezia_actions import TARGETS as AMNEZIA_TARGETS
from .amnezia_actions import status_command as amnezia_status_command
from .service_actions import status_command as service_status_command


MAX_DATABASE_BYTES = 4 * 1024**3
MAX_TOKEN_BYTES = 128
MAX_MANIFEST_BYTES = 2048
MAX_RESTORE_PLAN_BYTES = 4096
SNAPSHOT_SECONDS = 180
MAX_SNAPSHOTS = 1000
FREE_MARGIN_BYTES = 16 * 1024**2
TOKEN = re.compile(rb"[0-9]{5,20}:[A-Za-z0-9_-]{30,80}\n?\Z")
SHA = re.compile(r"[0-9a-f]{64}\Z")


class BackupError(RuntimeError):
    """Fixed, secret-free failure code."""


@dataclass(frozen=True)
class Layout:
    parent: Path = Path("/var/lib/sovagrid")
    data: Path = Path("/var/lib/sovagrid/hub")
    backups: Path = Path("/var/lib/sovagrid/backups")
    external_token: Path = Path("/etc/sovagrid-hub/bot.token")


def _directory(path: Path, uid: int, gid: int, mode: int) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise BackupError("DIRECTORY_UNAVAILABLE") from exc
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != uid or info.st_gid != gid or
            stat.S_IMODE(info.st_mode) != mode):
        raise BackupError("UNSAFE_DIRECTORY")


def _regular(path: Path, uid: int, gid: int, mode: int, maximum: int) -> int:
    try:
        info = path.lstat()
    except OSError as exc:
        raise BackupError("FILE_UNAVAILABLE") from exc
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_gid != gid or
            info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != mode or
            not 0 < info.st_size <= maximum):
        raise BackupError("UNSAFE_FILE")
    return info.st_size


def _read_file(path: Path, uid: int, gid: int, mode: int, maximum: int) -> bytes:
    size = _regular(path, uid, gid, mode, maximum)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid or
                    info.st_gid != gid or info.st_nlink != 1 or
                    stat.S_IMODE(info.st_mode) != mode or info.st_size != size):
                raise BackupError("FILE_CHANGED")
            raw = os.read(fd, maximum + 1)
        finally:
            os.close(fd)
    except OSError as exc:
        raise BackupError("FILE_UNAVAILABLE") from exc
    if len(raw) != size:
        raise BackupError("FILE_CHANGED")
    return raw


def _digest(path: Path, *, maximum: int) -> tuple[int, str]:
    size = path.stat().st_size
    if not 0 < size <= maximum:
        raise BackupError("SIZE_LIMIT")
    hashed = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            hashed.update(block)
    return size, hashed.hexdigest()


def _copy_private(source: Path, destination: Path, uid: int, gid: int,
                  maximum: int) -> None:
    """Copy a Hub-owned snapshot into a new root-owned inode without following links."""
    size = _regular(source, uid, gid, 0o600, maximum)
    try:
        source_fd = os.open(source, os.O_RDONLY | os.O_NONBLOCK |
                            os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            before = os.fstat(source_fd)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != uid or
                    before.st_gid != gid or before.st_nlink != 1 or
                    stat.S_IMODE(before.st_mode) != 0o600 or before.st_size != size):
                raise BackupError("FILE_CHANGED")
            output_fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                                os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            try:
                remaining = size
                while remaining:
                    block = os.read(source_fd, min(1024 * 1024, remaining))
                    if not block:
                        raise BackupError("FILE_CHANGED")
                    remaining -= len(block)
                    view = memoryview(block)
                    while view:
                        view = view[os.write(output_fd, view):]
                after = os.fstat(source_fd)
                if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
                        after.st_ctime_ns) != (before.st_dev, before.st_ino, before.st_size,
                                               before.st_mtime_ns, before.st_ctime_ns):
                    raise BackupError("FILE_CHANGED")
                os.fsync(output_fd)
            finally:
                os.close(output_fd)
        finally:
            os.close(source_fd)
    except OSError as exc:
        raise BackupError("FILE_UNAVAILABLE") from exc


def _json_bytes(value: dict) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def _sqlite_uri(path: Path, options: str) -> str:
    return "file:" + quote(str(path), safe="/") + "?" + options


def _unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate key")
        value[key] = item
    return value


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _exchange_directories(left: Path, right: Path) -> None:
    """Atomically exchange two Linux directories; never emulate with two renames."""
    if sys.platform != "linux":
        raise BackupError("ATOMIC_SWAP_UNAVAILABLE")
    libc = ctypes.CDLL(None, use_errno=True)
    try:
        renameat2 = libc.renameat2
    except AttributeError as exc:
        raise BackupError("ATOMIC_SWAP_UNAVAILABLE") from exc
    renameat2.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                          ctypes.c_char_p, ctypes.c_uint)
    renameat2.restype = ctypes.c_int
    if renameat2(-100, os.fsencode(left), -100, os.fsencode(right), 2) != 0:
        reason = ctypes.get_errno()
        if reason in (errno.ENOSYS, errno.EINVAL, errno.EXDEV, errno.EBUSY):
            raise BackupError("ATOMIC_SWAP_UNAVAILABLE")
        raise BackupError("RESTORE_SWAP_FAILED")


def _fingerprint_file(path: Path, uid: int, gid: int, maximum: int) -> dict:
    """Include inode metadata so a same-content replacement invalidates a review."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            before = os.fstat(fd)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != uid or
                    before.st_gid != gid or before.st_nlink != 1 or
                    stat.S_IMODE(before.st_mode) != 0o600 or
                    not 0 <= before.st_size <= maximum):
                raise BackupError("UNSAFE_FILE")
            digest = hashlib.sha256()
            remaining = before.st_size
            while remaining:
                block = os.read(fd, min(1024 * 1024, remaining))
                if not block:
                    raise BackupError("FILE_CHANGED")
                remaining -= len(block)
                digest.update(block)
            after = os.fstat(fd)
            fields = lambda value: (value.st_dev, value.st_ino, value.st_size,
                                    value.st_mtime_ns, value.st_ctime_ns)
            if fields(before) != fields(after):
                raise BackupError("FILE_CHANGED")
            return {"device": before.st_dev, "inode": before.st_ino,
                    "size": before.st_size, "mtime_ns": before.st_mtime_ns,
                    "ctime_ns": before.st_ctime_ns, "sha256": digest.hexdigest()}
        finally:
            os.close(fd)
    except OSError as exc:
        raise BackupError("FILE_UNAVAILABLE") from exc


class HubBackups:
    def __init__(self, *, layout: Layout = Layout(), require_root: bool = True,
                 hub_uid: int | None = None, hub_gid: int | None = None):
        self.layout = layout
        self.require_root = require_root
        # The restore orchestrator holds the update lock across Docker stop,
        # snapshot, exchange and restart. Its calls back into this class must
        # reuse that lock rather than deadlock on a second open file description.
        self._restore_lock_depth = 0
        self._restore_lock_owner = None
        self.root_uid = 0 if require_root else os.geteuid()
        self.root_gid = 0 if require_root else os.getegid()
        if require_root:
            if (os.getuid(), os.geteuid(), os.getgid(), os.getegid()) != (0, 0, 0, 0):
                raise BackupError("ROOT_REQUIRED")
            if layout != Layout():
                raise BackupError("INVALID_LAYOUT")
            try:
                account = pwd.getpwnam("sovagrid-hub")
            except KeyError as exc:
                raise BackupError("HUB_IDENTITY_CHANGED") from exc
            if (account.pw_uid, account.pw_gid) != (10001, 10001):
                raise BackupError("HUB_IDENTITY_CHANGED")
            self.hub_uid, self.hub_gid = 10001, 10001
        else:
            self.hub_uid = os.geteuid() if hub_uid is None else hub_uid
            self.hub_gid = os.getegid() if hub_gid is None else hub_gid
        if (layout.data.parent != layout.parent or layout.backups.parent != layout.parent or
                any(not path.is_absolute() for path in
                    (layout.parent, layout.data, layout.backups, layout.external_token))):
            raise BackupError("INVALID_LAYOUT")

    def _source(self) -> None:
        _directory(self.layout.parent, self.root_uid, self.root_gid, 0o700)
        _directory(self.layout.data, self.hub_uid, self.hub_gid, 0o700)
        _regular(self.layout.data / "hub.sqlite", self.hub_uid, self.hub_gid,
                 0o600, MAX_DATABASE_BYTES)

    def _backups(self, *, create: bool) -> None:
        _directory(self.layout.parent, self.root_uid, self.root_gid, 0o700)
        if create and not self.layout.backups.exists() and not self.layout.backups.is_symlink():
            try:
                self.layout.backups.mkdir(mode=0o700)
            except FileExistsError:
                pass
            _fsync_dir(self.layout.parent)
        _directory(self.layout.backups, self.root_uid, self.root_gid, 0o700)

    def _token_source(self, data_dir: Path, *, include_external: bool = True) -> tuple[str, Path, int, int, int] | None:
        managed = data_dir / "telegram-bot-token"
        external = self.layout.external_token
        present_managed = managed.exists() or managed.is_symlink()
        present_external = include_external and (external.exists() or external.is_symlink())
        if present_managed and present_external:
            raise BackupError("TOKEN_SOURCE_AMBIGUOUS")
        if present_managed:
            return ("managed", managed, self.hub_uid, self.hub_gid, 0o600)
        if present_external:
            if self.require_root:
                _directory(external.parent, 0, self.hub_gid, 0o750)
            return ("external", external, self.root_uid, self.hub_gid, 0o640)
        return None

    def _token_bytes(self, source: tuple[str, Path, int, int, int] | None) -> bytes | None:
        if source is None:
            return None
        _, path, uid, gid, mode = source
        raw = _read_file(path, uid, gid, mode, MAX_TOKEN_BYTES)
        if TOKEN.fullmatch(raw) is None:
            raise BackupError("INVALID_TOKEN")
        return raw

    def _snapshot_worker(self, stage: Path, data_dir: Path | None = None,
                         expected: tuple[str | None, bytes | None] | None = None,
                         reserve_second_copy: bool = True) -> None:
        """Run only as the Hub UID; source paths can be modified by that UID."""
        if os.geteuid() != self.hub_uid or os.getegid() != self.hub_gid:
            raise BackupError("HUB_IDENTITY_CHANGED")
        data_dir = self.layout.data if data_dir is None else data_dir
        if expected is None:
            source = self._token_source(data_dir)
            token_before = self._token_bytes(source)
            source_name = None if source is None else source[0]
        else:
            source_name, token_before = expected
            managed = self._token_source(data_dir, include_external=False)
            if ((source_name == "managed") != (managed is not None) or
                    (managed is not None and self._token_bytes(managed) != token_before)):
                raise BackupError("TOKEN_CHANGED")
        db_path = data_dir / "hub.sqlite"
        _regular(db_path, self.hub_uid, self.hub_gid, 0o600, MAX_DATABASE_BYTES)
        uri = _sqlite_uri(db_path, "mode=ro")
        with closing(sqlite3.connect(uri, uri=True, timeout=10)) as db:
            page_size = db.execute("PRAGMA page_size").fetchone()[0]
            if type(page_size) is not int or not 512 <= page_size <= 65536:
                raise BackupError("INVALID_DATABASE")
            page_count = db.execute("PRAGMA page_count").fetchone()[0]
            if (type(page_count) is not int or not 0 < page_count <=
                    MAX_DATABASE_BYTES // page_size):
                raise BackupError("SIZE_LIMIT")
            projected = page_size * page_count
            space = os.statvfs(stage)
            copies = 2 if reserve_second_copy else 1
            if space.f_bavail * space.f_frsize < copies * projected + FREE_MARGIN_BYTES:
                raise BackupError("INSUFFICIENT_SPACE")
            output = stage / "hub.sqlite"
            with closing(sqlite3.connect(output)) as copy:
                def progress(_status, _remaining, total):
                    if total * page_size > MAX_DATABASE_BYTES:
                        raise BackupError("SIZE_LIMIT")
                db.backup(copy, pages=256, progress=progress, sleep=0.05)
        os.chmod(output, 0o600)
        if expected is None:
            token_after_source = self._token_source(data_dir)
            token_after = self._token_bytes(token_after_source)
            if source != token_after_source or token_before != token_after:
                raise BackupError("TOKEN_CHANGED")
        else:
            managed = self._token_source(data_dir, include_external=False)
            if ((source_name == "managed") != (managed is not None) or
                    (managed is not None and self._token_bytes(managed) != token_before)):
                raise BackupError("TOKEN_CHANGED")
        if token_before is not None:
            token = stage / (source_name + "-telegram-bot-token")
            fd = os.open(token, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            try:
                with os.fdopen(fd, "wb") as stream:
                    stream.write(token_before)
                    stream.flush()
                    os.fsync(stream.fileno())
            except Exception:
                raise
        _check_database(output)
        _check_token_database(output, token_before)
        if set(path.name for path in stage.iterdir()) != (
                {"hub.sqlite"} | ({source_name + "-telegram-bot-token"}
                                  if token_before is not None else set())):
            raise BackupError("UNEXPECTED_SNAPSHOT_FILE")
        fd = os.open(output, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        _fsync_dir(stage)

    def _run_worker(self, stage: Path) -> None:
        if not self.require_root:
            self._snapshot_worker(stage)
            return
        # The parent directory is root:root 0700. Chroot to the already opened
        # Hub data directory before dropping privileges; SQLite then resolves
        # both the database and its WAL without traversing that parent.
        source_before = self._token_source(self.layout.data)
        token_before = self._token_bytes(source_before)
        source_name = None if source_before is None else source_before[0]
        same_device = (self.layout.data.stat().st_dev ==
                       self.layout.backups.stat().st_dev)
        data_fd = os.open(self.layout.data, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            child = os.fork()
        except BaseException:
            os.close(data_fd)
            raise
        if child == 0:
            try:
                os.fchdir(data_fd)
                os.close(data_fd)
                os.chroot(".")
                os.chdir("/")
                os.setgroups([])
                os.setgid(self.hub_gid)
                os.setuid(self.hub_uid)
                self._snapshot_worker(Path("/") / stage.name, Path("/"),
                                      (source_name, token_before), same_device)
            except BaseException:
                os._exit(2)
            os._exit(0)
        os.close(data_fd)
        deadline = time.monotonic() + SNAPSHOT_SECONDS
        while True:
            finished, status = os.waitpid(child, os.WNOHANG)
            if finished:
                if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
                    raise BackupError("SNAPSHOT_FAILED")
                source_after = self._token_source(self.layout.data)
                token_after = self._token_bytes(source_after)
                if source_before != source_after or token_before != token_after:
                    raise BackupError("TOKEN_CHANGED")
                return
            if time.monotonic() >= deadline:
                os.kill(child, signal.SIGKILL)
                os.waitpid(child, 0)
                raise BackupError("SNAPSHOT_TIMEOUT")
            time.sleep(0.05)

    def create(self, *, identity: str | None = None) -> dict:
        # A root broker may reserve the exact result ID before starting a
        # long snapshot. Replaying its request can then inspect the same ID
        # rather than silently creating a second copy after a lost reply.
        if identity is not None and not _canonical_id(identity):
            raise BackupError("INVALID_ID")
        self._source()
        self._backups(create=True)
        existing = sum(_canonical_id(item.name) for item in self.layout.backups.iterdir())
        if existing >= MAX_SNAPSHOTS:
            raise BackupError("TOO_MANY_SNAPSHOTS")
        database_size = (self.layout.data / "hub.sqlite").stat().st_size
        data_space = os.statvfs(self.layout.data)
        backup_space = os.statvfs(self.layout.backups)
        data_available = data_space.f_bavail * data_space.f_frsize
        backup_available = backup_space.f_bavail * backup_space.f_frsize
        if self.layout.data.stat().st_dev == self.layout.backups.stat().st_dev:
            enough = data_available >= 2 * database_size + FREE_MARGIN_BYTES
        else:
            enough = (data_available >= database_size + FREE_MARGIN_BYTES and
                      backup_available >= database_size + FREE_MARGIN_BYTES)
        if not enough:
            raise BackupError("INSUFFICIENT_SPACE")
        identity = str(uuid.uuid4()) if identity is None else identity
        stage = self.layout.data / (".backup-" + identity)
        candidate = self.layout.backups / (".new-" + identity)
        final = self.layout.backups / identity
        if any(path.exists() or path.is_symlink() for path in (stage, candidate, final)):
            raise BackupError("BACKUP_ID_IN_USE")
        try:
            stage.mkdir(mode=0o700)
            os.chown(stage, self.hub_uid, self.hub_gid)
            stage_inode = stage.lstat()
            self._run_worker(stage)
            _directory(stage, self.hub_uid, self.hub_gid, 0o700)
            current_inode = stage.lstat()
            if (stage_inode.st_dev, stage_inode.st_ino) != (
                    current_inode.st_dev, current_inode.st_ino):
                raise BackupError("DIRECTORY_CHANGED")
            staged_bytes = _regular(stage / "hub.sqlite", self.hub_uid,
                                    self.hub_gid, 0o600, MAX_DATABASE_BYTES)
            destination_space = os.statvfs(self.layout.backups)
            if (destination_space.f_bavail * destination_space.f_frsize <
                    staged_bytes + FREE_MARGIN_BYTES):
                raise BackupError("INSUFFICIENT_SPACE")
            # Never transfer Hub-owned inodes into the published backup. The Hub
            # process might still hold an open descriptor to one of those inodes.
            candidate.mkdir(mode=0o700)
            for path in stage.iterdir():
                if path.name not in ("hub.sqlite", "managed-telegram-bot-token",
                                     "external-telegram-bot-token"):
                    raise BackupError("UNEXPECTED_SNAPSHOT_FILE")
                _copy_private(path, candidate / path.name, self.hub_uid, self.hub_gid,
                              MAX_DATABASE_BYTES if path.name == "hub.sqlite" else MAX_TOKEN_BYTES)
            shutil.rmtree(stage)
            _fsync_dir(self.layout.data)
            manifest = self._manifest(identity, candidate)
            token_info = manifest["telegram_token"]
            token_raw = (None if token_info is None else
                         _read_file(candidate / (token_info["source"] + "-telegram-bot-token"),
                                    self.root_uid, self.root_gid, 0o600, MAX_TOKEN_BYTES))
            _check_database(candidate / "hub.sqlite")
            _check_token_database(candidate / "hub.sqlite", token_raw)
            raw = _json_bytes(manifest)
            if len(raw) > MAX_MANIFEST_BYTES:
                raise BackupError("INVALID_MANIFEST")
            fd = os.open(candidate / "manifest.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as output:
                output.write(raw)
                output.flush()
                os.fsync(output.fileno())
            _fsync_dir(candidate)
            os.replace(candidate, final)
            _fsync_dir(self.layout.backups)
            return {"id": identity, "created_at": manifest["created_at"],
                    "database_bytes": manifest["database"]["size"],
                    "telegram_token_included": manifest["telegram_token"] is not None}
        except Exception:
            for path in (stage, candidate):
                if path.exists() and not path.is_symlink():
                    shutil.rmtree(path)
            raise

    def _manifest(self, identity: str, directory: Path) -> dict:
        db_size, db_hash = _digest(directory / "hub.sqlite", maximum=MAX_DATABASE_BYTES)
        token = None
        for source in ("managed", "external"):
            token_file = directory / (source + "-telegram-bot-token")
            if token_file.exists():
                if token is not None:
                    raise BackupError("TOKEN_SOURCE_AMBIGUOUS")
                token_size, token_hash = _digest(token_file, maximum=MAX_TOKEN_BYTES)
                token = {"source": source, "size": token_size, "sha256": token_hash}
        return {"format": 1, "id": identity, "created_at": int(time.time()),
                "database": {"size": db_size, "sha256": db_hash},
                "telegram_token": token}

    def verify(self, identity: str) -> dict:
        self._backups(create=False)
        if not _canonical_id(identity):
            raise BackupError("INVALID_ID")
        directory = self.layout.backups / identity
        _directory(directory, self.root_uid, self.root_gid, 0o700)
        raw = _read_file(directory / "manifest.json", self.root_uid, self.root_gid,
                         0o600, MAX_MANIFEST_BYTES)
        try:
            value = json.loads(raw, object_pairs_hook=_unique)
        except (UnicodeError, ValueError) as exc:
            raise BackupError("INVALID_MANIFEST") from exc
        if (not isinstance(value, dict) or set(value) !=
                {"format", "id", "created_at", "database", "telegram_token"} or
                type(value["format"]) is not int or value["format"] != 1 or
                value["id"] != identity or type(value["created_at"]) is not int or
                not 1 <= value["created_at"] <= 253402300799 or
                raw != _json_bytes(value)):
            raise BackupError("INVALID_MANIFEST")
        expected = value["database"]
        if (not isinstance(expected, dict) or set(expected) != {"size", "sha256"} or
                type(expected["size"]) is not int or not 0 < expected["size"] <= MAX_DATABASE_BYTES or
                not isinstance(expected["sha256"], str) or SHA.fullmatch(expected["sha256"]) is None):
            raise BackupError("INVALID_MANIFEST")
        database = directory / "hub.sqlite"
        _regular(database, self.root_uid, self.root_gid, 0o600, MAX_DATABASE_BYTES)
        if _digest(database, maximum=MAX_DATABASE_BYTES) != (expected["size"], expected["sha256"]):
            raise BackupError("HASH_MISMATCH")
        expected_token = value["telegram_token"]
        if expected_token is not None:
            if (not isinstance(expected_token, dict) or
                    set(expected_token) != {"source", "size", "sha256"} or
                    expected_token["source"] not in ("managed", "external") or
                    type(expected_token["size"]) is not int or
                    not 0 < expected_token["size"] <= MAX_TOKEN_BYTES or
                    not isinstance(expected_token["sha256"], str) or
                    SHA.fullmatch(expected_token["sha256"]) is None):
                raise BackupError("INVALID_MANIFEST")
            token_path = directory / (expected_token["source"] + "-telegram-bot-token")
            _regular(token_path, self.root_uid, self.root_gid, 0o600, MAX_TOKEN_BYTES)
            if _digest(token_path, maximum=MAX_TOKEN_BYTES) != (
                    expected_token["size"], expected_token["sha256"]):
                raise BackupError("HASH_MISMATCH")
        if set(path.name for path in directory.iterdir()) != (
                {"manifest.json", "hub.sqlite"} |
                ({expected_token["source"] + "-telegram-bot-token"}
                 if expected_token is not None else set())):
            raise BackupError("UNEXPECTED_SNAPSHOT_FILE")
        _check_database(database)
        token_raw = (None if expected_token is None else
                     _read_file(token_path, self.root_uid, self.root_gid,
                                0o600, MAX_TOKEN_BYTES))
        _check_token_database(database, token_raw)
        return {"id": identity, "created_at": value["created_at"],
                "database_bytes": expected["size"],
                "telegram_token_included": expected_token is not None,
                "verified": True}

    def list(self) -> dict:
        self._backups(create=False)
        names = sorted((item.name for item in self.layout.backups.iterdir()
                        if _canonical_id(item.name)), reverse=True)
        if len(names) > MAX_SNAPSHOTS:
            raise BackupError("TOO_MANY_SNAPSHOTS")
        return {"ids": names}

    @contextmanager
    def _restore_lock(self):
        """Serialize with both Blueprint update workers before touching Hub data."""
        if not self.require_root:
            yield
            return
        owner = threading.get_ident()
        if self._restore_lock_depth and self._restore_lock_owner == owner:
            self._restore_lock_depth += 1
            try:
                yield
            finally:
                self._restore_lock_depth -= 1
            return
        root = Path("/opt/sovagrid-candidates")
        _directory(root, 0, 0, 0o700)
        try:
            fd = os.open(root / ".lock", os.O_RDWR | os.O_CREAT |
                         os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            try:
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or
                        info.st_gid != 0 or info.st_nlink != 1 or
                        stat.S_IMODE(info.st_mode) != 0o600):
                    raise BackupError("UNSAFE_LOCK")
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError as exc:
                    raise BackupError("UPDATE_BUSY") from exc
                self._restore_lock_owner = owner
                self._restore_lock_depth = 1
                try:
                    yield
                finally:
                    self._restore_lock_depth = 0
                    self._restore_lock_owner = None
            finally:
                os.close(fd)
        except OSError as exc:
            raise BackupError("UNSAFE_LOCK") from exc

    def _require_offline(self) -> None:
        if not self.require_root:
            return
        if os.path.ismount(self.layout.data):
            raise BackupError("DATA_MOUNTPOINT")
        command = ["docker", "container", "ls", "-a", "--quiet", "--filter",
                   "label=com.docker.compose.project=sovagrid", "--filter",
                   "label=com.docker.compose.service=hub"]
        try:
            listing = subprocess.run(command, capture_output=True, text=True,
                                     timeout=10, check=False)
            if listing.returncode != 0:
                raise BackupError("HUB_STATE_UNAVAILABLE")
            ids = listing.stdout.split()
            if not ids:
                raise BackupError("HUB_CONTAINER_MISSING")
            for identity in ids:
                state = subprocess.run(
                    ["docker", "inspect", "--format",
                     "{{.State.Running}} {{.State.Paused}} {{.State.Restarting}}", identity],
                    capture_output=True, text=True, timeout=10, check=False)
                if state.returncode != 0 or state.stdout.strip() not in (
                        "false false false", "False False False"):
                    raise BackupError("HUB_NOT_STOPPED")
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise BackupError("HUB_STATE_UNAVAILABLE") from exc

    def _source_fingerprint(self) -> dict:
        self._source()
        source = self._token_source(self.layout.data)
        if source is not None and source[0] == "external":
            raise BackupError("EXTERNAL_TOKEN_RESTORE_UNSUPPORTED")
        allowed = {"hub.sqlite", "hub.sqlite-wal", "hub.sqlite-shm",
                   "telegram-bot-token"}
        names = {item.name for item in self.layout.data.iterdir()}
        if not names <= allowed or "hub.sqlite" not in names:
            raise BackupError("UNEXPECTED_DATA_FILE")
        if ("telegram-bot-token" in names) != (source is not None):
            raise BackupError("UNSAFE_FILE")
        files = {}
        for name in sorted(names):
            maximum = MAX_TOKEN_BYTES if name == "telegram-bot-token" else MAX_DATABASE_BYTES
            files[name] = _fingerprint_file(self.layout.data / name, self.hub_uid,
                                            self.hub_gid, maximum)
        return files

    def _restore_target(self, identity: str) -> tuple[dict, bytes]:
        self.verify(identity)
        directory = self.layout.backups / identity
        raw = _read_file(directory / "manifest.json", self.root_uid, self.root_gid,
                         0o600, MAX_MANIFEST_BYTES)
        manifest = json.loads(raw)
        token = manifest["telegram_token"]
        if token is not None and token["source"] == "external":
            raise BackupError("EXTERNAL_TOKEN_RESTORE_UNSUPPORTED")
        return manifest, raw

    def _plan_path(self, identity: str) -> Path:
        if not _canonical_id(identity):
            raise BackupError("INVALID_ID")
        return self.layout.backups / (".restore-plan-" + identity + ".json")

    def _read_plan(self, identity: str) -> dict:
        raw = _read_file(self._plan_path(identity), self.root_uid, self.root_gid,
                         0o600, MAX_RESTORE_PLAN_BYTES)
        try:
            value = json.loads(raw, object_pairs_hook=_unique)
        except (UnicodeError, ValueError) as exc:
            raise BackupError("INVALID_RESTORE_PLAN") from exc
        if (not isinstance(value, dict) or set(value) !=
                {"format", "id", "target_id", "safety_id", "target_manifest_sha256",
                 "source_files", "restored_files"} or type(value["format"]) is not int or
                value["format"] != 2 or value["id"] != identity or
                not _canonical_id(value["target_id"]) or
                not _canonical_id(value["safety_id"]) or
                not isinstance(value["target_manifest_sha256"], str) or
                SHA.fullmatch(value["target_manifest_sha256"]) is None or
                not isinstance(value["source_files"], dict) or
                (value["restored_files"] is not None and
                 not isinstance(value["restored_files"], dict)) or
                raw != _json_bytes(value)):
            raise BackupError("INVALID_RESTORE_PLAN")
        return value

    def _write_plan(self, identity: str, value: dict, *, replace: bool) -> None:
        raw = _json_bytes(value)
        if len(raw) > MAX_RESTORE_PLAN_BYTES:
            raise BackupError("INVALID_RESTORE_PLAN")
        destination = self._plan_path(identity)
        temporary = (self.layout.backups / (".restore-plan-" + identity +
                                            "." + uuid.uuid4().hex + ".tmp")) if replace else destination
        try:
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            with os.fdopen(fd, "wb") as output:
                output.write(raw)
                output.flush()
                os.fsync(output.fileno())
            if replace:
                # Only an already validated root-private plan may be replaced.
                self._read_plan(identity)
                os.replace(temporary, destination)
            _fsync_dir(self.layout.backups)
        finally:
            if replace and temporary.exists():
                temporary.unlink()

    def plan_restore(self, target_id: str) -> dict:
        """Make an offline safety snapshot and bind review to exact source inodes."""
        with self._restore_lock():
            self._require_offline()
            self._backups(create=True)
            target, manifest_raw = self._restore_target(target_id)
            self._source_fingerprint()
            self._require_compatible_token(target_id, target)
            safety = self.create()
            source_files = self._source_fingerprint()
            self._require_offline()
            identity = str(uuid.uuid4())
            plan = {"format": 2, "id": identity, "target_id": target_id,
                    "safety_id": safety["id"],
                    "target_manifest_sha256": hashlib.sha256(manifest_raw).hexdigest(),
                    "source_files": source_files, "restored_files": None}
            self._write_plan(identity, plan, replace=False)
            return {"plan_id": identity, "target_id": target_id,
                    "safety_id": safety["id"], "database_bytes": target["database"]["size"],
                    "telegram_token_included": target["telegram_token"] is not None,
                    "hub_must_remain_stopped": True}

    def _checked_plan(self, plan_id: str) -> tuple[dict, dict]:
        self._backups(create=False)
        plan = self._read_plan(plan_id)
        self.verify(plan["safety_id"])
        target, raw = self._restore_target(plan["target_id"])
        if hashlib.sha256(raw).hexdigest() != plan["target_manifest_sha256"]:
            raise BackupError("RESTORE_TARGET_CHANGED")
        return plan, target

    def _require_compatible_token(self, target_id: str, target: dict) -> None:
        if target["telegram_token"] is None:
            return
        current = self._token_source(self.layout.data)
        if current is None or current[0] != "managed":
            raise BackupError("TOKEN_CHANGE_RESTORE_UNSUPPORTED")
        target_raw = _read_file(self.layout.backups / target_id /
                                "managed-telegram-bot-token", self.root_uid,
                                self.root_gid, 0o600, MAX_TOKEN_BYTES)
        if self._token_bytes(current) != target_raw:
            raise BackupError("TOKEN_CHANGE_RESTORE_UNSUPPORTED")

    def _neutralize_restored_work(self, stage: Path, safety_id: str,
                                   target: dict) -> None:
        """Prevent restored jobs, approvals, sessions and alerts from replaying."""
        db_path = stage / "hub.sqlite"
        now = int(time.time())
        with closing(sqlite3.connect(db_path, timeout=10)) as db:
            db.execute("PRAGMA journal_mode=DELETE")
            db.execute("BEGIN IMMEDIATE")
            tables = {row[0] for row in db.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
            db.execute("UPDATE jobs SET state='cancelled',command='',completed_at=? WHERE state='queued'", (now,))
            db.execute("UPDATE jobs SET state='timed_out',command='',completed_at=?,exit_code=NULL,output='' WHERE state='delivered'", (now,))
            # A recent successful broker status from the backup must not arm
            # a fresh mutation immediately after restoring old server state.
            amnezia_hashes = {hashlib.sha256(amnezia_status_command(target).encode()).hexdigest()
                              for target in AMNEZIA_TARGETS}
            last_rowid = 0
            while True:
                rows = db.execute("""SELECT rowid,id,command_sha256,output FROM jobs
                                   WHERE source='web' AND state='succeeded' AND rowid>?
                                   ORDER BY rowid LIMIT 256""", (last_rowid,)).fetchall()
                if not rows:
                    break
                stale_ids = []
                for rowid, job_id, command_hash, output in rows:
                    if command_hash in amnezia_hashes:
                        stale_ids.append((now, job_id))
                        continue
                    try:
                        value = json.loads(output)
                        if (isinstance(value, dict) and value.get("action") == "status" and
                                isinstance(value.get("unit"), str) and
                                hashlib.sha256(service_status_command(value["unit"]).encode()).hexdigest()
                                == command_hash):
                            stale_ids.append((now, job_id))
                    except (TypeError, ValueError, UnicodeError):
                        continue
                if stale_ids:
                    db.executemany("""UPDATE jobs SET state='cancelled',output='',completed_at=?
                                   WHERE id=?""", stale_ids)
                last_rowid = rows[-1][0]
            db.execute("DELETE FROM pending_commands")
            for name in ("sessions", "ssh_grants"):
                if name in tables:
                    db.execute(f"DELETE FROM {name}")
            if "bot_pairing_requests" in tables:
                db.execute("DELETE FROM bot_pairing_requests WHERE state='pending'")
            if "incident_outbox" in tables:
                db.execute("""UPDATE incident_outbox SET dropped_at=?,lease_until=NULL
                           WHERE delivered_at IS NULL AND dropped_at IS NULL""", (now,))
            if "maintenance_deferred" in tables:
                db.execute("DELETE FROM maintenance_deferred")
            if target["telegram_token"] is not None:
                token_raw = _read_file(stage / "telegram-bot-token", self.hub_uid,
                                       self.hub_gid, 0o600, MAX_TOKEN_BYTES)
                token_hash = hashlib.sha256(token_raw.removesuffix(b"\n")).hexdigest()
                safety_db = self.layout.backups / safety_id / "hub.sqlite"
                with closing(sqlite3.connect(_sqlite_uri(safety_db, "mode=ro&immutable=1"),
                                             uri=True, timeout=5)) as old:
                    old_tables = {row[0] for row in old.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'")}
                    current_cursor = (old.execute(
                        "SELECT next_offset FROM telegram_update_cursors WHERE token_hash=?",
                        (token_hash,)).fetchone() if "telegram_update_cursors" in old_tables
                                      else None)
                db.execute("""CREATE TABLE IF NOT EXISTS telegram_update_cursors (
                           token_hash TEXT PRIMARY KEY, next_offset INTEGER NOT NULL,
                           updated_at INTEGER NOT NULL)""")
                restored_cursor = db.execute(
                    "SELECT next_offset FROM telegram_update_cursors WHERE token_hash=?",
                    (token_hash,)).fetchone()
                offsets = [row[0] for row in (current_cursor, restored_cursor) if row is not None]
                if offsets:
                    if any(type(offset) is not int or not 0 <= offset < 2**63 for offset in offsets):
                        raise BackupError("INVALID_TELEGRAM_CURSOR")
                    db.execute("""INSERT INTO telegram_update_cursors(token_hash,next_offset,updated_at)
                               VALUES(?,?,?) ON CONFLICT(token_hash) DO UPDATE SET
                               next_offset=excluded.next_offset,updated_at=excluded.updated_at""",
                               (token_hash, max(offsets), now))
            db.commit()
        _check_database(db_path)
        token_raw = (None if target["telegram_token"] is None else
                     _read_file(stage / "telegram-bot-token", self.hub_uid,
                                self.hub_gid, 0o600, MAX_TOKEN_BYTES))
        _check_token_database(db_path, token_raw)

    def _copy_restore_target(self, plan_id: str, plan: dict, target: dict) -> tuple[Path, dict]:
        stage = self.layout.parent / (".restore-" + plan_id)
        if stage.exists() or stage.is_symlink():
            raise BackupError("RESTORE_RECOVERY_EXISTS")
        space = os.statvfs(self.layout.parent)
        if (space.f_bavail * space.f_frsize <
                target["database"]["size"] + FREE_MARGIN_BYTES):
            raise BackupError("INSUFFICIENT_SPACE")
        stage.mkdir(mode=0o700)
        try:
            os.chown(stage, self.hub_uid, self.hub_gid)
            source = self.layout.backups / plan["target_id"]
            names = ["hub.sqlite"]
            if target["telegram_token"] is not None:
                names.append("managed-telegram-bot-token")
            for name in names:
                destination = stage / ("telegram-bot-token" if name != "hub.sqlite" else name)
                _copy_private(source / name, destination, self.root_uid, self.root_gid,
                              MAX_TOKEN_BYTES if name != "hub.sqlite" else MAX_DATABASE_BYTES)
                os.chown(destination, self.hub_uid, self.hub_gid)
            _directory(stage, self.hub_uid, self.hub_gid, 0o700)
            self._matches_target(stage, target)
            self._neutralize_restored_work(stage, plan["safety_id"], target)
            restored_files = self._fingerprint_directory(stage)
            if set(restored_files) != ({"hub.sqlite"} |
                    ({"telegram-bot-token"} if target["telegram_token"] else set())):
                raise BackupError("UNEXPECTED_DATA_FILE")
            _fsync_dir(stage)
            _fsync_dir(self.layout.parent)
            return stage, restored_files
        except Exception:
            shutil.rmtree(stage)
            raise

    def _matches_target(self, directory: Path, target: dict) -> None:
        _directory(directory, self.hub_uid, self.hub_gid, 0o700)
        expected = {"hub.sqlite"}
        token = target["telegram_token"]
        if token is not None:
            expected.add("telegram-bot-token")
        if {item.name for item in directory.iterdir()} != expected:
            raise BackupError("RESTORE_DATA_DRIFT")
        database = directory / "hub.sqlite"
        database_info = _fingerprint_file(database, self.hub_uid, self.hub_gid,
                                          MAX_DATABASE_BYTES)
        if (database_info["size"], database_info["sha256"]) != (
                target["database"]["size"], target["database"]["sha256"]):
            raise BackupError("RESTORE_DATA_DRIFT")
        token_raw = None
        if token is not None:
            token_file = directory / "telegram-bot-token"
            token_raw = _read_file(token_file, self.hub_uid, self.hub_gid,
                                   0o600, MAX_TOKEN_BYTES)
            if (len(token_raw), hashlib.sha256(token_raw).hexdigest()) != (
                    token["size"], token["sha256"]):
                raise BackupError("RESTORE_DATA_DRIFT")
        _check_database(database)
        _check_token_database(database, token_raw)

    def apply_restore(self, plan_id: str) -> dict:
        """Exchange a stopped Hub's whole data directory; retain old data for undo."""
        with self._restore_lock():
            self._require_offline()
            plan, target = self._checked_plan(plan_id)
            if self._source_fingerprint() != plan["source_files"]:
                raise BackupError("RESTORE_SOURCE_CHANGED")
            self._require_compatible_token(plan["target_id"], target)
            stage, restored_files = self._copy_restore_target(plan_id, plan, target)
            try:
                plan["restored_files"] = restored_files
                self._write_plan(plan_id, plan, replace=True)
                self._require_offline()
                if self._source_fingerprint() != plan["source_files"]:
                    raise BackupError("RESTORE_SOURCE_CHANGED")
                _exchange_directories(self.layout.data, stage)
            except Exception:
                shutil.rmtree(stage)
                raise
            try:
                _fsync_dir(self.layout.parent)
                if self._fingerprint_directory(self.layout.data) != restored_files:
                    raise BackupError("RESTORE_DATA_DRIFT")
                # The old directory is still at stage, including any WAL.
                if self._fingerprint_directory(stage) != plan["source_files"]:
                    raise BackupError("RESTORE_RECOVERY_CHANGED")
            except Exception as exc:
                try:
                    _exchange_directories(self.layout.data, stage)
                    _fsync_dir(self.layout.parent)
                    if self._source_fingerprint() != plan["source_files"]:
                        raise BackupError("RESTORE_RECOVERY_CHANGED")
                except Exception as rollback_exc:
                    raise BackupError("RESTORE_RECOVERY_REQUIRED") from rollback_exc
                raise BackupError("RESTORE_ROLLED_BACK") from exc
            return {"plan_id": plan_id, "target_id": plan["target_id"],
                    "safety_id": plan["safety_id"], "recovery_directory": str(stage),
                    "hub_must_remain_stopped": True, "restored": True}

    def _fingerprint_directory(self, directory: Path) -> dict:
        _directory(directory, self.hub_uid, self.hub_gid, 0o700)
        names = {item.name for item in directory.iterdir()}
        if not names <= {"hub.sqlite", "hub.sqlite-wal", "hub.sqlite-shm",
                         "telegram-bot-token"} or "hub.sqlite" not in names:
            raise BackupError("UNEXPECTED_DATA_FILE")
        return {name: _fingerprint_file(directory / name, self.hub_uid,
                                        self.hub_gid, MAX_TOKEN_BYTES if name ==
                                        "telegram-bot-token" else MAX_DATABASE_BYTES)
                for name in sorted(names)}

    def undo_restore(self, plan_id: str) -> dict:
        """Undo only an untouched, still-offline restore using its retained dir."""
        with self._restore_lock():
            self._require_offline()
            plan, target = self._checked_plan(plan_id)
            stage = self.layout.parent / (".restore-" + plan_id)
            if plan["restored_files"] is None:
                raise BackupError("INVALID_RESTORE_PLAN")
            if self._fingerprint_directory(stage) != plan["source_files"]:
                raise BackupError("RESTORE_RECOVERY_CHANGED")
            if self._fingerprint_directory(self.layout.data) != plan["restored_files"]:
                raise BackupError("RESTORE_DATA_DRIFT")
            _exchange_directories(self.layout.data, stage)
            try:
                _fsync_dir(self.layout.parent)
                if self._source_fingerprint() != plan["source_files"]:
                    raise BackupError("RESTORE_RECOVERY_CHANGED")
            except Exception as exc:
                try:
                    _exchange_directories(self.layout.data, stage)
                    _fsync_dir(self.layout.parent)
                except Exception as rollback_exc:
                    raise BackupError("RESTORE_RECOVERY_REQUIRED") from rollback_exc
                raise BackupError("RESTORE_ROLLED_BACK") from exc
            # Keep the target snapshot itself. Remove only the now-exchanged
            # staging directory and its one-use review record.
            try:
                shutil.rmtree(stage)
                self._plan_path(plan_id).unlink()
                _fsync_dir(self.layout.parent)
                _fsync_dir(self.layout.backups)
                cleanup_pending = False
            except OSError:
                cleanup_pending = True
            return {"plan_id": plan_id, "restored_previous_data": True,
                    "cleanup_pending": cleanup_pending,
                    "hub_must_remain_stopped": True}

    def finalize_restore(self, plan_id: str) -> dict:
        """Discard retained old files after an independently confirmed restart."""
        with self._restore_lock():
            plan, _target = self._checked_plan(plan_id)
            stage = self.layout.parent / (".restore-" + plan_id)
            if self._fingerprint_directory(stage) != plan["source_files"]:
                raise BackupError("RESTORE_RECOVERY_CHANGED")
            # The safety snapshot remains in backups. Never remove the active
            # data path here; the caller can invoke this while Hub is running.
            if (self.layout.data.stat().st_dev, self.layout.data.stat().st_ino) == (
                    stage.stat().st_dev, stage.stat().st_ino):
                raise BackupError("RESTORE_RECOVERY_CHANGED")
            try:
                shutil.rmtree(stage)
                self._plan_path(plan_id).unlink()
                _fsync_dir(self.layout.parent)
                _fsync_dir(self.layout.backups)
            except OSError as exc:
                raise BackupError("RESTORE_CLEANUP_FAILED") from exc
            return {"plan_id": plan_id, "finalized": True,
                    "safety_id": plan["safety_id"]}


def _canonical_id(value: object) -> bool:
    try:
        return isinstance(value, str) and str(uuid.UUID(value)) == value
    except (ValueError, AttributeError):
        return False


def _check_database(path: Path) -> None:
    try:
        with closing(sqlite3.connect(_sqlite_uri(path, "mode=ro&immutable=1"),
                                     uri=True, timeout=5)) as db:
            if db.execute("PRAGMA quick_check").fetchone() != ("ok",):
                raise BackupError("DATABASE_INTEGRITY")
            tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if not {"hub_users", "servers", "metrics", "jobs", "telegram_bot_info"} <= tables:
                raise BackupError("DATABASE_SCHEMA")
    except sqlite3.Error as exc:
        raise BackupError("DATABASE_INTEGRITY") from exc


def _check_token_database(path: Path, token: bytes | None) -> None:
    if token is not None and TOKEN.fullmatch(token) is None:
        raise BackupError("INVALID_TOKEN")
    try:
        with closing(sqlite3.connect(_sqlite_uri(path, "mode=ro&immutable=1"),
                                     uri=True, timeout=5)) as db:
            row = db.execute("SELECT token_hash FROM telegram_bot_info WHERE singleton=1").fetchone()
    except sqlite3.Error as exc:
        raise BackupError("DATABASE_INTEGRITY") from exc
    if row is not None:
        plain = None if token is None else token.removesuffix(b"\n")
        if plain is None or hashlib.sha256(plain).hexdigest() != row[0]:
            raise BackupError("TOKEN_DATABASE_MISMATCH")


def main(argv: list[str] | None = None) -> int:
    os.umask(0o077)
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) not in (1, 2) or args[0] not in (
            "create", "list", "verify", "plan-restore", "apply-restore", "undo-restore",
            "finalize-restore") or (
            args[0] in ("verify", "plan-restore", "apply-restore", "undo-restore",
                        "finalize-restore")) != (
                len(args) == 2):
        print(json.dumps({"ok": False, "error": "INVALID_ARGUMENTS"}))
        return 2
    try:
        manager = HubBackups()
        if args[0] == "create":
            result = manager.create()
        elif args[0] == "list":
            result = manager.list()
        elif args[0] == "verify":
            result = manager.verify(args[1])
        elif args[0] == "plan-restore":
            result = manager.plan_restore(args[1])
        elif args[0] == "apply-restore":
            result = manager.apply_restore(args[1])
        elif args[0] == "undo-restore":
            result = manager.undo_restore(args[1])
        else:
            result = manager.finalize_restore(args[1])
    except (BackupError, OSError, sqlite3.Error) as exc:
        code = str(exc) if isinstance(exc, BackupError) else "BACKUP_FAILED"
        print(json.dumps({"ok": False, "error": code}, separators=(",", ":")))
        return 2
    print(json.dumps({"ok": True, **result}, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
