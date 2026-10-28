# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Systemd socket broker for bounded, root-only Hub backup operations.

The Hub container sees only the Unix socket, never the backup directory.  A
create request reserves its result UUID on disk before taking the snapshot, so
a lost HTTP/socket response can be replayed without making a second backup.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
import subprocess
import sys
import time
import uuid

from .backup import (BackupError, HubBackups, _canonical_id, _directory,
                     _fsync_dir, _json_bytes, _read_file)
from .backup_restore import RestoreOrchestrator
from .public_settings import (PublicSettingsError, PublicSettingsExecutor,
                              validate_request as validate_public_request)
from .local_settings import (LocalSettingsExecutor,
                             validate_request as validate_local_request)


SOCKET_PATH = Path("/run/sovagrid-hub-backup/control.sock")
REQUESTS = Path("/var/lib/sovagrid/backups/.broker-requests")
MAX_REQUEST = 1024
MAX_RESPONSE = 65536
MAX_LEDGER = 256
PEER_UID = 10001
CREATE_INTERVAL_SECONDS = 300
WEB_MIN_FREE_BYTES = 1024**3
HOST_ID = re.compile(r"[0-9a-f]{32}\Z")
HOST_SHA = re.compile(r"[0-9a-f]{64}\Z")
HOST_ERROR = re.compile(r"[A-Z][A-Z0-9_]{1,63}\Z")
HOST_SCRIPT = Path("/opt/sovagrid-src/sovagrid-blueprint/deploy/host_backup.py")
HOST_OPERATION_SCRIPT = Path(
    "/opt/sovagrid-src/sovagrid-blueprint/deploy/host_backup_orchestrator.py")
HOST_PROTOCOL = "sovagrid-host-backup-v1"
HOST_OPERATION_PROTOCOL = "sovagrid-host-backup-operation-v1"


def _unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise BackupError("INVALID_REQUEST")
        value[key] = item
    return value


def _request(raw: bytes) -> dict:
    if not 0 < len(raw) <= MAX_REQUEST or not raw.endswith(b"\n"):
        raise BackupError("INVALID_REQUEST")
    try:
        value = json.loads(raw, object_pairs_hook=_unique)
    except (UnicodeError, ValueError) as exc:
        raise BackupError("INVALID_REQUEST") from exc
    if not isinstance(value, dict):
        raise BackupError("INVALID_REQUEST")
    action = value.get("action")
    if action == "list" and set(value) == {"action"}:
        return value
    if action == "verify" and set(value) == {"action", "id"} and _canonical_id(value["id"]):
        return value
    if (action == "create" and set(value) == {"action", "request_key"} and
            _canonical_id(value["request_key"])):
        return value
    if action == "restore_list" and set(value) == {"action"}:
        return value
    if (action in ("restore_status", "restore_recover") and
            set(value) == {"action", "request_id"} and
            _canonical_id(value["request_id"])):
        return value
    if (action == "restore_apply" and
            set(value) == {"action", "request_id", "target_id"} and
            _canonical_id(value["request_id"]) and
            _canonical_id(value["target_id"]) and
            value["request_id"] != value["target_id"]):
        return value
    if action in ("host_plan", "host_archives", "host_operations") and set(value) == {"action"}:
        return value
    if action == "host_verify" and set(value) == {"action", "id"} and isinstance(
            value["id"], str) and HOST_ID.fullmatch(value["id"]):
        return value
    if action in ("host_status", "host_recover") and set(value) == {"action", "request_id"} and isinstance(
            value["request_id"], str) and HOST_ID.fullmatch(value["request_id"]):
        return value
    if action == "host_start" and set(value) == {
            "action", "request_id", "expected_manifest_sha256"} and isinstance(
            value["request_id"], str) and HOST_ID.fullmatch(value["request_id"]) and isinstance(
            value["expected_manifest_sha256"], str) and HOST_SHA.fullmatch(
            value["expected_manifest_sha256"]):
        return value
    if action in ("public_status", "public_preview", "public_apply"):
        try:
            validated = validate_public_request(action.removeprefix("public_"),
                                                {key: item for key, item in value.items()
                                                 if key != "action"})
        except PublicSettingsError as exc:
            raise BackupError("INVALID_REQUEST") from exc
        return {"action": action, **validated}
    if action in ("local_status", "local_preview", "local_apply", "local_disable"):
        try:
            validated = validate_local_request(action.removeprefix("local_"),
                                               {key: item for key, item in value.items()
                                                if key != "action"})
        except PublicSettingsError as exc:
            raise BackupError("INVALID_REQUEST") from exc
        return {"action": action, **validated}
    raise BackupError("INVALID_REQUEST")


def _host_command(script: Path, *arguments: str, timeout: int = 120) -> dict:
    """Execute only the two installed root helpers; never a shell or caller path."""
    if script not in (HOST_SCRIPT, HOST_OPERATION_SCRIPT):
        raise BackupError("HOST_UNAVAILABLE")
    try:
        result = subprocess.run(["/usr/bin/python3", "-B", "-I", str(script), *arguments],
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise BackupError("HOST_UNAVAILABLE") from exc
    raw = result.stdout
    if not 0 < len(raw) <= MAX_RESPONSE or not raw.endswith(b"\n") or raw.count(b"\n") != 1:
        raise BackupError("HOST_UNAVAILABLE")
    try:
        value = json.loads(raw, object_pairs_hook=_unique)
    except (UnicodeError, ValueError) as exc:
        raise BackupError("HOST_UNAVAILABLE") from exc
    expected = HOST_PROTOCOL if script == HOST_SCRIPT else HOST_OPERATION_PROTOCOL
    if not isinstance(value, dict) or value.get("protocol") != expected or type(value.get("ok")) is not bool:
        raise BackupError("HOST_UNAVAILABLE")
    if result.returncode != 0 or value["ok"] is False:
        code = value.get("error")
        if (set(value) != {"ok", "protocol", "error"} or value["ok"] is not False or
                not isinstance(code, str) or HOST_ERROR.fullmatch(code) is None):
            raise BackupError("HOST_UNAVAILABLE")
        raise BackupError("HOST_" + code)
    return value


def _host_execute(payload: dict) -> dict:
    action = payload["action"]
    if action == "host_plan":
        source = _host_command(HOST_SCRIPT, "source", timeout=90)
        if (set(source) != {"ok", "protocol", "manifest_sha256"} or
                not isinstance(source["manifest_sha256"], str) or
                HOST_SHA.fullmatch(source["manifest_sha256"]) is None):
            raise BackupError("HOST_UNAVAILABLE")
        plan = _host_command(HOST_SCRIPT, "plan", timeout=60)
        if set(plan) != {"ok", "protocol", "layout", "active_units", "running_containers", "offline_ready"}:
            raise BackupError("HOST_UNAVAILABLE")
        return {"ok": True, "manifest_sha256": source["manifest_sha256"],
                "plan": {key: plan[key] for key in (
                    "layout", "active_units", "running_containers", "offline_ready")}}
    if action == "host_archives":
        value = _host_command(HOST_SCRIPT, "list")
        if set(value) != {"ok", "protocol", "archives"}:
            raise BackupError("HOST_UNAVAILABLE")
        return {"ok": True, "archives": value["archives"]}
    if action == "host_verify":
        value = _host_command(HOST_SCRIPT, "verify", payload["id"], timeout=420)
        if set(value) != {"ok", "protocol", "archive", "verified"}:
            raise BackupError("HOST_UNAVAILABLE")
        return {"ok": True, "archive": value["archive"], "verified": value["verified"]}
    operation_arguments = {
        "host_start": ("start", payload.get("request_id"), payload.get("expected_manifest_sha256")),
        "host_status": ("status", payload.get("request_id")),
        "host_operations": ("list",),
        "host_recover": ("recover", payload.get("request_id")),
    }[action]
    return _host_command(HOST_OPERATION_SCRIPT, *operation_arguments)


class BackupBroker:
    def __init__(self, *, manager: HubBackups | None = None,
                 requests: Path = REQUESTS,
                 restores: RestoreOrchestrator | None = None,
                 public_web: PublicSettingsExecutor | None = None,
                 local_web: LocalSettingsExecutor | None = None):
        self.manager = HubBackups() if manager is None else manager
        self.requests = requests
        self.restores = (RestoreOrchestrator(manager=self.manager) if restores is None
                         else restores)
        self.public_web = PublicSettingsExecutor() if public_web is None else public_web
        self.local_web = LocalSettingsExecutor() if local_web is None else local_web
        if requests.parent != self.manager.layout.backups:
            raise BackupError("INVALID_LEDGER_LAYOUT")

    def _ledger(self) -> None:
        self.manager._backups(create=True)
        if not self.requests.exists() and not self.requests.is_symlink():
            self.requests.mkdir(mode=0o700)
            _fsync_dir(self.requests.parent)
        _directory(self.requests, self.manager.root_uid, self.manager.root_gid, 0o700)

    def _reservation(self, key: str) -> tuple[str, bool]:
        self._ledger()
        path = self.requests / key
        if path.exists() or path.is_symlink():
            raw = _read_file(path, self.manager.root_uid, self.manager.root_gid,
                             0o600, MAX_LEDGER)
            try:
                value = json.loads(raw, object_pairs_hook=_unique)
            except (UnicodeError, ValueError) as exc:
                raise BackupError("INVALID_LEDGER") from exc
            if (not isinstance(value, dict) or set(value) !=
                    {"format", "request_key", "backup_id", "created_at"} or
                    type(value["format"]) is not int or value["format"] != 1 or
                    value["request_key"] != key or not _canonical_id(value["backup_id"]) or
                    type(value["created_at"]) is not int or not 1 <= value["created_at"] <= 253402300799 or
                    raw != _json_bytes(value)):
                raise BackupError("INVALID_LEDGER")
            return value["backup_id"], False
        recent = []
        for entry in self.requests.iterdir():
            if not _canonical_id(entry.name):
                raise BackupError("INVALID_LEDGER")
            info = entry.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.manager.root_uid or
                    info.st_gid != self.manager.root_gid or info.st_nlink != 1 or
                    stat.S_IMODE(info.st_mode) != 0o600):
                raise BackupError("INVALID_LEDGER")
            recent.append(info.st_mtime)
        if recent and time.time() - max(recent) < CREATE_INTERVAL_SECONDS:
            raise BackupError("CREATE_RATE_LIMITED")
        backup_id = str(uuid.uuid4())
        value = {"format": 1, "request_key": key, "backup_id": backup_id,
                 "created_at": int(time.time())}
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            with os.fdopen(fd, "wb") as output:
                output.write(_json_bytes(value))
                output.flush()
                os.fsync(output.fileno())
            _fsync_dir(self.requests)
        except Exception:
            path.unlink(missing_ok=True)
            raise
        return backup_id, True

    def _space_for_web_backup(self) -> None:
        # Web-triggered snapshots cannot consume the host's final free space.
        self.manager._source()
        self.manager._backups(create=True)
        data = self.manager.layout.data
        backups = self.manager.layout.backups
        size = (data / "hub.sqlite").stat().st_size
        data_fs = os.statvfs(data)
        backup_fs = os.statvfs(backups)
        margin = max(WEB_MIN_FREE_BYTES,
                     backup_fs.f_blocks * backup_fs.f_frsize // 20)
        data_free = data_fs.f_bavail * data_fs.f_frsize
        backup_free = backup_fs.f_bavail * backup_fs.f_frsize
        if data.stat().st_dev == backups.stat().st_dev:
            enough = data_free >= 2 * size + margin
        else:
            enough = data_free >= size + WEB_MIN_FREE_BYTES and backup_free >= size + margin
        if not enough:
            raise BackupError("INSUFFICIENT_SPACE")

    def _space_for_web_restore(self, target_id: str) -> None:
        # Reserve room for the safety snapshot, SQLite's live copy and the
        # restored stage before stopping the only Hub container. Existing
        # low-level margins remain an independent check during each step.
        self.manager._source()
        self.manager._backups(create=False)
        target = self.manager.verify(target_id)
        current = (self.manager.layout.data / "hub.sqlite").stat().st_size
        future = target["database_bytes"]
        data = self.manager.layout.data
        backups = self.manager.layout.backups
        data_fs = os.statvfs(data)
        backup_fs = os.statvfs(backups)
        data_free = data_fs.f_bavail * data_fs.f_frsize
        backup_free = backup_fs.f_bavail * backup_fs.f_frsize
        data_margin = max(WEB_MIN_FREE_BYTES,
                          data_fs.f_blocks * data_fs.f_frsize // 20)
        backup_margin = max(WEB_MIN_FREE_BYTES,
                            backup_fs.f_blocks * backup_fs.f_frsize // 20)
        if data.stat().st_dev == backups.stat().st_dev:
            enough = data_free >= 2 * current + future + data_margin
        else:
            enough = (data_free >= current + future + data_margin and
                      backup_free >= current + backup_margin)
        if not enough:
            raise BackupError("INSUFFICIENT_SPACE")

    def execute(self, payload: dict) -> dict:
        action = payload["action"]
        if action.startswith("public_"):
            try:
                return self.public_web.execute(
                    action.removeprefix("public_"),
                    {key: item for key, item in payload.items() if key != "action"})
            except PublicSettingsError as exc:
                raise BackupError("PUBLIC_" + exc.code) from exc
        if action.startswith("local_"):
            try:
                return self.local_web.execute(
                    action.removeprefix("local_"),
                    {key: item for key, item in payload.items() if key != "action"})
            except PublicSettingsError as exc:
                raise BackupError("LOCAL_" + exc.code) from exc
        if action.startswith("host_"):
            return _host_execute(payload)
        if action == "list":
            return {"ok": True, **self.manager.list()}
        if action == "verify":
            return {"ok": True, "backup": self.manager.verify(payload["id"])}
        if action == "restore_list":
            return self.restores.list()
        if action == "restore_status":
            return self.restores.status(payload["request_id"])
        if action == "restore_recover":
            with self.manager._restore_lock():
                state = self.restores.status(payload["request_id"])
                if state["phase"] not in ("complete", "failed_recovered"):
                    # A post-start recovery can need one more coherent
                    # snapshot before reusing the restored database.
                    self._space_for_web_backup()
                return self.restores.recover(payload["request_id"])
        if action == "restore_apply":
            # A replayed request already has a journal. Do not let falling
            # disk space obscure its result, and never run a second swap.
            with self.manager._restore_lock():
                journal = self.restores._path(payload["request_id"])
                if not journal.exists() and not journal.is_symlink():
                    self._space_for_web_restore(payload["target_id"])
                return self.restores.apply(payload["target_id"], payload["request_id"])
        # The same lock protects automatic/server updates and offline restore.
        # Do not let a web-triggered snapshot race an upgrade of the Hub data.
        with self.manager._restore_lock():
            identity, _fresh = self._reservation(payload["request_key"])
            final = self.manager.layout.backups / identity
            if final.exists() or final.is_symlink():
                backup = self.manager.verify(identity)
                return {"ok": True, "created": False, "backup": backup}
            for path in (self.manager.layout.data / (".backup-" + identity),
                         self.manager.layout.backups / (".new-" + identity)):
                if path.exists() or path.is_symlink():
                    raise BackupError("BACKUP_RECOVERY_REQUIRED")
            self._space_for_web_backup()
            backup = self.manager.create(identity=identity)
            return {"ok": True, "created": True,
                    "backup": {**backup, "verified": True}}


def _response(value: dict) -> bytes:
    raw = _json_bytes(value)
    if len(raw) > MAX_RESPONSE:
        return _json_bytes({"ok": False, "error": "RESPONSE_LIMIT"})
    return raw


def _peer_uid(connection: socket.socket) -> int:
    if not hasattr(socket, "SO_PEERCRED"):
        raise BackupError("PEER_UNAVAILABLE")
    raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                struct.calcsize("3i"))
    pid, uid, _gid = struct.unpack("3i", raw)
    if pid <= 0:
        raise BackupError("PEER_UNAVAILABLE")
    return uid


def handle(connection: socket.socket, broker: BackupBroker) -> None:
    connection.settimeout(10)
    try:
        if _peer_uid(connection) != PEER_UID:
            raise BackupError("PEER_DENIED")
        raw = bytearray()
        while len(raw) <= MAX_REQUEST:
            chunk = connection.recv(min(MAX_REQUEST + 1 - len(raw), MAX_REQUEST + 1))
            if not chunk:
                break
            raw.extend(chunk)
            if b"\n" in chunk:
                break
        payload = _request(bytes(raw))
        result = broker.execute(payload)
    except BackupError as exc:
        result = {"ok": False, "error": str(exc)}
    except (OSError, ValueError, TypeError):
        result = {"ok": False, "error": "BACKUP_FAILED"}
    try:
        connection.sendall(_response(result))
    except (OSError, socket.timeout):
        pass


def main() -> None:
    os.umask(0o077)
    if (sys.platform != "linux" or os.getuid() != 0 or os.geteuid() != 0 or
            os.environ.get("LISTEN_PID") != str(os.getpid()) or
            os.environ.get("LISTEN_FDS") != "1"):
        raise SystemExit("socket activation and root are required")
    descriptor = 3
    info = os.fstat(descriptor)
    if not stat.S_ISSOCK(info.st_mode):
        raise SystemExit("systemd did not pass a socket")
    listener = socket.socket(fileno=descriptor)
    if listener.family != socket.AF_UNIX or listener.type != socket.SOCK_STREAM:
        raise SystemExit("unsupported socket")
    if listener.getsockname() != str(SOCKET_PATH):
        raise SystemExit("unexpected socket path")
    broker = BackupBroker()
    while True:
        connection, _ = listener.accept()
        with connection:
            handle(connection, broker)


if __name__ == "__main__":
    main()
