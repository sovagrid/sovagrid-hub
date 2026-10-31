# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Systemd socket broker for bounded, root-only Hub backup operations.

The Hub container sees only the Unix socket, never the backup directory.  A
create request reserves its result UUID on disk before taking the snapshot, so
a lost HTTP/socket response can be replayed without making a second backup.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import select
import signal
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
from .external_agent_control import (SCRIPT as EXTERNAL_SCRIPT,
                                     valid_request as valid_external_request,
                                     valid_result as valid_external_result)
from .external_agent_operations import ExternalOperationError, ExternalOperationStore


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
HOST_IMAGE_SCRIPT = Path(
    "/opt/sovagrid-src/sovagrid-blueprint/deploy/host_image_export.py")
HOST_ARCHIVES = Path("/var/lib/sovagrid-host-backups")
HOST_IMAGES = Path("/var/lib/sovagrid-host-image-exports")
FEED_SCRIPT = Path("/opt/sovagrid-src/sovagrid-blueprint/deploy/release_feed.py")
HOST_PROTOCOL = "sovagrid-host-backup-v1"
HOST_OPERATION_PROTOCOL = "sovagrid-host-backup-operation-v1"
HOST_IMAGE_PROTOCOL = "sovagrid-host-images-v1"
HOST_DOWNLOAD_PROTOCOL = "sovagrid-host-download-v1"
MAX_STREAM_CHILDREN = 2
MAX_STREAM_SECONDS = 5_400
MAX_STREAM_BYTES = 8 * 1024**3
FEED_SHA = re.compile(r"[0-9a-f]{64}\Z")
FEED_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+\Z")
FEED_KEY_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,63}\Z")
FEED_STATUS_FIELDS = frozenset(("format", "channel", "enabled", "key_id", "available_keys",
                               "timer_installed", "timer_enabled", "timer_active",
                               "manual_candidate_active", "installed_manifest_sha256",
                               "ledger", "state_revision"))


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
    if action in ("host_plan", "host_archives", "host_operations",
                  "host_portable_capabilities") and set(value) == {"action"}:
        return value
    if action == "host_verify" and set(value) == {"action", "id"} and isinstance(
            value["id"], str) and HOST_ID.fullmatch(value["id"]):
        return value
    if action in ("host_status", "host_recover", "host_portable_status", "host_portable_verify") and set(value) == {"action", "request_id"} and isinstance(
            value["request_id"], str) and HOST_ID.fullmatch(value["request_id"]):
        return value
    if (action == "host_portable_stream" and
            set(value) == {"action", "request_id", "part"} and
            isinstance(value["request_id"], str) and HOST_ID.fullmatch(value["request_id"]) and
            value["part"] in ("archive", "images", "receipt")):
        return value
    if action in ("host_start", "host_portable_start") and set(value) == {
            "action", "request_id", "expected_manifest_sha256"} and isinstance(
            value["request_id"], str) and HOST_ID.fullmatch(value["request_id"]) and isinstance(
            value["expected_manifest_sha256"], str) and HOST_SHA.fullmatch(
            value["expected_manifest_sha256"]):
        return value
    if action == "feed_status" and set(value) == {"action"}:
        return value
    if (action in ("feed_enable", "feed_disable") and
            set(value) == {"action", "expected_state"} and
            isinstance(value["expected_state"], str) and
            FEED_SHA.fullmatch(value["expected_state"]) is not None):
        return value
    if action in ("external_status", "external_preview", "external_preflight",
                  "external_apply", "external_operation_status",
                  "external_operation_list") and valid_external_request(value):
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


def _host_command_cancellable(command: list[str], timeout: int,
                              connection: socket.socket) -> tuple[bytes, int]:
    """Bound helper output and stop its process group when the caller leaves."""
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               start_new_session=True)
    output = bytearray()
    completed = False
    try:
        if process.stdout is None:
            raise BackupError("HOST_UNAVAILABLE")
        descriptor = process.stdout.fileno()
        os.set_blocking(descriptor, False)
        deadline = time.monotonic() + timeout
        eof = False
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise BackupError("HOST_UNAVAILABLE")
            watched = [connection] + ([] if eof else [process.stdout])
            ready, _, _ = select.select(watched, [], [], min(1, remaining))
            if connection in ready:
                # After the one request, readability means EOF or unexpected
                # extra input. Neither caller can use this result safely.
                raise BackupError("HOST_UNAVAILABLE")
            if not eof and process.stdout in ready:
                block = os.read(descriptor, min(4096, MAX_RESPONSE + 1 - len(output)))
                if block:
                    output.extend(block)
                    if len(output) > MAX_RESPONSE:
                        raise BackupError("HOST_UNAVAILABLE")
                else:
                    eof = True
            if eof and process.poll() is not None:
                completed = True
                return bytes(output), process.returncode
    finally:
        if not completed:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        process.wait()
        if process.stdout is not None:
            process.stdout.close()


def _host_command(script: Path, *arguments: str, timeout: int = 120,
                  cancel_connection: socket.socket | None = None) -> dict:
    """Execute only the installed root helpers; never a shell or caller path."""
    if script not in (HOST_SCRIPT, HOST_OPERATION_SCRIPT, HOST_IMAGE_SCRIPT):
        raise BackupError("HOST_UNAVAILABLE")
    try:
        command = ["/usr/bin/python3", "-B", "-I", str(script), *arguments]
        if cancel_connection is None:
            result = subprocess.run(command, stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                    timeout=timeout, check=False)
            raw, returncode = result.stdout, result.returncode
        else:
            raw, returncode = _host_command_cancellable(command, timeout,
                                                         cancel_connection)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise BackupError("HOST_UNAVAILABLE") from exc
    if not 0 < len(raw) <= MAX_RESPONSE or not raw.endswith(b"\n") or raw.count(b"\n") != 1:
        raise BackupError("HOST_UNAVAILABLE")
    try:
        value = json.loads(raw, object_pairs_hook=_unique)
    except (UnicodeError, ValueError) as exc:
        raise BackupError("HOST_UNAVAILABLE") from exc
    expected = (HOST_PROTOCOL if script == HOST_SCRIPT else
                HOST_IMAGE_PROTOCOL if script == HOST_IMAGE_SCRIPT else HOST_OPERATION_PROTOCOL)
    if not isinstance(value, dict) or value.get("protocol") != expected or type(value.get("ok")) is not bool:
        raise BackupError("HOST_UNAVAILABLE")
    if returncode != 0 or value["ok"] is False:
        code = value.get("error")
        if (set(value) != {"ok", "protocol", "error"} or value["ok"] is not False or
                not isinstance(code, str) or HOST_ERROR.fullmatch(code) is None):
            raise BackupError("HOST_UNAVAILABLE")
        raise BackupError("HOST_" + code)
    return value


def _host_execute(payload: dict, *,
                  cancel_connection: socket.socket | None = None) -> dict:
    action = payload["action"]
    if action == "host_portable_capabilities":
        supported = True
        for script, commands in ((HOST_OPERATION_SCRIPT,
                                  (b"start-portable", b"portable-status")),
                                 (HOST_IMAGE_SCRIPT, (b"verify-portable",))):
            try:
                info = script.lstat()
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or
                        info.st_nlink != 1 or info.st_mode & 0o022 or
                        not 0 < info.st_size <= 1024 * 1024):
                    supported = False
                    break
                source = script.read_bytes()
                if len(source) != info.st_size or any(command not in source for command in commands):
                    supported = False
                    break
            except OSError:
                supported = False
                break
        return {"ok": True, "supported": supported, "download": supported}
    if action in ("host_portable_status", "host_portable_verify"):
        command_options = ({"cancel_connection": cancel_connection}
                           if action == "host_portable_verify" else {})
        status = _host_command(HOST_OPERATION_SCRIPT, "portable-status",
                               payload["request_id"], **command_options)
        if action == "host_portable_status":
            return status
        return _host_verify_portable(status, payload["request_id"],
                                     cancel_connection=cancel_connection)
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
        "host_portable_start": ("start-portable", payload.get("request_id"), payload.get("expected_manifest_sha256")),
        "host_status": ("status", payload.get("request_id")),
        "host_operations": ("list",),
        "host_recover": ("recover", payload.get("request_id")),
    }[action]
    return _host_command(HOST_OPERATION_SCRIPT, *operation_arguments)


def _host_verify_portable(status: dict, request_id: str, *,
                          cancel_connection: socket.socket | None = None) -> dict:
    archive = status.get("archive")
    receipt = status.get("image_receipt")
    if (set(status) != {"ok", "protocol", "request_id", "phase", "archive", "error",
                        "created_at", "image_receipt"} or
            status["ok"] is not True or status["protocol"] != HOST_OPERATION_PROTOCOL or
            status["request_id"] != request_id or status["phase"] != "complete" or
            not isinstance(archive, dict) or not isinstance(archive.get("id"), str) or
            HOST_ID.fullmatch(archive["id"]) is None or
            type(archive.get("bytes")) is not int or not 0 < archive["bytes"] <= MAX_STREAM_BYTES or
            not isinstance(receipt, dict)):
        raise BackupError("HOST_NOT_READY")
    checked = _host_command(HOST_IMAGE_SCRIPT, "verify-portable", archive["id"],
                            timeout=2_100, cancel_connection=cancel_connection)
    if (set(checked) != {"ok", "protocol", "id", "verified", "image_count", "bytes",
                         "apply_available", "receipt", "platforms"} or
            checked["id"] != archive["id"] or checked["verified"] is not True or
            checked["receipt"] != receipt or type(checked["bytes"]) is not int or
            not 0 < checked["bytes"] <= MAX_STREAM_BYTES):
        raise BackupError("HOST_UNAVAILABLE")
    return {"ok": True, "request_id": request_id, "archive": archive,
            "images_bytes": checked["bytes"], "receipt": receipt}


def _stream_open(path: Path, *, parent: Path, size: int | None) -> tuple[int, os.stat_result]:
    """Open only an exact, root-owned regular file below a fixed private root."""
    for directory in (*reversed(parent.parents), parent):
        info = directory.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or
                info.st_mode & 0o022 or
                (directory in (HOST_ARCHIVES, HOST_IMAGES, parent) and
                 stat.S_IMODE(info.st_mode) != 0o700)):
            raise BackupError("HOST_UNAVAILABLE")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or
            info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600 or
            not 0 < info.st_size <= MAX_STREAM_BYTES or
            (size is not None and info.st_size != size)):
        os.close(fd)
        raise BackupError("HOST_UNAVAILABLE")
    return fd, info


def _stream_send(connection: socket.socket, payload: dict) -> None:
    """Stream one independently verified portable artifact with bounded memory."""
    sent_header = False
    fd = None
    try:
        request_id, part = payload["request_id"], payload["part"]
        status = _host_command(HOST_OPERATION_SCRIPT, "portable-status", request_id,
                               cancel_connection=connection)
        checked = _host_verify_portable(status, request_id,
                                        cancel_connection=connection)
        archive_id = checked["archive"]["id"]
        receipt = checked["receipt"]
        if part == "archive":
            path = HOST_ARCHIVES / (archive_id + ".tar.gz")
            parent = HOST_ARCHIVES
            size = checked["archive"]["bytes"]
            expected = receipt.get("host_archive_sha256")
        elif part == "images":
            parent = HOST_IMAGES / archive_id
            path = parent / "images.tar"
            size = checked["images_bytes"]
            expected = receipt.get("images_sha256")
        else:
            parent = HOST_IMAGES / archive_id
            path = parent / "receipt.json"
            size = None
            expected = None
        if part != "receipt" and (not isinstance(expected, str) or
                                  HOST_SHA.fullmatch(expected) is None):
            raise BackupError("HOST_UNAVAILABLE")
        fd, before = _stream_open(path, parent=parent, size=size)
        if part == "receipt":
            if before.st_size > 8192:
                raise BackupError("HOST_UNAVAILABLE")
            raw = bytearray()
            while len(raw) < before.st_size:
                block = os.read(fd, before.st_size - len(raw))
                if not block:
                    raise BackupError("HOST_UNAVAILABLE")
                raw.extend(block)
            try:
                parsed = json.loads(raw, object_pairs_hook=_unique)
            except (UnicodeError, ValueError) as exc:
                raise BackupError("HOST_UNAVAILABLE") from exc
            if parsed != receipt:
                raise BackupError("HOST_UNAVAILABLE")
            expected = hashlib.sha256(raw).hexdigest()
            os.lseek(fd, 0, os.SEEK_SET)
        # The verifier checks the whole pair; bind the descriptor we will
        # actually send to its receipt digest before emitting HTTP headers.
        preflight = hashlib.sha256()
        counted = 0
        deadline = time.monotonic() + 1_200
        while counted < before.st_size:
            if select.select([connection], [], [], 0)[0]:
                raise BackupError("HOST_UNAVAILABLE")
            if time.monotonic() > deadline:
                raise BackupError("HOST_UNAVAILABLE")
            block = os.read(fd, min(131072, before.st_size - counted))
            if not block:
                raise BackupError("HOST_UNAVAILABLE")
            preflight.update(block)
            counted += len(block)
        current = os.fstat(fd)
        if (preflight.hexdigest() != expected or
                (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                 before.st_ctime_ns) !=
                (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns,
                 current.st_ctime_ns)):
            raise BackupError("HOST_UNAVAILABLE")
        os.lseek(fd, 0, os.SEEK_SET)
        header = {"ok": True, "protocol": HOST_DOWNLOAD_PROTOCOL,
                  "request_id": request_id, "part": part,
                  "bytes": before.st_size, "sha256": expected}
        connection.settimeout(30)
        connection.sendall(_response(header))
        sent_header = True
        digest = hashlib.sha256()
        count = 0
        while count < before.st_size:
            block = os.read(fd, min(131072, before.st_size - count))
            if not block:
                raise BackupError("HOST_UNAVAILABLE")
            digest.update(block)
            connection.sendall(block)
            count += len(block)
        after = os.fstat(fd)
        if (digest.hexdigest() != expected or
                (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                 before.st_ctime_ns) !=
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
                 after.st_ctime_ns)):
            raise BackupError("HOST_UNAVAILABLE")
    except (BackupError, OSError, ValueError, TypeError):
        if not sent_header:
            try:
                connection.sendall(_response({"ok": False, "error": "HOST_UNAVAILABLE"}))
            except (OSError, socket.timeout):
                pass
    finally:
        if fd is not None:
            os.close(fd)


def _feed_status_shape(value: object) -> bool:
    if not isinstance(value, dict) or set(value) != FEED_STATUS_FIELDS:
        return False
    ledger = value["ledger"]
    keys = value["available_keys"]
    return (
        type(value["format"]) is int and value["format"] == 1 and value["channel"] == "stable" and
        type(value["enabled"]) is bool and
        (value["key_id"] is None or isinstance(value["key_id"], str) and
         FEED_KEY_ID.fullmatch(value["key_id"]) is not None) and
        isinstance(keys, dict) and len(keys) <= 8 and all(
            isinstance(key, str) and FEED_KEY_ID.fullmatch(key) is not None and
            isinstance(digest, str) and FEED_SHA.fullmatch(digest) is not None
            for key, digest in keys.items()) and
        all(type(value[name]) is bool for name in (
            "timer_installed", "timer_enabled", "timer_active", "manual_candidate_active")) and
        (value["installed_manifest_sha256"] is None or
         isinstance(value["installed_manifest_sha256"], str) and
         FEED_SHA.fullmatch(value["installed_manifest_sha256"]) is not None) and
        isinstance(value["state_revision"], str) and
        FEED_SHA.fullmatch(value["state_revision"]) is not None and
        isinstance(ledger, dict) and set(ledger) == {
            "format", "highest_sequence", "highest_version", "highest_issued_at", "last_seen_at"} and
        type(ledger["format"]) is int and ledger["format"] == 1 and
        all(type(ledger[name]) is int and ledger[name] >= 0 for name in (
            "highest_sequence", "highest_issued_at", "last_seen_at")) and
        isinstance(ledger["highest_version"], str) and
        FEED_VERSION.fullmatch(ledger["highest_version"]) is not None)


def _feed_command(*arguments: str, timeout: int = 65) -> bytes:
    """Run only the installed release-feed CLI, never caller-selected code."""
    try:
        result = subprocess.run(["/usr/bin/python3", "-B", "-I", str(FEED_SCRIPT), *arguments],
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, timeout=timeout, check=False,
                                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise BackupError("FEED_UNAVAILABLE") from exc
    raw = result.stdout
    if not 0 < len(raw) <= 8192 or not raw.endswith(b"\n") or raw.count(b"\n") != 1:
        raise BackupError("FEED_UNAVAILABLE")
    if result.returncode == 40:
        match = re.fullmatch(rb"SG_RELEASE_FEED_REFUSE:([A-Z][A-Z0-9_]{1,63})\n", raw)
        code = match.group(1).decode("ascii") if match else ""
        mapped = {"STATE_CHANGED", "HUB_ONLY_UNSUPPORTED", "UNCONFIGURED_TRUST"}
        raise BackupError("FEED_" + code if code in mapped else
                          "FEED_TIMER_UNAVAILABLE" if code in ("TIMER_NOT_INSTALLED", "TIMER_UNAVAILABLE")
                          else "FEED_UNAVAILABLE")
    if result.returncode != 0:
        raise BackupError("FEED_UNAVAILABLE")
    return raw


def _feed_execute(payload: dict) -> dict:
    action = payload["action"]
    if action == "feed_status":
        raw = _feed_command("status")
    else:
        command = "enable" if action == "feed_enable" else "disable"
        response = _feed_command(command, "--expected-state", payload["expected_state"], timeout=100)
        accepted = (re.fullmatch(rb"SG_RELEASE_FEED:ENABLED:[a-z0-9][a-z0-9-]{0,63}\n", response)
                    is not None if action == "feed_enable"
                    else response == b"SG_RELEASE_FEED:DISABLED\n")
        if not accepted:
            raise BackupError("FEED_UNAVAILABLE")
        raw = _feed_command("status")
    try:
        value = json.loads(raw, object_pairs_hook=_unique)
    except (UnicodeError, ValueError, BackupError) as exc:
        raise BackupError("FEED_UNAVAILABLE") from exc
    if not _feed_status_shape(value):
        raise BackupError("FEED_UNAVAILABLE")
    return {"ok": True, "status": value}


def _external_execute(payload: dict) -> dict:
    """Run only the installed reviewed updater with exact digest arguments."""
    action = payload["action"]
    if action == "external_apply":
        # The backup broker is mounted read-only at /opt. The updater atomically
        # exchanges /opt/sovagrid-agent and must run in its own fixed unit.
        # Accept no mutating operation until that durable unit is installed.
        raise BackupError("EXTERNAL_UNAVAILABLE")
    arguments = [] if action == "external_status" else [
        payload["archive_sha256"], payload["current_hub_manifest_sha256"]]
    try:
        result = subprocess.run(
            ["/usr/bin/python3", "-B", "-I", str(EXTERNAL_SCRIPT),
             action.removeprefix("external_"), *arguments],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=180, check=False, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
    except subprocess.TimeoutExpired as exc:
        raise BackupError("EXTERNAL_UNCERTAIN") from exc
    except OSError as exc:
        raise BackupError("EXTERNAL_UNAVAILABLE") from exc
    if result.returncode != 0:
        raise BackupError("EXTERNAL_REFUSED" if result.returncode == 40 else
                          "EXTERNAL_UNAVAILABLE")
    raw = result.stdout
    if not 0 < len(raw) <= 32769 or not raw.endswith(b"\n") or raw.count(b"\n") != 1:
        raise BackupError("EXTERNAL_UNAVAILABLE")
    try:
        value = json.loads(raw, object_pairs_hook=_unique)
    except (UnicodeError, ValueError, BackupError) as exc:
        raise BackupError("EXTERNAL_UNAVAILABLE") from exc
    if not valid_external_result(action, value):
        raise BackupError("EXTERNAL_UNAVAILABLE")
    return {"ok": True, "result": value}


class BackupBroker:
    def __init__(self, *, manager: HubBackups | None = None,
                 requests: Path = REQUESTS,
                 restores: RestoreOrchestrator | None = None,
                 public_web: PublicSettingsExecutor | None = None,
                 local_web: LocalSettingsExecutor | None = None,
                 external_operations: ExternalOperationStore | None = None):
        self.manager = HubBackups() if manager is None else manager
        self.requests = requests
        self.restores = (RestoreOrchestrator(manager=self.manager) if restores is None
                         else restores)
        self.public_web = PublicSettingsExecutor() if public_web is None else public_web
        self.local_web = LocalSettingsExecutor() if local_web is None else local_web
        self.external_operations = (ExternalOperationStore() if external_operations is None
                                    else external_operations)
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
        if action == "host_portable_stream":
            raise BackupError("HOST_STREAM_REQUIRED")
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
        if action.startswith("feed_"):
            return _feed_execute(payload)
        if action in ("external_apply", "external_operation_status", "external_operation_list"):
            try:
                if action == "external_apply":
                    record = self.external_operations.apply(
                        payload["request_id"], payload["archive_sha256"],
                        payload["current_hub_manifest_sha256"],
                        payload["external_agent_manifest_sha256"], payload["review_sha256"])
                    return {"ok": True, "operation": record}
                if action == "external_operation_status":
                    return {"ok": True, "operation": self.external_operations.status(
                        payload["request_id"])}
                return {"ok": True, "operations": self.external_operations.list()}
            except ExternalOperationError as exc:
                raise BackupError(str(exc)) from exc
        if action.startswith("external_"):
            return _external_execute(payload)
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


def _reap_streams(children: dict[int, tuple[str, str] | None]) -> None:
    for pid in tuple(children):
        try:
            finished, _ = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            finished = pid
        if finished:
            children.pop(pid, None)


def handle(connection: socket.socket, broker: BackupBroker, *,
           stream_children: dict[int, tuple[str, str] | None] | None = None,
           listener: socket.socket | None = None) -> None:
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
        if payload["action"] in ("host_portable_stream", "host_portable_verify"):
            if stream_children is None:
                if payload["action"] == "host_portable_stream":
                    _stream_send(connection, payload)
                else:
                    connection.sendall(_response(_host_execute(
                        payload, cancel_connection=connection)))
                return
            _reap_streams(stream_children)
            stream_key = ((payload["request_id"], payload["part"])
                          if payload["action"] == "host_portable_stream" else None)
            if stream_key is not None and stream_key in tuple(stream_children.values()):
                raise BackupError("HOST_STREAM_ACTIVE")
            if len(stream_children) >= MAX_STREAM_CHILDREN or listener is None:
                raise BackupError("HOST_STREAM_BUSY")
            pid = os.fork()
            if pid:
                stream_children[pid] = stream_key
                return
            # A streaming child only owns this accepted connection. The root
            # broker keeps accepting normal control requests independently.
            listener.close()
            signal.signal(signal.SIGCHLD, signal.SIG_DFL)
            signal.alarm(MAX_STREAM_SECONDS)
            try:
                if payload["action"] == "host_portable_stream":
                    _stream_send(connection, payload)
                else:
                    try:
                        answer = _host_execute(payload, cancel_connection=connection)
                    except BackupError as exc:
                        answer = {"ok": False, "error": str(exc)}
                    except (OSError, ValueError, TypeError):
                        answer = {"ok": False, "error": "BACKUP_FAILED"}
                    connection.sendall(_response(answer))
            finally:
                connection.close()
                os._exit(0)
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
    # The socket-accepting parent is the only writer. A child owns its key
    # until SIGCHLD reaps it, including client disconnects and worker crashes.
    stream_children: dict[int, tuple[str, str] | None] = {}
    signal.signal(signal.SIGCHLD, lambda _signal, _frame: _reap_streams(stream_children))
    while True:
        connection, _ = listener.accept()
        with connection:
            handle(connection, broker, stream_children=stream_children, listener=listener)


if __name__ == "__main__":
    main()
