# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Strict, metadata-only client for the host's optional root backup broker."""

from __future__ import annotations

import json
import re
import select
import socket
import time
import uuid
from datetime import datetime, timedelta

from .backup_broker import (MAX_RESPONSE, SOCKET_PATH, FEED_SHA, _feed_status_shape,
                            HOST_DOWNLOAD_PROTOCOL)
from .external_agent_control import valid_result as valid_external_result, valid_sha as valid_external_sha
from .external_agent_operations import (canonical_id as external_operation_id,
                                        valid_status as valid_external_operation)


MAX_DATABASE_BYTES = 4 * 1024**3
RESTORE_FIELDS = frozenset(("ok", "protocol", "request_id", "target_id", "phase",
                            "safety_id", "plan_id", "hub_running", "error", "created_at"))
RESTORE_PHASES = frozenset(("pending", "stopping", "stopped", "planning", "planned",
                            "applying", "applied", "starting", "started", "finalizing",
                            "complete", "failed_recovered", "recovery_required"))
ERROR_CODE = re.compile(r"[A-Z][A-Z0-9_]{2,63}\Z")
HOST_ID = re.compile(r"[0-9a-f]{32}\Z")
HOST_SHA = re.compile(r"[0-9a-f]{64}\Z")
HOST_IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")
HOST_UNIT = re.compile(r"sovagrid-[a-z0-9_.@-]{1,80}\.(?:service|socket|timer)\Z")
HOST_PHASES = frozenset(("accepted", "stopping", "archiving", "restarting",
                         "complete", "recovery_requested", "recovered", "failed",
                         "recovery_required"))
HOST_PROTOCOL = "sovagrid-host-backup-operation-v1"
HOST_MAX_BYTES = 8 * 1024**3
HOST_COMPOSE_SERVICES = frozenset(("hub", "web", "ssh-gateway"))
HOST_PORTABLE_RECEIPT = "sovagrid-portable-host-receipt-v1"
HOST_PARTS = frozenset(("archive", "host_manifest", "images", "images_manifest",
                       "receipt"))


class BackupClientError(RuntimeError):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


def canonical_id(value: object) -> bool:
    try:
        return isinstance(value, str) and str(uuid.UUID(value)) == value
    except (ValueError, AttributeError):
        return False


def _unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate key")
        value[key] = item
    return value


def _backup(value: object, *, expected: str | None = None) -> dict:
    if (not isinstance(value, dict) or set(value) !=
            {"id", "created_at", "database_bytes", "telegram_token_included", "verified"} or
            not canonical_id(value["id"]) or
            (expected is not None and value["id"] != expected) or
            type(value["created_at"]) is not int or not 1 <= value["created_at"] <= 253402300799 or
            type(value["database_bytes"]) is not int or
            not 0 < value["database_bytes"] <= MAX_DATABASE_BYTES or
            type(value["telegram_token_included"]) is not bool or value["verified"] is not True):
        raise BackupClientError(503, "Invalid backup broker reply")
    return value


def _restore(value: object, *, request_id: str | None = None,
             target_id: str | None = None) -> dict:
    if (not isinstance(value, dict) or set(value) != RESTORE_FIELDS or
            type(value["ok"]) is not bool or
            type(value["protocol"]) is not int or value["protocol"] != 1 or
            not canonical_id(value["request_id"]) or
            (request_id is not None and value["request_id"] != request_id) or
            not canonical_id(value["target_id"]) or
            (target_id is not None and value["target_id"] != target_id) or
            not isinstance(value["phase"], str) or value["phase"] not in RESTORE_PHASES or
            value["ok"] is not (value["phase"] == "complete") or
            (value["safety_id"] is not None and not canonical_id(value["safety_id"])) or
            (value["plan_id"] is not None and not canonical_id(value["plan_id"])) or
            (value["hub_running"] is not None and type(value["hub_running"]) is not bool) or
            (value["error"] is not None and
             (not isinstance(value["error"], str) or ERROR_CODE.fullmatch(value["error"]) is None)) or
            (value["phase"] == "complete" and value["error"] is not None) or
            (value["phase"] != "complete" and value["error"] is None) or
            type(value["created_at"]) is not int or
            not 1 <= value["created_at"] <= 253402300799):
        raise BackupClientError(503, "Invalid restore broker reply")
    return value


class BackupBrokerClient:
    def __init__(self, socket_path: str = str(SOCKET_PATH)):
        self.socket_path = socket_path

    def _request(self, payload: dict, *, restore_record: bool = False,
                 timeout_seconds: int = 930,
                 cancel_socket: socket.socket | None = None) -> dict:
        raw = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(5)
                connection.connect(self.socket_path)
                connection.settimeout(timeout_seconds)
                connection.sendall(raw)
                response = bytearray()
                deadline = time.monotonic() + timeout_seconds
                watched_peer = cancel_socket
                while len(response) <= MAX_RESPONSE:
                    if watched_peer is not None:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise BackupClientError(503, "Backup broker timed out")
                        ready, _, _ = select.select(
                            [connection, watched_peer], [], [], min(1, remaining))
                        if watched_peer in ready:
                            try:
                                pending = watched_peer.recv(1, socket.MSG_PEEK)
                            except OSError:
                                pending = b""
                            if not pending:
                                raise BackupClientError(499, "Request client disconnected")
                            # Keep pipelined HTTP bytes for its own handler.
                            watched_peer = None
                        if connection not in ready:
                            continue
                    chunk = connection.recv(min(4096, MAX_RESPONSE + 1 - len(response)))
                    if not chunk:
                        break
                    response.extend(chunk)
                    if b"\n" in chunk:
                        break
        except (OSError, socket.timeout) as exc:
            raise BackupClientError(503, "Backup broker unavailable; result may be uncertain") from exc
        if not response.endswith(b"\n") or len(response) > MAX_RESPONSE:
            raise BackupClientError(503, "Invalid backup broker reply")
        try:
            value = json.loads(response, object_pairs_hook=_unique)
        except (UnicodeError, ValueError) as exc:
            raise BackupClientError(503, "Invalid backup broker reply") from exc
        if not isinstance(value, dict) or type(value.get("ok")) is not bool:
            raise BackupClientError(503, "Invalid backup broker reply")
        if not value["ok"] and not (restore_record and set(value) == RESTORE_FIELDS):
            code = value.get("error")
            if set(value) != {"ok", "error"} or not isinstance(code, str):
                raise BackupClientError(503, "Invalid backup broker reply")
            if code == "CREATE_RATE_LIMITED":
                raise BackupClientError(429, "Wait before creating another backup")
            if code == "FEED_STATE_CHANGED":
                raise BackupClientError(409, "STATE_CHANGED")
            if code == "FEED_HUB_ONLY_UNSUPPORTED":
                raise BackupClientError(409, "HUB_ONLY_UNSUPPORTED")
            if code == "FEED_UNCONFIGURED_TRUST":
                raise BackupClientError(503, "UNCONFIGURED_TRUST")
            if code == "FEED_TIMER_UNAVAILABLE":
                raise BackupClientError(503, "TIMER_UNAVAILABLE")
            if code == "FEED_UNAVAILABLE":
                raise BackupClientError(503, "FEED_UNAVAILABLE")
            if code == "EXTERNAL_REFUSED":
                raise BackupClientError(409, "EXTERNAL_REFUSED")
            if code == "EXTERNAL_UNCERTAIN":
                raise BackupClientError(503, "EXTERNAL_UNCERTAIN")
            if code == "EXTERNAL_UNAVAILABLE":
                raise BackupClientError(503, "EXTERNAL_UNAVAILABLE")
            if code == "EXTERNAL_REQUEST_CONFLICT":
                raise BackupClientError(409, "EXTERNAL_REQUEST_CONFLICT")
            if code == "EXTERNAL_BUSY":
                raise BackupClientError(409, "EXTERNAL_BUSY")
            if code == "EXTERNAL_OPERATION_LIMIT":
                raise BackupClientError(409, "EXTERNAL_OPERATION_LIMIT")
            if code == "EXTERNAL_NOT_FOUND":
                raise BackupClientError(404, "EXTERNAL_NOT_FOUND")
            if code == "EXTERNAL_INVALID_REQUEST":
                raise BackupClientError(400, "INVALID_REQUEST")
            if code == "EXTERNAL_INVALID_STATE":
                raise BackupClientError(503, "EXTERNAL_UNAVAILABLE")
            if code == "UPDATE_BUSY":
                raise BackupClientError(503, "Server update or restore is busy")
            if code == "FILE_UNAVAILABLE":
                raise BackupClientError(404, "Backup not found")
            if code == "HOST_NOT_FOUND":
                raise BackupClientError(404, "Host backup or operation not found")
            if code == "HOST_STREAM_BUSY":
                raise BackupClientError(429, "Too many host backup downloads")
            if code == "HOST_STREAM_ACTIVE":
                raise BackupClientError(409, "This portable backup download is already active")
            if code in {"HOST_BUSY", "HOST_SOURCE_CHANGED", "HOST_STATE_CHANGED",
                        "HOST_DEGRADED_CONTAINERS", "HOST_ARCHIVE_LIMIT",
                        "HOST_OPERATION_LIMIT", "HOST_RECOVERY_FAILED",
                        "HOST_RESTART_INCOMPLETE", "HOST_SERVICES_RUNNING",
                        "HOST_CONTAINERS_RUNNING", "HOST_STACK_NOT_READY",
                        "HOST_NOT_READY", "HOST_NOT_PORTABLE"}:
                raise BackupClientError(409, "Host backup needs administrator attention")
            if code == "RESTORE_NOT_FOUND":
                raise BackupClientError(404, "Restore request not found")
            if code == "INSUFFICIENT_SPACE":
                raise BackupClientError(409, "Not enough free space for this operation")
            if code in {"RESTORE_BUSY", "RESTORE_KEY_REUSED", "HUB_CONTAINER_AMBIGUOUS",
                        "HUB_NOT_HEALTHY", "HUB_CONTAINER_CHANGED"}:
                raise BackupClientError(409, "Restore needs administrator attention")
            if code in {"BACKUP_ID_IN_USE", "BACKUP_RECOVERY_REQUIRED", "TOO_MANY_SNAPSHOTS"}:
                raise BackupClientError(409, "Backup creation needs administrator attention")
            raise BackupClientError(503, "Backup broker refused the request")
        return value

    def list(self) -> dict:
        value = self._request({"action": "list"})
        ids = value.get("ids")
        if set(value) != {"ok", "ids"} or not isinstance(ids, list) or len(ids) > 1000 or any(
                not canonical_id(item) for item in ids) or len(set(ids)) != len(ids):
            raise BackupClientError(503, "Invalid backup broker reply")
        return {"ids": ids}

    def verify(self, identity: str) -> dict:
        if not canonical_id(identity):
            raise BackupClientError(400, "Invalid backup ID")
        value = self._request({"action": "verify", "id": identity})
        if set(value) != {"ok", "backup"}:
            raise BackupClientError(503, "Invalid backup broker reply")
        return _backup(value["backup"], expected=identity)

    def create(self, request_key: str) -> tuple[dict, bool]:
        if not canonical_id(request_key):
            raise BackupClientError(400, "Invalid idempotency key")
        value = self._request({"action": "create", "request_key": request_key})
        if set(value) != {"ok", "created", "backup"} or type(value["created"]) is not bool:
            raise BackupClientError(503, "Invalid backup broker reply")
        return _backup(value["backup"]), value["created"]

    def restore_list(self) -> dict:
        value = self._request({"action": "restore_list"})
        records = value.get("restores")
        if (set(value) != {"ok", "protocol", "restores"} or value["ok"] is not True or
                type(value["protocol"]) is not int or value["protocol"] != 1 or
                not isinstance(records, list) or len(records) > 100):
            raise BackupClientError(503, "Invalid restore broker reply")
        checked = [_restore(item) for item in records]
        if len({item["request_id"] for item in checked}) != len(checked):
            raise BackupClientError(503, "Invalid restore broker reply")
        return {"restores": checked}

    def restore_status(self, request_id: str) -> dict:
        if not canonical_id(request_id):
            raise BackupClientError(400, "Invalid restore request ID")
        return _restore(self._request({"action": "restore_status", "request_id": request_id},
                                      restore_record=True), request_id=request_id)

    def restore_apply(self, target_id: str, request_id: str) -> dict:
        if not canonical_id(target_id) or not canonical_id(request_id) or target_id == request_id:
            raise BackupClientError(400, "Invalid restore request")
        return _restore(self._request({"action": "restore_apply", "target_id": target_id,
                                       "request_id": request_id}, restore_record=True,
                                      timeout_seconds=1800),
                        request_id=request_id, target_id=target_id)

    def restore_recover(self, request_id: str) -> dict:
        if not canonical_id(request_id):
            raise BackupClientError(400, "Invalid restore request ID")
        return _restore(self._request({"action": "restore_recover", "request_id": request_id},
                                      restore_record=True, timeout_seconds=1800),
                        request_id=request_id)


def _host_id(value: object) -> bool:
    return isinstance(value, str) and HOST_ID.fullmatch(value) is not None


def _host_time(value: object) -> bool:
    if not isinstance(value, str) or len(value) > 40 or not value.endswith("+00:00"):
        return False
    try:
        return datetime.fromisoformat(value).utcoffset() == timedelta(0)
    except ValueError:
        return False


def _host_archive(value: object, *, identity: str | None = None) -> dict:
    if (not isinstance(value, dict) or set(value) != {"id", "created_at", "layout", "bytes", "files"} or
            not _host_id(value["id"]) or (identity is not None and value["id"] != identity) or
            not _host_time(value["created_at"]) or value["layout"] not in ("full", "hub-only") or
            type(value["bytes"]) is not int or not 0 < value["bytes"] <= HOST_MAX_BYTES or
            type(value["files"]) is not int or not 0 < value["files"] <= 20_000):
        raise BackupClientError(503, "Invalid host backup broker reply")
    return value


def _host_operation(value: object, *, identity: str | None = None) -> dict:
    keys = {"ok", "protocol", "request_id", "phase", "archive", "error", "created_at"}
    if (not isinstance(value, dict) or set(value) != keys or value["ok"] is not True or
            value["protocol"] != HOST_PROTOCOL or not _host_id(value["request_id"]) or
            (identity is not None and value["request_id"] != identity) or
            not isinstance(value["phase"], str) or value["phase"] not in HOST_PHASES or
            not _host_time(value["created_at"]) or
            (value["error"] is not None and
             (not isinstance(value["error"], str) or ERROR_CODE.fullmatch(value["error"]) is None))):
        raise BackupClientError(503, "Invalid host backup broker reply")
    if value["archive"] is not None:
        _host_archive(value["archive"])
    if value["phase"] == "complete" and value["archive"] is None:
        raise BackupClientError(503, "Invalid host backup broker reply")
    return value


def _host_receipt(value: object, *, archive_id: str | None = None) -> dict:
    keys = {"protocol", "host_archive_id", "host_archive_sha256",
            "source_manifest_sha256", "images_sha256", "images", "container_ids",
            "exported_configs", "rootfs_sha256", "active_units", "unit_hashes"}
    if (not isinstance(value, dict) or set(value) != keys or
            value["protocol"] != HOST_PORTABLE_RECEIPT or
            not _host_id(value["host_archive_id"]) or
            (archive_id is not None and value["host_archive_id"] != archive_id) or
            any(not isinstance(value[key], str) or HOST_SHA.fullmatch(value[key]) is None
                for key in ("host_archive_sha256", "source_manifest_sha256", "images_sha256")) or
            not isinstance(value["images"], dict) or
            set(value["images"]) not in ({"hub", "web"}, {"hub", "web", "ssh-gateway"}) or
            any(not isinstance(image, str) or HOST_IMAGE_ID.fullmatch(image) is None
                for image in value["images"].values()) or
            any(not isinstance(value[key], dict) or set(value[key]) != set(value["images"]) or
                any(not isinstance(item, str) or HOST_SHA.fullmatch(item) is None
                    for item in value[key].values())
                for key in ("container_ids", "rootfs_sha256")) or
            not isinstance(value["exported_configs"], dict) or
            set(value["exported_configs"]) != set(value["images"]) or
            any(not isinstance(item, str) or HOST_IMAGE_ID.fullmatch(item) is None
                for item in value["exported_configs"].values()) or
            not isinstance(value["active_units"], list) or len(value["active_units"]) > 32 or
            any(not isinstance(unit, str) or HOST_UNIT.fullmatch(unit) is None
                for unit in value["active_units"]) or
            len(set(value["active_units"])) != len(value["active_units"]) or
            not isinstance(value["unit_hashes"], dict) or
            set(value["unit_hashes"]) != set(value["active_units"]) or
            any(not isinstance(digest, str) or HOST_SHA.fullmatch(digest) is None
                for digest in value["unit_hashes"].values())):
        raise BackupClientError(503, "Invalid portable backup broker reply")
    return value


def _host_portable_operation(value: object, *, identity: str | None = None) -> dict:
    if not isinstance(value, dict) or "image_receipt" not in value:
        raise BackupClientError(503, "Invalid portable backup broker reply")
    operation = _host_operation({key: item for key, item in value.items()
                                 if key != "image_receipt"}, identity=identity)
    receipt = value["image_receipt"]
    if (operation["phase"] == "complete") != (receipt is not None):
        raise BackupClientError(503, "Invalid portable backup broker reply")
    if receipt is not None:
        _host_receipt(receipt, archive_id=operation["archive"]["id"])
    return value


class HostPortableStream:
    """One exact artifact body from the root broker, with bounded reads."""

    def __init__(self, connection: socket.socket, reader, size: int, sha256: str):
        self.connection, self.reader = connection, reader
        self.size, self.sha256, self.remaining = size, sha256, size

    def read(self, maximum: int = 131072) -> bytes:
        if self.remaining == 0:
            return b""
        try:
            block = self.reader.read(min(maximum, self.remaining))
        except (OSError, socket.timeout) as exc:
            raise BackupClientError(503, "Portable backup stream interrupted") from exc
        if not block:
            raise BackupClientError(503, "Portable backup stream truncated")
        self.remaining -= len(block)
        return block

    def close(self) -> None:
        try:
            self.reader.close()
        finally:
            self.connection.close()

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()


class HostBackupBrokerClient(BackupBrokerClient):
    """Restricted host backup metadata and one-artifact stream protocol."""

    def portable_capabilities(self) -> dict:
        value = self._request({"action": "host_portable_capabilities"}, timeout_seconds=15)
        if (set(value) != {"ok", "supported", "download"} or value["ok"] is not True or
                type(value["supported"]) is not bool or
                type(value["download"]) is not bool or
                value["download"] != value["supported"]):
            raise BackupClientError(503, "Invalid portable backup broker reply")
        return {"supported": value["supported"], "download": value["download"]}

    def plan(self) -> dict:
        value = self._request({"action": "host_plan"}, timeout_seconds=180)
        plan = value.get("plan")
        digest = value.get("manifest_sha256")
        if (set(value) != {"ok", "plan", "manifest_sha256"} or
                not isinstance(digest, str) or HOST_SHA.fullmatch(digest) is None or
                not isinstance(plan, dict) or set(plan) != {
                    "layout", "active_units", "running_containers", "offline_ready"} or
                plan["layout"] not in ("full", "hub-only") or
                type(plan["offline_ready"]) is not bool or
                not isinstance(plan["active_units"], list) or len(plan["active_units"]) > 32 or
                not isinstance(plan["running_containers"], list) or
                len(plan["running_containers"]) > len(HOST_COMPOSE_SERVICES) or
                any(not isinstance(unit, str) or HOST_UNIT.fullmatch(unit) is None
                    for unit in plan["active_units"]) or
                any(container not in HOST_COMPOSE_SERVICES for container in plan["running_containers"]) or
                len(set(plan["active_units"])) != len(plan["active_units"]) or
                len(set(plan["running_containers"])) != len(plan["running_containers"]) or
                plan["offline_ready"] != (not plan["active_units"] and not plan["running_containers"])):
            raise BackupClientError(503, "Invalid host backup broker reply")
        return {"plan": plan, "manifest_sha256": digest}

    def archives(self) -> dict:
        value = self._request({"action": "host_archives"}, timeout_seconds=90)
        archives = value.get("archives")
        if set(value) != {"ok", "archives"} or not isinstance(archives, list) or len(archives) > 100:
            raise BackupClientError(503, "Invalid host backup broker reply")
        checked = [_host_archive(item) for item in archives]
        if len({_item["id"] for _item in checked}) != len(checked):
            raise BackupClientError(503, "Invalid host backup broker reply")
        return {"archives": checked}

    def verify_archive(self, identity: str) -> dict:
        if not _host_id(identity):
            raise BackupClientError(400, "Invalid host archive ID")
        value = self._request({"action": "host_verify", "id": identity}, timeout_seconds=450)
        if set(value) != {"ok", "archive", "verified"} or value["verified"] is not True:
            raise BackupClientError(503, "Invalid host backup broker reply")
        return {"archive": _host_archive(value["archive"], identity=identity), "verified": True}

    def operations(self) -> dict:
        value = self._request({"action": "host_operations"}, timeout_seconds=90)
        records = value.get("operations")
        if set(value) != {"ok", "protocol", "operations"} or value["protocol"] != HOST_PROTOCOL or (
                not isinstance(records, list) or len(records) > 100):
            raise BackupClientError(503, "Invalid host backup broker reply")
        checked = [_host_operation(item) for item in records]
        if len({item["request_id"] for item in checked}) != len(checked):
            raise BackupClientError(503, "Invalid host backup broker reply")
        return {"operations": checked}

    def operation_status(self, request_id: str) -> dict:
        if not _host_id(request_id):
            raise BackupClientError(400, "Invalid host backup request ID")
        return _host_operation(self._request({"action": "host_status", "request_id": request_id},
                                             timeout_seconds=90), identity=request_id)

    def start(self, request_id: str, expected_manifest_sha256: str) -> dict:
        if not _host_id(request_id) or not isinstance(expected_manifest_sha256, str) or (
                HOST_SHA.fullmatch(expected_manifest_sha256) is None):
            raise BackupClientError(400, "Invalid host backup request")
        return _host_operation(self._request({"action": "host_start", "request_id": request_id,
                                             "expected_manifest_sha256": expected_manifest_sha256},
                                            timeout_seconds=180), identity=request_id)

    def start_portable(self, request_id: str, expected_manifest_sha256: str) -> dict:
        if not _host_id(request_id) or not isinstance(expected_manifest_sha256, str) or (
                HOST_SHA.fullmatch(expected_manifest_sha256) is None):
            raise BackupClientError(400, "Invalid portable backup request")
        return _host_operation(self._request({"action": "host_portable_start",
                                             "request_id": request_id,
                                             "expected_manifest_sha256": expected_manifest_sha256},
                                            timeout_seconds=180), identity=request_id)

    def portable_status(self, request_id: str) -> dict:
        if not _host_id(request_id):
            raise BackupClientError(400, "Invalid portable backup request ID")
        return _host_portable_operation(self._request({"action": "host_portable_status",
                                                      "request_id": request_id},
                                                     timeout_seconds=90), identity=request_id)

    def verify_portable(self, request_id: str, *,
                        cancel_socket: socket.socket | None = None) -> dict:
        if not _host_id(request_id):
            raise BackupClientError(400, "Invalid portable backup request ID")
        value = self._request({"action": "host_portable_verify", "request_id": request_id},
                              timeout_seconds=2_300, cancel_socket=cancel_socket)
        archive = value.get("archive")
        receipt = value.get("receipt")
        if (set(value) != {"ok", "request_id", "archive", "images_bytes", "receipt"} or
                value["ok"] is not True or value["request_id"] != request_id or
                type(value["images_bytes"]) is not int or
                not 0 < value["images_bytes"] <= HOST_MAX_BYTES):
            raise BackupClientError(503, "Invalid portable backup broker reply")
        checked_archive = _host_archive(archive)
        _host_receipt(receipt, archive_id=checked_archive["id"])
        return value

    def open_portable_stream(self, request_id: str, part: str, *,
                             cancel_socket: socket.socket | None = None) -> HostPortableStream:
        if not _host_id(request_id) or part not in HOST_PARTS:
            raise BackupClientError(400, "Invalid portable backup download")
        raw = (json.dumps({"action": "host_portable_stream", "request_id": request_id,
                           "part": part}, separators=(",", ":")) + "\n").encode("ascii")
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        reader = None
        result = None
        try:
            connection.settimeout(5)
            connection.connect(self.socket_path)
            connection.sendall(raw)
            # Root verifies the full pair and then hashes this descriptor
            # before sending the first response byte.
            connection.settimeout(3_600)
            if cancel_socket is None:
                reader = connection.makefile("rb")
                header = reader.readline(1025)
            else:
                # The browser can leave while root verifies the pair. Close
                # our Unix connection promptly so its child can cancel work.
                header_bytes = bytearray()
                deadline = time.monotonic() + 3_600
                watched_peer = cancel_socket
                while len(header_bytes) <= 1024 and not header_bytes.endswith(b"\n"):
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise BackupClientError(503, "Portable backup broker timed out")
                    watched = [connection]
                    if watched_peer is not None:
                        watched.append(watched_peer)
                    ready, _, _ = select.select(watched, [], [], min(1, remaining))
                    if watched_peer is not None and watched_peer in ready:
                        try:
                            pending = watched_peer.recv(1, socket.MSG_PEEK)
                        except OSError:
                            pending = b""
                        if not pending:
                            raise BackupClientError(499, "Download client disconnected")
                        # An HTTP peer may pipeline a later request. Do not
                        # consume its bytes or spin on their readiness.
                        watched_peer = None
                    if connection in ready:
                        chunk = connection.recv(1)
                        if not chunk:
                            break
                        header_bytes.extend(chunk)
                header = bytes(header_bytes)
                reader = connection.makefile("rb")
            if not header.endswith(b"\n") or len(header) > 1024:
                raise BackupClientError(503, "Invalid portable backup stream")
            try:
                value = json.loads(header, object_pairs_hook=_unique)
            except (UnicodeError, ValueError) as exc:
                raise BackupClientError(503, "Invalid portable backup stream") from exc
            if isinstance(value, dict) and value == {"ok": False, "error": "HOST_STREAM_BUSY"}:
                raise BackupClientError(429, "Too many host backup downloads")
            if isinstance(value, dict) and value == {"ok": False, "error": "HOST_STREAM_ACTIVE"}:
                raise BackupClientError(409, "This portable backup download is already active")
            if not isinstance(value, dict) or value.get("ok") is not True:
                raise BackupClientError(503, "Portable backup stream unavailable")
            if (set(value) != {"ok", "protocol", "request_id", "part", "bytes", "sha256"} or
                    value["protocol"] != HOST_DOWNLOAD_PROTOCOL or
                    value["request_id"] != request_id or value["part"] != part or
                    type(value["bytes"]) is not int or
                    not 0 < value["bytes"] <= HOST_MAX_BYTES or
                    not isinstance(value["sha256"], str) or
                    HOST_SHA.fullmatch(value["sha256"]) is None or
                    (part == "receipt" and value["bytes"] > 8192) or
                    (part == "host_manifest" and value["bytes"] > 2048) or
                    (part == "images_manifest" and value["bytes"] > 4096)):
                raise BackupClientError(503, "Invalid portable backup stream")
            connection.settimeout(45)
            result = HostPortableStream(connection, reader, value["bytes"], value["sha256"])
            return result
        except (OSError, socket.timeout) as exc:
            raise BackupClientError(503, "Portable backup broker unavailable") from exc
        finally:
            # Ownership transfers to HostPortableStream only after a valid header.
            if result is None:
                if reader is not None:
                    reader.close()
                connection.close()

    def recover(self, request_id: str) -> dict:
        if not _host_id(request_id):
            raise BackupClientError(400, "Invalid host backup request ID")
        return _host_operation(self._request({"action": "host_recover", "request_id": request_id},
                                             timeout_seconds=90), identity=request_id)


class ReleaseFeedBrokerClient(BackupBrokerClient):
    """Restricted status and opt-in control through the existing root socket."""

    def _feed_request(self, payload: dict, *, timeout_seconds: int) -> dict:
        try:
            return self._request(payload, timeout_seconds=timeout_seconds)
        except BackupClientError as exc:
            if exc.status == 503 and str(exc) not in {
                "UNCONFIGURED_TRUST", "TIMER_UNAVAILABLE", "FEED_UNAVAILABLE"}:
                raise BackupClientError(503, "FEED_UNAVAILABLE") from exc
            raise

    @staticmethod
    def _status(value: dict) -> dict:
        if set(value) != {"ok", "status"} or value["ok"] is not True or not _feed_status_shape(value["status"]):
            raise BackupClientError(503, "FEED_UNAVAILABLE")
        return value["status"]

    def status(self) -> dict:
        return self._status(self._feed_request({"action": "feed_status"}, timeout_seconds=75))

    def enable(self, expected_state: str) -> dict:
        if not isinstance(expected_state, str) or FEED_SHA.fullmatch(expected_state) is None:
            raise BackupClientError(400, "INVALID_REQUEST")
        return self._status(self._feed_request({"action": "feed_enable", "expected_state": expected_state},
                                               timeout_seconds=115))

    def disable(self, expected_state: str) -> dict:
        if not isinstance(expected_state, str) or FEED_SHA.fullmatch(expected_state) is None:
            raise BackupClientError(400, "INVALID_REQUEST")
        return self._status(self._feed_request({"action": "feed_disable", "expected_state": expected_state},
                                               timeout_seconds=115))


class ExternalAgentUpdateBrokerClient(BackupBrokerClient):
    """Exact-digest, metadata-only external Agent updater over the root socket."""

    def _external(self, action: str, **digests: str) -> dict:
        if not all(valid_external_sha(value) for value in digests.values()):
            raise BackupClientError(400, "INVALID_REQUEST")
        try:
            value = self._request({"action": "external_" + action, **digests},
                                  timeout_seconds=1240 if action == "apply" else 195)
        except BackupClientError as exc:
            if action == "apply" and exc.status == 503 and "may be uncertain" in str(exc):
                raise BackupClientError(503, "EXTERNAL_UNCERTAIN") from exc
            raise
        result = value.get("result")
        if set(value) != {"ok", "result"} or value["ok"] is not True or not valid_external_result(
                "external_" + action, result):
            raise BackupClientError(503, "EXTERNAL_UNAVAILABLE")
        if ("current_hub_manifest_sha256" in digests and
                result.get("current_hub_manifest_sha256", digests["current_hub_manifest_sha256"]) !=
                digests["current_hub_manifest_sha256"]):
            raise BackupClientError(503, "EXTERNAL_UNAVAILABLE")
        if action == "preflight" and result["archive_sha256"] != digests["archive_sha256"]:
            raise BackupClientError(503, "EXTERNAL_UNAVAILABLE")
        if action == "apply" and (result["external_agent_manifest_sha256"] !=
                                  digests["current_hub_manifest_sha256"] or
                                  result["review_sha256"] != digests["review_sha256"]):
            raise BackupClientError(503, "EXTERNAL_UNAVAILABLE")
        return result

    def status(self) -> dict:
        return self._external("status")

    def preview(self, archive_sha256: str, current_hub_manifest_sha256: str) -> dict:
        return self._external("preview", archive_sha256=archive_sha256,
                              current_hub_manifest_sha256=current_hub_manifest_sha256)

    def preflight(self, archive_sha256: str, current_hub_manifest_sha256: str) -> dict:
        return self._external("preflight", archive_sha256=archive_sha256,
                              current_hub_manifest_sha256=current_hub_manifest_sha256)

    @staticmethod
    def _operation(value: dict, request_id: str) -> dict:
        operation = value.get("operation")
        if (set(value) != {"ok", "operation"} or value["ok"] is not True or
                not valid_external_operation(operation, request_id=request_id)):
            raise BackupClientError(503, "EXTERNAL_UNAVAILABLE")
        return operation

    def apply(self, request_id: str, archive_sha256: str,
              current_hub_manifest_sha256: str, external_agent_manifest_sha256: str,
              review_sha256: str) -> dict:
        if not external_operation_id(request_id) or not all(valid_external_sha(value) for value in (
                archive_sha256, current_hub_manifest_sha256,
                external_agent_manifest_sha256, review_sha256)):
            raise BackupClientError(400, "INVALID_REQUEST")
        payload = {"action": "external_apply", "request_id": request_id,
                   "archive_sha256": archive_sha256,
                   "current_hub_manifest_sha256": current_hub_manifest_sha256,
                   "external_agent_manifest_sha256": external_agent_manifest_sha256,
                   "review_sha256": review_sha256}
        try:
            value = self._request(payload, timeout_seconds=30)
        except BackupClientError as exc:
            if exc.status == 503 and "may be uncertain" in str(exc):
                raise BackupClientError(503, "EXTERNAL_UNCERTAIN") from exc
            raise
        return self._operation(value, request_id)

    def operation_status(self, request_id: str) -> dict:
        if not external_operation_id(request_id):
            raise BackupClientError(400, "INVALID_REQUEST")
        value = self._request({"action": "external_operation_status", "request_id": request_id},
                              timeout_seconds=30)
        return self._operation(value, request_id)

    def operations(self) -> dict:
        value = self._request({"action": "external_operation_list"}, timeout_seconds=30)
        operations = value.get("operations")
        if (set(value) != {"ok", "operations"} or value["ok"] is not True or
                not isinstance(operations, list) or len(operations) > 64 or
                not all(valid_external_operation(item) for item in operations) or
                len({item["request_id"] for item in operations}) != len(operations)):
            raise BackupClientError(503, "EXTERNAL_UNAVAILABLE")
        return {"operations": operations}
