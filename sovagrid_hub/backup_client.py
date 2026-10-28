# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Strict, metadata-only client for the host's optional root backup broker."""

from __future__ import annotations

import json
import re
import socket
import uuid
from datetime import datetime, timedelta

from .backup_broker import MAX_RESPONSE, SOCKET_PATH


MAX_DATABASE_BYTES = 4 * 1024**3
RESTORE_FIELDS = frozenset(("ok", "protocol", "request_id", "target_id", "phase",
                            "safety_id", "plan_id", "hub_running", "error", "created_at"))
RESTORE_PHASES = frozenset(("pending", "stopping", "stopped", "planning", "planned",
                            "applying", "applied", "starting", "started", "finalizing",
                            "complete", "failed_recovered", "recovery_required"))
ERROR_CODE = re.compile(r"[A-Z][A-Z0-9_]{2,63}\Z")
HOST_ID = re.compile(r"[0-9a-f]{32}\Z")
HOST_SHA = re.compile(r"[0-9a-f]{64}\Z")
HOST_UNIT = re.compile(r"sovagrid-[a-z0-9_.@-]{1,80}\.(?:service|socket|timer)\Z")
HOST_PHASES = frozenset(("accepted", "stopping", "archiving", "restarting",
                         "complete", "recovery_requested", "recovered", "failed",
                         "recovery_required"))
HOST_PROTOCOL = "sovagrid-host-backup-operation-v1"
HOST_MAX_BYTES = 8 * 1024**3
HOST_COMPOSE_SERVICES = frozenset(("hub", "web", "ssh-gateway"))


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
                 timeout_seconds: int = 930) -> dict:
        raw = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(5)
                connection.connect(self.socket_path)
                connection.settimeout(timeout_seconds)
                connection.sendall(raw)
                response = bytearray()
                while len(response) <= MAX_RESPONSE:
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
            if code == "UPDATE_BUSY":
                raise BackupClientError(503, "Server update or restore is busy")
            if code == "FILE_UNAVAILABLE":
                raise BackupClientError(404, "Backup not found")
            if code == "HOST_NOT_FOUND":
                raise BackupClientError(404, "Host backup or operation not found")
            if code in {"HOST_BUSY", "HOST_SOURCE_CHANGED", "HOST_STATE_CHANGED",
                        "HOST_DEGRADED_CONTAINERS", "HOST_ARCHIVE_LIMIT",
                        "HOST_OPERATION_LIMIT", "HOST_RECOVERY_FAILED",
                        "HOST_RESTART_INCOMPLETE", "HOST_SERVICES_RUNNING",
                        "HOST_CONTAINERS_RUNNING"}:
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


class HostBackupBrokerClient(BackupBrokerClient):
    """Metadata-only protocol to the already installed root backup socket."""

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

    def recover(self, request_id: str) -> dict:
        if not _host_id(request_id):
            raise BackupClientError(400, "Invalid host backup request ID")
        return _host_operation(self._request({"action": "host_recover", "request_id": request_id},
                                             timeout_seconds=90), identity=request_id)
