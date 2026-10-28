# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Bounded, ephemeral relay for Agent file operations.

Requests and results live only in Hub process memory. Neither paths nor file
bytes are written to SQLite, the audit log, or a general remote-command job.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import threading
import time
import uuid

MAX_CONTENT = 8192
MAX_BINARY_BYTES = 4 * 1024 * 1024
MAX_DOWNLOAD_BYTES = 32 * 1024 * 1024
CHUNK_BYTES = 64 * 1024
MAX_FILE_BODY = 90000
MAX_OPERATIONS = 64
MAX_WAITERS = 16
TTL_SECONDS = 120
_ROOT = re.compile(r"[a-z][a-z0-9_-]{0,31}\Z")
_ETAG = re.compile(r"[0-9a-f]{64}\Z")
_ENCODED = re.compile(r"[A-Za-z0-9_-]*\Z")
_CODES = {"disabled", "invalid_request", "invalid_path", "unknown_root", "invalid_content",
          "invalid_etag", "not_found", "unsupported", "too_large", "conflict", "denied", "unavailable", "busy"}


class FileRelayError(Exception):
    def __init__(self, status: int, message: str):
        self.status = status
        super().__init__(message)


def _path(value) -> bool:
    if not isinstance(value, str) or "\x00" in value or "\\" in value:
        return False
    try:
        if len(value.encode("utf-8")) > 512:
            return False
    except UnicodeEncodeError:
        return False
    if value == "":
        return True
    parts = value.split("/")
    try:
        return len(parts) <= 20 and all(part not in ("", ".", "..") and part.isprintable()
                                        and len(part.encode("utf-8")) <= 255 for part in parts)
    except UnicodeEncodeError:
        return False


def _content(value):
    if not isinstance(value, str) or len(value) > 10923 or not _ENCODED.fullmatch(value):
        raise FileRelayError(400, "Invalid file content")
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        text = raw.decode("utf-8")
    except (ValueError, UnicodeDecodeError, base64.binascii.Error) as exc:
        raise FileRelayError(400, "Invalid file content") from exc
    if (len(raw) > MAX_CONTENT or "\x00" in text
            or base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != value):
        raise FileRelayError(400, "Invalid file content")
    return raw


def _binary_content(value):
    if not isinstance(value, str) or len(value) > 87382 or not _ENCODED.fullmatch(value):
        raise FileRelayError(400, "Invalid binary content")
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, base64.binascii.Error) as exc:
        raise FileRelayError(400, "Invalid binary content") from exc
    if len(raw) > CHUNK_BYTES or base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != value:
        raise FileRelayError(400, "Invalid binary content")
    return raw


def _canonical_uuid(value):
    try:
        return isinstance(value, str) and str(uuid.UUID(value)) == value
    except (ValueError, AttributeError):
        return False


def validate_request(value):
    if not isinstance(value, dict):
        raise FileRelayError(400, "Expected file operation")
    action = value.get("action")
    if action == "roots" and set(value) == {"action"}:
        return value
    if action not in ("list", "read", "write", "binary_info", "binary_chunk", "upload_begin",
                      "upload_chunk", "upload_commit", "upload_cancel"):
        raise FileRelayError(400, "Invalid file action")
    fields = {"action", "root", "path"} | {
        "write": {"etag", "content"}, "binary_chunk": {"etag", "offset"},
        "upload_begin": {"size", "sha256", "etag"},
        "upload_chunk": {"upload_id", "offset", "content"},
        "upload_commit": {"upload_id"}, "upload_cancel": {"upload_id"},
    }.get(action, set())
    if (set(value) != fields or not isinstance(value.get("root"), str)
            or not _ROOT.fullmatch(value["root"]) or not _path(value.get("path"))
            or (action != "list" and value["path"] == "")):
        raise FileRelayError(400, "Invalid file path")
    if action == "write":
        if not isinstance(value["etag"], str) or not _ETAG.fullmatch(value["etag"]):
            raise FileRelayError(400, "Invalid file ETag")
        _content(value["content"])
    if action == "binary_chunk":
        if (not isinstance(value["etag"], str) or not _ETAG.fullmatch(value["etag"])
                or type(value["offset"]) is not int or value["offset"] < 0
                or value["offset"] % CHUNK_BYTES or value["offset"] >= MAX_DOWNLOAD_BYTES):
            raise FileRelayError(400, "Invalid binary chunk")
    if action == "upload_begin":
        if (type(value["size"]) is not int or not 0 <= value["size"] <= MAX_BINARY_BYTES
                or not isinstance(value["sha256"], str) or not _ETAG.fullmatch(value["sha256"])
                or (value["etag"] is not None and
                    (not isinstance(value["etag"], str) or not _ETAG.fullmatch(value["etag"])))):
            raise FileRelayError(400, "Invalid upload")
    if action in ("upload_chunk", "upload_commit", "upload_cancel"):
        if not _canonical_uuid(value["upload_id"]):
            raise FileRelayError(400, "Invalid upload")
        if action == "upload_chunk":
            if (type(value["offset"]) is not int or value["offset"] < 0
                    or value["offset"] >= MAX_BINARY_BYTES or not _binary_content(value["content"])):
                raise FileRelayError(400, "Invalid upload chunk")
    return value


def validate_result(action: str, value):
    if not isinstance(value, dict):
        raise FileRelayError(400, "Invalid Agent file result")
    if action == "roots":
        roots = value.get("roots")
        if set(value) != {"roots"} or not isinstance(roots, list) or len(roots) > 8 or any(
                not isinstance(root, str) or not _ROOT.fullmatch(root) for root in roots) or len(set(roots)) != len(roots):
            raise FileRelayError(400, "Invalid Agent file result")
    elif action == "list":
        entries = value.get("entries")
        if set(value) != {"entries", "truncated"} or type(value.get("truncated")) is not bool or not isinstance(entries, list) or len(entries) > 200:
            raise FileRelayError(400, "Invalid Agent file result")
        names = set()
        for entry in entries:
            if (not isinstance(entry, dict) or set(entry) != {"name", "kind", "size"}
                    or not isinstance(entry["name"], str) or not _path(entry["name"])
                    or "/" in entry["name"] or not entry["name"] or entry["name"] in names
                    or entry["kind"] not in ("file", "directory")
                    or (entry["kind"] == "directory" and entry["size"] is not None)
                    or (entry["kind"] == "file" and (type(entry["size"]) is not int or entry["size"] < 0))):
                raise FileRelayError(400, "Invalid Agent file result")
            names.add(entry["name"])
    elif action == "read":
        if (set(value) != {"content", "etag", "size"} or not isinstance(value["etag"], str)
                or not _ETAG.fullmatch(value["etag"]) or type(value["size"]) is not int):
            raise FileRelayError(400, "Invalid Agent file result")
        if len(_content(value["content"])) != value["size"]:
            raise FileRelayError(400, "Invalid Agent file result")
    elif action == "write":
        if (set(value) != {"etag", "size"} or not isinstance(value["etag"], str)
                or not _ETAG.fullmatch(value["etag"]) or type(value["size"]) is not int
                or not 0 <= value["size"] <= MAX_CONTENT):
            raise FileRelayError(400, "Invalid Agent file result")
    elif action == "binary_info":
        if (set(value) != {"size", "etag", "sha256"} or type(value["size"]) is not int
                or not 0 <= value["size"] <= MAX_DOWNLOAD_BYTES
                or not isinstance(value["etag"], str) or not _ETAG.fullmatch(value["etag"])
                or not isinstance(value["sha256"], str) or not _ETAG.fullmatch(value["sha256"])):
            raise FileRelayError(400, "Invalid Agent file result")
    elif action == "binary_chunk":
        if (set(value) != {"content", "offset", "size", "etag"}
                or type(value["offset"]) is not int or value["offset"] < 0 or value["offset"] % CHUNK_BYTES
                or value["offset"] >= MAX_DOWNLOAD_BYTES
                or type(value["size"]) is not int or not 0 < value["size"] <= CHUNK_BYTES
                or not isinstance(value["etag"], str) or not _ETAG.fullmatch(value["etag"])
                or len(_binary_content(value["content"])) != value["size"]):
            raise FileRelayError(400, "Invalid Agent file result")
    elif action == "upload_begin":
        if (set(value) != {"upload_id", "size"} or not _canonical_uuid(value["upload_id"])
                or type(value["size"]) is not int or not 0 <= value["size"] <= MAX_BINARY_BYTES):
            raise FileRelayError(400, "Invalid Agent file result")
    elif action == "upload_chunk":
        if (set(value) != {"received", "size"} or type(value["received"]) is not int
                or type(value["size"]) is not int or not 0 <= value["received"] <= value["size"] <= MAX_BINARY_BYTES):
            raise FileRelayError(400, "Invalid Agent file result")
    elif action == "upload_commit":
        if (set(value) != {"size", "sha256", "etag"} or type(value["size"]) is not int
                or not 0 <= value["size"] <= MAX_BINARY_BYTES
                or not isinstance(value["sha256"], str) or not _ETAG.fullmatch(value["sha256"])
                or not isinstance(value["etag"], str) or not _ETAG.fullmatch(value["etag"])):
            raise FileRelayError(400, "Invalid Agent file result")
    elif action == "upload_cancel":
        if set(value) != {"cancelled"} or value["cancelled"] is not True:
            raise FileRelayError(400, "Invalid Agent file result")
    return value


class FileRegistry:
    def __init__(self):
        self._condition = threading.Condition()
        self._operations: dict[str, dict] = {}
        self._next_waiting: set[str] = set()

    def _purge(self):
        now = time.monotonic()
        for operation_id, item in list(self._operations.items()):
            if now - item["created"] > TTL_SECONDS:
                del self._operations[operation_id]

    @staticmethod
    def _forget_write_content(item):
        if item["request"]["action"] in ("write", "upload_chunk"):
            item["request"] = {key: item["request"][key] for key in ("action", "root", "path")}

    def create(self, server_id: str, owner_hash: str, idempotency_key: str, request: dict):
        validate_request(request)
        digest = hashlib.sha256(json.dumps(request, sort_keys=True, ensure_ascii=True,
                                          separators=(",", ":")).encode("utf-8")).hexdigest()
        try:
            if str(uuid.UUID(idempotency_key)) != idempotency_key:
                raise ValueError()
        except (ValueError, AttributeError) as exc:
            raise FileRelayError(400, "Idempotency-Key must be a canonical UUID") from exc
        with self._condition:
            self._purge()
            for item in self._operations.values():
                if item["owner"] == owner_hash and item["key"] == idempotency_key:
                    if item["server_id"] != server_id or item["request_digest"] != digest:
                        raise FileRelayError(409, "Idempotency-Key was used for another operation")
                    return {"id": item["id"], "state": item["state"]}, False
            if len(self._operations) >= MAX_OPERATIONS or sum(
                    item["owner"] == owner_hash for item in self._operations.values()) >= 32:
                raise FileRelayError(429, "Too many active file operations")
            operation_id = str(uuid.uuid4())
            item = {"id": operation_id, "server_id": server_id, "owner": owner_hash,
                    "key": idempotency_key, "request": request, "request_digest": digest, "state": "queued",
                    "result": None, "created": time.monotonic()}
            self._operations[operation_id] = item
            self._condition.notify_all()
            return {"id": operation_id, "state": "queued"}, True

    def next_agent(self, server_id: str, allowed):
        deadline = time.monotonic() + 8
        with self._condition:
            if server_id in self._next_waiting or len(self._next_waiting) >= MAX_WAITERS:
                raise FileRelayError(429, "File waiter limit reached")
            self._next_waiting.add(server_id)
            try:
                while True:
                    self._purge()
                    for item in self._operations.values():
                        if item["server_id"] == server_id and item["state"] == "queued":
                            if not allowed(item["owner"]):
                                item["state"] = "failed"
                                item["result"] = {"code": "disabled"}
                                self._forget_write_content(item)
                                continue
                            item["state"] = "running"
                            return {"id": item["id"], "request": item["request"]}
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        return None
                    self._condition.wait(remaining)
            finally:
                self._next_waiting.discard(server_id)

    def result(self, server_id: str, operation_id: str, value: dict):
        with self._condition:
            self._purge()
            item = self._operations.get(operation_id)
            if not item or item["server_id"] != server_id:
                raise FileRelayError(404, "File operation not found")
            if item["state"] != "running":
                raise FileRelayError(409, "File operation is not running")
            if not isinstance(value, dict) or value.get("state") not in ("succeeded", "failed"):
                raise FileRelayError(400, "Invalid Agent file result")
            if value["state"] == "succeeded":
                if set(value) != {"state", "value"}:
                    raise FileRelayError(400, "Invalid Agent file result")
                result = validate_result(item["request"]["action"], value["value"])
            else:
                if set(value) != {"state", "code"} or value.get("code") not in _CODES:
                    raise FileRelayError(400, "Invalid Agent file result")
                result = {"code": value["code"]}
            item["state"] = value["state"]
            item["result"] = result
            # A queued write may carry sensitive content. Release it as soon
            # as the Agent completes; keep only action/path metadata for audit.
            self._forget_write_content(item)
            self._condition.notify_all()
            return {"id": operation_id, "state": item["state"]}

    def get(self, server_id: str, operation_id: str, owner_hash: str):
        with self._condition:
            self._purge()
            item = self._operations.get(operation_id)
            if not item or item["server_id"] != server_id or item["owner"] != owner_hash:
                raise FileRelayError(404, "File operation not found")
            return {"id": operation_id, "state": item["state"],
                    "result": item["result"] if item["state"] in ("succeeded", "failed") else None}

    def audit_meta(self, server_id: str, operation_id: str):
        with self._condition:
            item = self._operations.get(operation_id)
            if not item or item["server_id"] != server_id:
                raise FileRelayError(404, "File operation not found")
            return item["request"]["action"], path_digest(item["request"])

    def owner_hash(self, server_id: str, operation_id: str):
        with self._condition:
            item = self._operations.get(operation_id)
            if not item or item["server_id"] != server_id:
                raise FileRelayError(404, "File operation not found")
            return item["owner"]

    def close_operation(self, server_id: str, operation_id: str):
        with self._condition:
            item = self._operations.get(operation_id)
            if item and item["server_id"] == server_id:
                del self._operations[operation_id]
                self._condition.notify_all()

    def close_server(self, server_id: str):
        with self._condition:
            self._operations = {key: item for key, item in self._operations.items() if item["server_id"] != server_id}
            self._condition.notify_all()

    def has_active(self, server_id: str) -> bool:
        """Report queued/running relays retained by this Hub process."""
        with self._condition:
            self._purge()
            return any(item["server_id"] == server_id and
                       item["state"] in ("queued", "running")
                       for item in self._operations.values())

    def close_owner(self, owner_hash: str):
        with self._condition:
            self._operations = {key: item for key, item in self._operations.items() if item["owner"] != owner_hash}
            self._condition.notify_all()

    def close_all(self):
        with self._condition:
            self._operations.clear()
            self._condition.notify_all()


def path_digest(request: dict) -> str:
    target = f"{request.get('root', '')}/{request.get('path', '')}".encode("utf-8")
    return hashlib.sha256(target).hexdigest()[:16]
