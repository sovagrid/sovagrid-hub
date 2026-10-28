# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Bounded public-Web control over the existing root-owned Hub broker socket.

Only the installed public_web.py helper can modify the host. The root-owned
request journal makes a completed apply replayable if Web or Hub disconnects.
An interrupted apply remains uncertain; callers must read status and use CAS.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import socket
import stat
import subprocess
import uuid


SCRIPT = Path("/opt/sovagrid-src/sovagrid-blueprint/deploy/public_web.py")
SOCKET = "/run/sovagrid-hub-backup/control.sock"
REQUESTS = Path("/var/lib/sovagrid/.public-web-requests")
HASH = re.compile(r"[0-9a-f]{64}\Z")
PANEL_PATH = re.compile(r"/(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?/){1,3}\Z")
LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
TLD = re.compile(r"[a-z][a-z0-9-]*\Z")
ERROR_CODE = re.compile(r"[A-Z][A-Z0-9_]{1,63}\Z")
HELPER_ERRORS = frozenset(("INVALID_REQUEST", "UNMANAGED", "SOURCE_UNTRUSTED",
                           "STATE_UNTRUSTED", "STATE_CHANGED", "LOCAL_ACTIVE", "ADDRESS_NOT_LOCAL",
                           "IPV6_UNAVAILABLE", "PORT_BUSY", "COMMAND_FAILED",
                           "LOCAL_UNHEALTHY", "PUBLIC_UNHEALTHY", "ROLLBACK_FAILED",
                           "BUSY", "ROOT_REQUIRED"))
MAX_REPLY = 8192
MAX_JOURNAL = 2048
MAX_RECORDS = 10000


class PublicSettingsError(ValueError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class PublicSettingsClientError(RuntimeError):
    def __init__(self, status: int, message: str):
        self.status = status
        super().__init__(message)


def _unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("Duplicate field")
        value[key] = item
    return value


def _canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")


def valid_hash(value: object, *, nullable: bool = False) -> bool:
    return (value is None and nullable) or (isinstance(value, str) and
                                            HASH.fullmatch(value) is not None)


def valid_id(value: object) -> bool:
    try:
        return isinstance(value, str) and str(uuid.UUID(value)) == value
    except (ValueError, AttributeError):
        return False


def validate_config(value: object) -> dict:
    """Mirror the public helper's accepted configuration, then require full form."""
    if not isinstance(value, dict) or set(value) != {
            "mode", "address", "acme_environment", "panel_path", "root_behavior"}:
        raise PublicSettingsError("INVALID_REQUEST")
    mode, address = value["mode"], value["address"]
    environment, panel_path = value["acme_environment"], value["panel_path"]
    root_behavior = value["root_behavior"]
    if (mode not in ("ip", "dns") or not isinstance(address, str) or
            not 1 <= len(address) <= 253 or environment not in ("production", "staging") or
            not isinstance(panel_path, str) or len(panel_path) > 96 or
            PANEL_PATH.fullmatch(panel_path) is None or
            panel_path.split("/")[1] in {"api", "healthz"} or
            root_behavior not in ("panel", "redirect", "not_found", "untouched")):
        raise PublicSettingsError("INVALID_REQUEST")
    if mode == "ip":
        try:
            ip = ipaddress.ip_address(address)
        except ValueError as exc:
            raise PublicSettingsError("INVALID_REQUEST") from exc
        if (not ip.is_global or ip.is_multicast or getattr(ip, "ipv4_mapped", None) or
                ip.compressed != address):
            raise PublicSettingsError("INVALID_REQUEST")
    else:
        labels = address.split(".")
        if (not address.isascii() or address != address.lower() or
                len(labels) < 2 or not all(LABEL.fullmatch(label) for label in labels) or
                TLD.fullmatch(labels[-1]) is None or
                address.endswith((".local", ".localhost", ".internal", ".test",
                                  ".invalid", ".example"))):
            raise PublicSettingsError("INVALID_REQUEST")
    return dict(value)


def validate_reply(action: str, value: object, *, config: dict | None = None,
                   source_sha: str | None = None) -> dict:
    """Reject additional helper fields and contradictions before crossing trust boundary."""
    if not isinstance(value, dict) or value.get("protocol") != 1 or type(value.get("protocol")) is not int:
        raise PublicSettingsError("UNAVAILABLE")
    if value.get("ok") is False:
        error = value.get("error")
        if (set(value) != {"protocol", "ok", "error"} or not isinstance(error, dict) or
                set(error) != {"code", "message"} or
                not isinstance(error.get("code"), str) or error["code"] not in HELPER_ERRORS or
                not isinstance(error.get("message"), str) or len(error["message"]) > 256):
            raise PublicSettingsError("UNAVAILABLE")
        raise PublicSettingsError(error["code"])
    if value.get("ok") is not True:
        raise PublicSettingsError("UNAVAILABLE")
    if action == "status":
        if (set(value) != {"protocol", "ok", "enabled", "config", "expected_state_sha256"} or
                type(value["enabled"]) is not bool or
                not valid_hash(value["expected_state_sha256"], nullable=True)):
            raise PublicSettingsError("UNAVAILABLE")
        if value["enabled"]:
            if value["expected_state_sha256"] is None:
                raise PublicSettingsError("UNAVAILABLE")
            try:
                validate_config(value["config"])
            except PublicSettingsError as exc:
                raise PublicSettingsError("UNAVAILABLE") from exc
        elif value["config"] is not None or value["expected_state_sha256"] is not None:
            raise PublicSettingsError("UNAVAILABLE")
        return value
    fields = {"protocol", "ok", "config", "expected_state_sha256",
              "source_manifest_sha256", "changed", "url", "certificate_verified"}
    if action == "apply":
        fields.add("enabled")
    if (set(value) != fields or value["config"] != config or
            not valid_hash(value["expected_state_sha256"], nullable=True) or
            not valid_hash(value["source_manifest_sha256"]) or
            type(value["changed"]) is not bool or
            type(value["certificate_verified"]) is not bool or
            value["url"] != "https://" + ("[" + config["address"] + "]" if ":" in config["address"]
                                           else config["address"])):
        raise PublicSettingsError("UNAVAILABLE")
    if action == "preview":
        if value["certificate_verified"] is not False:
            raise PublicSettingsError("UNAVAILABLE")
    elif (value["enabled"] is not True or
          value["expected_state_sha256"] is None or
          value["source_manifest_sha256"] != source_sha or
          value["certificate_verified"] is not (config["acme_environment"] == "production")):
        raise PublicSettingsError("UNAVAILABLE")
    return value


def validate_request(action: str, value: object) -> dict:
    if action == "status":
        if value != {}:
            raise PublicSettingsError("INVALID_REQUEST")
        return {}
    if not isinstance(value, dict):
        raise PublicSettingsError("INVALID_REQUEST")
    if action == "preview":
        if set(value) != {"config"}:
            raise PublicSettingsError("INVALID_REQUEST")
        return {"config": validate_config(value["config"])}
    if action == "apply":
        if (set(value) != {"config", "expected_state_sha256",
                           "source_manifest_sha256", "request_id"} or
                not valid_hash(value["expected_state_sha256"], nullable=True) or
                not valid_hash(value["source_manifest_sha256"]) or
                not valid_id(value["request_id"])):
            raise PublicSettingsError("INVALID_REQUEST")
        return {**value, "config": validate_config(value["config"])}
    raise PublicSettingsError("INVALID_REQUEST")


class PublicSettingsExecutor:
    """Root side. A single systemd broker process serializes all requests."""

    expected_script = SCRIPT
    helper_errors = HELPER_ERRORS

    def __init__(self, *, script: Path = SCRIPT, requests: Path = REQUESTS,
                 uid: int = 0):
        self.script, self.requests, self.uid = script, requests, uid

    @staticmethod
    def _validate_request(action: str, value: object) -> dict:
        return validate_request(action, value)

    @staticmethod
    def _validate_reply(action: str, value: object, *, config: dict | None,
                        source_sha: str | None) -> dict:
        return validate_reply(action, value, config=config, source_sha=source_sha)

    def _command(self, action: str, value: dict) -> dict:
        if self.script != self.expected_script or action not in {"status", "preview", "apply", "disable"}:
            raise PublicSettingsError("UNAVAILABLE")
        payload = ({key: item for key, item in value.items() if key != "request_id"}
                   if action != "status" else None)
        raw = _canonical(payload) if payload is not None else None
        timeout = {"status": 45, "preview": 90, "apply": 600, "disable": 600}[action]
        try:
            process = subprocess.Popen(["/usr/bin/python3", "-B", "-I", str(self.expected_script), action],
                                       stdin=subprocess.PIPE if raw is not None else subprocess.DEVNULL,
                                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                       start_new_session=True)
            try:
                output, _ = process.communicate(raw, timeout=timeout)
            except subprocess.TimeoutExpired as exc:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.communicate(timeout=30)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.communicate()
                raise PublicSettingsError("UNCERTAIN") from exc
        except OSError as exc:
            raise PublicSettingsError("UNAVAILABLE") from exc
        if not 0 < len(output) <= MAX_REPLY or output.count(b"\n") != 1 or not output.endswith(b"\n"):
            raise PublicSettingsError("UNAVAILABLE")
        try:
            response = json.loads(output, object_pairs_hook=_unique)
        except (UnicodeError, ValueError) as exc:
            raise PublicSettingsError("UNAVAILABLE") from exc
        if (not isinstance(response, dict) or process.returncode not in (0, 1) or
                (process.returncode == 0) != (response.get("ok") is True)):
            raise PublicSettingsError("UNAVAILABLE")
        return self._validate_reply(action, response, config=value.get("config"),
                                    source_sha=value.get("source_manifest_sha256"))

    def _journal_directory(self):
        parent = self.requests.parent
        info = parent.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != self.uid or
                stat.S_IMODE(info.st_mode) != 0o700):
            raise PublicSettingsError("UNAVAILABLE")
        try:
            self.requests.mkdir(mode=0o700)
            self._sync(parent)
        except FileExistsError:
            pass
        info = self.requests.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != self.uid or
                stat.S_IMODE(info.st_mode) != 0o700):
            raise PublicSettingsError("UNAVAILABLE")

    @staticmethod
    def _sync(path: Path):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def _read(self, request_id: str) -> dict | None:
        path = self.requests / request_id
        try:
            info = path.lstat()
        except FileNotFoundError:
            return None
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.uid or
                stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or
                info.st_size > MAX_JOURNAL):
            raise PublicSettingsError("UNAVAILABLE")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            raw = os.read(fd, MAX_JOURNAL + 1)
        finally:
            os.close(fd)
        try:
            value = json.loads(raw, object_pairs_hook=_unique)
        except (UnicodeError, ValueError) as exc:
            raise PublicSettingsError("UNAVAILABLE") from exc
        if not isinstance(value, dict):
            raise PublicSettingsError("UNAVAILABLE")
        legacy = set(value) == {"format", "request_id", "request_sha256", "phase", "result"}
        current = set(value) == {"format", "action", "request_id", "request_sha256", "phase", "result"}
        action = "apply" if legacy else value.get("action")
        if (not (legacy or current) or
                value["format"] != (1 if legacy else 2) or type(value["format"]) is not int or
                not isinstance(action, str) or action not in {"apply", "disable"} or
                value["request_id"] != request_id or not valid_hash(value["request_sha256"]) or
                not isinstance(value["phase"], str) or
                value["phase"] not in {"pending", "complete", "failed"} or
                raw != _canonical(value)):
            raise PublicSettingsError("UNAVAILABLE")
        if value["phase"] == "pending" and value["result"] is not None:
            raise PublicSettingsError("UNAVAILABLE")
        if value["phase"] == "complete":
            try:
                result = value["result"]
                self._validate_reply(action, result,
                                     config=result["config"] if action == "apply" else None,
                                     source_sha=(result["source_manifest_sha256"]
                                                 if action == "apply" else None))
            except (KeyError, TypeError, PublicSettingsError) as exc:
                raise PublicSettingsError("UNAVAILABLE") from exc
        if (value["phase"] == "failed" and
                (not isinstance(value["result"], str) or
                 value["result"] not in self.helper_errors | {"UNAVAILABLE", "UNCERTAIN"})):
            raise PublicSettingsError("UNAVAILABLE")
        return value

    def _write(self, record: dict, *, create: bool):
        path = self.requests / record["request_id"]
        raw = _canonical(record)
        if len(raw) > MAX_JOURNAL:
            raise PublicSettingsError("UNAVAILABLE")
        temporary = path if create else self.requests / (".tmp-" + uuid.uuid4().hex)
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, "wb") as output:
                output.write(raw)
                output.flush()
                os.fsync(output.fileno())
            if not create:
                os.replace(temporary, path)
            self._sync(self.requests)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise

    def execute(self, action: str, value: dict) -> dict:
        value = self._validate_request(action, value)
        if action not in {"apply", "disable"}:
            return self._command(action, value)
        self._journal_directory()
        request_id = value["request_id"]
        digest = hashlib.sha256(_canonical({key: item for key, item in value.items()
                                            if key != "request_id"})).hexdigest()
        record = self._read(request_id)
        if record is not None:
            recorded_action = record.get("action", "apply")
            if record["request_sha256"] != digest or recorded_action != action:
                raise PublicSettingsError("KEY_REUSED")
            if record["phase"] == "complete":
                return record["result"]
            if record["phase"] == "failed":
                raise PublicSettingsError(record["result"])
            raise PublicSettingsError("UNCERTAIN")
        if len(list(self.requests.iterdir())) >= MAX_RECORDS:
            raise PublicSettingsError("REQUEST_LIMIT")
        record = {"format": 2, "action": action, "request_id": request_id,
                  "request_sha256": digest, "phase": "pending", "result": None}
        self._write(record, create=True)
        try:
            result = self._command(action, value)
        except PublicSettingsError as exc:
            # A timeout or malformed reply may hide a committed state. Keep
            # pending so a replay cannot trigger a second host mutation.
            if exc.code not in {"UNAVAILABLE", "UNCERTAIN"}:
                self._write({**record, "phase": "failed", "result": exc.code}, create=False)
            raise
        self._write({**record, "phase": "complete", "result": result}, create=False)
        return result


class PublicSettingsClient:
    """Hub side. No host files or Docker access are mounted into the container."""

    action_prefix = "public_"
    error_prefix = "PUBLIC_"
    label = "Public Web"
    helper_errors = HELPER_ERRORS

    def __init__(self, socket_path: str = SOCKET):
        self.socket_path = socket_path

    @staticmethod
    def _validate_request(action: str, value: object) -> dict:
        return validate_request(action, value)

    @staticmethod
    def _validate_reply(action: str, value: object, *, config: dict | None,
                        source_sha: str | None) -> dict:
        return validate_reply(action, value, config=config, source_sha=source_sha)

    def _error_status(self, code: str) -> tuple[int, str]:
        if code in {"INVALID_REQUEST", "IPV6_UNAVAILABLE"}:
            return 400, "Invalid public address or panel path"
        if code == "LOCAL_ACTIVE":
            return 409, "Local-only panel is active; disable it before enabling public HTTPS"
        if code in {"STATE_CHANGED", "KEY_REUSED", "BUSY", "PORT_BUSY", "ADDRESS_NOT_LOCAL",
                    "REQUEST_LIMIT"}:
            return 409, "Public Web settings changed or cannot be applied"
        if code in {"UNCERTAIN", "ROLLBACK_FAILED"}:
            return 503, "Public Web result uncertain; refresh status"
        if code in self.helper_errors | {"UNAVAILABLE"}:
            return 503, "Public Web unavailable; refresh status"
        return 503, "Invalid Public Web broker reply"

    def _request(self, action: str, value: dict, *, timeout: int = 645) -> dict:
        try:
            value = self._validate_request(action, value)
        except PublicSettingsError as exc:
            raise PublicSettingsClientError(400, f"Invalid {self.label} request") from exc
        raw = _canonical({"action": self.action_prefix + action, **value})
        if len(raw) > 1024:
            raise PublicSettingsClientError(400, f"{self.label} request is too large")
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(5)
                connection.connect(self.socket_path)
                connection.settimeout(timeout)
                connection.sendall(raw)
                reply = bytearray()
                while len(reply) <= MAX_REPLY:
                    chunk = connection.recv(min(4096, MAX_REPLY + 1 - len(reply)))
                    if not chunk:
                        break
                    reply.extend(chunk)
                    if b"\n" in chunk:
                        break
        except (OSError, socket.timeout) as exc:
            raise PublicSettingsClientError(503, f"{self.label} result uncertain; refresh status") from exc
        if not 0 < len(reply) <= MAX_REPLY or reply.count(b"\n") != 1 or not reply.endswith(b"\n"):
            raise PublicSettingsClientError(503, f"Invalid {self.label} broker reply")
        try:
            result = json.loads(reply, object_pairs_hook=_unique)
        except (UnicodeError, ValueError) as exc:
            raise PublicSettingsClientError(503, f"Invalid {self.label} broker reply") from exc
        if isinstance(result, dict) and result.get("ok") is False:
            code = result.get("error")
            if (set(result) != {"ok", "error"} or not isinstance(code, str) or
                    not code.startswith(self.error_prefix)):
                raise PublicSettingsClientError(503, f"Invalid {self.label} broker reply")
            status, message = self._error_status(code[len(self.error_prefix):])
            raise PublicSettingsClientError(status, message)
        try:
            return self._validate_reply(action, result, config=value.get("config"),
                                        source_sha=value.get("source_manifest_sha256"))
        except PublicSettingsError as exc:
            raise PublicSettingsClientError(503, f"Invalid {self.label} broker reply") from exc

    def status(self) -> dict:
        return self._request("status", {}, timeout=75)

    def preview(self, config: dict) -> dict:
        return self._request("preview", {"config": config}, timeout=120)

    def apply(self, config: dict, expected_state_sha256: str | None,
              source_manifest_sha256: str, request_id: str) -> dict:
        return self._request("apply", {"config": config,
                                       "expected_state_sha256": expected_state_sha256,
                                       "source_manifest_sha256": source_manifest_sha256,
                                       "request_id": request_id})
