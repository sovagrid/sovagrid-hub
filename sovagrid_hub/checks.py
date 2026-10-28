# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Opt-in network checks: bounded configuration, token-bound leases and history.

The Hub never connects to targets. Only an authenticated Agent receives targets;
viewer/operator summaries contain fixed typed results rather than remote text.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import ipaddress
import json
import re
import ssl
import time
import uuid
from urllib.parse import urlsplit

from .auth import AuthenticationError

MAX_CHECKS = 16
MAX_CA_CERT_DER = 1536
MAX_AGENT_RESPONSE = 4096
HISTORY_LIMIT = 60
LEASE_SECONDS = 90
ERROR_CODES = frozenset(("dns_error", "connect_error", "tls_error", "timeout",
                         "http_error", "invalid_response", "internal_error", "dns_mismatch"))
RESULT_FIELDS = frozenset(("observed_at", "status", "latency_ms", "http_status",
                           "tls_expires_at", "error_code"))
_DNS_LABEL = re.compile(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\Z")
_NUMERIC_ALIAS = re.compile(r"(?:0[xX][0-9a-fA-F]+|[0-9]+)(?:\.(?:0[xX][0-9a-fA-F]+|[0-9]+))*\Z")


class CheckError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


def _integer(value, low, high):
    return type(value) is int and low <= value <= high


def canonical_uuid(value):
    try:
        if not isinstance(value, str) or str(uuid.UUID(value)) != value:
            raise ValueError
    except (ValueError, AttributeError):
        raise ValueError("Check and lease IDs must be canonical UUIDs") from None
    return value


def validate_host(value):
    if (not isinstance(value, str) or not value or len(value) > 253
            or not value.isascii() or any(c.isspace() or ord(c) < 33 or ord(c) == 127 for c in value)
            or any(c in value for c in "/\\@%[]")):
        raise ValueError("Invalid check host")
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        if (":" in value or _NUMERIC_ALIAS.fullmatch(value)
                or not all(_DNS_LABEL.fullmatch(label) for label in value.removesuffix(".").split("."))):
            raise ValueError("Invalid check host") from None
    else:
        mapped = getattr(address, "ipv4_mapped", None)
        if (address.is_unspecified or address.is_multicast
                or (mapped is not None and (mapped.is_unspecified or mapped.is_multicast))):
            raise ValueError("Unspecified and multicast check addresses are not supported")
    return value


def validate_dns_target(host, record_type, expected_ip):
    validate_host(host)
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ValueError("DNS check needs a hostname, not an IP address")
    if record_type not in ("A", "AAAA"):
        raise ValueError("DNS record type must be A or AAAA")
    if expected_ip is not None:
        if not isinstance(expected_ip, str):
            raise ValueError("Expected DNS address must be an IP address or null")
        try:
            address = ipaddress.ip_address(expected_ip)
        except ValueError:
            raise ValueError("Expected DNS address must be an IP address or null") from None
        mapped = getattr(address, "ipv4_mapped", None)
        if (address.version != (4 if record_type == "A" else 6) or "%" in expected_ip
                or address.is_unspecified or address.is_multicast
                or (mapped is not None and (mapped.is_unspecified or mapped.is_multicast))):
            raise ValueError("Expected DNS address has the wrong family")
    return host


def http_target(value):
    try:
        if (not isinstance(value, str) or len(value.encode("utf-8")) > 1024
                or any(c.isspace() or ord(c) < 33 or ord(c) == 127 for c in value)
                or any(c in value for c in "\\?#")):
            raise ValueError
        parsed = urlsplit(value)
        host, port = parsed.hostname, parsed.port
        if (parsed.scheme not in ("http", "https") or not parsed.netloc or parsed.netloc.endswith(":")
                or parsed.username is not None or parsed.password is not None or host is None):
            raise ValueError
        validate_host(host)
        authority = f"[{host}]" if ":" in host else host
        if not re.fullmatch(re.escape(authority) + r"(?::[0-9]+)?", parsed.netloc, re.IGNORECASE):
            raise ValueError
        if port is not None and not 1 <= port <= 65535:
            raise ValueError
    except (ValueError, UnicodeError):
        raise ValueError("Expected an HTTP/HTTPS URL without credentials, query or fragment") from None
    return parsed


def _der_tlv(data, offset, limit):
    """Read one definite-length DER element inside a bounded parent."""
    if offset + 2 > limit:
        raise ValueError("Invalid HTTPS CA certificate")
    tag = data[offset]
    length = data[offset + 1]
    start = offset + 2
    if length & 0x80:
        count = length & 0x7f
        if count == 0 or count > 2 or start + count > limit or data[start] == 0:
            raise ValueError("Invalid HTTPS CA certificate")
        length = int.from_bytes(data[start:start + count], "big")
        if length < 128:
            raise ValueError("Invalid HTTPS CA certificate")
        start += count
    end = start + length
    if end > limit:
        raise ValueError("Invalid HTTPS CA certificate")
    return tag, start, end


def _der_members(data, start, end):
    while start < end:
        tag, value_start, value_end = _der_tlv(data, start, end)
        yield tag, value_start, value_end
        start = value_end


def _ca_extensions(der):
    """Require a CA BasicConstraints extension and, if present, keyCertSign."""
    tag, start, end = _der_tlv(der, 0, len(der))
    if tag != 0x30 or end != len(der):
        raise ValueError("Invalid HTTPS CA certificate")
    certificate = list(_der_members(der, start, end))
    if len(certificate) != 3 or certificate[0][0] != 0x30:
        raise ValueError("Invalid HTTPS CA certificate")
    tbs = certificate[0]
    wrappers = [member for member in _der_members(der, tbs[1], tbs[2]) if member[0] == 0xa3]
    if len(wrappers) != 1:
        raise ValueError("HTTPS CA certificate must have BasicConstraints CA=true")
    wrapper = list(_der_members(der, wrappers[0][1], wrappers[0][2]))
    if len(wrapper) != 1 or wrapper[0][0] != 0x30:
        raise ValueError("Invalid HTTPS CA certificate")
    seen = set()
    is_ca = False
    can_sign = True
    for extension in _der_members(der, wrapper[0][1], wrapper[0][2]):
        if extension[0] != 0x30:
            raise ValueError("Invalid HTTPS CA certificate")
        fields = list(_der_members(der, extension[1], extension[2]))
        if len(fields) not in (2, 3) or fields[0][0] != 0x06 or fields[-1][0] != 0x04:
            raise ValueError("Invalid HTTPS CA certificate")
        oid = der[fields[0][1]:fields[0][2]]
        if oid not in (b"\x55\x1d\x13", b"\x55\x1d\x0f"):
            continue
        if oid in seen:
            raise ValueError("Invalid HTTPS CA certificate")
        seen.add(oid)
        payload = der[fields[-1][1]:fields[-1][2]]
        inner_tag, inner_start, inner_end = _der_tlv(payload, 0, len(payload))
        if inner_end != len(payload):
            raise ValueError("Invalid HTTPS CA certificate")
        if oid == b"\x55\x1d\x13":
            if inner_tag != 0x30:
                raise ValueError("Invalid HTTPS CA certificate")
            constraints = list(_der_members(payload, inner_start, inner_end))
            is_ca = bool(constraints and constraints[0][0] == 0x01
                         and payload[constraints[0][1]:constraints[0][2]] == b"\xff")
        else:
            if inner_tag != 0x03 or inner_end - inner_start < 2:
                raise ValueError("Invalid HTTPS CA certificate")
            bits = payload[inner_start:inner_end]
            can_sign = bits[0] <= 7 and bool(bits[1] & 0x04)
    if not is_ca or not can_sign:
        raise ValueError("HTTPS CA certificate must permit CA signing")


def validate_ca_certificate(value):
    if not isinstance(value, str) or len(value) > 4 * ((MAX_CA_CERT_DER + 2) // 3):
        raise ValueError("HTTPS CA certificate must be base64 DER up to 1536 bytes")
    try:
        der = base64.b64decode(value, validate=True)
        if not der or len(der) > MAX_CA_CERT_DER or base64.b64encode(der).decode("ascii") != value:
            raise ValueError
        ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).load_verify_locations(cadata=ssl.DER_cert_to_PEM_cert(der))
        _ca_extensions(der)
    except (ValueError, UnicodeError, binascii.Error, ssl.SSLError):
        raise ValueError("Invalid HTTPS CA certificate") from None
    return value


def _validate_lease_size(value):
    executable = {key: item for key, item in value.items()
                  if key != "tls_alert_days" and not (key == "ca_cert_der_b64" and item is None)}
    envelope = {"lease": {"id": "0" * 36, "check_id": value["id"],
                          "config_revision": 2**63 - 1, "expires_at": 253402300799,
                          "check": executable}}
    if len(json.dumps(envelope, ensure_ascii=False, separators=(",", ":")).encode("utf-8")) > MAX_AGENT_RESPONSE:
        raise ValueError("Check definition exceeds Agent response limit")


def validate_definition(value):
    common = {"id", "name", "kind", "enabled", "interval_seconds", "timeout_seconds"}
    if not isinstance(value, dict) or value.get("kind") not in ("http", "tcp", "dns"):
        raise ValueError("Check kind must be http, tcp or dns")
    expected = common | ({"url"} if value["kind"] == "http" else
                         {"host", "port"} if value["kind"] == "tcp" else
                         {"host", "record_type", "expected_ip"})
    fields = set(value)
    optional = {"tls_alert_days", "ca_cert_der_b64"} if value["kind"] == "http" else set()
    if not expected <= fields or fields - expected - optional:
        raise ValueError("Unexpected or missing check fields")
    canonical_uuid(value["id"])
    name = value["name"]
    if (not isinstance(name, str) or not 1 <= len(name) <= 80 or name != name.strip()
            or any(ord(c) < 32 or ord(c) == 127 for c in name)):
        raise ValueError("Check name must contain 1–80 characters without surrounding whitespace or controls")
    try:
        name.encode("utf-8")
    except UnicodeError:
        raise ValueError("Check name must contain valid Unicode") from None
    if (type(value["enabled"]) is not bool
            or not _integer(value["interval_seconds"], 60, 3600)
            or not _integer(value["timeout_seconds"], 1, 10)):
        raise ValueError("Check interval must be 60–3600 seconds and timeout 1–10 seconds")
    if value["kind"] == "http":
        scheme = http_target(value["url"]).scheme
        if "tls_alert_days" in value and (scheme != "https" or
                (value["tls_alert_days"] is not None and not _integer(value["tls_alert_days"], 1, 90))):
            raise ValueError("HTTPS certificate alert must be null or 1–90 days")
        if "ca_cert_der_b64" in value:
            if scheme != "https":
                raise ValueError("Custom CA is only supported for HTTPS checks")
            if value["ca_cert_der_b64"] is not None:
                validate_ca_certificate(value["ca_cert_der_b64"])
    elif value["kind"] == "tcp":
        validate_host(value["host"])
        if not _integer(value["port"], 1, 65535):
            raise ValueError("TCP check port must be between 1 and 65535")
    else:
        validate_dns_target(value["host"], value["record_type"], value["expected_ip"])
    _validate_lease_size(value)
    return dict(value)


def validate_config(payload):
    if not isinstance(payload, dict) or set(payload) != {"revision", "checks"}:
        raise ValueError("Expected revision and checks")
    if not _integer(payload["revision"], 0, 2**63 - 2):
        raise ValueError("Invalid check configuration revision")
    if not isinstance(payload["checks"], list) or len(payload["checks"]) > MAX_CHECKS:
        raise ValueError("At most 16 checks are supported per server")
    checks = [validate_definition(value) for value in payload["checks"]]
    if len({item["id"] for item in checks}) != len(checks):
        raise ValueError("Duplicate check ID")
    if len(json.dumps(payload, ensure_ascii=False).encode("utf-8")) > 32768:
        raise ValueError("Check configuration exceeds 32 KiB")
    return payload["revision"], checks


def validate_result(payload, definition, now):
    if not isinstance(payload, dict) or set(payload) != RESULT_FIELDS | {"lease_id", "config_revision"}:
        raise ValueError("Unexpected or missing check result fields")
    canonical_uuid(payload["lease_id"])
    if (not _integer(payload["config_revision"], 1, 2**63 - 1)
            or not _integer(payload["observed_at"], 1, 253402300799)
            or abs(payload["observed_at"] - now) > 300
            or not _integer(payload["latency_ms"], 0, 10000)
            or payload["status"] not in ("up", "down")
            or (payload["http_status"] is not None and not _integer(payload["http_status"], 100, 599))
            or (payload["tls_expires_at"] is not None and not _integer(payload["tls_expires_at"], 1, 253402300799))
            or (payload["error_code"] is not None and (not isinstance(payload["error_code"], str) or payload["error_code"] not in ERROR_CODES))):
        raise ValueError("Invalid check result types or observation time")
    status, code, http, tls = (payload[key] for key in ("status", "error_code", "http_status", "tls_expires_at"))
    if ((status == "up") != (code is None)
            or (code == "http_error" and (http is None or 200 <= http < 300))
            or (code in ("dns_error", "connect_error", "tls_error") and http is not None)
            or (code == "tls_error" and tls is not None)
            or (status == "up" and http is not None and not 200 <= http < 300)):
        raise ValueError("Inconsistent check result")
    if definition["kind"] in ("tcp", "dns"):
        if http is not None or tls is not None or code in ("http_error", "tls_error"):
            raise ValueError("TCP and DNS checks cannot report HTTP or TLS data")
        if definition["kind"] == "dns" and code == "connect_error":
            raise ValueError("DNS checks cannot report TCP connection errors")
        if definition["kind"] == "dns" and code == "dns_mismatch" and definition["expected_ip"] is None:
            raise ValueError("DNS mismatch needs an expected address")
        if definition["kind"] == "tcp" and code == "dns_mismatch":
            raise ValueError("TCP checks cannot report DNS mismatches")
    else:
        scheme = http_target(definition["url"]).scheme
        if ((scheme != "https" and tls is not None) or (status == "up" and http is None)
                or (scheme == "https" and status == "up" and tls is None)
                or code == "dns_mismatch"):
            raise ValueError("Result does not match check type")
    return {key: payload[key] for key in sorted(RESULT_FIELDS)}


def migrate_checks(db):
    """Use the caller's transaction; executescript would commit its DDL early."""
    db.execute("""CREATE TABLE IF NOT EXISTS server_check_configs (
        server_id TEXT PRIMARY KEY REFERENCES servers(id) ON DELETE CASCADE,
        revision INTEGER NOT NULL DEFAULT 0, worker_seen_at INTEGER)""")
    db.execute("""CREATE TABLE IF NOT EXISTS server_checks (
        server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
        check_id TEXT NOT NULL, position INTEGER NOT NULL, definition_json TEXT NOT NULL,
        next_due_at INTEGER NOT NULL, manual_requested_at INTEGER,
        lease_id TEXT, lease_revision INTEGER, lease_until INTEGER, lease_token_hash TEXT,
        PRIMARY KEY(server_id,check_id))""")
    db.execute("""CREATE TABLE IF NOT EXISTS check_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        server_id TEXT NOT NULL, check_id TEXT NOT NULL,
        lease_id TEXT NOT NULL, config_revision INTEGER NOT NULL,
        lease_until INTEGER NOT NULL, agent_token_hash TEXT NOT NULL,
        received_at INTEGER NOT NULL, result_json TEXT NOT NULL,
        FOREIGN KEY(server_id,check_id) REFERENCES server_checks(server_id,check_id) ON DELETE CASCADE,
        UNIQUE(server_id,check_id,lease_id))""")
    db.execute("CREATE INDEX IF NOT EXISTS check_results_recent ON check_results(server_id,check_id,id DESC)")


class CheckStore:
    """Mixin using Store.connection, account authorization and audit helpers."""

    @staticmethod
    def _check_server(db, server_id):
        if db.execute("SELECT 1 FROM servers WHERE id=?", (server_id,)).fetchone() is None:
            raise CheckError(404, "Server not found")

    @staticmethod
    def _check_agent(db, server_id, token):
        if not isinstance(token, str) or not token or len(token) > 256:
            raise AuthenticationError("Unauthorized")
        row = db.execute("SELECT agent_token_hash FROM servers WHERE id=?", (server_id,)).fetchone()
        digest = hashlib.sha256(token.encode()).hexdigest()
        if row is None or not hmac.compare_digest(row[0], digest):
            raise AuthenticationError("Unauthorized")
        return digest

    @staticmethod
    def _check_config(db, server_id):
        row = db.execute("SELECT revision,worker_seen_at FROM server_check_configs WHERE server_id=?", (server_id,)).fetchone()
        return (row["revision"], row["worker_seen_at"]) if row else (0, None)

    @staticmethod
    def _check_definitions(db, server_id):
        return [json.loads(row[0]) for row in db.execute(
            "SELECT definition_json FROM server_checks WHERE server_id=? ORDER BY position,check_id", (server_id,))]

    def _retire_check_alert(self, db, server_id, check_id, now, name, *, tls_only=False):
        """An administrative change ends the old target without claiming recovery."""
        kinds = ("tls:" + check_id,) if tls_only else ("check:" + check_id, "tls:" + check_id)
        for kind in kinds:
            event = self._set_incident(db, server_id, kind, False, now, subject=name)
            if event is None:
                continue
            db.execute("DELETE FROM maintenance_deferred WHERE incident_id=?", (event["id"],))
            db.execute("""UPDATE incident_outbox SET dropped_at=?, lease_until=NULL
                          WHERE incident_id=? AND delivered_at IS NULL AND dropped_at IS NULL""",
                       (now, event["id"]))

    def check_config(self, server_id, *, session_token=None):
        with self.connection() as db:
            db.execute("BEGIN")
            self._require_server_session(db, session_token, server_id, "admin")
            self._check_server(db, server_id)
            revision, _ = self._check_config(db, server_id)
            return {"server_id": server_id, "revision": revision, "checks": self._check_definitions(db, server_id)}

    def save_check_config(self, server_id, payload, *, session_token=None, now=None):
        revision, checks = validate_config(payload)
        now = int(time.time()) if now is None else now
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            identity = self._require_server_session(db, session_token, server_id, "admin")
            self._check_server(db, server_id)
            current, _ = self._check_config(db, server_id)
            if current != revision:
                raise CheckError(409, "Check configuration changed; reload before saving")
            old = {row["check_id"]: row for row in db.execute("SELECT * FROM server_checks WHERE server_id=?", (server_id,))}
            ids = {item["id"] for item in checks}
            for check_id in old.keys() - ids:
                previous = json.loads(old[check_id]["definition_json"])
                self._retire_check_alert(db, server_id, check_id, now, previous["name"])
                db.execute("DELETE FROM server_checks WHERE server_id=? AND check_id=?", (server_id, check_id))
            for position, item in enumerate(checks):
                previous = json.loads(old[item["id"]]["definition_json"]) if item["id"] in old else None
                endpoint_keys = {"kind", "url", "host", "port", "record_type", "expected_ip"}
                changed_endpoint = previous is not None and any(previous.get(key) != item.get(key) for key in endpoint_keys)
                # Older clients do not know this Hub-only rule. An omitted field
                # keeps it for the same target; explicit null disables it.
                if previous is not None and not changed_endpoint and item["kind"] == "http":
                    for key in ("tls_alert_days", "ca_cert_der_b64"):
                        if key not in item and key in previous:
                            item = dict(item, **{key: previous[key]})
                    checks[position] = item
                    _validate_lease_size(item)
                changed_target = changed_endpoint or (previous is not None and
                    previous.get("ca_cert_der_b64") != item.get("ca_cert_der_b64"))
                if previous is not None:
                    if changed_target or (previous["enabled"] and not item["enabled"]):
                        self._retire_check_alert(db, server_id, item["id"], now, previous["name"])
                    elif previous.get("tls_alert_days") != item.get("tls_alert_days"):
                        self._retire_check_alert(db, server_id, item["id"], now, previous["name"], tls_only=True)
                    if previous["name"] != item["name"]:
                        db.execute("""UPDATE incidents SET subject=? WHERE server_id=? AND kind=?
                                      AND state='firing'""",
                                   (item["name"], server_id, "check:" + item["id"]))
                        db.execute("""UPDATE incidents SET subject=? WHERE server_id=? AND kind=?
                                      AND state='firing'""",
                                   (item["name"], server_id, "tls:" + item["id"]))
                if changed_target:
                    db.execute("DELETE FROM check_results WHERE server_id=? AND check_id=?", (server_id, item["id"]))
                reschedule = previous is None or changed_target or previous["enabled"] != item["enabled"] or previous["interval_seconds"] != item["interval_seconds"]
                due = now if reschedule else old[item["id"]]["next_due_at"]
                db.execute("""INSERT INTO server_checks (server_id,check_id,position,definition_json,next_due_at)
                    VALUES (?,?,?,?,?) ON CONFLICT(server_id,check_id) DO UPDATE SET
                    position=excluded.position,definition_json=excluded.definition_json,next_due_at=excluded.next_due_at,
                    lease_id=NULL,lease_revision=NULL,lease_until=NULL,lease_token_hash=NULL""",
                    (server_id, item["id"], position, json.dumps(item, separators=(",", ":"), ensure_ascii=False), due))
            db.execute("""INSERT INTO server_check_configs (server_id,revision) VALUES (?,?)
                ON CONFLICT(server_id) DO UPDATE SET revision=excluded.revision""", (server_id, revision + 1))
            self._audit_account(db, identity, "checks_config_changed", server_id, details={
                "revision": revision + 1, "checks": [{key: item[key] for key in
                    ("id", "kind", "enabled", "interval_seconds", "timeout_seconds")} for item in checks]}, now=now)
            return {"server_id": server_id, "revision": revision + 1, "checks": checks}

    def run_check(self, server_id, check_id, payload, *, session_token=None, now=None):
        canonical_uuid(check_id)
        if not isinstance(payload, dict) or set(payload) != {"revision"} or not _integer(payload["revision"], 0, 2**63 - 1):
            raise ValueError("Expected check configuration revision")
        now = int(time.time()) if now is None else now
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            identity = self._require_server_session(db, session_token, server_id, "admin")
            self._check_server(db, server_id)
            if self._check_config(db, server_id)[0] != payload["revision"]:
                raise CheckError(409, "Check configuration changed; reload before running")
            row = db.execute("SELECT * FROM server_checks WHERE server_id=? AND check_id=?", (server_id,check_id)).fetchone()
            if row is None:
                raise CheckError(404, "Check not found")
            if not json.loads(row["definition_json"])["enabled"]:
                raise CheckError(409, "Enable this check before running it")
            if row["lease_until"] is not None and row["lease_until"] > now:
                raise CheckError(409, "Check is already running")
            if row["manual_requested_at"] is not None and now - row["manual_requested_at"] < 10:
                raise CheckError(429, "Wait ten seconds before running this check again")
            db.execute("UPDATE server_checks SET next_due_at=?,manual_requested_at=? WHERE server_id=? AND check_id=?", (now,now,server_id,check_id))
            self._audit_account(db, identity, "check_run_requested", server_id, check_id, now=now)
            return {"server_id": server_id, "check_id": check_id, "scheduled": True}

    @staticmethod
    def _public_check_result(row):
        return dict(json.loads(row["result_json"]), received_at=row["received_at"]) if row else None

    def checks_summary(self, server_id, *, session_token=None, bot=None, now=None):
        now = int(time.time()) if now is None else now
        with self.connection() as db:
            db.execute("BEGIN")
            self._require_server_session(db, session_token, server_id, "viewer")
            if bot is not None and not self._bot_allowed(db, *bot, server_id):
                raise PermissionError("Server access denied")
            self._check_server(db, server_id)
            revision, seen = self._check_config(db, server_id)
            offline = self._monitoring_settings(db)["offline_seconds"]
            result = []
            for item in self._check_definitions(db, server_id):
                latest = self._public_check_result(db.execute("SELECT * FROM check_results WHERE server_id=? AND check_id=? ORDER BY id DESC LIMIT 1", (server_id,item["id"])).fetchone())
                if not item["enabled"]:
                    state = "disabled"
                elif latest is None:
                    state = "waiting"
                elif (now - latest["received_at"] > max(90, 2 * item["interval_seconds"])
                      or seen is None or now - seen > max(90, offline)):
                    state = "stale"
                else:
                    state = latest["status"]
                result.append({**{key: item[key] for key in ("id", "name", "kind", "enabled", "interval_seconds", "timeout_seconds")},
                               "tls_alert_days": item.get("tls_alert_days"), "latest": latest, "state": state})
            return {"server_id": server_id, "revision": revision, "worker_seen_at": seen, "checks": result}

    def check_history(self, server_id, check_id, limit=60, *, session_token=None):
        canonical_uuid(check_id)
        if not _integer(limit, 1, HISTORY_LIMIT):
            raise ValueError("Check history limit must be between 1 and 60")
        with self.connection() as db:
            db.execute("BEGIN")
            self._require_server_session(db, session_token, server_id, "viewer")
            self._check_server(db, server_id)
            if db.execute("SELECT 1 FROM server_checks WHERE server_id=? AND check_id=?", (server_id,check_id)).fetchone() is None:
                raise CheckError(404, "Check not found")
            rows = db.execute("SELECT * FROM check_results WHERE server_id=? AND check_id=? ORDER BY id DESC LIMIT ?", (server_id,check_id,limit))
            return {"server_id": server_id, "check_id": check_id, "results": [self._public_check_result(row) for row in rows]}

    def claim_check(self, server_id, token, payload, *, now=None):
        if not isinstance(payload, dict) or set(payload) != {"protocol"} or type(payload["protocol"]) is not int or payload["protocol"] != 1:
            raise ValueError("Expected check protocol 1")
        now = int(time.time()) if now is None else now
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            digest = self._check_agent(db, server_id, token)
            db.execute("""INSERT INTO server_check_configs(server_id,revision,worker_seen_at) VALUES (?,0,?)
                ON CONFLICT(server_id) DO UPDATE SET worker_seen_at=excluded.worker_seen_at""", (server_id,now))
            revision, _ = self._check_config(db, server_id)
            active = db.execute("SELECT COUNT(*) FROM server_checks WHERE server_id=? AND lease_until>?", (server_id,now)).fetchone()[0]
            if active >= 2:
                return {"lease": None}
            rows = db.execute("""SELECT * FROM server_checks WHERE server_id=? AND next_due_at<=?
                AND (lease_until IS NULL OR lease_until<=?) ORDER BY next_due_at,position,check_id""", (server_id,now,now))
            for row in rows:
                definition = json.loads(row["definition_json"])
                if not definition["enabled"]:
                    continue
                lease_id = str(uuid.uuid4())
                db.execute("""UPDATE server_checks SET lease_id=?,lease_revision=?,lease_until=?,lease_token_hash=?
                    WHERE server_id=? AND check_id=?""", (lease_id,revision,now+LEASE_SECONDS,digest,server_id,row["check_id"]))
                # The rule is evaluated by Hub, not the probe. Keep leases
                # compatible with Agents that validate the old exact union.
                executable = {key: value for key, value in definition.items()
                              if key != "tls_alert_days" and not (key == "ca_cert_der_b64" and value is None)}
                return {"lease": {"id": lease_id, "check_id": row["check_id"], "config_revision": revision,
                    "expires_at": now + LEASE_SECONDS, "check": executable}}
            return {"lease": None}

    def record_check_result(self, server_id, check_id, token, payload, *, now=None):
        canonical_uuid(check_id)
        now = int(time.time()) if now is None else now
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            digest = self._check_agent(db, server_id, token)
            row = db.execute("SELECT * FROM server_checks WHERE server_id=? AND check_id=?", (server_id,check_id)).fetchone()
            if row is None:
                raise CheckError(409, "Check or lease is no longer current")
            if not isinstance(payload, dict) or not _integer(payload.get("config_revision"), 1, 2**63 - 1):
                raise ValueError("Invalid check configuration revision")
            if self._check_config(db, server_id)[0] != payload["config_revision"]:
                raise CheckError(409, "Check configuration changed")
            clean = validate_result(payload, json.loads(row["definition_json"]), now)
            encoded = json.dumps(clean, separators=(",", ":"), sort_keys=True)
            completed = db.execute("SELECT * FROM check_results WHERE server_id=? AND check_id=? AND lease_id=?", (server_id,check_id,payload["lease_id"])).fetchone()
            if completed is not None:
                if (completed["lease_until"] <= now or completed["config_revision"] != payload["config_revision"]
                        or not hmac.compare_digest(completed["agent_token_hash"], digest) or completed["result_json"] != encoded):
                    raise CheckError(409, "Check lease expired or result differs")
                return {"accepted": True}
            if (row["lease_id"] != payload["lease_id"] or row["lease_revision"] != payload["config_revision"]
                    or row["lease_until"] is None or row["lease_until"] <= now
                    or row["lease_token_hash"] is None or not hmac.compare_digest(row["lease_token_hash"], digest)):
                raise CheckError(409, "Check lease is no longer current")
            db.execute("""INSERT INTO check_results(server_id,check_id,lease_id,config_revision,lease_until,agent_token_hash,received_at,result_json)
                VALUES (?,?,?,?,?,?,?,?)""", (server_id,check_id,payload["lease_id"],payload["config_revision"],row["lease_until"],digest,now,encoded))
            definition = json.loads(row["definition_json"])
            db.execute("""UPDATE server_checks SET next_due_at=?,lease_id=NULL,lease_revision=NULL,lease_until=NULL,lease_token_hash=NULL
                WHERE server_id=? AND check_id=?""", (now+definition["interval_seconds"],server_id,check_id))
            # The result row is also the idempotency record; pruning it bounds
            # both history and duplicate metadata independently of UI reads.
            db.execute("""DELETE FROM check_results WHERE server_id=? AND check_id=? AND id NOT IN
                (SELECT id FROM check_results WHERE server_id=? AND check_id=? ORDER BY id DESC LIMIT 60)""", (server_id,check_id,server_id,check_id))
            kind = "check:" + check_id
            if clean["status"] == "down":
                candidate = db.execute("""SELECT last_seen FROM incident_candidates
                                          WHERE server_id=? AND kind=?""", (server_id, kind)).fetchone()
                if candidate is not None and now - candidate["last_seen"] > max(90, 2 * definition["interval_seconds"]):
                    # A stale worker cannot prove that the target stayed down
                    # throughout the gap. Require a fresh hold period.
                    db.execute("DELETE FROM incident_candidates WHERE server_id=? AND kind=?", (server_id, kind))
            settings = self._monitoring_settings(db)
            event = self._set_incident(db, server_id, kind, clean["status"] == "down",
                                       now, 1.0 if clean["status"] == "down" else 0.0, 1.0,
                                       settings["trigger_minutes"] * 60,
                                       subject=definition["name"])
            events = [event] if event else []
            tls_kind = "tls:" + check_id
            days = definition.get("tls_alert_days")
            if days is not None and clean["tls_expires_at"] is not None:
                remaining_days = (clean["tls_expires_at"] - now) / 86400
                active = remaining_days <= days
                if active:
                    candidate = db.execute("""SELECT last_seen FROM incident_candidates
                                              WHERE server_id=? AND kind=?""", (server_id, tls_kind)).fetchone()
                    if candidate is not None and now - candidate["last_seen"] > max(90, 2 * definition["interval_seconds"]):
                        db.execute("DELETE FROM incident_candidates WHERE server_id=? AND kind=?", (server_id, tls_kind))
                tls_event = self._set_incident(db, server_id, tls_kind, active, now,
                                               remaining_days, float(days), settings["trigger_minutes"] * 60,
                                               subject=definition["name"])
                if tls_event is not None:
                    events.append(tls_event)
            else:
                # A failed handshake cannot prove renewal or continued expiry.
                # Preserve a firing incident, but reset an unconfirmed hold.
                db.execute("DELETE FROM incident_candidates WHERE server_id=? AND kind=?", (server_id, tls_kind))
            self._maintenance_notifications(db, events, now)
            return {"accepted": True}
