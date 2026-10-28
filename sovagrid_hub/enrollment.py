# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Idempotent registration of credentials generated on a remote Agent.

The provisioning API receives only a token digest. Runtime authenticated Agent
requests still send the bearer over HTTPS, as they do for existing servers.
Cancelled IDs remain tombstones; cancellation never deletes an active server.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import time
import uuid


MAX_PENDING_ENROLLMENTS = 128


class EnrollmentError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


def enrollment_id(value):
    try:
        if not isinstance(value, str) or str(uuid.UUID(value)) != value:
            raise ValueError
    except (ValueError, AttributeError):
        raise ValueError("Enrollment and server IDs must be canonical UUIDs") from None
    return value


def registration_payload(payload):
    if not isinstance(payload, dict) or set(payload) != {"server_id", "name", "agent_token_sha256"}:
        raise ValueError("Invalid enrollment registration fields")
    enrollment_id(payload["server_id"])
    name = payload["name"]
    if (not isinstance(name, str) or not 1 <= len(name) <= 80
            or name != name.strip() or not name.isprintable()):
        raise ValueError("Server name must contain 1–80 printable characters without surrounding whitespace")
    try:
        name.encode("utf-8")
    except UnicodeError:
        raise ValueError("Server name must contain valid Unicode") from None
    digest = payload["agent_token_sha256"]
    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise ValueError("Invalid enrollment credential digest")
    encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def migrate_enrollments(db):
    # server_id intentionally is not a foreign key: a cancelled tombstone must
    # retain that exact ID after deleting its never-used server. Creator IDs
    # likewise remain audit history after the account itself is deleted.
    db.execute("""CREATE TABLE IF NOT EXISTS agent_enrollments (
        id TEXT PRIMARY KEY, server_id TEXT NOT NULL UNIQUE,
        name TEXT NOT NULL, request_hash TEXT NOT NULL,
        registered_token_hash TEXT NOT NULL, creator_id TEXT,
        created_at INTEGER NOT NULL, revision INTEGER NOT NULL DEFAULT 1,
        cancelled_at INTEGER)""")
    db.execute("CREATE INDEX IF NOT EXISTS agent_enrollments_pending ON agent_enrollments(cancelled_at,server_id)")


def _quoted_identifier(name):
    return '"' + name.replace('"', '""') + '"'


class EnrollmentStore:
    """Mixin sharing Store's existing connection and account authorization."""

    @staticmethod
    def _public_enrollment(db, row):
        if row is None:
            return None
        server = db.execute("SELECT last_seen FROM servers WHERE id=?", (row["server_id"],)).fetchone()
        if row["cancelled_at"] is not None:
            state, seen = "cancelled", None
        elif server is None:
            raise EnrollmentError(409, "Enrollment server is no longer available")
        else:
            seen = server["last_seen"]
            state = "active" if seen is not None else "pending"
        return {"id": row["id"], "server_id": row["server_id"], "name": row["name"],
                "state": state, "revision": row["revision"], "created_at": row["created_at"], "last_seen": seen}

    def agent_enrollment(self, identifier, *, session_token=None):
        enrollment_id(identifier)
        with self.connection() as db:
            db.execute("BEGIN")
            self._require_unrestricted_admin(db, session_token)
            row = db.execute("SELECT * FROM agent_enrollments WHERE id=?", (identifier,)).fetchone()
            return self._public_enrollment(db, row)

    def register_agent_enrollment(self, identifier, payload, *, session_token=None, now=None):
        enrollment_id(identifier)
        request_hash = registration_payload(payload)
        now = int(time.time()) if now is None else now
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            actor = self._require_unrestricted_admin(db, session_token)
            row = db.execute("SELECT * FROM agent_enrollments WHERE id=?", (identifier,)).fetchone()
            if row is not None:
                if row["cancelled_at"] is not None:
                    raise EnrollmentError(409, "Enrollment was cancelled; prepare a new operation")
                if not hmac.compare_digest(row["request_hash"], request_hash):
                    raise EnrollmentError(409, "Enrollment request differs from its original registration")
                server = db.execute("SELECT agent_token_hash FROM servers WHERE id=?", (row["server_id"],)).fetchone()
                if server is None or not hmac.compare_digest(server[0], row["registered_token_hash"]):
                    raise EnrollmentError(409, "Enrollment credentials changed; automatic retry is unavailable")
                return self._public_enrollment(db, row), False
            occupied = db.execute("SELECT 1 FROM servers WHERE id=?", (payload["server_id"],)).fetchone()
            reserved = db.execute("SELECT 1 FROM agent_enrollments WHERE server_id=?", (payload["server_id"],)).fetchone()
            if occupied or reserved:
                raise EnrollmentError(409, "Server ID is already in use")
            pending = db.execute("""SELECT COUNT(*) FROM agent_enrollments e
                LEFT JOIN servers s ON s.id=e.server_id
                WHERE e.cancelled_at IS NULL AND s.last_seen IS NULL""").fetchone()[0]
            if pending >= MAX_PENDING_ENROLLMENTS:
                raise EnrollmentError(409, "Too many unfinished Agent enrollments; finish or cancel one first")
            db.execute("""INSERT INTO servers(id,name,agent_token_hash,created_at,last_seen)
                VALUES (?,?,?,?,NULL)""", (payload["server_id"],payload["name"],payload["agent_token_sha256"],now))
            db.execute("""INSERT INTO agent_enrollments
                (id,server_id,name,request_hash,registered_token_hash,creator_id,created_at)
                VALUES (?,?,?,?,?,?,?)""", (identifier,payload["server_id"],payload["name"],request_hash,
                payload["agent_token_sha256"],actor["id"] if actor is not None else None,now))
            self._audit_account(db, actor, "agent_enrollment_registered", payload["server_id"], identifier,
                                {"revision": 1}, now=now)
            row = db.execute("SELECT * FROM agent_enrollments WHERE id=?", (identifier,)).fetchone()
            return self._public_enrollment(db, row), True

    @staticmethod
    def _require_empty_enrollment_server(db, row):
        server = db.execute("SELECT * FROM servers WHERE id=?", (row["server_id"],)).fetchone()
        if server is None:
            raise EnrollmentError(409, "Enrollment server is no longer available")
        if server["last_seen"] is not None:
            raise EnrollmentError(409, "Agent has already connected; automatic cancellation is unavailable")
        if (server["name"] != row["name"] or server["created_at"] != row["created_at"]
                or server["remote_commands_enabled"] or not hmac.compare_digest(server["agent_token_hash"], row["registered_token_hash"])):
            raise EnrollmentError(409, "Server settings changed; automatic cancellation is unavailable")
        # Fail closed for new direct server FKs as well as today's metrics,
        # jobs, incidents, maintenance and check tables. Empty protocol-1
        # polling can create only a revision-0 check config before metrics;
        # that bookkeeping is safe to remove, but an admin save is not.
        tables = [item[0] for item in db.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        for table in tables:
            quoted = _quoted_identifier(table)
            for foreign in db.execute("PRAGMA foreign_key_list(" + quoted + ")"):
                if foreign["table"] != "servers":
                    continue
                if foreign["to"] != "id" or foreign["seq"] != 0:
                    raise EnrollmentError(409, "Server has unsupported dependent state")
                column = _quoted_identifier(foreign["from"])
                sql = "SELECT 1 FROM " + quoted + " WHERE " + column + "=?"
                if table == "server_check_configs":
                    sql += " AND revision<>0"
                if db.execute(sql + " LIMIT 1", (row["server_id"],)).fetchone() is not None:
                    raise EnrollmentError(409, "Server has saved data; automatic cancellation is unavailable")

    def cancel_agent_enrollment(self, identifier, payload, *, session_token=None, now=None):
        enrollment_id(identifier)
        if (not isinstance(payload, dict) or set(payload) != {"revision"}
                or type(payload["revision"]) is not int or not 1 <= payload["revision"] <= 2**63 - 1):
            raise ValueError("Expected a positive enrollment revision")
        now = int(time.time()) if now is None else now
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            actor = self._require_unrestricted_admin(db, session_token)
            row = db.execute("SELECT * FROM agent_enrollments WHERE id=?", (identifier,)).fetchone()
            if row is None:
                raise EnrollmentError(404, "Enrollment not found")
            if row["cancelled_at"] is not None:
                if payload["revision"] != row["revision"] - 1:
                    raise EnrollmentError(409, "Enrollment revision changed")
                return self._public_enrollment(db, row)
            if row["revision"] != payload["revision"]:
                raise EnrollmentError(409, "Enrollment revision changed")
            self._require_empty_enrollment_server(db, row)
            db.execute("DELETE FROM servers WHERE id=?", (row["server_id"],))
            db.execute("UPDATE agent_enrollments SET revision=revision+1,cancelled_at=? WHERE id=?", (now,identifier))
            self._audit_account(db, actor, "agent_enrollment_cancelled", row["server_id"], identifier,
                                {"revision": row["revision"] + 1}, now=now)
            row = db.execute("SELECT * FROM agent_enrollments WHERE id=?", (identifier,)).fetchone()
            return self._public_enrollment(db, row)
