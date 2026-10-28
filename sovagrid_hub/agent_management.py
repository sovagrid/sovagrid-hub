# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Compare-and-swap command access for an already enrolled remote Agent."""
from __future__ import annotations

import hmac
import re
import time

from .enrollment import EnrollmentError, enrollment_id

MAX_REVISION = 2**63 - 1
MAX_MANAGEMENT_SERVERS = 256


def migrate_agent_management(db):
    columns = {row["name"] for row in db.execute("PRAGMA table_info(servers)")}
    if columns and "management_revision" not in columns:
        db.execute("ALTER TABLE servers ADD COLUMN management_revision INTEGER NOT NULL DEFAULT 0")


def management_payload(payload):
    if not isinstance(payload, dict) or set(payload) != {
            "enrollment_id", "agent_token_sha256", "expected_revision", "enabled"}:
        raise ValueError("Invalid Agent management fields")
    enrollment_id(payload["enrollment_id"])
    digest = payload["agent_token_sha256"]
    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise ValueError("Invalid Agent credential digest")
    if type(payload["expected_revision"]) is not int or not 0 <= payload["expected_revision"] <= MAX_REVISION:
        raise ValueError("Agent management revision must be a nonnegative 64-bit integer")
    if type(payload["enabled"]) is not bool:
        raise ValueError("Expected boolean enabled")


class AgentManagementStore:
    """Uses Store's authorization, audit and serialized SQLite transactions."""

    @staticmethod
    def _management_row(db, server_id):
        server = db.execute("SELECT * FROM servers WHERE id=?", (server_id,)).fetchone()
        if server is None:
            raise EnrollmentError(404, "Server not found")
        registered = db.execute("SELECT * FROM agent_enrollments WHERE server_id=?", (server_id,)).fetchone()
        if registered is None:
            raise EnrollmentError(404, "Remote Agent enrollment not found")
        if registered["cancelled_at"] is not None or server["last_seen"] is None:
            raise EnrollmentError(409, "Remote Agent enrollment is not active")
        if (not isinstance(server["agent_token_hash"], str)
                or re.fullmatch(r"[0-9a-f]{64}", server["agent_token_hash"]) is None
                or not isinstance(registered["registered_token_hash"], str)
                or re.fullmatch(r"[0-9a-f]{64}", registered["registered_token_hash"]) is None
                or not hmac.compare_digest(server["agent_token_hash"], registered["registered_token_hash"])):
            raise EnrollmentError(409, "Agent enrollment credentials changed")
        if (server["remote_commands_enabled"] not in (0, 1)
                or type(server["management_revision"]) is not int
                or not 0 <= server["management_revision"] <= MAX_REVISION):
            raise EnrollmentError(409, "Agent management state is invalid")
        return server, registered

    @staticmethod
    def _public_management(server, registered):
        return {"server_id": server["id"], "enrollment_id": registered["id"],
                "agent_token_sha256": registered["registered_token_hash"],
                "enabled": bool(server["remote_commands_enabled"]), "revision": server["management_revision"]}

    def agent_management_servers(self, *, session_token=None):
        with self.connection() as db:
            db.execute("BEGIN")
            identity = self._require_admin_session(db, session_token)
            visible = self._visible_server_ids(db, identity=identity, role="admin")
            if visible is not None and not visible:
                return {"servers": [], "truncated": False}
            query = """SELECT s.id,s.name FROM servers s
                JOIN agent_enrollments e ON e.server_id=s.id
                WHERE e.cancelled_at IS NULL AND s.last_seen IS NOT NULL
                  AND e.registered_token_hash=s.agent_token_hash"""
            args = []
            if visible is not None:
                query += " AND s.id IN (" + ",".join("?" for _ in visible) + ")"
                args.extend(sorted(visible))
            rows = db.execute(query + " ORDER BY s.name,s.id LIMIT ?", (*args, MAX_MANAGEMENT_SERVERS + 1)).fetchall()
            return {"servers": [{"id": row["id"], "name": row["name"]} for row in rows[:MAX_MANAGEMENT_SERVERS]],
                    "truncated": len(rows) > MAX_MANAGEMENT_SERVERS}

    def agent_management(self, server_id, *, session_token=None):
        enrollment_id(server_id)
        with self.connection() as db:
            db.execute("BEGIN")
            self._require_server_session(db, session_token, server_id, "admin")
            return self._public_management(*self._management_row(db, server_id))

    def _write_command_gate(self, db, server, enabled, identity, *, enrollment=None):
        """Shared by legacy and CAS writers; caller holds BEGIN IMMEDIATE."""
        previous = bool(server["remote_commands_enabled"])
        changed = previous != enabled
        revision = server["management_revision"]
        if changed:
            if revision >= MAX_REVISION:
                raise EnrollmentError(409, "Agent management revision limit reached")
            revision += 1
            db.execute("UPDATE servers SET remote_commands_enabled=?,management_revision=? WHERE id=?",
                       (int(enabled), revision, server["id"]))
        if not enabled:
            db.execute("UPDATE jobs SET state='cancelled',command='',completed_at=? WHERE server_id=? AND state='queued'",
                       (int(time.time()), server["id"]))
            db.execute("DELETE FROM pending_commands WHERE server_id=?", (server["id"],))
        self._audit_account(db, identity, "remote_commands_enabled" if enabled else "remote_commands_disabled",
                            server["id"], enrollment,
                            {"enabled": enabled, "changed": changed, "revision": revision})
        return revision, changed

    def save_agent_management(self, server_id, payload, *, session_token=None):
        enrollment_id(server_id)
        management_payload(payload)
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            identity = self._require_server_session(db, session_token, server_id, "admin")
            server, registered = self._management_row(db, server_id)
            if (registered["id"] != payload["enrollment_id"]
                    or not hmac.compare_digest(registered["registered_token_hash"], payload["agent_token_sha256"])):
                raise EnrollmentError(409, "Agent management identity changed")
            if server["management_revision"] != payload["expected_revision"]:
                raise EnrollmentError(409, "Agent management revision changed")
            revision, changed = self._write_command_gate(db, server, payload["enabled"], identity,
                                                          enrollment=registered["id"])
            return {**self._public_management(server, registered), "enabled": payload["enabled"],
                    "revision": revision, "changed": changed}
