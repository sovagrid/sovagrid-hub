# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Bounded command-queue lease for a planned external Agent restart.

This lease serializes with SQLite job enqueue and dispatch. It also lets the
HTTP layer stop *new* terminal and file relay requests. It is deliberately not
an Agent idle proof: a file operation already handed to an older Agent can
outlive the Hub's in-memory relay record or a Hub process restart.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import time


LEASE_SECONDS = 120
MAX_LIFETIME_SECONDS = 900
SCOPE = "jobs_and_new_relays"
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_TOKEN = re.compile(r"[A-Za-z0-9_-]{43}\Z")


class MaintenanceLeaseBusy(PermissionError):
    """An active lease or uncertain work prevents a new action."""


class MaintenanceLeaseInvalid(ValueError):
    """The lease token is missing, expired, or belongs to another server."""


def migrate_agent_maintenance(db) -> None:
    db.execute("""CREATE TABLE IF NOT EXISTS agent_maintenance_leases (
        server_id TEXT PRIMARY KEY REFERENCES servers(id) ON DELETE CASCADE,
        token_hash TEXT NOT NULL CHECK(length(token_hash)=64),
        bundle_manifest_sha256 TEXT NOT NULL CHECK(length(bundle_manifest_sha256)=64),
        hub_epoch TEXT NOT NULL CHECK(length(hub_epoch)=32),
        issued_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL CHECK(expires_at > issued_at),
        max_until INTEGER NOT NULL CHECK(max_until >= expires_at)
    )""")


class AgentMaintenanceStore:
    @staticmethod
    def _agent_maintenance_active(db, server_id: str, now: int) -> bool:
        return db.execute("""SELECT 1 FROM agent_maintenance_leases
            WHERE server_id=? AND expires_at>? LIMIT 1""", (server_id, now)).fetchone() is not None

    @staticmethod
    def _agent_maintenance_credential(db, server_id: str, agent_token: str) -> bool:
        if not isinstance(agent_token, str) or not agent_token or len(agent_token) > 256:
            return False
        row = db.execute("SELECT agent_token_hash FROM servers WHERE id=?", (server_id,)).fetchone()
        return (row is not None and isinstance(row["agent_token_hash"], str) and
                _SHA.fullmatch(row["agent_token_hash"]) is not None and
                hmac.compare_digest(row["agent_token_hash"],
                                    hashlib.sha256(agent_token.encode()).hexdigest()))

    @classmethod
    def _reject_agent_maintenance(cls, db, server_id: str, now: int) -> None:
        if cls._agent_maintenance_active(db, server_id, now):
            raise MaintenanceLeaseBusy("Agent maintenance is in progress")

    def agent_maintenance_active(self, server_id: str, now: int | None = None) -> bool:
        now = int(time.time()) if now is None else now
        with self.connection() as db:
            return self._agent_maintenance_active(db, server_id, now)

    def acquire_agent_maintenance_lease(self, server_id: str, agent_token: str,
                                        bundle_manifest_sha256: str, *,
                                        hub_epoch: str, relays_active: bool,
                                        now: int | None = None) -> dict | None:
        """Reserve one server under a write transaction; caller holds relay lock.

        Returning None means the Agent credential changed. The HTTP caller
        must take the same in-process lock around relay creation and this call.
        """
        if (not isinstance(bundle_manifest_sha256, str) or
                _SHA.fullmatch(bundle_manifest_sha256) is None or
                not isinstance(hub_epoch, str) or
                re.fullmatch(r"[0-9a-f]{32}\Z", hub_epoch) is None or
                type(relays_active) is not bool):
            raise ValueError("Invalid maintenance lease request")
        now = int(time.time()) if now is None else now
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            if not self._agent_maintenance_credential(db, server_id, agent_token):
                return None
            self._reject_agent_maintenance(db, server_id, now)
            if relays_active:
                raise MaintenanceLeaseBusy("Active terminal or file relay")
            if db.execute("""SELECT 1 FROM jobs WHERE server_id=? AND state IN ('queued','delivered')
                            LIMIT 1""", (server_id,)).fetchone():
                raise MaintenanceLeaseBusy("Queued or delivered Agent job")
            if db.execute("""SELECT 1 FROM pending_commands WHERE server_id=? AND expires_at>=?
                            LIMIT 1""", (server_id, now)).fetchone():
                raise MaintenanceLeaseBusy("Pending Telegram command")
            expired = db.execute("""DELETE FROM agent_maintenance_leases
                                    WHERE server_id=? AND expires_at<=?""", (server_id, now)).rowcount
            if expired:
                self._audit(db, "system", "agent_maintenance_expired", server_id, now=now)
            token = secrets.token_urlsafe(32)
            assert _TOKEN.fullmatch(token) is not None
            expires_at = now + LEASE_SECONDS
            db.execute("""INSERT INTO agent_maintenance_leases
                (server_id,token_hash,bundle_manifest_sha256,hub_epoch,issued_at,expires_at,max_until)
                VALUES (?,?,?,?,?,?,?)""",
                (server_id, hashlib.sha256(token.encode()).hexdigest(),
                 bundle_manifest_sha256, hub_epoch, now, expires_at,
                 now + MAX_LIFETIME_SECONDS))
            self._audit(db, f"agent:{server_id}", "agent_maintenance_acquired", server_id,
                        details={"scope": SCOPE, "expires_at": expires_at,
                                 "bundle_manifest_sha256": bundle_manifest_sha256}, now=now)
            return {"protocol": 1, "scope": SCOPE, "lease_token": token,
                    "hub_epoch": hub_epoch,
                    "expires_at": expires_at, "max_until": now + MAX_LIFETIME_SECONDS,
                    "agent_idle_proven": False}

    def renew_agent_maintenance_lease(self, server_id: str, agent_token: str,
                                      lease_token: str, *, hub_epoch: str,
                                      bundle_manifest_sha256: str,
                                      now: int | None = None) -> dict | None:
        if not isinstance(lease_token, str) or _TOKEN.fullmatch(lease_token) is None:
            raise MaintenanceLeaseInvalid("Invalid maintenance lease token")
        now = int(time.time()) if now is None else now
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            if not self._agent_maintenance_credential(db, server_id, agent_token):
                return None
            row = db.execute("SELECT * FROM agent_maintenance_leases WHERE server_id=?",
                             (server_id,)).fetchone()
            if (row is None or row["expires_at"] <= now or row["max_until"] <= now or
                    row["hub_epoch"] != hub_epoch or
                    row["bundle_manifest_sha256"] != bundle_manifest_sha256 or
                    not hmac.compare_digest(row["token_hash"],
                                            hashlib.sha256(lease_token.encode()).hexdigest())):
                raise MaintenanceLeaseInvalid("Maintenance lease is no longer valid")
            expires_at = min(now + LEASE_SECONDS, row["max_until"])
            db.execute("UPDATE agent_maintenance_leases SET expires_at=? WHERE server_id=?",
                       (expires_at, server_id))
            self._audit(db, f"agent:{server_id}", "agent_maintenance_renewed", server_id,
                        details={"expires_at": expires_at}, now=now)
            return {"protocol": 1, "scope": SCOPE, "expires_at": expires_at,
                    "max_until": row["max_until"], "hub_epoch": hub_epoch,
                    "agent_idle_proven": False}

    def release_agent_maintenance_lease(self, server_id: str, agent_token: str,
                                        lease_token: str, now: int | None = None) -> bool | None:
        if not isinstance(lease_token, str) or _TOKEN.fullmatch(lease_token) is None:
            raise MaintenanceLeaseInvalid("Invalid maintenance lease token")
        now = int(time.time()) if now is None else now
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            if not self._agent_maintenance_credential(db, server_id, agent_token):
                return None
            row = db.execute("SELECT token_hash,expires_at FROM agent_maintenance_leases WHERE server_id=?",
                             (server_id,)).fetchone()
            if (row is None or row["expires_at"] <= now or
                    not hmac.compare_digest(row["token_hash"],
                                            hashlib.sha256(lease_token.encode()).hexdigest())):
                raise MaintenanceLeaseInvalid("Maintenance lease is no longer valid")
            db.execute("DELETE FROM agent_maintenance_leases WHERE server_id=?", (server_id,))
            self._audit(db, f"agent:{server_id}", "agent_maintenance_released", server_id,
                        now=now)
            return True
