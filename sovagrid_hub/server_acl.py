# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
"""Optional per-server grants for Hub sessions and Telegram bindings.

An absent policy means the legacy ``all`` mode.  A selected policy denies
unlisted servers.  The account or binding role always caps a grant's role.
"""

from __future__ import annotations

import time

from .auth import AuthenticationError, AuthorizationError, ROLES


class AccessConflict(Exception):
    """A server access policy changed after the caller read its revision."""


def migrate_server_acl(db):
    # Called within Store.migrate's BEGIN IMMEDIATE (and initialize's schema
    # transaction).  No backfill is needed: absent policies preserve access.
    db.execute("""CREATE TABLE IF NOT EXISTS user_server_policies (
        user_id TEXT PRIMARY KEY REFERENCES hub_users(id) ON DELETE CASCADE,
        mode TEXT NOT NULL CHECK(mode IN ('all','selected')),
        revision INTEGER NOT NULL CHECK(revision>=1), updated_at INTEGER NOT NULL
    )""")
    db.execute("""CREATE TABLE IF NOT EXISTS user_server_grants (
        user_id TEXT NOT NULL REFERENCES user_server_policies(user_id) ON DELETE CASCADE,
        server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
        role TEXT NOT NULL CHECK(role IN ('viewer','operator','admin')),
        PRIMARY KEY(user_id,server_id)
    )""")
    db.execute("""CREATE TABLE IF NOT EXISTS bot_server_policies (
        user_id INTEGER NOT NULL, chat_id INTEGER NOT NULL,
        mode TEXT NOT NULL CHECK(mode IN ('all','selected')),
        revision INTEGER NOT NULL CHECK(revision>=1), updated_at INTEGER NOT NULL,
        PRIMARY KEY(user_id,chat_id),
        FOREIGN KEY(user_id,chat_id) REFERENCES bot_users(user_id,chat_id) ON DELETE CASCADE
    )""")
    db.execute("""CREATE TABLE IF NOT EXISTS bot_server_grants (
        user_id INTEGER NOT NULL, chat_id INTEGER NOT NULL,
        server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
        role TEXT NOT NULL CHECK(role IN ('viewer','operator','admin')),
        PRIMARY KEY(user_id,chat_id,server_id),
        FOREIGN KEY(user_id,chat_id) REFERENCES bot_server_policies(user_id,chat_id) ON DELETE CASCADE
    )""")


class ServerACLStore:
    """Mixin using Store.connection, session helpers and audit."""

    @staticmethod
    def _policy(db, kind, key):
        if kind == "user":
            return db.execute("SELECT mode,revision FROM user_server_policies WHERE user_id=?", key).fetchone()
        return db.execute("SELECT mode,revision FROM bot_server_policies WHERE user_id=? AND chat_id=?", key).fetchone()

    @classmethod
    def _effective_user_role(cls, db, identity, server_id):
        """Return the role actually available on one server for this session."""
        if identity is None:  # trusted local CLI
            return "admin"
        policy = cls._policy(db, "user", (identity["id"],))
        if policy is None or policy["mode"] == "all":
            return identity["role"]
        grant = db.execute("SELECT role FROM user_server_grants WHERE user_id=? AND server_id=?",
                           (identity["id"], server_id)).fetchone()
        if grant is None:
            return None
        return min((identity["role"], grant["role"]), key=lambda role: ROLES[role])

    @classmethod
    def _effective_bot_role(cls, db, user_id, chat_id, server_id):
        binding = db.execute("SELECT role FROM bot_users WHERE user_id=? AND chat_id=?",
                             (user_id, chat_id)).fetchone()
        if binding is None:
            return None
        policy = cls._policy(db, "bot", (user_id, chat_id))
        if policy is None or policy["mode"] == "all":
            return binding["role"]
        grant = db.execute("""SELECT role FROM bot_server_grants
                              WHERE user_id=? AND chat_id=? AND server_id=?""",
                           (user_id, chat_id, server_id)).fetchone()
        if grant is None:
            return None
        return min((binding["role"], grant["role"]), key=lambda role: ROLES[role])

    @classmethod
    def _user_allowed(cls, db, identity, server_id, role="viewer"):
        if identity is None:  # trusted local CLI
            return True
        if ROLES[identity["role"]] < ROLES[role]:
            return False
        policy = cls._policy(db, "user", (identity["id"],))
        if policy is None or policy["mode"] == "all":
            return True
        grant = db.execute("SELECT role FROM user_server_grants WHERE user_id=? AND server_id=?",
                           (identity["id"], server_id)).fetchone()
        return grant is not None and ROLES[grant["role"]] >= ROLES[role]

    @classmethod
    def _bot_allowed(cls, db, user_id, chat_id, server_id, role="viewer"):
        binding = db.execute("SELECT role FROM bot_users WHERE user_id=? AND chat_id=?",
                             (user_id, chat_id)).fetchone()
        if binding is None or ROLES[binding["role"]] < ROLES[role]:
            return False
        policy = cls._policy(db, "bot", (user_id, chat_id))
        if policy is None or policy["mode"] == "all":
            return True
        grant = db.execute("""SELECT role FROM bot_server_grants
                              WHERE user_id=? AND chat_id=? AND server_id=?""",
                           (user_id, chat_id, server_id)).fetchone()
        return grant is not None and ROLES[grant["role"]] >= ROLES[role]

    @classmethod
    def _require_server_session(cls, db, token, server_id, role="viewer", now=None):
        identity = cls._require_role_session(db, token, role, now)
        if not cls._user_allowed(db, identity, server_id, role):
            raise AuthorizationError("Server access denied")
        return identity

    @classmethod
    def _require_unrestricted_admin(cls, db, token):
        identity = cls._require_admin_session(db, token)
        if identity is not None:
            policy = cls._policy(db, "user", (identity["id"],))
            if policy is not None and policy["mode"] == "selected":
                raise AuthorizationError("Unrestricted administrator required")
        return identity

    def server_access_allowed(self, token, server_id, role="viewer"):
        with self.connection() as db:
            identity = self._session_row(db, token)
            return identity is not None and self._user_allowed(db, identity, server_id, role)

    def unrestricted_admin(self, token):
        with self.connection() as db:
            identity = self._session_row(db, token)
            if identity is None or identity["role"] != "admin":
                return False
            policy = self._policy(db, "user", (identity["id"],))
            return policy is None or policy["mode"] == "all"

    def session_unrestricted(self, token):
        with self.connection() as db:
            identity = self._session_row(db, token)
            if identity is None:
                return False
            policy = self._policy(db, "user", (identity["id"],))
            return policy is None or policy["mode"] == "all"

    def own_access_summary(self, token):
        """Small capability summary for clients; mutations still recheck ACLs."""
        with self.connection() as db:
            identity = self._require_role_session(db, token, "viewer")
            policy = self._policy(db, "user", (identity["id"],))
            mode = policy["mode"] if policy is not None else "all"
            return {"mode": mode, "revision": policy["revision"] if policy is not None else 0,
                    "unrestricted_admin": identity["role"] == "admin" and mode == "all"}

    def bot_server_allowed(self, user_id, chat_id, server_id, role="viewer"):
        with self.connection() as db:
            return self._bot_allowed(db, user_id, chat_id, server_id, role)

    def bot_unrestricted(self, user_id, chat_id):
        with self.connection() as db:
            binding = db.execute("SELECT 1 FROM bot_users WHERE user_id=? AND chat_id=?", (user_id, chat_id)).fetchone()
            policy = self._policy(db, "bot", (user_id, chat_id))
            return binding is not None and (policy is None or policy["mode"] == "all")

    @classmethod
    def _visible_server_ids(cls, db, *, identity=None, bot=None, role="viewer"):
        if identity is None and bot is None:
            return None  # trusted local caller
        if identity is not None:
            if ROLES[identity["role"]] < ROLES[role]:
                return set()
            policy = cls._policy(db, "user", (identity["id"],))
            if policy is None or policy["mode"] == "all":
                return None
            allowed = [r for r in ROLES if ROLES[r] >= ROLES[role]]
            return {row[0] for row in db.execute("""SELECT server_id FROM user_server_grants
                WHERE user_id=? AND role IN (""" + ",".join("?" for _ in allowed) + ")", (identity["id"], *allowed))}
        user_id, chat_id = bot
        binding = db.execute("SELECT role FROM bot_users WHERE user_id=? AND chat_id=?", bot).fetchone()
        if binding is None or ROLES[binding["role"]] < ROLES[role]:
            return set()
        policy = cls._policy(db, "bot", bot)
        if policy is None or policy["mode"] == "all":
            return None
        allowed = [r for r in ROLES if ROLES[r] >= ROLES[role]]
        return {row[0] for row in db.execute("SELECT server_id FROM bot_server_grants WHERE user_id=? AND chat_id=? AND role IN (" + ",".join("?" for _ in allowed) + ")", (user_id, chat_id, *allowed))}

    @staticmethod
    def _validate_policy(payload):
        if not isinstance(payload, dict) or set(payload) != {"revision", "mode", "grants"}:
            raise ValueError("Expected revision, mode and grants")
        revision = payload["revision"]
        if type(revision) is not int or not 0 <= revision < 2**63 - 1:
            raise ValueError("Invalid access revision")
        mode = payload["mode"]
        grants = payload["grants"]
        if mode not in ("all", "selected") or not isinstance(grants, list) or len(grants) > 1024:
            raise ValueError("Invalid access mode or grants")
        if mode == "all" and grants:
            raise ValueError("All mode cannot contain grants")
        seen = set()
        for grant in grants:
            if (not isinstance(grant, dict) or set(grant) != {"server_id", "role"}
                    or not isinstance(grant["server_id"], str)
                    or not isinstance(grant["role"], str) or grant["role"] not in ROLES
                    or grant["server_id"] in seen):
                raise ValueError("Invalid or repeated server grant")
            seen.add(grant["server_id"])
        return revision, mode, grants

    @classmethod
    def _public_policy(cls, db, kind, key):
        policy = cls._policy(db, kind, key)
        if policy is None:
            return {"revision": 0, "mode": "all", "grants": []}
        if kind == "user":
            grants = db.execute("SELECT server_id,role FROM user_server_grants WHERE user_id=? ORDER BY server_id", key)
        else:
            grants = db.execute("SELECT server_id,role FROM bot_server_grants WHERE user_id=? AND chat_id=? ORDER BY server_id", key)
        return {"revision": policy["revision"], "mode": policy["mode"],
                "grants": [dict(row) for row in grants]}

    def server_access_policy(self, kind, key, *, session_token):
        with self.connection() as db:
            self._require_unrestricted_admin(db, session_token)
            if kind == "user":
                exists = db.execute("SELECT 1 FROM hub_users WHERE id=?", key).fetchone()
            else:
                exists = db.execute("SELECT 1 FROM bot_users WHERE user_id=? AND chat_id=?", key).fetchone()
            return self._public_policy(db, kind, key) if exists else None

    def save_server_access_policy(self, kind, key, payload, *, session_token):
        revision, mode, grants = self._validate_policy(payload)
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            actor = self._require_unrestricted_admin(db, session_token)
            if kind == "user":
                subject = db.execute("SELECT id,role,enabled FROM hub_users WHERE id=?", key).fetchone()
            else:
                subject = db.execute("SELECT user_id,chat_id,role FROM bot_users WHERE user_id=? AND chat_id=?", key).fetchone()
            if subject is None:
                return None
            current = self._public_policy(db, kind, key)
            if current["revision"] != revision:
                raise AccessConflict("Server access changed; reload before saving")
            if kind == "user" and actor is not None and actor["id"] == key[0] and mode == "selected":
                raise ValueError("An administrator cannot restrict their own account")
            if kind == "user" and subject["role"] == "admin" and subject["enabled"] and mode == "selected":
                other = db.execute("""SELECT 1 FROM hub_users u LEFT JOIN user_server_policies p ON p.user_id=u.id
                    WHERE u.id<>? AND u.role='admin' AND u.enabled=1 AND (p.mode IS NULL OR p.mode='all')""", key).fetchone()
                if other is None:
                    raise AccessConflict("At least one unrestricted administrator is required")
            for grant in grants:
                if db.execute("SELECT 1 FROM servers WHERE id=?", (grant["server_id"],)).fetchone() is None:
                    raise ValueError("Unknown server in grants")
            now = int(time.time())
            if kind == "user":
                db.execute("""INSERT INTO user_server_policies VALUES (?,?,?,?)
                    ON CONFLICT(user_id) DO UPDATE SET mode=excluded.mode,revision=excluded.revision,updated_at=excluded.updated_at""",
                    (key[0], mode, revision + 1, now))
                db.execute("DELETE FROM user_server_grants WHERE user_id=?", key)
                db.executemany("INSERT INTO user_server_grants VALUES (?,?,?)",
                               [(key[0], g["server_id"], g["role"]) for g in grants])
            else:
                db.execute("""INSERT INTO bot_server_policies VALUES (?,?,?,?,?)
                    ON CONFLICT(user_id,chat_id) DO UPDATE SET mode=excluded.mode,revision=excluded.revision,updated_at=excluded.updated_at""",
                    (key[0], key[1], mode, revision + 1, now))
                db.execute("DELETE FROM bot_server_grants WHERE user_id=? AND chat_id=?", key)
                db.executemany("INSERT INTO bot_server_grants VALUES (?,?,?,?)",
                               [(key[0], key[1], g["server_id"], g["role"]) for g in grants])
            if kind == "user":
                db.execute("""UPDATE jobs SET state='cancelled',command='',completed_at=?
                    WHERE source='web' AND state='queued' AND session_token_hash IN
                    (SELECT token_hash FROM sessions WHERE user_id=?)""", (now, key[0]))
                hashes = [row[0] for row in db.execute("SELECT token_hash FROM sessions WHERE user_id=?", key)]
            else:
                db.execute("DELETE FROM pending_commands WHERE actor_user_id=? AND chat_id=?", key)
                db.execute("""UPDATE jobs SET state='cancelled',command='',completed_at=?
                    WHERE source='telegram' AND state='queued' AND actor_user_id=? AND chat_id=?""", (now, *key))
                hashes = []
            self._audit_account(db, actor, "server_access_changed", subject_id=str(key[0]),
                                details={"kind": kind, "mode": mode, "revision": revision + 1,
                                         "grant_count": len(grants)})
            return self._public_policy(db, kind, key) | {"_revoked_hashes": hashes}
