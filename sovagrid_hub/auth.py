# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Hub accounts, transactional role checks, and scoped session revocation."""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sqlite3
import time
import uuid


ROLES = {"viewer": 0, "operator": 1, "admin": 2}
USER_FIELDS = ("id", "username", "role", "enabled", "revision", "created_at", "updated_at")
USER_SCHEMA = """CREATE TABLE IF NOT EXISTS hub_users (
    id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE,
    salt BLOB NOT NULL, password_hash BLOB NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('viewer','operator','admin')),
    enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
    revision INTEGER NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
)"""
SESSION_SCHEMA = """CREATE TABLE sessions (
    token_hash TEXT PRIMARY KEY, expires_at INTEGER NOT NULL,
    user_id TEXT NOT NULL REFERENCES hub_users(id) ON DELETE CASCADE
)"""
SSH_GRANT_SCHEMA = """CREATE TABLE IF NOT EXISTS ssh_grants (
    grant_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES hub_users(id) ON DELETE CASCADE,
    user_revision INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
)"""
SSH_GRANT_TTL_SECONDS = 60
SSH_SESSION_TTL_SECONDS = 3600


class AuthenticationError(PermissionError):
    """The bearer token has expired or its account is unavailable."""


class AuthorizationError(PermissionError):
    """The authenticated account lacks the required role."""


class UserConflict(Exception):
    """A duplicate login, stale revision, or last-admin safeguard."""


def public_user(row) -> dict:
    return {key: bool(row[key]) if key == "enabled" else row[key] for key in USER_FIELDS}


def validate_password(password: object) -> str:
    if not isinstance(password, str) or not 12 <= len(password) <= 1024 or not password.strip():
        raise ValueError("Password must contain 12–1024 characters and not be blank")
    try:
        password.encode("utf-8")
    except UnicodeError:
        raise ValueError("Password must contain valid Unicode text") from None
    return password


def password_digest(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1)


def migrate_accounts(db, now: int | None = None) -> None:
    """Run inside Store.migrate's write transaction, including all legacy DDL."""
    now = int(time.time()) if now is None else now
    db.execute(USER_SCHEMA)
    legacy = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='admin'").fetchone()
    legacy_ids = []
    if legacy is not None:
        for row in db.execute("SELECT username,salt,password_hash FROM admin").fetchall():
            existing = db.execute("SELECT id FROM hub_users WHERE username=?", (row["username"],)).fetchone()
            user_id = existing["id"] if existing else str(uuid.uuid4())
            if existing is None:
                db.execute("""INSERT INTO hub_users VALUES (?, ?, ?, ?, 'admin', 1, 1, ?, ?)""",
                           (user_id, row["username"], row["salt"], row["password_hash"], now, now))
            legacy_ids.append(user_id)
    columns = {row["name"] for row in db.execute("PRAGMA table_info(sessions)")}
    if not columns:
        db.execute(SESSION_SCHEMA)
    elif "user_id" not in columns:
        db.execute(SESSION_SCHEMA.replace("CREATE TABLE sessions", "CREATE TABLE migrated_sessions"))
        # The former schema had one admin. If identity is ambiguous, expire
        # legacy sessions instead of assigning someone's bearer to another user.
        if len(legacy_ids) == 1:
            db.execute("""INSERT INTO migrated_sessions(token_hash,expires_at,user_id)
                          SELECT token_hash,expires_at,? FROM sessions""", (legacy_ids[0],))
        db.execute("DROP TABLE sessions")
        db.execute("ALTER TABLE migrated_sessions RENAME TO sessions")
    if legacy is not None:
        db.execute("DROP TABLE admin")
    db.execute("CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id)")
    db.execute(SSH_GRANT_SCHEMA)
    db.execute("CREATE INDEX IF NOT EXISTS ssh_grants_expiry ON ssh_grants(expires_at)")


class AccountStore:
    """Mixin using Store.connection, Store._audit, and its journal lock/cache."""

    @staticmethod
    def _session_row(db, token: str, now: int | None = None):
        if not isinstance(token, str) or not token or len(token) > 256:
            return None
        now = int(time.time()) if now is None else now
        return db.execute("""SELECT u.*,s.expires_at,s.token_hash FROM sessions AS s
            JOIN hub_users AS u ON u.id=s.user_id
            WHERE s.token_hash=? AND s.expires_at>? AND u.enabled=1""",
                          (hashlib.sha256(token.encode()).hexdigest(), now)).fetchone()

    @classmethod
    def _require_role_session(cls, db, token: str | None, role: str = "admin", now: int | None = None):
        # None is reserved for trusted local CLI calls. HTTP always supplies
        # its bearer string, even when the header is missing.
        if token is None:
            return None
        row = cls._session_row(db, token, now)
        if row is None:
            raise AuthenticationError("Session has expired")
        if ROLES[row["role"]] < ROLES[role]:
            raise AuthorizationError("Insufficient role")
        return row

    @classmethod
    def _require_admin_session(cls, db, token: str | None):
        return cls._require_role_session(db, token)

    @classmethod
    def _audit_account(cls, db, identity, action: str, server_id=None, subject_id=None,
                       details=None, now=None):
        actor = "local-cli" if identity is None else "hub:" + identity["id"]
        details = dict(details or {})
        if identity is not None:
            details["actor_username"] = identity["username"]
        cls._audit(db, actor, action, server_id, subject_id, details, now)

    def session_info(self, token: str, now: int | None = None) -> dict | None:
        with self.connection() as db:
            row = self._session_row(db, token, now)
            return {"user": public_user(row), "expires_at": row["expires_at"]} if row else None

    def session_valid(self, token: str, now: int | None = None) -> bool:
        return self.session_info(token, now) is not None

    def login(self, username: str, password: str, now: int | None = None) -> tuple[str, int] | None:
        if not isinstance(username, str) or not isinstance(password, str) or len(password) > 1024:
            return None
        now = int(time.time()) if now is None else now
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM hub_users WHERE username=?", (username,)).fetchone()
            try:
                digest = password_digest(password, row["salt"] if row else b"\0" * 16)
            except UnicodeError:
                return None
            if row is None or not row["enabled"] or not hmac.compare_digest(digest, row["password_hash"]):
                return None
            token = secrets.token_urlsafe(32)
            expires = now + 8 * 3600
            db.execute("DELETE FROM sessions WHERE expires_at < ?", (now,))
            db.execute("INSERT INTO sessions(token_hash,expires_at,user_id) VALUES (?, ?, ?)",
                       (hashlib.sha256(token.encode()).hexdigest(), expires, row["id"]))
            self._audit_account(db, row, "session_login", now=now)
            return token, expires

    def issue_ssh_grant(self, now: int | None = None) -> dict:
        """Mint a grant only in the host-authorized one-shot Hub container.

        Docker access on the host requires root or an equivalent Docker-group
        privilege. A one-shot container starts as PID 1 under the same UID as
        the Hub service, so SQLite's WAL ownership remains correct. An exec
        child of the running Hub cannot pass this process-boundary check.
        """
        if os.getpid() != 1 or os.getuid() != 10001 or os.geteuid() != 10001:
            raise PermissionError("SSH grant issuance requires the host-authorized one-shot Hub container")
        now = int(time.time()) if now is None else now
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("""SELECT u.* FROM hub_users u
                LEFT JOIN user_server_policies p ON p.user_id=u.id
                WHERE u.role='admin' AND u.enabled=1 AND (p.mode IS NULL OR p.mode='all')
                ORDER BY u.created_at,u.rowid LIMIT 1""").fetchone()
            if row is None:
                raise AuthenticationError("No enabled local administrator")
            grant = secrets.token_urlsafe(32)
            expires = now + SSH_GRANT_TTL_SECONDS
            db.execute("DELETE FROM ssh_grants WHERE expires_at<=?", (now,))
            db.execute("""INSERT INTO ssh_grants(grant_hash,user_id,user_revision,expires_at)
                          VALUES (?,?,?,?)""",
                       (hashlib.sha256(grant.encode("ascii")).hexdigest(), row["id"], row["revision"], expires))
            self._audit(db, "ssh:root", "ssh_grant_issued", subject_id=row["id"],
                        details={"username": row["username"], "expires_at": expires}, now=now)
            return {"protocol": 1, "grant": grant, "expires_at": expires, "username": row["username"]}

    def redeem_ssh_grant(self, grant: object, now: int | None = None) -> tuple[str, int] | None:
        """Atomically consume a grant and bind a short session to its admin."""
        if (not isinstance(grant, str) or len(grant) != 43 or
                any(ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for ch in grant)):
            return None
        now = int(time.time()) if now is None else now
        grant_hash = hashlib.sha256(grant.encode("ascii")).hexdigest()
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("""SELECT g.expires_at AS grant_expires,g.user_revision,u.*
                                FROM ssh_grants AS g JOIN hub_users AS u ON u.id=g.user_id
                                WHERE g.grant_hash=?""", (grant_hash,)).fetchone()
            # Consume the proof even when its account or revision changed.
            db.execute("DELETE FROM ssh_grants WHERE grant_hash=?", (grant_hash,))
            if (row is None or row["grant_expires"] <= now or not row["enabled"] or
                    row["role"] != "admin" or row["revision"] != row["user_revision"]):
                return None
            token = secrets.token_urlsafe(32)
            expires = now + SSH_SESSION_TTL_SECONDS
            db.execute("DELETE FROM sessions WHERE expires_at<=?", (now,))
            db.execute("INSERT INTO sessions(token_hash,expires_at,user_id) VALUES (?,?,?)",
                       (hashlib.sha256(token.encode("ascii")).hexdigest(), expires, row["id"]))
            self._audit(db, "ssh:root", "ssh_grant_redeemed", subject_id=row["id"],
                        details={"username": row["username"]}, now=now)
            return token, expires

    @staticmethod
    def _revision(value) -> int:
        if type(value) is not int or not 1 <= value <= 2**63 - 2:
            raise ValueError("revision must be a positive integer")
        return value

    @staticmethod
    def _last_admin_guard(db, row, role: str, enabled: bool) -> None:
        if row["role"] == "admin" and row["enabled"] and not (role == "admin" and enabled):
            if db.execute("""SELECT 1 FROM hub_users u LEFT JOIN user_server_policies p ON p.user_id=u.id
                           WHERE u.id<>? AND u.role='admin' AND u.enabled=1
                             AND (p.mode IS NULL OR p.mode='all')""",
                          (row["id"],)).fetchone() is None:
                raise UserConflict("At least one unrestricted administrator is required")

    @staticmethod
    def _revoke_user_sessions(db, user_id: str, now: int) -> tuple[list[str], list[str], int]:
        hashes = [row[0] for row in db.execute("SELECT token_hash FROM sessions WHERE user_id=?", (user_id,))]
        jobs = [row[0] for row in db.execute("""SELECT j.id FROM jobs AS j JOIN sessions AS s
                         ON s.token_hash=j.session_token_hash WHERE s.user_id=?""", (user_id,))]
        cancelled = db.execute("""UPDATE jobs SET state='cancelled',command='',completed_at=?
                         WHERE source='web' AND state='queued' AND session_token_hash IN
                         (SELECT token_hash FROM sessions WHERE user_id=?)""", (now, user_id)).rowcount
        db.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
        return hashes, jobs, cancelled

    def users(self, *, session_token: str | None = None) -> list[dict]:
        with self.connection() as db:
            self._require_unrestricted_admin(db, session_token)
            return [public_user(row) for row in db.execute("SELECT * FROM hub_users ORDER BY username,id")]

    def create_user(self, username: object, password: object, role: object, *, session_token=None) -> dict:
        if (not isinstance(username, str) or not 1 <= len(username) <= 80 or
                not username.isprintable() or username != username.strip()):
            raise ValueError("Username must contain 1–80 printable characters without surrounding spaces")
        validate_password(password)
        if not isinstance(role, str) or role not in ROLES:
            raise ValueError("Invalid user role")
        salt = secrets.token_bytes(16)
        digest = password_digest(password, salt)
        now, user_id = int(time.time()), str(uuid.uuid4())
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            actor = self._require_unrestricted_admin(db, session_token)
            if db.execute("SELECT COUNT(*) FROM hub_users").fetchone()[0] >= 1000:
                raise UserConflict("User limit reached")
            try:
                db.execute("INSERT INTO hub_users VALUES (?, ?, ?, ?, ?, 1, 1, ?, ?)",
                           (user_id, username, salt, digest, role, now, now))
            except sqlite3.IntegrityError:
                raise UserConflict("Username already exists") from None
            self._audit_account(db, actor, "user_created", subject_id=user_id,
                                details={"username": username, "role": role}, now=now)
            return public_user(db.execute("SELECT * FROM hub_users WHERE id=?", (user_id,)).fetchone())

    def update_user(self, user_id: str, payload: object, *, session_token=None) -> dict | None:
        if (not isinstance(payload, dict) or not {"revision"} < set(payload) or
                set(payload) - {"revision", "role", "enabled"}):
            raise ValueError("Expected revision and role or enabled")
        revision = self._revision(payload["revision"])
        if "role" in payload and (not isinstance(payload["role"], str) or payload["role"] not in ROLES):
            raise ValueError("Invalid user role")
        if "enabled" in payload and type(payload["enabled"]) is not bool:
            raise ValueError("enabled must be a boolean")
        with self._journal_lock:
            with self.connection() as db:
                db.execute("BEGIN IMMEDIATE")
                actor = self._require_unrestricted_admin(db, session_token)
                row = db.execute("SELECT * FROM hub_users WHERE id=?", (user_id,)).fetchone()
                if row is None:
                    return None
                if row["revision"] != revision:
                    raise UserConflict("User changed in another session; reload before saving")
                role, enabled = payload.get("role", row["role"]), payload.get("enabled", bool(row["enabled"]))
                self._last_admin_guard(db, row, role, enabled)
                changed = role != row["role"] or enabled != bool(row["enabled"])
                hashes, jobs, cancelled = self._revoke_user_sessions(db, user_id, int(time.time())) if changed else ([], [], 0)
                now = int(time.time())
                db.execute("UPDATE hub_users SET role=?,enabled=?,revision=revision+1,updated_at=? WHERE id=?",
                           (role, int(enabled), now, user_id))
                self._audit_account(db, actor, "user_updated", subject_id=user_id,
                    details={"username": row["username"], "role": role, "enabled": enabled,
                             "queued_web_jobs_cancelled": cancelled}, now=now)
                user = public_user(db.execute("SELECT * FROM hub_users WHERE id=?", (user_id,)).fetchone())
            for job in jobs:
                self._journal_outputs.pop(job, None)
            return {"user": user, "sessions_revoked": changed, "_revoked_hashes": hashes}

    def delete_user(self, user_id: str, revision: object, *, session_token=None) -> dict | None:
        revision = self._revision(revision)
        with self._journal_lock:
            with self.connection() as db:
                db.execute("BEGIN IMMEDIATE")
                actor = self._require_unrestricted_admin(db, session_token)
                row = db.execute("SELECT * FROM hub_users WHERE id=?", (user_id,)).fetchone()
                if row is None:
                    return None
                if row["revision"] != revision:
                    raise UserConflict("User changed in another session; reload before deleting")
                self._last_admin_guard(db, row, row["role"], False)
                hashes, jobs, cancelled = self._revoke_user_sessions(db, user_id, int(time.time()))
                db.execute("DELETE FROM hub_users WHERE id=?", (user_id,))
                self._audit_account(db, actor, "user_deleted", subject_id=user_id,
                    details={"username": row["username"], "queued_web_jobs_cancelled": cancelled})
            for job in jobs:
                self._journal_outputs.pop(job, None)
            return {"removed": True, "_revoked_hashes": hashes}

    def _replace_user_password(self, db, row, new_password: str, actor) -> tuple[dict, list[str], list[str]]:
        now, salt = int(time.time()), secrets.token_bytes(16)
        digest = password_digest(new_password, salt)
        hashes, jobs, cancelled = self._revoke_user_sessions(db, row["id"], now)
        db.execute("UPDATE hub_users SET salt=?,password_hash=?,revision=revision+1,updated_at=? WHERE id=?",
                   (salt, digest, now, row["id"]))
        self._audit_account(db, actor, "password_changed", subject_id=row["id"],
                            details={"queued_web_jobs_cancelled": cancelled})
        user = public_user(db.execute("SELECT * FROM hub_users WHERE id=?", (row["id"],)).fetchone())
        return user, hashes, jobs

    def reset_user_password(self, user_id: str, revision: object, password: object, *, session_token=None) -> dict | None:
        revision = self._revision(revision)
        validate_password(password)
        with self._journal_lock:
            with self.connection() as db:
                db.execute("BEGIN IMMEDIATE")
                actor = self._require_unrestricted_admin(db, session_token)
                row = db.execute("SELECT * FROM hub_users WHERE id=?", (user_id,)).fetchone()
                if row is None:
                    return None
                if row["revision"] != revision:
                    raise UserConflict("User changed in another session; reload before resetting password")
                user, hashes, jobs = self._replace_user_password(db, row, password, actor)
            for job in jobs:
                self._journal_outputs.pop(job, None)
            return {"user": user, "sessions_revoked": True, "_revoked_hashes": hashes}

    def change_session_password(self, token: str, old_password: str, new_password: str) -> dict | None:
        validate_password(new_password)
        with self._journal_lock:
            with self.connection() as db:
                db.execute("BEGIN IMMEDIATE")
                row = self._require_role_session(db, token, "viewer")
                if not hmac.compare_digest(password_digest(old_password, row["salt"]), row["password_hash"]):
                    return None
                _, hashes, jobs = self._replace_user_password(db, row, new_password, row)
            for job in jobs:
                self._journal_outputs.pop(job, None)
            return {"_revoked_hashes": hashes}

    def change_password(self, username: str | None, old_password: str, new_password: str) -> bool:
        """Trusted CLI compatibility; HTTP changes must use the session-bound method."""
        validate_password(new_password)
        with self._journal_lock:
            with self.connection() as db:
                db.execute("BEGIN IMMEDIATE")
                row = (db.execute("SELECT * FROM hub_users WHERE username=?", (username,)).fetchone()
                       if username is not None else db.execute("SELECT * FROM hub_users WHERE role='admin' ORDER BY created_at,id LIMIT 1").fetchone())
                if row is None or not hmac.compare_digest(password_digest(old_password, row["salt"]), row["password_hash"]):
                    return False
                _, _, jobs = self._replace_user_password(db, row, new_password, None)
            for job in jobs:
                self._journal_outputs.pop(job, None)
            return True
