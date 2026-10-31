# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Durable, secret-free Telegram job and pairing notices.

Enqueue is idempotent. Telegram sendMessage has no idempotency key, so a crash
between HTTP success and the delivered marker may cause a duplicate delivery.
"""

from __future__ import annotations

import time

NOTICE_TTL_SECONDS = 7 * 86400
NOTICE_HISTORY_SECONDS = 30 * 86400
NOTICE_MAX_PENDING = 1000
NOTICE_LEASE_SECONDS = 60
NOTICE_RETRY_MAX_SECONDS = 3600

TELEGRAM_OUTBOX_DDL = (
    """CREATE TABLE IF NOT EXISTS telegram_notice_outbox (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        kind TEXT NOT NULL CHECK(kind IN ('job_result','pairing_approved','pairing_rejected')),
        source_id TEXT NOT NULL, chat_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
        server_id TEXT, role TEXT CHECK(role IN ('viewer','operator','admin')),
        pairing_requested_at INTEGER,
        created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at INTEGER NOT NULL,
        lease_generation INTEGER NOT NULL DEFAULT 0, lease_until INTEGER,
        delivered_at INTEGER, dropped_at INTEGER,
        UNIQUE(kind, source_id, chat_id)
    )""",
    """CREATE INDEX IF NOT EXISTS telegram_notice_due
       ON telegram_notice_outbox(next_attempt_at, id)
       WHERE delivered_at IS NULL AND dropped_at IS NULL""",
    """CREATE INDEX IF NOT EXISTS telegram_notice_expiry
       ON telegram_notice_outbox(expires_at, id)
       WHERE delivered_at IS NULL AND dropped_at IS NULL""",
)


def migrate_telegram_outbox(db) -> None:
    for statement in TELEGRAM_OUTBOX_DDL:
        db.execute(statement)


class TelegramOutboxStore:
    def _prune_telegram_notices(self, db, now: int) -> None:
        expired = db.execute("""UPDATE telegram_notice_outbox
            SET dropped_at=?, lease_until=NULL
            WHERE delivered_at IS NULL AND dropped_at IS NULL AND expires_at<=?""",
            (now, now)).rowcount
        if expired:
            self._audit(db, "system", "telegram_notice_expired",
                        details={"count": expired}, now=now)
        db.execute("""DELETE FROM telegram_notice_outbox
            WHERE delivered_at<? OR dropped_at<?""",
            (now - NOTICE_HISTORY_SECONDS, now - NOTICE_HISTORY_SECONDS))

    def _queue_telegram_notice(self, db, *, kind: str, source_id: str,
                               user_id: int, chat_id: int, now: int,
                               server_id: str | None = None, role: str | None = None,
                               pairing_requested_at: int | None = None) -> bool:
        if (kind not in ("job_result", "pairing_approved", "pairing_rejected") or
                not isinstance(source_id, str) or not 1 <= len(source_id) <= 128 or
                type(user_id) is not int or type(chat_id) is not int or
                user_id != chat_id or not 0 < user_id <= 2**63 - 1 or
                type(now) is not int or now < 0):
            raise ValueError("Invalid Telegram notice")
        if kind == "job_result":
            if not isinstance(server_id, str) or role is not None or pairing_requested_at is not None:
                raise ValueError("Invalid job notice")
        elif (server_id is not None or type(pairing_requested_at) is not int or
              pairing_requested_at < 0 or
              (kind == "pairing_approved" and role not in ("viewer", "operator", "admin")) or
              (kind == "pairing_rejected" and role is not None)):
            raise ValueError("Invalid pairing notice")
        self._prune_telegram_notices(db, now)
        if db.execute("""SELECT 1 FROM telegram_notice_outbox
            WHERE kind=? AND source_id=? AND chat_id=?""",
            (kind, source_id, chat_id)).fetchone():
            return False
        pending = db.execute("""SELECT COUNT(*) FROM telegram_notice_outbox
            WHERE delivered_at IS NULL AND dropped_at IS NULL""").fetchone()[0]
        if pending >= NOTICE_MAX_PENDING:
            oldest = db.execute("""SELECT id FROM telegram_notice_outbox
                WHERE delivered_at IS NULL AND dropped_at IS NULL
                  AND (lease_until IS NULL OR lease_until<=?)
                ORDER BY id LIMIT 1""", (now,)).fetchone()
            if oldest is None:
                self._audit(db, "system", "telegram_notice_overflow_dropped",
                            details={"count": 1}, now=now)
                return False
            db.execute("""UPDATE telegram_notice_outbox SET dropped_at=?, lease_until=NULL
                WHERE id=? AND delivered_at IS NULL AND dropped_at IS NULL""",
                (now, oldest["id"]))
            self._audit(db, "system", "telegram_notice_overflow_dropped",
                        details={"count": 1}, now=now)
        db.execute("""INSERT INTO telegram_notice_outbox
            (kind,source_id,chat_id,user_id,server_id,role,pairing_requested_at,
             created_at,expires_at,next_attempt_at)
            VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (kind, source_id, chat_id, user_id, server_id, role,
             pairing_requested_at, now, now + NOTICE_TTL_SECONDS, now))
        return True

    def _telegram_notice_allowed(self, db, row) -> dict | None:
        if row["user_id"] != row["chat_id"]:
            return None
        if row["kind"] == "job_result":
            job = db.execute("""SELECT id,server_id,actor_user_id,chat_id,source,
                       state,exit_code,completed_at FROM jobs WHERE id=?""",
                (row["source_id"],)).fetchone()
            if (job is None or job["source"] != "telegram" or
                    job["actor_user_id"] != row["user_id"] or
                    job["chat_id"] != row["chat_id"] or
                    job["server_id"] != row["server_id"] or
                    job["completed_at"] is None or
                    job["state"] not in ("succeeded", "failed", "timed_out", "output_limited") or
                    not self._bot_allowed(db, row["user_id"], row["chat_id"],
                                          row["server_id"], "admin")):
                return None
            return {"job_state": job["state"], "exit_code": job["exit_code"]}
        if row["kind"] == "pairing_approved":
            binding = db.execute("SELECT role FROM bot_users WHERE user_id=? AND chat_id=?",
                                 (row["user_id"], row["chat_id"])).fetchone()
            return {} if binding is not None and binding["role"] == row["role"] else None
        if row["kind"] == "pairing_rejected":
            pairing = db.execute("""SELECT state,requested_at FROM bot_pairing_requests
                WHERE user_id=? AND chat_id=?""",
                (row["user_id"], row["chat_id"])).fetchone()
            binding = db.execute("SELECT 1 FROM bot_users WHERE user_id=? AND chat_id=?",
                                 (row["user_id"], row["chat_id"])).fetchone()
            return ({} if binding is None and pairing is not None and
                    pairing["state"] == "rejected" and
                    pairing["requested_at"] == row["pairing_requested_at"] else None)
        return None

    def claim_telegram_notice(self, now: int | None = None) -> dict | None:
        now = int(time.time()) if now is None else now
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            self._prune_telegram_notices(db, now)
            for _ in range(100):
                row = db.execute("""SELECT * FROM telegram_notice_outbox
                    WHERE delivered_at IS NULL AND dropped_at IS NULL
                      AND next_attempt_at<=? AND (lease_until IS NULL OR lease_until<=?)
                    ORDER BY id LIMIT 1""", (now, now)).fetchone()
                if row is None:
                    return None
                details = self._telegram_notice_allowed(db, row)
                if details is None:
                    db.execute("UPDATE telegram_notice_outbox SET dropped_at=?, lease_until=NULL WHERE id=?",
                               (now, row["id"]))
                    continue
                generation = row["lease_generation"] + 1
                db.execute("""UPDATE telegram_notice_outbox
                    SET lease_generation=?, lease_until=? WHERE id=?""",
                    (generation, now + NOTICE_LEASE_SECONDS, row["id"]))
                return {**dict(row), **details, "lease_generation": generation,
                        "lease_until": now + NOTICE_LEASE_SECONDS}
            return None

    def telegram_notice_send_allowed(self, row_id: int, generation: int,
                                     now: int | None = None) -> bool:
        now = int(time.time()) if now is None else now
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("""SELECT * FROM telegram_notice_outbox
                WHERE id=? AND lease_generation=? AND delivered_at IS NULL AND dropped_at IS NULL
                  AND lease_until>? AND expires_at>?""",
                (row_id, generation, now, now)).fetchone()
            if row is None:
                return False
            if self._telegram_notice_allowed(db, row) is None:
                db.execute("UPDATE telegram_notice_outbox SET dropped_at=?, lease_until=NULL WHERE id=?",
                           (now, row_id))
                return False
            return True

    def complete_telegram_notice(self, row_id: int, generation: int,
                                 now: int | None = None) -> bool:
        now = int(time.time()) if now is None else now
        with self.connection() as db:
            return db.execute("""UPDATE telegram_notice_outbox
                SET delivered_at=?, lease_until=NULL
                WHERE id=? AND lease_generation=? AND delivered_at IS NULL AND dropped_at IS NULL""",
                (now, row_id, generation)).rowcount == 1

    def retry_telegram_notice(self, row_id: int, generation: int, *, permanent: bool = False,
                              now: int | None = None, retry_after: int | None = None) -> bool:
        now = int(time.time()) if now is None else now
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("""SELECT * FROM telegram_notice_outbox
                WHERE id=? AND lease_generation=? AND delivered_at IS NULL AND dropped_at IS NULL""",
                (row_id, generation)).fetchone()
            if row is None:
                return False
            if permanent or row["expires_at"] <= now:
                db.execute("UPDATE telegram_notice_outbox SET dropped_at=?, lease_until=NULL WHERE id=?",
                           (now, row_id))
            else:
                attempts = min(row["attempts"] + 1, 1000000)
                delay = min(NOTICE_RETRY_MAX_SECONDS, 5 * (2 ** min(attempts - 1, 10)))
                if type(retry_after) is int and 0 <= retry_after <= 2**31 - 1:
                    delay = max(delay, retry_after)
                db.execute("""UPDATE telegram_notice_outbox
                    SET attempts=?, next_attempt_at=?, lease_until=NULL WHERE id=?""",
                    (attempts, now + delay, row_id))
            return True

    def telegram_notice_pending_count(self) -> int:
        with self.connection() as db:
            return db.execute("""SELECT COUNT(*) FROM telegram_notice_outbox
                WHERE delivered_at IS NULL AND dropped_at IS NULL""").fetchone()[0]
