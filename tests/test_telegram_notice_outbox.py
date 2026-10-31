# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Job and pairing notices survive restarts without persisting secret text."""

from __future__ import annotations

import sqlite3
import io
import tempfile
import time
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

from sovagrid_hub.store import Store
from sovagrid_hub.telegram import TelegramBot
from sovagrid_hub.telegram_runtime import TelegramRuntime
from sovagrid_hub import telegram_outbox


class TelegramNoticeOutboxTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "hub.sqlite"
        self.store = Store(self.path)
        self.store.initialize("admin", "very-long-test-password")
        self.sid = self.store.create_server("test-host")["id"]
        self.now = int(time.time())

    def rows(self):
        with self.store.connection() as db:
            return [dict(row) for row in db.execute(
                "SELECT * FROM telegram_notice_outbox ORDER BY id")]

    def bot(self):
        bot = TelegramBot("123456789:private-test-token", self.store)
        sent = []
        bot.send_message = lambda chat_id, message: sent.append((chat_id, message))
        return bot, sent

    def complete_command(self, chat=101, output="PRIVATE_OUTPUT"):
        self.store.add_bot_user(chat, chat, "admin")
        self.store.set_remote_commands(self.sid, True)
        code = self.store.request_command(self.sid, chat, chat, "echo PRIVATE_COMMAND")
        job = self.store.confirm_command(code, chat, chat)
        self.assertIsNotNone(job)
        self.assertEqual(self.store.lease_job(self.sid)["id"], job["id"])
        completed = self.store.finish_job(self.sid, job["id"], "succeeded", 0, output)
        self.assertTrue(completed["just_completed"])
        return job["id"]

    def test_job_completion_is_atomic_deduplicated_and_survives_restart(self):
        job_id = self.complete_command()
        self.assertEqual(self.store.telegram_notice_pending_count(), 1)
        self.assertEqual(TelegramRuntime(self.store, self.path).status()["pending_telegram_notices"], 1)
        second = self.store.finish_job(self.sid, job_id, "succeeded", 0, "PRIVATE_OUTPUT")
        self.assertFalse(second["just_completed"])
        self.assertEqual(len(self.rows()), 1)
        self.assertNotIn("PRIVATE_COMMAND", str(self.rows()))
        self.assertNotIn("PRIVATE_OUTPUT", str(self.rows()))
        self.store = Store(self.path)
        self.store.migrate()
        self.store.migrate()
        self.assertEqual(self.store.telegram_notice_pending_count(), 1)
        bot, sent = self.bot()
        self.assertTrue(bot.deliver_notice_once())
        self.assertFalse(bot.deliver_notice_once())
        self.assertEqual(len(sent), 1)
        self.assertIn(job_id, sent[0][1])
        self.assertIn("/result", sent[0][1])
        self.assertNotIn("PRIVATE_OUTPUT", sent[0][1])
        self.assertEqual(self.store.telegram_notice_pending_count(), 0)

    def test_retry_and_access_revocation_before_send(self):
        self.complete_command()
        bot, sent = self.bot()
        bot.send_message = lambda *_: (_ for _ in ()).throw(TimeoutError("offline"))
        self.assertTrue(bot.deliver_notice_once(now=self.now))
        row = self.rows()[0]
        self.assertEqual(row["attempts"], 1)
        self.assertEqual(row["next_attempt_at"], self.now + 5)
        self.store = Store(self.path)
        self.store.migrate()
        self.store.add_bot_user(101, 101, "viewer")
        resumed, sent = self.bot()
        self.assertFalse(resumed.deliver_notice_once(now=self.now + 5))
        self.assertEqual(sent, [])
        self.assertIsNotNone(self.rows()[0]["dropped_at"])

    def test_pairing_decision_is_durable_and_stale_decision_is_not_sent(self):
        self.assertEqual(self.store.request_bot_pairing(201, 201, now=self.now), "created")
        self.assertEqual(self.store.approve_bot_pairing(201, 201, "operator", now=self.now + 1)["role"],
                         "operator")
        self.assertEqual(self.store.telegram_notice_pending_count(), 1)
        self.store = Store(self.path)
        self.store.migrate()
        bot, sent = self.bot()
        self.assertTrue(bot.deliver_notice_once(now=self.now + 2))
        self.assertEqual(sent[0][0], 201)
        self.assertIn("operator", sent[0][1])
        self.assertEqual(self.store.request_bot_pairing(202, 202, now=self.now), "created")
        self.assertTrue(self.store.reject_bot_pairing(202, 202, now=self.now + 1))
        self.store.add_bot_user(202, 202, "viewer")
        self.assertFalse(bot.deliver_notice_once(now=self.now + 2))
        self.assertEqual(len(sent), 1)
        self.assertIsNotNone(self.rows()[-1]["dropped_at"])

    def test_rejection_delivers_once_and_flood_control_retries(self):
        self.assertEqual(self.store.request_bot_pairing(204, 204, now=self.now), "created")
        self.assertTrue(self.store.reject_bot_pairing(204, 204, now=self.now + 1))
        bot, sent = self.bot()
        error = urllib.error.HTTPError(
            "https://api.telegram.org/botPRIVATE/sendMessage", 429, "Too Many Requests",
            {"Retry-After": "15"}, io.BytesIO(b'{}'))
        bot.send_message = lambda *_: (_ for _ in ()).throw(error)
        self.assertTrue(bot.deliver_notice_once(now=self.now + 2))
        self.assertEqual(self.rows()[0]["next_attempt_at"], self.now + 17)
        resumed, sent = self.bot()
        self.assertTrue(resumed.deliver_notice_once(now=self.now + 17))
        self.assertIn("отклонён", sent[0][1])
        self.assertFalse(resumed.deliver_notice_once(now=self.now + 17))

    def test_pending_cap_and_expiry_are_bounded_and_audited(self):
        with mock.patch.object(telegram_outbox, "NOTICE_MAX_PENDING", 2):
            for chat in (301, 302, 303):
                self.assertEqual(self.store.request_bot_pairing(chat, chat, now=self.now), "created")
                self.store.approve_bot_pairing(chat, chat, "viewer", now=self.now + 1)
        self.assertEqual(self.store.telegram_notice_pending_count(), 2)
        self.assertEqual(sum(row["dropped_at"] is not None for row in self.rows()), 1)
        self.assertEqual(self.store.audit_events()[0]["action"], "telegram_notice_overflow_dropped")
        self.assertIsNone(self.store.claim_telegram_notice(now=self.now +
                           telegram_outbox.NOTICE_TTL_SECONDS + 2))
        self.assertEqual(self.store.telegram_notice_pending_count(), 0)
        self.assertEqual(self.store.audit_events()[0]["action"], "telegram_notice_expired")

    def test_full_leased_outbox_does_not_undo_a_completed_command(self):
        with mock.patch.object(telegram_outbox, "NOTICE_MAX_PENDING", 1):
            first = self.complete_command(chat=501)
            claimed = self.store.claim_telegram_notice(now=self.now + 5)
            self.assertEqual(claimed["source_id"], first)
            second = self.complete_command(chat=502)
        self.assertEqual(self.store.job(second)["state"], "succeeded")
        self.assertEqual(self.store.telegram_notice_pending_count(), 1)
        self.assertEqual(len(self.rows()), 1)
        self.assertEqual(self.store.audit_events()[0]["action"],
                         "telegram_notice_overflow_dropped")

    def test_migration_creates_notice_schema_on_existing_database(self):
        with self.store.connection() as db:
            db.execute("DROP TABLE telegram_notice_outbox")
        self.store.migrate()
        self.store.migrate()
        self.assertEqual(self.store.telegram_notice_pending_count(), 0)
        with sqlite3.connect(self.path) as db:
            self.assertIn("telegram_notice_due", {row[1] for row in
                          db.execute("PRAGMA index_list(telegram_notice_outbox)")})

    def test_job_completion_rolls_back_if_notice_cannot_be_durably_written(self):
        self.store.add_bot_user(401, 401, "admin")
        self.store.set_remote_commands(self.sid, True)
        code = self.store.request_command(self.sid, 401, 401, "true")
        job = self.store.confirm_command(code, 401, 401)
        self.store.lease_job(self.sid)
        with self.store.connection() as db:
            db.execute("DROP TABLE telegram_notice_outbox")
        with self.assertRaises(sqlite3.OperationalError):
            self.store.finish_job(self.sid, job["id"], "succeeded", 0, "output")
        self.assertEqual(self.store.job(job["id"])["state"], "delivered")
        self.store.migrate()
        self.store.finish_job(self.sid, job["id"], "succeeded", 0, "output")
        self.assertEqual(self.store.telegram_notice_pending_count(), 1)


if __name__ == "__main__":
    unittest.main()
