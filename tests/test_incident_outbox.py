# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Incident delivery survives Hub restarts without exposing bot credentials."""

import io
import sqlite3
import tempfile
import unittest
import urllib.error
from contextlib import closing, contextmanager
from pathlib import Path
from unittest import mock

from sovagrid_hub.store import Store
from sovagrid_hub.telegram import TelegramBot
from sovagrid_hub.telegram_runtime import TelegramRuntime


def metric(now, cpu=10):
    return {"collected_at": now, "cpu_percent": cpu, "memory_percent": 20,
            "disk_percent": 30, "network_rx_bytes": 100, "network_tx_bytes": 200,
            "load1": 0.5, "uptime_seconds": 3600}


class IncidentOutboxTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "hub.sqlite"
        self.store = Store(self.path, offline_seconds=120)
        self.store.initialize("admin", "very-long-test-password")
        self.sid = self.store.create_server("outbox-host")["id"]
        self.t = 1_000_000

    def tearDown(self):
        self.temp.cleanup()

    def bind(self, chat_id=101, role="viewer"):
        self.store.add_bot_user(chat_id, chat_id, role)

    def rows(self):
        with closing(sqlite3.connect(self.path)) as db:
            db.row_factory = sqlite3.Row
            return [dict(row) for row in db.execute("SELECT * FROM incident_outbox ORDER BY id")]

    def bot(self):
        bot = TelegramBot("123456789:secret-not-stored", self.store)
        sent = []
        bot.send_message = lambda chat, text: sent.append((chat, text))
        return bot, sent

    def test_no_token_and_restart_keep_exactly_one_firing_event(self):
        self.bind()
        self.store.ingest(self.sid, metric(self.t, cpu=96), now=self.t)
        self.store.ingest(self.sid, metric(self.t + 1, cpu=97), now=self.t + 1)
        self.assertEqual(self.store.incident_outbox_pending_count(), 1)
        self.assertEqual(TelegramRuntime(self.store, self.path).status()["pending_incident_notifications"], 1)
        self.store = Store(self.path)
        self.store.migrate()
        bot, sent = self.bot()
        self.assertTrue(bot.deliver_incident_once(now=self.t + 2))
        self.assertFalse(bot.deliver_incident_once(now=self.t + 2))
        self.assertEqual(len(sent), 1)
        self.assertIn("Тревога", sent[0][1])
        self.assertEqual(self.store.incident_outbox_pending_count(), 0)
        self.assertNotIn(b"secret-not-stored", self.path.read_bytes())

    def test_transient_retry_blocks_recovery_for_same_recipient_across_restart(self):
        self.bind()
        self.store.ingest(self.sid, metric(self.t, cpu=96), now=self.t)
        self.store.ingest(self.sid, metric(self.t + 1), now=self.t + 1)
        bot, sent = self.bot()
        attempts = []

        def first_failure(chat, text):
            attempts.append(text)
            raise TimeoutError("temporary Telegram outage")

        bot.send_message = first_failure
        self.assertTrue(bot.deliver_incident_once(now=self.t + 1))
        self.assertEqual(self.rows()[0]["attempts"], 1)
        self.assertEqual(self.rows()[0]["next_attempt_at"], self.t + 6)
        self.assertFalse(bot.deliver_incident_once(now=self.t + 2))
        self.store = Store(self.path)
        self.store.migrate()
        resumed, sent = self.bot()
        self.assertTrue(resumed.deliver_incident_once(now=self.t + 6))
        self.assertTrue(resumed.deliver_incident_once(now=self.t + 6))
        self.assertEqual(["Тревога" in text for _, text in sent], [True, False])
        self.assertIn("Восстановлено", sent[1][1])
        self.assertEqual(self.store.incident_outbox_pending_count(), 0)

    def test_inflight_lease_reopens_after_restart_without_early_duplicate(self):
        self.bind()
        self.store.ingest(self.sid, metric(self.t, cpu=96), now=self.t)
        first = self.store.claim_incident_outbox(now=self.t)
        self.assertIsNotNone(first)
        restarted = Store(self.path)
        restarted.migrate()
        self.assertIsNone(restarted.claim_incident_outbox(now=self.t + 59))
        reclaimed = restarted.claim_incident_outbox(now=self.t + 60)
        self.assertEqual(reclaimed["id"], first["id"])
        self.assertNotEqual(reclaimed["lease_generation"], first["lease_generation"])
        self.assertFalse(restarted.complete_incident_outbox(first["id"], first["lease_generation"], now=self.t + 61))
        self.assertTrue(restarted.complete_incident_outbox(reclaimed["id"], reclaimed["lease_generation"], now=self.t + 61))

    def test_retry_after_header_is_respected_and_permanent_error_cancels_recovery(self):
        self.bind()
        self.store.ingest(self.sid, metric(self.t, cpu=96), now=self.t)
        self.store.ingest(self.sid, metric(self.t + 1), now=self.t + 1)
        bot, _ = self.bot()
        marker = "BOT_TOKEN_MUST_NOT_BE_LOGGED"
        http_429 = urllib.error.HTTPError("https://api.telegram.org/bot" + marker,
                                         429, "rate limit", {"Retry-After": "999999"}, None)
        bot.send_message = lambda chat, text: (_ for _ in ()).throw(http_429)
        with mock.patch("sovagrid_hub.telegram.logging.error") as logs:
            self.assertTrue(bot.deliver_incident_once(now=self.t))
        self.assertNotIn(marker, str(logs.call_args_list))
        self.assertEqual(self.rows()[0]["next_attempt_at"], self.t + 999999)
        http_403 = urllib.error.HTTPError("https://api.telegram.org/bot" + marker,
                                         403, "blocked", {}, None)
        bot.send_message = lambda chat, text: (_ for _ in ()).throw(http_403)
        self.assertTrue(bot.deliver_incident_once(now=self.t + 999999))
        http_429.close()
        http_403.close()
        self.assertEqual(self.store.incident_outbox_pending_count(), 0)
        self.assertTrue(all(row["dropped_at"] is not None for row in self.rows()))

    def test_retry_delay_caps_at_one_hour(self):
        self.bind()
        self.store.ingest(self.sid, metric(self.t, cpu=96), now=self.t)
        for attempt in range(13):
            row = self.store.claim_incident_outbox(now=self.t + attempt * 4000)
            self.assertIsNotNone(row)
            now = self.t + attempt * 4000
            self.assertTrue(self.store.retry_incident_outbox(row["id"], row["lease_generation"], now=now))
            next_row = self.rows()[0]
            self.assertLessEqual(next_row["next_attempt_at"] - now, 3600)
        self.assertEqual(self.rows()[0]["next_attempt_at"], self.t + 12 * 4000 + 3600)

    def test_telegram_json_retry_after_precedes_header_without_persisting_error_body(self):
        self.bind()
        self.store.ingest(self.sid, metric(self.t, cpu=96), now=self.t)
        bot, _ = self.bot()
        marker = "ERROR_BODY_MUST_NOT_BE_STORED_OR_LOGGED"
        body = io.BytesIO((
            '{"ok":false,"error_code":429,"description":"' + marker +
            '","parameters":{"retry_after":120}}').encode())
        error = urllib.error.HTTPError("https://api.telegram.org/bot" + marker,
                                      429, "rate limit", {"Retry-After": "10"}, body)
        bot.send_message = lambda *args: (_ for _ in ()).throw(error)
        with mock.patch("sovagrid_hub.telegram.logging.error") as logs:
            self.assertTrue(bot.deliver_incident_once(now=self.t))
        self.assertEqual(self.rows()[0]["next_attempt_at"], self.t + 120)
        self.assertTrue(body.closed)
        self.assertNotIn(marker, str(logs.call_args_list))
        self.assertNotIn(marker.encode(), self.path.read_bytes())

    def test_telegram_retry_after_rejects_invalid_or_oversized_json_and_validates_delay(self):
        cases = (
            (b'{"parameters":{"retry_after":true}}', {"Retry-After": "90"}, 90),
            (b'{"parameters":{"retry_after":-1}}', {"Retry-After": "90"}, 90),
            (b'{"parameters":{"retry_after":"120"}}', {"Retry-After": "90"}, 90),
            (b'{"parameters":{"retry_after":120.0}}', {"Retry-After": "90"}, 90),
            (b'{"parameters":{"retry_after":2147483648}}', {"Retry-After": "90"}, 90),
            (b'{"parameters":null}', {"Retry-After": "90"}, 90),
            (b'[]', {"Retry-After": "90"}, 90),
            (b'{', {}, 5),
            (b'{', {"Retry-After": "-90"}, 5),
            (b'{', {"Retry-After": "90.0"}, 5),
            (b'{', {"Retry-After": "\u0669\u0660"}, 5),
            (b' ' * 4096 + b'{"parameters":{"retry_after":120}}', {"Retry-After": "90"}, 90),
            (b'{"parameters":{"retry_after":86400}}', {}, 86400),
        )
        for index, (data, headers, expected) in enumerate(cases):
            with self.subTest(index=index):
                store = Store(Path(self.temp.name) / f"rate-limit-{index}.sqlite")
                store.initialize("admin", "very-long-test-password")
                server_id = store.create_server("rate-limit-host")["id"]
                store.add_bot_user(101, 101, "viewer")
                store.ingest(server_id, metric(self.t, cpu=96), now=self.t)
                bot = TelegramBot("123:fixture", store)
                body = io.BytesIO(data)
                error = urllib.error.HTTPError("https://api.telegram.org/bot-fixture",
                                              429, "rate limit", headers, body)
                bot.send_message = lambda *args: (_ for _ in ()).throw(error)
                with mock.patch("sovagrid_hub.telegram.logging.error"):
                    self.assertTrue(bot.deliver_incident_once(now=self.t))
                with store.connection() as db:
                    next_attempt = db.execute("SELECT next_attempt_at FROM incident_outbox").fetchone()[0]
                self.assertEqual(next_attempt, self.t + expected)
                self.assertTrue(body.closed)

    def test_telegram_two_hour_flood_control_survives_restart_without_early_retry(self):
        self.bind()
        self.store.ingest(self.sid, metric(self.t, cpu=96), now=self.t)
        bot, _ = self.bot()
        error = urllib.error.HTTPError("https://api.telegram.org/bot-fixture", 429,
                                      "rate limit", {}, io.BytesIO(
                                          b'{"parameters":{"retry_after":7200}}'))
        bot.send_message = lambda *args: (_ for _ in ()).throw(error)
        with mock.patch("sovagrid_hub.telegram.logging.error"):
            self.assertTrue(bot.deliver_incident_once(now=self.t))
        self.assertEqual(self.rows()[0]["next_attempt_at"], self.t + 7200)
        self.store = Store(self.path)
        self.store.migrate()
        resumed, sent = self.bot()
        self.assertFalse(resumed.deliver_incident_once(now=self.t + 7199))
        self.assertEqual(sent, [])
        self.assertTrue(resumed.deliver_incident_once(now=self.t + 7200))
        self.assertEqual(len(sent), 1)

    def test_telegram_error_body_read_is_bounded_and_read_failure_uses_header(self):
        class RecordingBody(io.BytesIO):
            requested = None

            def read(self, size=-1):
                self.requested = size
                return super().read(size)

        body = RecordingBody(b"x" * 8192)
        with urllib.error.HTTPError("https://api.telegram.org/bot-fixture", 429,
                                    "rate limit", {"Retry-After": "90"}, body) as error:
            self.assertEqual(TelegramBot._retry_after(error), 90)
        self.assertEqual(body.requested, 4097)

        class InterruptedBody(io.BytesIO):
            def read(self, size=-1):
                raise OSError("interrupted error response")

        with urllib.error.HTTPError("https://api.telegram.org/bot-fixture", 429,
                                    "rate limit", {"Retry-After": "90"}, InterruptedBody()) as error:
            self.assertEqual(TelegramBot._retry_after(error), 90)

    def test_revoke_drops_pending_events_and_rebind_does_not_replay_them(self):
        self.bind(101, "admin")
        self.store.ingest(self.sid, metric(self.t, cpu=96), now=self.t)
        self.store.ingest(self.sid, metric(self.t + 1), now=self.t + 1)
        self.assertEqual(self.store.incident_outbox_pending_count(), 2)
        self.assertTrue(self.store.remove_bot_user(101, 101))
        self.bind(101, "viewer")
        bot, sent = self.bot()
        self.assertFalse(bot.deliver_incident_once(now=self.t + 2))
        self.assertEqual(sent, [])
        self.assertEqual(self.store.incident_outbox_pending_count(), 0)

    def test_binding_recheck_denies_claimed_message_after_revoke(self):
        self.bind()
        self.store.ingest(self.sid, metric(self.t, cpu=96), now=self.t)
        claimed = self.store.claim_incident_outbox(now=self.t)
        self.assertTrue(self.store.remove_bot_user(101, 101))
        self.assertFalse(self.store.incident_outbox_send_allowed(claimed["id"], claimed["lease_generation"], now=self.t))

    def test_role_demotion_to_viewer_keeps_incident_access(self):
        self.bind(101, "admin")
        self.store.ingest(self.sid, metric(self.t, cpu=96), now=self.t)
        self.bind(101, "viewer")
        bot, sent = self.bot()
        self.assertTrue(bot.deliver_incident_once(now=self.t))
        self.assertEqual(sent[0][0], 101)

    def test_maintenance_drops_claimed_old_alert_then_issues_one_reminder(self):
        self.bind()
        self.store.ingest(self.sid, metric(self.t, cpu=96), now=self.t)
        claimed = self.store.claim_incident_outbox(now=self.t)
        self.assertIsNotNone(claimed)
        self.store.create_maintenance(self.sid,
            {"ends_at": self.t + 61, "reason": "Planned update"}, now=self.t + 1)
        self.assertFalse(self.store.incident_outbox_send_allowed(claimed["id"], claimed["lease_generation"], now=self.t + 1))
        self.assertEqual(self.store.incident_outbox_pending_count(), 0)
        self.store.sweep_offline(now=self.t + 61)
        self.store.sweep_offline(now=self.t + 62)
        bot, sent = self.bot()
        self.assertTrue(bot.deliver_incident_once(now=self.t + 62))
        self.assertFalse(bot.deliver_incident_once(now=self.t + 62))
        self.assertEqual(len(sent), 1)
        self.assertIn("Повторное уведомление", sent[0][1])
        self.store.ingest(self.sid, metric(self.t + 63), now=self.t + 63)
        self.assertTrue(bot.deliver_incident_once(now=self.t + 63))
        self.assertIn("Восстановлено", sent[1][1])

    def test_recipients_progress_independently_but_each_preserves_order(self):
        self.bind(101)
        self.bind(202)
        self.store.ingest(self.sid, metric(self.t, cpu=96), now=self.t)
        self.store.ingest(self.sid, metric(self.t + 1), now=self.t + 1)
        bot, sent = self.bot()
        failed = False

        def send(chat, text):
            nonlocal failed
            if chat == 101 and not failed:
                failed = True
                raise TimeoutError("temporary")
            sent.append((chat, text))

        bot.send_message = send
        self.assertTrue(bot.deliver_incident_once(now=self.t + 1))
        self.assertTrue(bot.deliver_incident_once(now=self.t + 1))
        self.assertTrue(bot.deliver_incident_once(now=self.t + 1))
        self.assertEqual([chat for chat, _ in sent], [202, 202])
        self.assertTrue(bot.deliver_incident_once(now=self.t + 6))
        self.assertTrue(bot.deliver_incident_once(now=self.t + 6))
        self.assertEqual([chat for chat, _ in sent], [202, 202, 101, 101])
        self.assertEqual(self.store.incident_outbox_pending_count(), 0)

    def test_recovery_survives_unsent_or_claimed_stale_reminder_after_delivered_alert(self):
        self.bind()
        bot, sent = self.bot()
        for claimed_before_recovery in (False, True):
            with self.subTest(claimed_before_recovery=claimed_before_recovery):
                t = self.t + int(claimed_before_recovery) * 1000
                self.store.ingest(self.sid, metric(t, cpu=96), now=t)
                self.assertTrue(bot.deliver_incident_once(now=t))
                self.store.create_maintenance(self.sid,
                    {"ends_at": t + 61, "reason": "Planned update"}, now=t + 1)
                self.store.sweep_offline(now=t + 61)
                claimed = (self.store.claim_incident_outbox(now=t + 61)
                           if claimed_before_recovery else None)
                if claimed_before_recovery:
                    self.assertEqual(claimed["event_type"], "reminder")
                self.store.ingest(self.sid, metric(t + 62), now=t + 62)
                if claimed is not None:
                    self.assertFalse(self.store.incident_outbox_send_allowed(
                        claimed["id"], claimed["lease_generation"], now=t + 62))
                self.assertTrue(bot.deliver_incident_once(now=t + 62))
                self.assertIn("Восстановлено", sent[-1][1])
                self.assertFalse(bot.deliver_incident_once(now=t + 62))
                self.assertEqual(self.store.incident_outbox_pending_count(), 0)
        self.assertEqual(len(sent), 4)
        self.assertTrue(all("Повторное уведомление" not in text for _, text in sent))

    def test_stale_reminder_without_delivered_alert_drops_dependent_recovery(self):
        self.bind()
        t = self.t
        self.store.ingest(self.sid, metric(t, cpu=96), now=t)
        self.store.create_maintenance(self.sid,
            {"ends_at": t + 61, "reason": "Planned update"}, now=t + 1)
        self.store.sweep_offline(now=t + 61)
        self.store.ingest(self.sid, metric(t + 62), now=t + 62)
        bot, sent = self.bot()
        self.assertFalse(bot.deliver_incident_once(now=t + 62))
        self.assertEqual(sent, [])
        self.assertEqual(self.store.incident_outbox_pending_count(), 0)

    def test_migration_marks_legacy_active_alert_without_replaying_it(self):
        self.bind()
        self.store.ingest(self.sid, metric(self.t, cpu=96), now=self.t)
        with closing(sqlite3.connect(self.path)) as db:
            db.execute("DROP TABLE incident_outbox")
            db.commit()
        self.store.migrate()
        self.store.migrate()
        self.assertEqual(len(self.rows()), 1)
        self.assertIsNotNone(self.rows()[0]["delivered_at"])
        bot, sent = self.bot()
        self.assertFalse(bot.deliver_incident_once(now=self.t + 1))
        self.store.ingest(self.sid, metric(self.t + 2), now=self.t + 2)
        self.assertTrue(bot.deliver_incident_once(now=self.t + 2))
        self.assertEqual(len(sent), 1)
        self.assertIn("Восстановлено", sent[0][1])

    def test_interrupted_migration_rolls_back_schema_and_retries_legacy_backfill(self):
        self.bind()
        self.store.ingest(self.sid, metric(self.t, cpu=96), now=self.t)
        with self.store.connection() as db:
            db.execute("DROP TABLE incident_outbox")
        real_connection = self.store.connection

        class InterruptedMigration:
            def __init__(self, db):
                self.db = db

            def execute(self, sql, *args):
                if "INSERT OR IGNORE INTO incident_outbox" in sql:
                    raise RuntimeError("simulated migration interruption")
                return self.db.execute(sql, *args)

        @contextmanager
        def interrupted_connection():
            with real_connection() as db:
                yield InterruptedMigration(db)

        with mock.patch.object(self.store, "connection", interrupted_connection):
            with self.assertRaisesRegex(RuntimeError, "simulated migration interruption"):
                self.store.migrate()
        with real_connection() as db:
            self.assertIsNone(db.execute("SELECT 1 FROM sqlite_master WHERE name='incident_outbox'").fetchone())
        self.store.migrate()
        self.store.migrate()
        self.assertEqual(len(self.rows()), 1)
        self.assertIsNotNone(self.rows()[0]["delivered_at"])
        self.store.ingest(self.sid, metric(self.t + 1), now=self.t + 1)
        bot, sent = self.bot()
        self.assertTrue(bot.deliver_incident_once(now=self.t + 1))
        self.assertEqual(len(sent), 1)
        self.assertIn("Восстановлено", sent[0][1])

    def test_prune_keeps_active_history_then_removes_old_completed_rows(self):
        self.bind()
        self.store.ingest(self.sid, metric(self.t, cpu=96), now=self.t)
        bot, _ = self.bot()
        bot.deliver_incident_once(now=self.t)
        self.assertEqual(self.store.prune_incident_outbox(now=self.t + 31 * 86400), 0)
        self.store.ingest(self.sid, metric(self.t + 31 * 86400), now=self.t + 31 * 86400)
        bot.deliver_incident_once(now=self.t + 31 * 86400)
        self.assertEqual(self.store.prune_incident_outbox(now=self.t + 62 * 86400), 2)


if __name__ == "__main__":
    unittest.main()
