# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Live check results must use the same durable, role-aware incident outbox."""
import sqlite3
import tempfile
import unittest
import uuid
from pathlib import Path

from sovagrid_hub.store import Store
from sovagrid_hub.telegram import TelegramBot


class CheckAlertTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "hub.sqlite"
        self.store = Store(self.path)
        self.store.initialize("owner", "a-long-check-alert-password")
        server = self.store.create_server("check-alert-host")
        self.sid, self.token = server["id"], server["agent_token"]
        self.t = 1_000_000
        self.item = {"id": str(uuid.uuid4()), "name": "Private health", "kind": "http",
                     "enabled": True, "interval_seconds": 60, "timeout_seconds": 5,
                     "url": "https://private.example/health"}
        self.store.save_check_config(self.sid, {"revision": 0, "checks": [self.item]}, now=self.t)
        self.store.add_bot_user(123, 123, "viewer")

    def tearDown(self):
        self.temp.cleanup()

    def duration(self, minutes):
        settings = self.store.monitoring_settings()
        self.store.save_monitoring_settings({**settings, "trigger_minutes": minutes})

    def sample(self, now, *, down):
        lease = self.store.claim_check(self.sid, self.token, {"protocol": 1}, now=now)["lease"]
        self.assertIsNotNone(lease)
        result = {"lease_id": lease["id"], "config_revision": lease["config_revision"],
                  "observed_at": now, "status": "down" if down else "up",
                  "latency_ms": 12,
                  "http_status": (503 if down else 200) if self.item["kind"] == "http" else None,
                  "tls_expires_at": now + 86400 if self.item["kind"] == "http" else None,
                  "error_code": ("http_error" if self.item["kind"] == "http" else
                                 "dns_mismatch" if self.item["kind"] == "dns" else "connect_error") if down else None}
        self.assertEqual(self.store.record_check_result(self.sid, self.item["id"],
                                                        self.token, result, now=now),
                         {"accepted": True})
        return result

    def bot(self):
        bot = TelegramBot("123:ABC", self.store)
        sent = []
        bot.send_message = lambda chat, message: sent.append((chat, message))
        return bot, sent

    def test_flapping_hold_restart_replay_and_recovery_use_durable_outbox(self):
        self.duration(1)
        self.sample(self.t, down=True)
        self.sample(self.t + 60, down=False)
        self.assertEqual(self.store.incidents(), [])
        self.sample(self.t + 120, down=True)
        resumed = Store(self.path)
        resumed.migrate()
        self.store = resumed
        second = self.sample(self.t + 180, down=True)
        firing = self.store.incidents(state="firing")
        self.assertEqual(len(firing), 1)
        self.assertEqual((firing[0]["kind"], firing[0]["subject"], firing[0]["opened_at"]),
                         ("check:" + self.item["id"], self.item["name"], self.t + 120))
        self.assertEqual(self.store.record_check_result(self.sid, self.item["id"],
                                                        self.token, second, now=self.t + 181),
                         {"accepted": True})
        self.assertEqual(self.store.incident_outbox_pending_count(), 1)
        bot, sent = self.bot()
        self.assertTrue(bot.deliver_incident_once(now=self.t + 180))
        self.assertFalse(bot.deliver_incident_once(now=self.t + 180))
        self.sample(self.t + 240, down=False)
        self.assertEqual(len(self.store.incidents(state="firing")), 0)
        self.assertTrue(bot.deliver_incident_once(now=self.t + 240))
        self.assertEqual(len(sent), 2)
        self.assertIn("#" + self.item["id"][:8], sent[0][1])
        self.assertIn("Восстановлено", sent[1][1])
        self.assertIn("Длительность: 2 мин", sent[1][1])
        for _, text in sent:
            self.assertNotIn(self.item["url"], text)
            self.assertNotIn(self.token, text)

    def test_gap_resets_hold_and_only_subsequent_result_fires(self):
        self.duration(1)
        self.sample(self.t, down=True)
        self.sample(self.t + 180, down=True)
        self.assertEqual(self.store.incidents(), [])
        self.sample(self.t + 240, down=True)
        self.assertEqual(self.store.incidents(state="firing")[0]["opened_at"], self.t + 180)

    def test_tcp_failure_and_recovery_use_the_same_incident_rules(self):
        self.item = {"id": self.item["id"], "name": "TCP endpoint", "kind": "tcp",
                     "enabled": True, "interval_seconds": 60, "timeout_seconds": 5,
                     "host": "127.0.0.1", "port": 22}
        self.store.save_check_config(self.sid, {"revision": 1, "checks": [self.item]}, now=self.t - 1)
        self.sample(self.t, down=True)
        self.assertEqual(len(self.store.incidents(state="firing")), 1)
        self.sample(self.t + 60, down=False)
        self.assertEqual(len(self.store.incidents(state="firing")), 0)
        self.assertEqual(self.store.incident_outbox_pending_count(), 2)

    def test_dns_mismatch_and_recovery_keep_answers_out_of_telegram(self):
        self.item = {"id": self.item["id"], "name": "DNS endpoint", "kind": "dns",
                     "enabled": True, "interval_seconds": 60, "timeout_seconds": 5,
                     "host": "private.example", "record_type": "A", "expected_ip": "203.0.113.7"}
        self.store.save_check_config(self.sid, {"revision": 1, "checks": [self.item]}, now=self.t - 1)
        self.sample(self.t, down=True)
        self.assertEqual(len(self.store.incidents(state="firing")), 1)
        self.sample(self.t + 60, down=False)
        self.assertEqual(len(self.store.incidents(state="firing")), 0)
        bot, sent = self.bot()
        self.assertTrue(bot.deliver_incident_once(now=self.t + 60))
        self.assertTrue(bot.deliver_incident_once(now=self.t + 60))
        self.assertEqual(len(sent), 2)
        for _, message in sent:
            self.assertNotIn(self.item["host"], message)
            self.assertNotIn(self.item["expected_ip"], message)

    def test_maintenance_suppresses_then_reminds_and_recovers(self):
        self.duration(1)
        self.store.create_maintenance(self.sid, {"ends_at": self.t + 180,
                                                 "reason": "Planned update"}, now=self.t)
        self.sample(self.t + 10, down=True)
        self.sample(self.t + 70, down=True)
        self.assertEqual(self.store.incident_outbox_pending_count(), 0)
        reminders = self.store.sweep_offline(now=self.t + 180)
        self.assertEqual([(event["kind"], event["maintenance_reminder"])
                          for event in reminders], [("check:" + self.item["id"], True)])
        bot, sent = self.bot()
        self.assertTrue(bot.deliver_incident_once(now=self.t + 180))
        self.assertIn("Повторное уведомление", sent[0][1])
        self.sample(self.t + 181, down=False)
        self.assertTrue(bot.deliver_incident_once(now=self.t + 181))
        self.assertIn("Восстановлено", sent[1][1])

    def test_short_failure_inside_maintenance_never_generates_a_reminder(self):
        self.duration(1)
        self.store.create_maintenance(self.sid, {"ends_at": self.t + 180,
                                                 "reason": "Planned update"}, now=self.t)
        self.sample(self.t + 10, down=True)
        self.sample(self.t + 70, down=False)
        self.assertEqual(self.store.incidents(), [])
        self.assertEqual(self.store.sweep_offline(now=self.t + 180), [])
        self.assertEqual(self.store.incident_outbox_pending_count(), 0)

    def test_telegram_failure_retries_the_same_check_alert(self):
        self.item = {**self.item, "name": self.item["url"] + " token=sensitive-value"}
        self.store.save_check_config(self.sid, {"revision": 1, "checks": [self.item]}, now=self.t - 1)
        self.sample(self.t, down=True)
        with self.store.connection() as db:
            pending = dict(db.execute("SELECT * FROM incident_outbox").fetchone())
        self.assertNotIn(self.item["url"], str(pending))
        self.assertNotIn("sensitive-value", str(pending))
        bot = TelegramBot("123:ABC", self.store)
        attempts = []
        def send(chat, message):
            attempts.append((chat, message))
            if len(attempts) == 1:
                raise OSError("temporary delivery failure")
        bot.send_message = send
        self.assertTrue(bot.deliver_incident_once(now=self.t))
        self.assertEqual(self.store.incident_outbox_pending_count(), 1)
        self.assertFalse(bot.deliver_incident_once(now=self.t + 4))
        self.assertTrue(bot.deliver_incident_once(now=self.t + 5))
        self.assertEqual(self.store.incident_outbox_pending_count(), 0)
        self.assertEqual(len(attempts), 2)
        self.assertEqual(attempts[0], attempts[1])
        self.assertNotIn(self.item["url"], attempts[1][1])
        self.assertNotIn("sensitive-value", attempts[1][1])
        self.assertNotIn(self.item["name"], attempts[1][1])

    def test_revoked_chat_does_not_receive_a_pending_check_alert(self):
        self.sample(self.t, down=True)
        self.store.remove_bot_user(123, 123)
        bot, sent = self.bot()
        self.assertFalse(bot.deliver_incident_once(now=self.t))
        self.assertEqual(self.store.incident_outbox_pending_count(), 0)
        self.assertEqual(sent, [])

    def test_disable_retire_drops_unsent_alert_without_fake_recovery(self):
        self.sample(self.t, down=True)
        self.assertEqual(self.store.incident_outbox_pending_count(), 1)
        self.store.save_check_config(self.sid, {"revision": 1,
                                      "checks": [{**self.item, "enabled": False}]}, now=self.t + 1)
        self.assertEqual(self.store.incidents(state="firing"), [])
        self.assertEqual(self.store.incident_outbox_pending_count(), 0)
        bot, sent = self.bot()
        self.assertFalse(bot.deliver_incident_once(now=self.t + 2))
        self.assertEqual(sent, [])

    def test_target_change_and_delete_end_old_alert_without_disclosing_target(self):
        self.sample(self.t, down=True)
        replacement = {**self.item, "url": "https://other.example/health"}
        self.store.save_check_config(self.sid, {"revision": 1,
                                      "checks": [replacement]}, now=self.t + 1)
        self.assertEqual(self.store.incidents(state="firing"), [])
        self.assertEqual(self.store.incident_outbox_pending_count(), 0)
        self.item = replacement
        self.sample(self.t + 2, down=True)
        self.assertEqual(len(self.store.incidents(state="firing")), 1)
        self.store.save_check_config(self.sid, {"revision": 2,
                                      "checks": []}, now=self.t + 3)
        self.assertEqual(self.store.incidents(state="firing"), [])
        self.assertEqual(self.store.incident_outbox_pending_count(), 0)

    def test_additive_subject_migration_preserves_existing_incident(self):
        self.sample(self.t, down=True)
        identifier = self.store.incidents(state="firing")[0]["id"]
        with sqlite3.connect(self.path) as db:
            db.execute("ALTER TABLE incidents DROP COLUMN subject")
        self.store.migrate()
        self.store.migrate()
        incident = self.store.incidents(state="firing")[0]
        self.assertEqual(incident["id"], identifier)
        self.assertIsNone(incident["subject"])


if __name__ == "__main__":
    unittest.main()
