# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Opt-in verified certificate expiry alerts and their durable notifications."""
import tempfile
import unittest
import uuid
from pathlib import Path

from sovagrid_hub.checks import validate_definition
from sovagrid_hub.store import Store
from sovagrid_hub.telegram import TelegramBot


PASSWORD = "a-long-tls-alert-test-password"


class CheckTLSAlertTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "hub.sqlite"
        self.store = Store(self.path)
        self.store.initialize("owner", PASSWORD)
        server = self.store.create_server("tls-host")
        self.sid, self.token = server["id"], server["agent_token"]
        self.t = 1_000_000_000
        self.item = {"id": str(uuid.uuid4()), "name": "Private endpoint", "kind": "http",
                     "enabled": True, "interval_seconds": 60, "timeout_seconds": 5,
                     "url": "https://secret.example/health"}

    def tearDown(self):
        self.temp.cleanup()

    def configure(self, *, revision=0, now=None, **changes):
        self.item = {**self.item, **changes}
        return self.store.save_check_config(
            self.sid, {"revision": revision, "checks": [self.item]}, now=self.t if now is None else now)

    def sample(self, now, expires_at, *, down=False):
        lease = self.store.claim_check(self.sid, self.token, {"protocol": 1}, now=now)["lease"]
        self.assertIsNotNone(lease)
        self.assertNotIn("tls_alert_days", lease["check"])
        result = {"lease_id": lease["id"], "config_revision": lease["config_revision"],
                  "observed_at": now, "status": "down" if down else "up", "latency_ms": 12,
                  "http_status": None if down else 200, "tls_expires_at": expires_at,
                  "error_code": "tls_error" if down else None}
        self.assertEqual(self.store.record_check_result(self.sid, self.item["id"],
                                                        self.token, result, now=now), {"accepted": True})
        return result

    def bot(self):
        bot = TelegramBot("123:ABC", self.store)
        sent = []
        bot.send_message = lambda chat, message: sent.append((chat, message))
        return bot, sent

    def test_rule_validation_is_https_only_and_opt_in(self):
        self.assertEqual(validate_definition(self.item), self.item)
        for value in (None, 1, 14, 90):
            self.assertEqual(validate_definition({**self.item, "tls_alert_days": value})["tls_alert_days"], value)
        for value in (True, False, 0, 91, 2.5, "14"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_definition({**self.item, "tls_alert_days": value})
        for url in ("http://secret.example/health",):
            with self.assertRaises(ValueError):
                validate_definition({**self.item, "url": url, "tls_alert_days": 14})
        with self.assertRaises(ValueError):
            validate_definition({**self.item, "tls_alert_days": 14, "unexpected": True})

    def test_legacy_config_migrates_without_enabling_alerts(self):
        self.configure()
        # Older persisted JSON has no rule; reopening after upgrade leaves it off.
        self.store = Store(self.path)
        self.store.migrate()
        self.assertNotIn("tls_alert_days", self.store.check_config(self.sid)["checks"][0])
        self.assertIsNone(self.store.checks_summary(self.sid, now=self.t)["checks"][0]["tls_alert_days"])
        self.sample(self.t, self.t + 86400)
        self.assertEqual(self.store.incidents(), [])

    def test_rule_survives_legacy_save_but_explicit_null_disables(self):
        self.configure(tls_alert_days=14)
        old_client_payload = {key: value for key, value in self.item.items() if key != "tls_alert_days"}
        saved = self.store.save_check_config(self.sid, {"revision": 1, "checks": [old_client_payload]}, now=self.t + 1)
        self.assertEqual(saved["checks"][0]["tls_alert_days"], 14)
        self.item = saved["checks"][0]
        self.sample(self.t + 1, self.t + 86400)
        self.assertEqual(len(self.store.incidents(state="firing")), 1)
        self.store.save_check_config(self.sid, {"revision": 2,
                                     "checks": [{**self.item, "tls_alert_days": None}]}, now=self.t + 2)
        self.assertEqual(self.store.incidents(state="firing"), [])
        self.assertEqual(self.store.incident_outbox_pending_count(), 0)

    def test_verified_expiry_replay_recovery_and_role_bound_telegram_are_private(self):
        self.configure(name="https://secret.example token=private-value", tls_alert_days=14)
        self.store.add_bot_user(123, 123, "viewer")
        self.store.add_bot_user(124, 124, "operator")
        first = self.sample(self.t, self.t + 13 * 86400)
        active = self.store.incidents(state="firing")
        self.assertEqual(len(active), 1)
        self.assertEqual((active[0]["kind"], active[0]["threshold"]), ("tls:" + self.item["id"], 14))
        self.assertAlmostEqual(active[0]["current_value"], 13)
        self.assertEqual(self.store.record_check_result(self.sid, self.item["id"],
                                                        self.token, first, now=self.t + 1), {"accepted": True})
        self.sample(self.t + 60, self.t + 13 * 86400)
        self.assertEqual(len(self.store.incidents(state="firing")), 1)
        self.assertEqual(self.store.incident_outbox_pending_count(), 2)
        bot, sent = self.bot()
        self.assertTrue(bot.deliver_incident_once(now=self.t + 60))
        self.assertTrue(bot.deliver_incident_once(now=self.t + 60))
        self.assertEqual({chat for chat, _ in sent}, {123, 124})
        self.sample(self.t + 120, self.t + 90 * 86400)
        self.assertEqual(self.store.incidents(state="firing"), [])
        self.assertTrue(bot.deliver_incident_once(now=self.t + 120))
        self.assertTrue(bot.deliver_incident_once(now=self.t + 120))
        self.assertEqual(len(sent), 4)
        for _, message in sent:
            for secret in ("secret.example", "/health", "private-value", self.token):
                self.assertNotIn(secret, message)
            self.assertIn("#" + self.item["id"][:8], message)
        self.assertTrue(all("До истечения" in message for _, message in sent[:2]))
        self.assertTrue(all("Восстановлено" in message for _, message in sent[2:]))

    def test_missing_verified_expiry_preserves_firing_but_resets_pending_hold(self):
        self.configure(tls_alert_days=14)
        settings = self.store.monitoring_settings()
        self.store.save_monitoring_settings({**settings, "trigger_minutes": 1})
        self.sample(self.t, self.t + 2 * 86400)
        self.sample(self.t + 60, None, down=True)
        self.sample(self.t + 120, self.t + 2 * 86400)
        self.assertFalse(any(i["kind"].startswith("tls:") for i in self.store.incidents()))
        self.sample(self.t + 180, self.t + 2 * 86400)
        self.assertTrue(any(i["kind"].startswith("tls:") for i in self.store.incidents(state="firing")))
        self.sample(self.t + 240, None, down=True)
        self.assertTrue(any(i["kind"].startswith("tls:") for i in self.store.incidents(state="firing")))

    def test_worker_gap_resets_unconfirmed_expiry_hold(self):
        self.configure(tls_alert_days=14)
        settings = self.store.monitoring_settings()
        self.store.save_monitoring_settings({**settings, "trigger_minutes": 1})
        self.sample(self.t, self.t + 2 * 86400)
        self.sample(self.t + 180, self.t + 2 * 86400)
        self.assertEqual(self.store.incidents(state="firing"), [])
        self.sample(self.t + 240, self.t + 2 * 86400)
        self.assertEqual(self.store.incidents(state="firing")[0]["opened_at"], self.t + 180)

    def test_maintenance_reminder_then_recovery(self):
        self.configure(tls_alert_days=14)
        self.store.add_bot_user(123, 123, "viewer")
        self.store.create_maintenance(self.sid, {"ends_at": self.t + 180,
                                                 "reason": "Planned renewal"}, now=self.t)
        self.sample(self.t + 10, self.t + 86400)
        self.assertEqual(self.store.incident_outbox_pending_count(), 0)
        reminder = self.store.sweep_offline(now=self.t + 180)
        self.assertEqual([(event["kind"], event["maintenance_reminder"]) for event in reminder],
                         [("tls:" + self.item["id"], True)])
        bot, sent = self.bot()
        self.assertTrue(bot.deliver_incident_once(now=self.t + 180))
        self.assertIn("Повторное уведомление", sent[0][1])
        self.sample(self.t + 190, self.t + 90 * 86400)
        self.assertTrue(bot.deliver_incident_once(now=self.t + 190))
        self.assertIn("Восстановлено", sent[1][1])

    def test_target_change_retires_old_expiry_without_fake_recovery(self):
        self.configure(tls_alert_days=14)
        self.store.add_bot_user(123, 123, "viewer")
        self.sample(self.t, self.t + 86400)
        self.assertEqual(self.store.incident_outbox_pending_count(), 1)
        self.configure(revision=1, now=self.t + 1, url="https://other.example/health")
        self.assertEqual(self.store.incidents(state="firing"), [])
        self.assertEqual(self.store.incident_outbox_pending_count(), 0)
        self.assertEqual(self.store.checks_summary(self.sid, now=self.t + 1)["checks"][0]["tls_alert_days"], 14)

    def test_legacy_client_target_change_does_not_carry_expiry_rule(self):
        self.configure(tls_alert_days=14)
        replacement = {key: value for key, value in self.item.items() if key != "tls_alert_days"}
        replacement["url"] = "https://new.example/health"
        saved = self.store.save_check_config(self.sid, {"revision": 1, "checks": [replacement]}, now=self.t + 1)
        self.assertNotIn("tls_alert_days", saved["checks"][0])
        self.assertIsNone(self.store.checks_summary(self.sid, now=self.t + 1)["checks"][0]["tls_alert_days"])


if __name__ == "__main__":
    unittest.main()
