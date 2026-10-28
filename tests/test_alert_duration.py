# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
import sqlite3
import tempfile
import threading
import unittest
from contextlib import closing
from pathlib import Path

from sovagrid_hub.store import Store
from sovagrid_hub.telegram import TelegramBot


def metric(now, *, cpu=10, services=None):
    sample = {"collected_at": now, "cpu_percent": cpu, "memory_percent": 20,
              "disk_percent": 30, "network_rx_bytes": 100, "network_tx_bytes": 200,
              "load1": 0.5, "uptime_seconds": 3600}
    if services is not None:
        sample["details"] = {"services": {"failed_count": services, "units": []}}
    return sample


class AlertDurationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "hub.sqlite"
        self.store = Store(self.path, offline_seconds=10)
        self.store.initialize("admin", "very-long-test-password")
        self.sid = self.store.create_server("duration-host")["id"]
        self.start = 1_000_000

    def tearDown(self):
        self.temp.cleanup()

    def configure(self, **overrides):
        settings = self.store.monitoring_settings()
        return self.store.save_monitoring_settings({**settings, "trigger_minutes": 1, **overrides})

    def test_short_spike_never_opens_incident_and_restart_keeps_hold(self):
        self.configure(offline_seconds=120)
        t = self.start
        self.assertEqual(self.store.ingest(self.sid, metric(t, cpu=96), now=t), [])
        self.assertEqual(self.store.ingest(self.sid, metric(t + 59, cpu=96), now=t + 59), [])
        self.assertEqual(self.store.incidents(), [])
        restarted = Store(self.path, offline_seconds=999)
        restarted.migrate()
        opened = restarted.ingest(self.sid, metric(t + 60, cpu=96), now=t + 60)
        self.assertEqual([(event["kind"], event["state"]) for event in opened], [("high_cpu", "firing")])
        self.assertEqual(restarted.incidents()[0]["opened_at"], t)
        self.assertEqual(restarted.ingest(self.sid, metric(t + 61, cpu=97), now=t + 61), [])
        recovered = restarted.ingest(self.sid, metric(t + 62), now=t + 62)
        self.assertEqual([(event["id"], event["state"]) for event in recovered], [(opened[0]["id"], "resolved")])
        self.assertEqual(restarted.incidents()[0]["resolved_at"], t + 62)
        self.assertEqual(restarted.incidents()[0]["alerted_at"], t + 60)
        self.assertEqual(restarted.ingest(self.sid, metric(t + 63), now=t + 63), [])

    def test_recovery_of_unconfirmed_spike_is_silent_and_resets_hold(self):
        self.configure(offline_seconds=120)
        t = self.start
        self.store.ingest(self.sid, metric(t, cpu=98), now=t)
        self.assertEqual(self.store.ingest(self.sid, metric(t + 30), now=t + 30), [])
        self.assertEqual(self.store.incidents(), [])
        self.assertEqual(self.store.ingest(self.sid, metric(t + 31, cpu=98), now=t + 31), [])
        self.assertEqual(self.store.ingest(self.sid, metric(t + 90, cpu=98), now=t + 90), [])
        self.assertEqual(len(self.store.ingest(self.sid, metric(t + 91, cpu=98), now=t + 91)), 1)

    def test_threshold_change_and_telemetry_gap_reset_pending_resource_breach(self):
        self.configure(offline_seconds=120)
        t = self.start
        self.store.ingest(self.sid, metric(t, cpu=96), now=t)
        self.configure(high_cpu=95, revision=1)
        self.assertEqual(self.store.ingest(self.sid, metric(t + 5, cpu=96), now=t + 5), [])
        self.assertEqual(self.store.ingest(self.sid, metric(t + 60, cpu=96), now=t + 60), [])
        self.assertEqual(len(self.store.ingest(self.sid, metric(t + 65, cpu=96), now=t + 65)), 1)
        self.store.ingest(self.sid, metric(t + 66), now=t + 66)
        self.configure(offline_seconds=10, revision=2)
        self.assertEqual(self.store.ingest(self.sid, metric(t + 67, cpu=96), now=t + 67), [])
        # The 52-second telemetry gap cannot prove continuous CPU pressure.
        self.assertEqual(self.store.ingest(self.sid, metric(t + 119, cpu=96), now=t + 119), [])
        self.assertEqual(self.store.ingest(self.sid, metric(t + 179, cpu=96), now=t + 179), [])
        self.assertEqual(len(self.store.incidents(state="firing")), 0)

    def test_missing_service_inventory_resets_only_unconfirmed_candidate(self):
        self.configure(offline_seconds=120)
        t = self.start
        self.store.ingest(self.sid, metric(t, services=2), now=t)
        self.store.ingest(self.sid, metric(t + 30), now=t + 30)
        self.assertEqual(self.store.ingest(self.sid, metric(t + 61, services=2), now=t + 61), [])
        self.assertEqual(self.store.ingest(self.sid, metric(t + 120, services=2), now=t + 120), [])
        firing = self.store.ingest(self.sid, metric(t + 121, services=2), now=t + 121)
        self.assertEqual([event["kind"] for event in firing], ["failed_services"])
        self.assertEqual(self.store.ingest(self.sid, metric(t + 122), now=t + 122), [])
        self.assertEqual(len(self.store.incidents(state="firing")), 1)
        recovery = self.store.ingest(self.sid, metric(t + 123, services=0), now=t + 123)
        self.assertEqual([(event["kind"], event["state"]) for event in recovery], [("failed_services", "resolved")])

    def test_legacy_settings_post_keeps_the_configured_delay(self):
        self.configure(trigger_minutes=5)
        saved = self.store.monitoring_settings()
        legacy = {key: value for key, value in saved.items() if key != "trigger_minutes"}
        legacy["high_cpu"] = 85
        result = self.store.save_monitoring_settings(legacy)
        self.assertEqual(result["trigger_minutes"], 5)
        self.assertEqual(result["high_cpu"], 85)

    def test_offline_hold_is_persistent_and_concurrent_sweeps_emit_once(self):
        self.configure(offline_seconds=10)
        t = self.start
        self.store.ingest(self.sid, metric(t), now=t)
        self.assertEqual(self.store.sweep_offline(now=t + 11), [])
        restarted = Store(self.path, offline_seconds=999)
        restarted.migrate()
        self.assertEqual(restarted.sweep_offline(now=t + 70), [])
        batches = []
        threads = [threading.Thread(target=lambda: batches.append(restarted.sweep_offline(now=t + 71)))
                   for _ in range(6)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        firing = [event for batch in batches for event in batch]
        self.assertEqual([(event["kind"], event["state"]) for event in firing], [("offline", "firing")])
        self.assertEqual(restarted.incidents()[0]["opened_at"], t + 11)
        self.assertEqual(restarted.sweep_offline(now=t + 72), [])
        recovery = restarted.ingest(self.sid, metric(t + 73), now=t + 73)
        self.assertEqual([(event["kind"], event["state"]) for event in recovery], [("offline", "resolved")])

    def test_maintenance_suppresses_short_problem_and_releases_one_long_problem(self):
        self.configure(offline_seconds=120)
        self.store.add_bot_user(123, 123, "viewer")
        t = self.start
        self.store.create_maintenance(self.sid, {"ends_at": t + 180, "reason": "Planned update"}, now=t)
        self.store.ingest(self.sid, metric(t + 1, cpu=96), now=t + 1)
        self.assertEqual(self.store.ingest(self.sid, metric(t + 2), now=t + 2), [])
        self.assertEqual(self.store.incidents(), [])
        self.store.ingest(self.sid, metric(t + 50, cpu=96), now=t + 50)
        self.assertEqual(self.store.ingest(self.sid, metric(t + 110, cpu=96), now=t + 110), [])
        self.assertEqual(len(self.store.incidents(state="firing")), 1)
        restarted = Store(self.path)
        restarted.migrate()
        reminder = restarted.sweep_offline(now=t + 180)
        self.assertEqual([(event["kind"], event["state"]) for event in reminder], [("high_cpu", "firing")])
        self.assertEqual(restarted.sweep_offline(now=t + 181), [])
        bot = TelegramBot("123:ABC", restarted)
        sent = []
        bot.send_message = lambda chat, text: sent.append((chat, text))
        self.assertTrue(bot.deliver_incident_once(now=t + 180))
        recovered = restarted.ingest(self.sid, metric(t + 182), now=t + 182)
        self.assertEqual([(event["kind"], event["state"]) for event in recovered], [("high_cpu", "resolved")])
        self.assertTrue(bot.deliver_incident_once(now=t + 182))
        self.assertEqual([chat for chat, _ in sent], [123, 123])
        self.assertIn("Восстановлено", sent[1][1])
        self.assertIn("Длительность: 2 мин", sent[1][1])

    def test_recovery_after_maintenance_without_alert_stays_silent(self):
        self.configure(offline_seconds=120)
        t = self.start
        self.store.create_maintenance(self.sid, {"ends_at": t + 120, "reason": "Planned update"}, now=t)
        self.store.ingest(self.sid, metric(t + 1, cpu=96), now=t + 1)
        self.store.ingest(self.sid, metric(t + 61, cpu=96), now=t + 61)
        self.assertEqual(self.store.ingest(self.sid, metric(t + 121), now=t + 121), [])
        self.assertEqual(self.store.sweep_offline(now=t + 122), [])
        incident = self.store.incidents(state="resolved")[0]
        self.assertIsNone(incident["alerted_at"])

    def test_previously_alerted_problem_recovers_after_window_before_reminder(self):
        t = self.start
        opened = self.store.ingest(self.sid, metric(t, cpu=96), now=t)
        self.assertEqual(len(opened), 1)
        self.store.create_maintenance(self.sid, {"ends_at": t + 61, "reason": "Planned update"}, now=t + 1)
        recovered = self.store.ingest(self.sid, metric(t + 62), now=t + 62)
        self.assertEqual([(event["id"], event["state"]) for event in recovered], [(opened[0]["id"], "resolved")])
        self.assertEqual(self.store.sweep_offline(now=t + 63), [])

    def test_migration_preserves_saved_settings_and_marks_legacy_firing_incident(self):
        t = self.start
        self.store.ingest(self.sid, metric(t, cpu=96), now=t)
        self.store.save_monitoring_settings({**self.store.monitoring_settings(), "trigger_minutes": 1})
        with closing(sqlite3.connect(self.path)) as db:
            db.execute("ALTER TABLE monitoring_settings DROP COLUMN trigger_minutes")
            db.execute("ALTER TABLE incidents DROP COLUMN alerted_at")
            db.commit()
        self.store.migrate()
        self.store.migrate()
        self.assertEqual(self.store.monitoring_settings()["trigger_minutes"], 0)
        self.assertEqual(self.store.incidents(state="firing")[0]["alerted_at"], t)
        self.assertEqual(len(self.store.ingest(self.sid, metric(t + 1), now=t + 1)), 1)


if __name__ == "__main__":
    unittest.main()
