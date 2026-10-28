# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Optional Linux pressure alerts share durable incident and Telegram rules."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sovagrid_hub.store import PRESSURE_ALERT_FIELDS, PressureSettingsConflict, Store
from sovagrid_hub.telegram import TelegramBot


def sample(at: int, *, cpu_some: float | None = None, iowait: float | None = None) -> dict:
    details = {}
    if cpu_some is not None:
        details["pressure"] = {"cpu": {"some": {"avg10": cpu_some,
            "avg60": cpu_some, "avg300": cpu_some, "total_us": 1000}}}
    if iowait is not None:
        details["cpu_times"] = {"iowait_percent": iowait, "steal_percent": 0.0}
    return {"collected_at": at, "cpu_percent": 10, "memory_percent": 20,
            "disk_percent": 30, "network_rx_bytes": 100, "network_tx_bytes": 200,
            "load1": 0.5, "uptime_seconds": 3600,
            **({"details": details} if details else {})}


class PressureAlerts(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "hub.sqlite"
        self.store = Store(self.path)
        self.store.initialize("admin", "very-long-test-password")
        self.server_id = self.store.create_server("pressure-host")["id"]
        self.now = 1_000_000

    def enable(self, **overrides) -> dict:
        current = self.store.pressure_settings()
        payload = {**current, "thresholds": {**current["thresholds"], **overrides}}
        return self.store.save_pressure_settings(payload)

    def test_opt_in_hold_restart_missing_telemetry_and_durable_recovery(self) -> None:
        self.store.add_bot_user(101, 101, "viewer")
        self.assertEqual(self.store.pressure_settings(), {
            "thresholds": {kind: None for kind in PRESSURE_ALERT_FIELDS},
            "hold_seconds": 60, "revision": 0})
        self.assertEqual(self.store.ingest(self.server_id,
                                           sample(self.now, cpu_some=80, iowait=75),
                                           now=self.now), [])
        self.assertEqual(self.store.incidents(), [])
        self.enable(high_psi_cpu_some=50, high_cpu_iowait=40)
        self.store.ingest(self.server_id, sample(self.now + 1, cpu_some=80, iowait=75),
                          now=self.now + 1)
        restarted = Store(self.path)
        restarted.migrate()
        self.assertEqual(restarted.ingest(self.server_id,
                                          sample(self.now + 31, cpu_some=80, iowait=75),
                                          now=self.now + 31), [])
        opened = restarted.ingest(self.server_id,
                                  sample(self.now + 61, cpu_some=80, iowait=75),
                                  now=self.now + 61)
        self.assertEqual({event["kind"] for event in opened},
                         {"high_psi_cpu_some", "high_cpu_iowait"})
        self.assertEqual(restarted.incident_outbox_pending_count(), 2)
        # An old Agent cannot assert recovery for optional metrics it lacks.
        self.assertEqual(restarted.ingest(self.server_id, sample(self.now + 62),
                                          now=self.now + 62), [])
        self.assertEqual(len(restarted.incidents(state="firing")), 2)
        recovered = restarted.ingest(self.server_id,
                                     sample(self.now + 63, cpu_some=4, iowait=2),
                                     now=self.now + 63)
        self.assertEqual({event["kind"] for event in recovered},
                         {"high_psi_cpu_some", "high_cpu_iowait"})
        self.assertEqual({event["state"] for event in recovered}, {"resolved"})
        self.assertEqual(restarted.incident_outbox_pending_count(), 4)
        bot = TelegramBot("123:ABC", restarted)
        messages = []
        bot.send_message = lambda chat, body: messages.append((chat, body))
        for _ in range(4):
            self.assertTrue(bot.deliver_incident_once(now=self.now + 64))
        self.assertEqual(restarted.incident_outbox_pending_count(), 0)
        self.assertTrue(any("CPU перегружен" in body for _, body in messages))
        self.assertTrue(any("Восстановлено" in body for _, body in messages))
        self.assertTrue(all(chat == 101 for chat, _ in messages))

    def test_missing_details_and_policy_edit_reset_only_pending_hold(self) -> None:
        self.enable(high_psi_cpu_some=50)
        self.store.ingest(self.server_id, sample(self.now, cpu_some=80), now=self.now)
        self.store.ingest(self.server_id, sample(self.now + 30), now=self.now + 30)
        self.assertEqual(self.store.ingest(self.server_id,
                                           sample(self.now + 60, cpu_some=80),
                                           now=self.now + 60), [])
        current = self.store.pressure_settings()
        self.store.save_pressure_settings({**current, "hold_seconds": 90})
        self.assertEqual(self.store.ingest(self.server_id,
                                           sample(self.now + 120, cpu_some=80),
                                           now=self.now + 120), [])
        firing = self.store.ingest(self.server_id, sample(self.now + 210, cpu_some=80),
                                   now=self.now + 210)
        self.assertEqual([event["kind"] for event in firing], ["high_psi_cpu_some"])
        # Disabling the rule resolves it immediately, even if the Agent is
        # offline and cannot provide another sample.
        current = self.store.pressure_settings()
        with mock.patch("sovagrid_hub.store.time.time", return_value=self.now + 211):
            self.store.save_pressure_settings({**current, "thresholds": {
                **current["thresholds"], "high_psi_cpu_some": None}})
        resolved = self.store.incidents(state="resolved")
        self.assertEqual([(event["kind"], event["resolved_at"]) for event in resolved],
                         [("high_psi_cpu_some", self.now + 211)])
        self.assertEqual(self.store.ingest(self.server_id, sample(self.now + 212),
                                           now=self.now + 212), [])

    def test_disabling_offline_rule_queues_only_owed_recovery(self) -> None:
        self.store.add_bot_user(101, 101, "viewer")
        self.enable(high_psi_cpu_some=50)
        self.store.ingest(self.server_id, sample(self.now, cpu_some=80), now=self.now)
        self.store.ingest(self.server_id, sample(self.now + 60, cpu_some=80),
                          now=self.now + 60)
        bot = TelegramBot("123:ABC", self.store)
        messages = []
        bot.send_message = lambda chat, body: messages.append(body)
        self.assertTrue(bot.deliver_incident_once(now=self.now + 60))
        current = self.store.pressure_settings()
        with mock.patch("sovagrid_hub.store.time.time", return_value=self.now + 61):
            self.store.save_pressure_settings({**current, "thresholds": {
                **current["thresholds"], "high_psi_cpu_some": None}})
        self.assertEqual(len(self.store.incidents(state="firing")), 0)
        self.assertEqual(self.store.incident_outbox_pending_count(), 1)
        self.assertTrue(bot.deliver_incident_once(now=self.now + 61))
        self.assertEqual(["Тревога" in body for body in messages], [True, False])
        self.assertIn("Восстановлено", messages[1])

        # A breach first seen during maintenance was never announced. Turning
        # off its rule must not leak a recovery to Telegram after the window.
        self.enable(high_psi_cpu_some=50)
        self.store.create_maintenance(self.server_id,
                                      {"ends_at": self.now + 300, "reason": "Service work"},
                                      now=self.now + 100)
        self.store.ingest(self.server_id, sample(self.now + 101, cpu_some=80),
                          now=self.now + 101)
        self.store.ingest(self.server_id, sample(self.now + 161, cpu_some=80),
                          now=self.now + 161)
        self.assertEqual(self.store.incident_outbox_pending_count(), 0)
        current = self.store.pressure_settings()
        with mock.patch("sovagrid_hub.store.time.time", return_value=self.now + 162):
            self.store.save_pressure_settings({**current, "thresholds": {
                **current["thresholds"], "high_psi_cpu_some": None}})
        self.assertEqual(self.store.incident_outbox_pending_count(), 0)
        self.assertNotIn("high_psi_cpu_some",
                         {event["kind"] for event in self.store.sweep_offline(now=self.now + 301)})
        with self.store.connection() as db:
            self.assertEqual(db.execute("""SELECT COUNT(*) FROM incident_outbox AS o
                           JOIN incidents AS i ON i.id=o.incident_id
                           WHERE i.kind='high_psi_cpu_some' AND o.delivered_at IS NULL
                             AND o.dropped_at IS NULL""").fetchone()[0], 0)

    def test_invalid_policy_and_stale_revision_do_not_change_state(self) -> None:
        current = self.store.pressure_settings()
        for invalid in (
            {**current, "hold_seconds": 0}, {**current, "hold_seconds": True},
            {**current, "revision": True},
            {**current, "thresholds": {**current["thresholds"], "high_cpu_steal": -1}},
            {**current, "thresholds": {**current["thresholds"], "high_cpu_steal": True}},
            {**current, "thresholds": {**current["thresholds"], "high_cpu_steal": 10**400}},
            {**current, "thresholds": {"high_cpu_steal": 10}},
            {**current, "unexpected": "secret"},
        ):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                self.store.save_pressure_settings(invalid)
        self.assertEqual(self.store.pressure_settings(), current)
        self.enable(high_psi_io_full=75)
        with self.assertRaises(PressureSettingsConflict):
            self.store.save_pressure_settings(current)
        self.assertEqual(self.store.pressure_settings()["thresholds"]["high_psi_io_full"], 75)


if __name__ == "__main__":
    unittest.main()
