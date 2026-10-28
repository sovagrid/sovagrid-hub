# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Opt-in root inode incidents from verified filesystem counters."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sovagrid_hub.store import InodeSettingsConflict, Store
from sovagrid_hub.telegram import TelegramBot


def sample(at: int, *, total: int | None = None, available: int = 0,
           reported: float | None = None, root: bool = True) -> dict:
    details = {}
    if total is not None:
        used = round(100 * (1 - available / total), 2) if total else 0.0
        details["filesystems"] = [{
            "mountpoint": "/" if root else "/data", "fstype": "ext4",
            "total_bytes": 1_000_000, "available_bytes": 500_000,
            "used_percent": 50.0,
            "inodes_total": total, "inodes_available": available,
            "inodes_used_percent": used if reported is None else reported,
        }]
    return {"collected_at": at, "cpu_percent": 10, "memory_percent": 20,
            "disk_percent": 30, "network_rx_bytes": 100, "network_tx_bytes": 200,
            "load1": 0.5, "uptime_seconds": 3600,
            **({"details": details} if details else {})}


class RootInodeAlerts(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "hub.sqlite"
        self.store = Store(self.path)
        self.store.initialize("admin", "very-long-test-password")
        self.server_id = self.store.create_server("inode-host")["id"]
        self.now = 1_000_000

    def enable(self, threshold: float | None = 90, hold: int = 30):
        current = self.store.inode_settings()
        return self.store.save_inode_settings({
            **current, "threshold_percent": threshold, "hold_seconds": hold})

    def test_opt_in_hold_unknown_telemetry_recovery_and_outbox(self) -> None:
        self.store.add_bot_user(101, 101, "viewer")
        self.assertEqual(self.store.inode_settings(), {
            "threshold_percent": None, "hold_seconds": 60, "revision": 0})
        self.assertEqual(self.store.ingest(self.server_id,
                                           sample(self.now, total=1000, available=10),
                                           now=self.now), [])
        self.enable()
        self.assertEqual(self.store.ingest(self.server_id,
                                           sample(self.now + 1, total=1000, available=10),
                                           now=self.now + 1), [])
        restarted = Store(self.path)
        restarted.migrate()
        for offset, payload in (
            (20, sample(self.now + 20)),
            (21, sample(self.now + 21, total=0)),
            (22, sample(self.now + 22, total=1000, available=10, reported=3)),
            (23, sample(self.now + 23, total=1000, available=10, root=False)),
        ):
            self.assertEqual(restarted.ingest(self.server_id, payload,
                                               now=self.now + offset), [])
        # Unknown samples reset an unconfirmed hold; they cannot cause a
        # firing incident or claim that an existing one recovered.
        self.assertEqual(restarted.ingest(self.server_id,
                                          sample(self.now + 24, total=1000, available=10),
                                          now=self.now + 24), [])
        self.assertEqual(restarted.ingest(self.server_id,
                                          sample(self.now + 53, total=1000, available=10),
                                          now=self.now + 53), [])
        opened = restarted.ingest(self.server_id,
                                  sample(self.now + 54, total=1000, available=10),
                                  now=self.now + 54)
        self.assertEqual([(event["kind"], event["value"]) for event in opened],
                         [("high_root_inodes", 99.0)])
        self.assertEqual(restarted.incident_outbox_pending_count(), 1)
        self.assertEqual(restarted.ingest(self.server_id, sample(self.now + 55),
                                          now=self.now + 55), [])
        self.assertEqual(len(restarted.incidents(state="firing")), 1)
        recovered = restarted.ingest(self.server_id,
                                     sample(self.now + 56, total=1000, available=500),
                                     now=self.now + 56)
        self.assertEqual([(event["kind"], event["state"], event["value"])
                          for event in recovered],
                         [("high_root_inodes", "resolved", 50.0)])
        self.assertEqual(restarted.incident_outbox_pending_count(), 2)
        bot = TelegramBot("123:ABC", restarted)
        messages = []
        bot.send_message = lambda chat, body: messages.append((chat, body))
        self.assertTrue(bot.deliver_incident_once(now=self.now + 57))
        self.assertTrue(bot.deliver_incident_once(now=self.now + 57))
        self.assertEqual([chat for chat, _ in messages], [101, 101])
        self.assertIn("inode", messages[0][1])
        self.assertIn("Значение: 99.0%", messages[0][1])
        self.assertIn("Восстановлено", messages[1][1])

    def test_disable_retires_without_false_recovery_or_pending_notifications(self) -> None:
        self.store.add_bot_user(101, 101, "viewer")
        self.enable()
        self.store.ingest(self.server_id, sample(self.now, total=100, available=1),
                          now=self.now)
        self.store.ingest(self.server_id, sample(self.now + 30, total=100, available=1),
                          now=self.now + 30)
        bot = TelegramBot("123:ABC", self.store)
        delivered = []
        bot.send_message = lambda _chat, body: delivered.append(body)
        self.assertEqual(self.store.incident_outbox_pending_count(), 1)
        with mock.patch("sovagrid_hub.store.time.time", return_value=self.now + 31):
            self.enable(None)
        self.assertEqual(self.store.incidents(state="firing"), [])
        self.assertEqual(self.store.incident_outbox_pending_count(), 0)
        self.assertFalse(bot.deliver_incident_once(now=self.now + 31))
        self.assertEqual(delivered, [])

        self.enable()
        self.store.ingest(self.server_id, sample(self.now + 40, total=100, available=1),
                          now=self.now + 40)
        self.store.ingest(self.server_id, sample(self.now + 70, total=100, available=1),
                          now=self.now + 70)
        self.assertTrue(bot.deliver_incident_once(now=self.now + 70))
        with mock.patch("sovagrid_hub.store.time.time", return_value=self.now + 71):
            self.enable(None)
        self.assertEqual(self.store.incidents(state="firing"), [])
        self.assertEqual(self.store.incident_outbox_pending_count(), 0)
        self.assertFalse(bot.deliver_incident_once(now=self.now + 71))
        self.assertEqual(len(delivered), 1)
        self.assertIn("Тревога", delivered[0])

        self.enable()
        self.store.create_maintenance(self.server_id,
                                      {"ends_at": self.now + 300, "reason": "planned work"},
                                      now=self.now + 100)
        self.store.ingest(self.server_id, sample(self.now + 101, total=100, available=1),
                          now=self.now + 101)
        self.store.ingest(self.server_id, sample(self.now + 131, total=100, available=1),
                          now=self.now + 131)
        self.assertEqual(self.store.incident_outbox_pending_count(), 0)
        with mock.patch("sovagrid_hub.store.time.time", return_value=self.now + 132):
            self.enable(None)
        self.assertEqual(self.store.incident_outbox_pending_count(), 0)

    def test_threshold_and_hold_edits_retire_old_rule_without_recovery(self) -> None:
        self.store.add_bot_user(101, 101, "viewer")
        self.enable(90, 30)
        self.store.ingest(self.server_id, sample(self.now, total=100, available=1),
                          now=self.now)
        self.store.ingest(self.server_id, sample(self.now + 30, total=100, available=1),
                          now=self.now + 30)
        self.assertEqual(self.store.incident_outbox_pending_count(), 1)
        with mock.patch("sovagrid_hub.store.time.time", return_value=self.now + 31):
            self.enable(95, 30)
        self.assertEqual(self.store.incidents(state="firing"), [])
        self.assertEqual(self.store.incident_outbox_pending_count(), 0)
        self.assertEqual(self.store.ingest(self.server_id,
                                           sample(self.now + 32, total=100, available=1),
                                           now=self.now + 32), [])
        self.assertEqual(self.store.ingest(self.server_id,
                                           sample(self.now + 61, total=100, available=1),
                                           now=self.now + 61), [])
        self.assertEqual(len(self.store.ingest(
            self.server_id, sample(self.now + 62, total=100, available=1),
            now=self.now + 62)), 1)
        with mock.patch("sovagrid_hub.store.time.time", return_value=self.now + 63):
            self.enable(95, 60)
        self.assertEqual(self.store.incidents(state="firing"), [])
        self.assertEqual(self.store.incident_outbox_pending_count(), 0)
        self.assertEqual(self.store.ingest(self.server_id,
                                           sample(self.now + 64, total=100, available=1),
                                           now=self.now + 64), [])
        self.assertEqual(self.store.ingest(self.server_id,
                                           sample(self.now + 123, total=100, available=1),
                                           now=self.now + 123), [])
        opened = self.store.ingest(self.server_id,
                                   sample(self.now + 124, total=100, available=1),
                                   now=self.now + 124)
        self.assertEqual([event["kind"] for event in opened], ["high_root_inodes"])

    def test_invalid_policy_and_stale_revision(self) -> None:
        current = self.store.inode_settings()
        for payload in (
            {**current, "threshold_percent": -1},
            {**current, "threshold_percent": True},
            {**current, "threshold_percent": float("nan")},
            {**current, "threshold_percent": 10**400},
            {**current, "hold_seconds": 0},
            {**current, "hold_seconds": True},
            {**current, "revision": True},
            {**current, "unexpected": 1},
        ):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                self.store.save_inode_settings(payload)
        self.assertEqual(self.store.inode_settings(), current)
        self.enable()
        with self.assertRaises(InodeSettingsConflict):
            self.store.save_inode_settings(current)


if __name__ == "__main__":
    unittest.main()
