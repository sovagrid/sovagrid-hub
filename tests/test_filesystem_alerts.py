# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Per-mountpoint alarms require new, credible telemetry for every transition."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from sovagrid_hub.filesystem_alerts import (FilesystemAlertConflict,
                                            FilesystemAlertInventoryUnavailable,
                                            evidence, kind, validate_settings)
from sovagrid_hub.store import InvalidMetric, Store
from sovagrid_hub.telegram import TelegramBot


NOW = 1_800_000_000


def filesystem(path="/var/data", *, space=30, inodes=40):
    return {"mountpoint": path, "fstype": "ext4",
            "total_bytes": 1000, "available_bytes": 10 * (100 - space),
            "used_percent": float(space), "inodes_total": 100,
            "inodes_available": 100 - inodes,
            "inodes_used_percent": float(inodes)}


def metric(at, rows=None, *, truncated=None):
    details = {}
    if rows is not None:
        details["filesystems"] = rows
    if truncated is not None:
        details["filesystems_truncated"] = truncated
    return {"collected_at": at, "cpu_percent": 10, "memory_percent": 20,
            "disk_percent": 30, "network_rx_bytes": 1, "network_tx_bytes": 2,
            "load1": 0.5, "uptime_seconds": 100, "details": details}


def rule(path="/var/data", metric_name="space", threshold=80):
    return {"mountpoint": path, "metric": metric_name,
            "threshold_percent": threshold}


class FilesystemAlertTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(Path(self.temp.name) / "hub.sqlite")
        self.store.initialize("admin", "very-long-test-password")
        self.server = self.store.create_server("node", now=NOW)["id"]

    def report(self, at, rows=None, *, truncated=None, received=None):
        return self.store.ingest(self.server, metric(at, rows, truncated=truncated),
                                 now=at if received is None else received)

    def save(self, revision, *, rules=None, hold=60, now=NOW):
        return self.store.save_filesystem_alert_settings(self.server, {
            "revision": revision, "hold_seconds": hold,
            "rules": [rule()] if rules is None else rules}, now=now)

    def test_default_off_requires_present_fresh_measurement_and_cas(self):
        self.assertEqual(self.store.filesystem_alert_settings(self.server, now=NOW), {
            "server_id": self.server, "revision": 0, "hold_seconds": 120, "rules": [],
            "source_status": "unavailable", "observed_at": None,
            "filesystems": [], "observations": []})
        with self.assertRaises(FilesystemAlertInventoryUnavailable):
            self.save(0)
        self.report(NOW, [filesystem()], truncated=True)
        with self.assertRaises(FilesystemAlertInventoryUnavailable):
            self.save(0)
        self.report(NOW + 1, [filesystem()], truncated=False)
        saved = self.save(0, now=NOW + 1)
        self.assertEqual(saved["revision"], 1)
        self.assertEqual(saved["source_status"], "ok")
        self.assertEqual(saved["filesystems"][0]["space_used_percent"], 30.0)
        self.assertEqual(saved["observations"], [{"mountpoint": "/var/data", "metric": "space",
                                                   "status": "normal", "used_percent": 30.0}])
        with self.assertRaises(FilesystemAlertConflict):
            self.save(0, now=NOW + 1)
        self.assertEqual(self.store.filesystem_alert_settings(self.server, now=NOW + 200)
                         ["source_status"], "stale")

    def test_hold_duplicate_clipped_and_missing_never_falsely_recover(self):
        self.report(NOW, [filesystem()])
        self.save(0, now=NOW)
        self.assertEqual(self.report(NOW + 1, [filesystem(space=90)]), [])
        # A second receipt of the same Agent timestamp cannot complete hold.
        self.assertEqual(self.report(NOW + 1, [filesystem(space=90)], received=NOW + 62), [])
        self.assertEqual(self.store.incidents(state="firing"), [])
        events = self.report(NOW + 63, [filesystem(space=90)])
        self.assertEqual([(e["kind"], e["state"]) for e in events],
                         [(kind("/var/data", "space"), "firing")])
        self.assertEqual(self.report(NOW + 64, [], truncated=True), [])
        self.assertEqual(self.report(NOW + 65, None), [])
        self.assertEqual(len(self.store.incidents(state="firing")), 1)
        self.assertEqual(self.report(NOW + 66, [filesystem(space=30)], truncated=True)[0]["state"],
                         "resolved")

    def test_clipped_list_can_measure_present_rule_but_missing_rule_is_unknown(self):
        self.report(NOW, [filesystem()])
        self.save(0, hold=0, now=NOW)
        # A 16-row old Agent list has unknown overall coverage, even without
        # the newer explicit truncation flag. Present measured rows remain safe.
        rows = [filesystem()] + [filesystem(f"/mnt/disk-{i}") for i in range(15)]
        self.report(NOW + 1, rows)
        view = self.store.filesystem_alert_settings(self.server, now=NOW + 1)
        self.assertEqual(view["source_status"], "partial")
        self.assertEqual(view["filesystems"], [])
        self.assertEqual(view["observations"][0]["status"], "normal")
        with self.assertRaises(FilesystemAlertInventoryUnavailable):
            self.save(1, rules=[rule(), rule("/mnt/disk-0")], now=NOW + 1)
        self.assertEqual(self.report(NOW + 2, [filesystem(space=90)], truncated=True)[0]["state"],
                         "firing")
        self.assertEqual(self.report(NOW + 3, [], truncated=True), [])
        self.assertEqual(len(self.store.incidents(state="firing")), 1)

    def test_policy_removal_retires_without_telegram_recovery_or_mountpoint_leak(self):
        self.report(NOW, [filesystem()])
        self.save(0, hold=0, now=NOW)
        self.report(NOW + 1, [filesystem(space=90)])
        incident = self.store.incidents(state="firing")[0]
        self.assertEqual(incident["subject"], "/var/data")
        notice = TelegramBot._incident_message({
            "kind": incident["kind"], "event_type": "firing", "server_name": "node",
            "event_at": NOW + 1, "opened_at": NOW + 1, "value": 90.0})
        self.assertIn("файловой системе #", notice)
        self.assertNotIn("/var/data", notice)
        self.save(1, rules=[], hold=0, now=NOW + 2)
        self.assertEqual(self.store.incidents(state="firing"), [])
        with self.store.connection() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM incident_outbox WHERE event_type='recovery'")
                             .fetchone()[0], 0)

    def test_inodes_and_clock_skew(self):
        self.report(NOW + 165, [filesystem()], received=NOW)
        self.assertEqual(self.store.filesystem_alert_settings(self.server, now=NOW)
                         ["source_status"], "ok")
        self.save(0, rules=[rule(metric_name="inodes", threshold=70)], hold=0, now=NOW)
        events = self.report(NOW + 166, [filesystem(inodes=90)], received=NOW + 1)
        self.assertEqual(events[0]["kind"], kind("/var/data", "inodes"))
        self.assertEqual(events[0]["value"], 90.0)

    def test_threshold_edit_restarts_hold_and_survives_store_reopen(self):
        self.report(NOW, [filesystem()])
        self.save(0, hold=60, now=NOW)
        self.assertEqual(self.report(NOW + 1, [filesystem(space=90)]), [])
        self.save(1, rules=[rule(threshold=85)], hold=60, now=NOW + 30)
        reopened = Store(Path(self.temp.name) / "hub.sqlite")
        reopened.migrate()
        self.store = reopened
        self.assertEqual(self.store.filesystem_alert_settings(self.server, now=NOW + 30)
                         ["rules"], [rule(threshold=85)])
        self.assertEqual(self.report(NOW + 31, [filesystem(space=90)]), [])
        self.assertEqual(self.report(NOW + 62, [filesystem(space=90)]), [])
        fired = self.report(NOW + 92, [filesystem(space=90)])
        self.assertEqual(len(fired), 1)
        self.assertEqual(fired[0]["opened_at"], NOW + 31)

    def test_older_metric_cannot_replace_latest_observation(self):
        self.report(NOW + 2, [filesystem(space=90)])
        self.report(NOW + 1, [filesystem(space=10)], received=NOW + 3)
        view = self.store.filesystem_alert_settings(self.server, now=NOW + 3)
        self.assertEqual(view["filesystems"][0]["space_used_percent"], 90.0)

    def test_maintenance_and_outbox_are_durable(self):
        self.store.add_bot_user(41, 41, "viewer")
        self.report(NOW, [filesystem()])
        self.save(0, hold=0, now=NOW)
        window = self.store.create_maintenance(self.server, {
            "ends_at": NOW + 120, "reason": "planned deploy"}, now=NOW)
        self.assertEqual(self.report(NOW + 1, [filesystem(space=90)]), [])
        with self.store.connection() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM maintenance_deferred").fetchone()[0], 1)
        _, reminders = self.store.cancel_maintenance(self.server, window["id"], now=NOW + 2)
        self.assertEqual(reminders[0]["kind"], kind("/var/data", "space"))
        self.store.migrate()
        with self.store.connection() as db:
            self.assertEqual(db.execute("SELECT event_type FROM incident_outbox").fetchone()[0], "reminder")

    def test_validation_and_contradictory_counters(self):
        valid = {"revision": 0, "hold_seconds": 0, "rules": [rule()]}
        for bad in (valid | {"hold_seconds": True}, valid | {"rules": [rule(), rule()]},
                    valid | {"rules": [rule(threshold=0)]},
                    valid | {"rules": [rule("/a/../b")]},
                    valid | {"rules": [rule("//server/share")]},
                    valid | {"rules": [rule() | {"secret": "x"}]}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                validate_settings(bad)
        self.assertEqual(evidence({"filesystems": [filesystem(space=90)]}, observed_at=NOW,
                                  received_at=NOW, now=NOW)["source_status"], "ok")
        bad_row = filesystem(); bad_row["used_percent"] = 10.0
        self.report(NOW, [bad_row])
        self.assertEqual(self.store.filesystem_alert_settings(self.server, now=NOW)
                         ["source_status"], "partial")
        with self.assertRaises(InvalidMetric):
            self.report(NOW + 1, [filesystem()], truncated="yes")


if __name__ == "__main__":
    unittest.main()
