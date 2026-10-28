# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Opt-in container alarms require successive complete Docker evidence."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from sovagrid_hub.container_alerts import (ContainerAlertConflict,
                                           ContainerAlertInventoryUnavailable,
                                           evidence, kind, validate_settings)
from sovagrid_hub.store import Store
from sovagrid_hub.telegram import TelegramBot


NOW = 1_800_000_000
IDENT = "a" * 64


def snapshot(at: int, *, state: str = "running", health: str | None = "healthy",
             present: bool = True, truncated: bool = False, available: bool = True) -> dict:
    items = ([{"id": IDENT, "name": "api-service", "image": "example/api:1",
               "state": state, "health": health, "restarts": 0,
               "cpu_percent": None, "memory_bytes": None}] if present else [])
    return {"version": 1, "collected_at": at, "engines": [
        {"engine": "docker", "source_status": "ok" if available else "unavailable",
         "reason": None if available else "no_socket", "truncated": truncated if available else False,
         "containers": items if available else []},
        {"engine": "podman", "source_status": "unavailable", "reason": "no_socket",
         "truncated": False, "containers": []},
    ]}


def metric(at: int, inventory: dict | None) -> dict:
    details = {"containers": inventory} if inventory is not None else {}
    return {"collected_at": at, "cpu_percent": 10, "memory_percent": 20,
            "disk_percent": 30, "network_rx_bytes": 1, "network_tx_bytes": 2,
            "load1": 0.5, "uptime_seconds": 100, "details": details}


def rule(*, stopped=True, unhealthy=True, missing=True) -> dict:
    return {"name": "api-service", "stopped": stopped,
            "unhealthy": unhealthy, "missing": missing}


class ContainerAlertTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(Path(self.temp.name) / "hub.sqlite")
        self.store.initialize("admin", "very-long-test-password")
        self.server = self.store.create_server("node", now=NOW)["id"]

    def report(self, at: int, inventory: dict | None) -> list[dict]:
        return self.store.ingest(self.server, metric(at, inventory), now=at)

    def save(self, revision: int, *, hold=60, rules=None, now=NOW) -> dict:
        return self.store.save_container_alert_settings(self.server, {
            "revision": revision, "hold_seconds": hold,
            "rules": [rule()] if rules is None else rules}, now=now)

    def test_default_is_off_and_rule_requires_current_complete_inventory(self) -> None:
        self.assertEqual(self.store.container_alert_settings(self.server, now=NOW), {
            "revision": 0, "hold_seconds": 120, "rules": [], "source_status": "unavailable",
            "observed_at": None, "observations": []})
        with self.assertRaises(ContainerAlertInventoryUnavailable):
            self.save(0)
        self.report(NOW, snapshot(NOW, truncated=True))
        with self.assertRaises(ContainerAlertInventoryUnavailable):
            self.save(0)
        self.report(NOW + 1, snapshot(NOW + 1))
        saved = self.save(0, now=NOW + 1)
        self.assertEqual(saved["revision"], 1)
        self.assertEqual(saved["source_status"], "ok")
        self.assertEqual(saved["observations"], [{"name": "api-service", "status": "running"}])
        with self.assertRaises(ContainerAlertConflict):
            self.save(0, now=NOW + 1)
        self.assertEqual(self.store.container_alert_settings(self.server, now=NOW + 200)
                         ["source_status"], "stale")

    def test_hold_needs_new_fresh_snapshot_and_unknown_never_recovers(self) -> None:
        self.report(NOW, snapshot(NOW))
        self.save(0, now=NOW)
        self.assertEqual(self.report(NOW + 1, snapshot(NOW + 1, state="exited")), [])
        # Replaying one old collector snapshot in a later Agent metric cannot
        # complete the hold even though the Hub receipt time advances.
        self.assertEqual(self.report(NOW + 62, snapshot(NOW + 1, state="exited")), [])
        self.assertEqual(self.store.incidents(state="firing"), [])
        events = self.report(NOW + 63, snapshot(NOW + 63, state="exited"))
        self.assertEqual([(event["kind"], event["state"]) for event in events],
                         [(kind("api-service"), "firing")])
        self.assertEqual(self.report(NOW + 64, snapshot(NOW + 64, truncated=True)), [])
        self.assertEqual(self.report(NOW + 65, None), [])
        self.assertEqual(self.report(NOW + 66, snapshot(NOW + 66, state="unknown")), [])
        self.assertEqual(len(self.store.incidents(state="firing")), 1)
        recovered = self.report(NOW + 67, snapshot(NOW + 67, state="running", health="starting"))
        self.assertEqual([(event["kind"], event["state"]) for event in recovered],
                         [(kind("api-service"), "resolved")])

    def test_missing_only_from_complete_inventory_and_recreation_uses_name(self) -> None:
        self.report(NOW, snapshot(NOW))
        self.save(0, hold=0, now=NOW)
        self.assertEqual(self.report(NOW + 1, snapshot(NOW + 1, present=False, truncated=True)), [])
        self.assertEqual(self.report(NOW + 2, snapshot(NOW + 2, available=False)), [])
        events = self.report(NOW + 3, snapshot(NOW + 3, present=False))
        self.assertEqual(events[0]["kind"], kind("api-service"))
        restored = snapshot(NOW + 4)
        restored["engines"][0]["containers"][0]["id"] = "b" * 64
        self.assertEqual(self.report(NOW + 4, restored)[0]["state"], "resolved")

    def test_admin_policy_change_retires_without_false_recovery_or_name_in_telegram(self) -> None:
        self.report(NOW, snapshot(NOW))
        self.save(0, hold=0, now=NOW)
        events = self.report(NOW + 1, snapshot(NOW + 1, state="exited"))
        self.assertEqual(len(events), 1)
        current = self.store.incidents(state="firing")[0]
        self.assertEqual(current["subject"], "api-service")
        notification = TelegramBot._incident_message({
            "kind": current["kind"], "event_type": "firing", "server_name": "node",
            "event_at": NOW + 1, "opened_at": NOW + 1, "value": None})
        self.assertIn("Docker-контейнером #", notification)
        self.assertNotIn("api-service", notification)
        self.save(1, hold=0, rules=[], now=NOW + 2)
        self.assertEqual(self.store.incidents(state="firing"), [])
        with self.store.connection() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM incident_outbox WHERE event_type='recovery'")
                             .fetchone()[0], 0)

    def test_existing_rule_can_be_removed_when_collector_is_unavailable(self) -> None:
        self.report(NOW, snapshot(NOW))
        self.save(0, now=NOW)
        self.report(NOW + 1, snapshot(NOW + 1, available=False))
        removed = self.save(1, rules=[], now=NOW + 1)
        self.assertEqual(removed["rules"], [])
        self.assertEqual(removed["source_status"], "unavailable")
        self.store.migrate()
        self.assertEqual(self.store.container_alert_settings(self.server, now=NOW + 1)
                         ["revision"], 2)

    def test_maintenance_defers_container_alert_into_durable_outbox(self) -> None:
        self.store.add_bot_user(41, 41, "viewer")
        self.report(NOW, snapshot(NOW))
        self.save(0, hold=0, now=NOW)
        window = self.store.create_maintenance(self.server, {
            "ends_at": NOW + 120, "reason": "planned deploy"}, now=NOW)
        self.assertEqual(self.report(NOW + 1, snapshot(NOW + 1, health="unhealthy")), [])
        self.assertEqual(self.store.incidents(state="firing")[0]["kind"], kind("api-service"))
        with self.store.connection() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM maintenance_deferred").fetchone()[0], 1)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM incident_outbox").fetchone()[0], 0)
        _, reminders = self.store.cancel_maintenance(self.server, window["id"], now=NOW + 2)
        self.assertEqual([(event["kind"], event["state"]) for event in reminders],
                         [(kind("api-service"), "firing")])
        with self.store.connection() as db:
            self.assertEqual(db.execute("SELECT event_type FROM incident_outbox").fetchone()[0],
                             "reminder")

    def test_invalid_rules_and_typed_evidence(self) -> None:
        valid = {"revision": 0, "hold_seconds": 0, "rules": [rule()]}
        for bad in (valid | {"hold_seconds": True}, valid | {"rules": [rule(), rule()]},
                    valid | {"rules": [rule(stopped=False, unhealthy=False, missing=False)]},
                    valid | {"rules": [rule() | {"name": "bad/name"}]},
                    valid | {"rules": [rule() | {"secret": "x"}]}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                validate_settings(bad)
        self.assertEqual(evidence(snapshot(NOW, health=None), metric_collected_at=NOW,
                                  received_at=NOW, now=NOW)
                         ["states"]["api-service"], "running")
        self.assertEqual(evidence(snapshot(NOW, health="starting"), metric_collected_at=NOW,
                                  received_at=NOW, now=NOW)
                         ["states"]["api-service"], "running")
        self.assertEqual(evidence(snapshot(NOW, health="unhealthy"), metric_collected_at=NOW,
                                  received_at=NOW, now=NOW)
                         ["states"]["api-service"], "unhealthy")

    def test_agent_and_hub_clock_skew_does_not_stale_fresh_inventory(self) -> None:
        # Agent is 165 seconds ahead. Both Agent timestamps agree within five
        # seconds, while Hub receipt is current on Hub's separate clock.
        self.store.ingest(self.server, metric(NOW + 165, snapshot(NOW + 160)), now=NOW)
        view = self.store.container_alert_settings(self.server, now=NOW)
        self.assertEqual(view["source_status"], "ok")
        self.save(0, now=NOW)
        self.assertEqual(self.store.container_alert_settings(self.server, now=NOW)
                         ["observations"], [{"name": "api-service", "status": "running"}])
        self.assertEqual(evidence(snapshot(NOW + 166), metric_collected_at=NOW + 165,
                                  received_at=NOW, now=NOW)["source_status"], "stale")


if __name__ == "__main__":
    unittest.main()
