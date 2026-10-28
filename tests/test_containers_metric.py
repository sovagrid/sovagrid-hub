# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Hub accepts only sanitized transient container diagnostics."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from sovagrid_hub.store import InvalidMetric, Store, validate_metric

NOW = 1_800_000_000
IDENT = "a" * 64


def snapshot():
    return {"version": 1, "collected_at": NOW, "engines": [
        {"engine": "docker", "source_status": "ok", "reason": None, "truncated": False, "containers": [
            {"id": IDENT, "name": "api", "image": "registry.example/api:1", "state": "running",
             "health": "healthy", "restarts": 2, "cpu_percent": 1.5, "memory_bytes": 2048}]},
        {"engine": "podman", "source_status": "unavailable", "reason": "no_socket", "truncated": False, "containers": []},
    ]}


def metric(containers):
    return {"collected_at": NOW, "cpu_percent": 10, "memory_percent": 20, "disk_percent": 30,
            "network_rx_bytes": 1, "network_tx_bytes": 2, "load1": 0.5,
            "uptime_seconds": 3600, "details": {"containers": containers}}


class ContainerMetricTests(unittest.TestCase):
    def test_sanitized_inventory_is_visible_but_not_stored_in_history(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / "hub.sqlite")
            store.initialize("admin", "long-local-test-password")
            server = store.create_server("test", now=NOW)
            store.ingest(server["id"], metric(snapshot()), now=NOW)
            latest = store.servers(now=NOW)[0]["latest"]
            self.assertEqual(latest["details"]["containers"], snapshot())
            with store.connection() as db:
                persisted = db.execute("SELECT details_json FROM metrics LIMIT 1").fetchone()[0]
            self.assertNotIn("containers", json.loads(persisted))
            self.assertNotIn("registry.example", persisted)
            # The next report without inventory clears the transient cache.
            store.ingest(server["id"], metric(snapshot() | {"engines": [
                {"engine": "docker", "source_status": "unavailable", "reason": "no_socket", "truncated": False, "containers": []},
                snapshot()["engines"][1]]}), now=NOW + 1)
            self.assertEqual(store.servers(now=NOW + 1)[0]["latest"]["details"]["containers"]["engines"][0]["source_status"], "unavailable")

    def test_unknown_engine_fields_and_unbounded_values_are_rejected(self):
        good = snapshot()
        self.assertEqual(validate_metric(metric(good), NOW)["details"]["containers"], good)
        # Host and Hub may disagree on UTC by more than five minutes. That
        # must not suppress otherwise valid CPU/RAM/disk telemetry.
        self.assertEqual(validate_metric(metric(good | {"collected_at": NOW + 600}), NOW)["cpu_percent"], 10.0)
        cases = [
            good | {"secret": "DO_NOT_LEAK"},
            good | {"collected_at": 253402300800},
            good | {"engines": good["engines"][:1]},
            good | {"engines": [good["engines"][1], good["engines"][0]]},
        ]
        for case in cases:
            with self.subTest(case=case), self.assertRaises(InvalidMetric):
                validate_metric(metric(case), NOW)
        item = good["engines"][0]["containers"][0]
        for change in ({"env": "SECRET=x"}, {"name": "bad\nname"}, {"cpu_percent": float("nan")},
                       {"memory_bytes": True}, {"id": "x" * 64}, {"health": {"Status": "healthy"}}):
            changed = snapshot()
            changed["engines"][0]["containers"][0] = item | change
            with self.subTest(change=change), self.assertRaises(InvalidMetric):
                validate_metric(metric(changed), NOW)


if __name__ == "__main__":
    unittest.main()
