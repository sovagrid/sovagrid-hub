# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Fixed-cardinality PSI and CPU-wait metric contract."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from sovagrid_hub.store import InvalidMetric, Store, validate_metric


NOW = 1_800_000_000
WINDOW = {"avg10": 1.5, "avg60": 1.0, "avg300": 0.5, "total_us": 12345}


def sample(details=None):
    return {"collected_at": NOW, "cpu_percent": 10, "memory_percent": 20,
            "disk_percent": 30, "network_rx_bytes": 100, "network_tx_bytes": 200,
            "load1": 0.5, "uptime_seconds": 3600,
            **({"details": details} if details is not None else {})}


def valid_details():
    return {"cpu_times": {"iowait_percent": 3.5, "steal_percent": 1.25},
            "pressure": {"cpu": {"some": dict(WINDOW)},
                         "memory": {"some": dict(WINDOW), "full": dict(WINDOW)},
                         "io": {"some": dict(WINDOW), "full": dict(WINDOW)}}}


class PressureMetricTests(unittest.TestCase):
    def test_persisted_history_preserves_new_details_and_legacy_rows(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / "hub.sqlite")
            store.initialize("admin", "long-local-test-password")
            sid = store.create_server("test", now=NOW)["id"]
            store.ingest(sid, sample(), now=NOW)
            store.ingest(sid, sample(valid_details()), now=NOW + 1)
            history = store.history(sid)
            self.assertEqual(len(history), 2)
            self.assertEqual(history[0]["details"], {})
            self.assertEqual(history[1]["details"], valid_details())
            self.assertEqual(store.servers(now=NOW + 1)[0]["latest"]["details"], valid_details())
            with store.connection() as db:
                rows = db.execute("SELECT details_json FROM metrics ORDER BY id").fetchall()
            self.assertEqual(json.loads(rows[0][0]), {})
            self.assertEqual(json.loads(rows[1][0]), valid_details())

    def test_invalid_shapes_percentages_and_private_fields_are_rejected(self):
        good = valid_details()
        self.assertEqual(validate_metric(sample(good), NOW)["details"], good)
        bad = [
            {"pressure": {}},
            {"pressure": {"cpu": {"full": dict(WINDOW)}}},
            {"pressure": {"unknown": {"some": dict(WINDOW)}}},
            {"pressure": {"cpu": {"some": dict(WINDOW, avg10=101)}}},
            {"pressure": {"cpu": {"some": dict(WINDOW, avg10=float("nan"))}}},
            {"pressure": {"cpu": {"some": dict(WINDOW, total_us=-1)}}},
            {"pressure": {"cpu": {"some": dict(WINDOW, total_us=2**63)}}},
            {"pressure": {"cpu": {"some": dict(WINDOW, avg10=10**400)}}},
            {"pressure": {"cpu": {"some": dict(WINDOW, total_us=1.0)}}},
            {"pressure": {"cpu": {"some": dict(WINDOW, private_key="secret")}}},
            {"cpu_times": {"iowait_percent": True, "steal_percent": 0}},
            {"cpu_times": {"iowait_percent": 2, "steal_percent": -1}},
            {"cpu_times": {"iowait_percent": 2, "steal_percent": 0, "host": "secret"}},
        ]
        for detail in bad:
            with self.subTest(detail=detail), self.assertRaises(InvalidMetric):
                validate_metric(sample(detail), NOW)


if __name__ == "__main__":
    unittest.main()
