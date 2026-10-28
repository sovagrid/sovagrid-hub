# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Hub accepts bounded read-only clock diagnostics without trusting stale time."""

from __future__ import annotations

import unittest
import tempfile
from pathlib import Path

from sovagrid_hub.store import InvalidMetric, Store, validate_metric


NOW = 1_800_000_000


def sample(*, collected_at=NOW, clock=None):
    return {
        "collected_at": collected_at,
        "cpu_percent": 12,
        "memory_percent": 23,
        "disk_percent": 34,
        "network_rx_bytes": 100,
        "network_tx_bytes": 200,
        "load1": 0.5,
        "uptime_seconds": 500,
        **({"details": {"clock": clock}} if clock is not None else {}),
    }


def clock(*, epoch=NOW, sync=False, rtc=None):
    return {
        "system_utc_epoch": epoch,
        "timezone": "Etc/UTC",
        "ntp_synchronized": sync,
        "rtc_local_time": False,
        "rtc_utc_epoch": rtc,
        "rtc_offset_seconds": rtc - epoch if rtc is not None else None,
    }


class ClockMetricTests(unittest.TestCase):
    def test_unsynchronized_clock_is_visible_and_rtc_offset_is_preserved(self):
        data = validate_metric(sample(clock=clock(epoch=NOW - 165, rtc=NOW),
                                      collected_at=NOW - 165), NOW)
        self.assertEqual(data["collected_at"], NOW)
        self.assertEqual(data["details"]["clock"]["rtc_offset_seconds"], 165)

    def test_skewed_unsynchronized_host_uses_hub_time_for_history(self):
        data = validate_metric(sample(clock=clock(epoch=NOW - 900, rtc=NOW),
                                      collected_at=NOW - 900), NOW)
        self.assertEqual(data["collected_at"], NOW)
        self.assertEqual(data["details"]["clock"]["system_utc_epoch"], NOW - 900)
        for payload in (sample(collected_at=NOW - 900),
                        sample(clock=clock(epoch=NOW - 900, sync=True), collected_at=NOW - 900),
                        sample(clock=clock(epoch=NOW), collected_at=NOW - 900),
                        sample(clock=clock(epoch=NOW - 90000), collected_at=NOW - 90000)):
            with self.subTest(payload=payload), self.assertRaises(InvalidMetric):
                validate_metric(payload, NOW)

    def test_malformed_clock_fields_are_rejected(self):
        good = clock(rtc=NOW + 165)
        changes = (
            {"system_utc_epoch": True},
            {"timezone": "Etc/UTC<script>"},
            {"ntp_synchronized": "no"},
            {"rtc_local_time": 0},
            {"rtc_utc_epoch": True},
            {"rtc_offset_seconds": 166},
            {"rtc_local_time": True},
            {"rtc_utc_epoch": None},
        )
        for change in changes:
            with self.subTest(change=change), self.assertRaises(InvalidMetric):
                validate_metric(sample(clock=good | change), NOW)
        with self.assertRaises(InvalidMetric):
            validate_metric(sample(clock=good | {"unexpected": "field"}), NOW)

    def test_missing_clock_and_unknown_rtc_remain_compatible(self):
        self.assertNotIn("details", validate_metric(sample(), NOW))
        data = validate_metric(sample(clock=clock()), NOW)
        self.assertIsNone(data["details"]["clock"]["rtc_utc_epoch"])

    def test_skewed_clock_survives_ingest_and_server_response(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / "hub.sqlite")
            store.initialize("admin", "long-local-test-password")
            server = store.create_server("unsynchronized-host", now=NOW)
            store.ingest(server["id"], sample(clock=clock(epoch=NOW - 900, rtc=NOW),
                                               collected_at=NOW - 900), now=NOW)
            listing = store.servers(now=NOW)
            self.assertEqual(len(listing), 1)
            self.assertEqual(listing[0]["latest"]["collected_at"], NOW)
            self.assertEqual(listing[0]["latest"]["details"]["clock"]["rtc_offset_seconds"], 900)
            self.assertTrue(listing[0]["online"])


if __name__ == "__main__":
    unittest.main()
