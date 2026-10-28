# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""The public Amnezia schema must never forward Docker/config secrets."""

import unittest

from sovagrid_hub.amnezia_status import project_amnezia_details


class AmneziaProjectionTests(unittest.TestCase):
    def setUp(self):
        self.source = {"amnezia_details": {"schema_version": 1, "collected_at": 1000,
            "source_status": "ok", "services": [
                {"name": "amnezia-awg2", "status": "ready", "configured_clients": 2,
                 "runtime_clients": 2, "awg3_fields": True, "active_last_3m": 1,
                 "latest_handshake_at": 999, "received_bytes": 123, "sent_bytes": 456},
                {"name": "amnezia-wireguard", "status": "interface_down",
                 "configured_clients": 1, "runtime_clients": 0, "awg3_fields": False},
                {"name": "amnezia-xray", "status": "ready", "configured_clients": 1,
                 "runtime_clients": None, "api_enabled": False, "stats_enabled": False},
            ]}}

    def test_valid_fixed_schema_and_staleness(self):
        result = project_amnezia_details(self.source, 1000, 1000)
        self.assertEqual(result["source_status"], "ok")
        self.assertEqual([row["name"] for row in result["services"]],
                         ["amnezia-awg2", "amnezia-wireguard", "amnezia-xray"])
        self.assertEqual(project_amnezia_details(self.source, 1000, 1200)["source_status"], "stale")

    def test_secret_or_invalid_fields_fail_only_this_source(self):
        self.source["amnezia_details"]["services"][0]["private_key"] = "must never publish"
        self.assertEqual(project_amnezia_details(self.source, 1000, 1000),
                         {"schema_version": 1, "source_status": "error", "services": []})
        self.source["amnezia_details"]["services"][0].pop("private_key")
        self.source["amnezia_details"]["services"][1]["runtime_clients"] = True
        self.assertEqual(project_amnezia_details(self.source, 1000, 1000)["source_status"], "error")


if __name__ == "__main__":
    unittest.main()
