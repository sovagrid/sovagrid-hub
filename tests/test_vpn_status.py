# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Sanitized VPN API projection keeps Docker and managed sources independent."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from sovagrid_hub.vpn_status import read_vpn_status


def snapshot() -> dict:
    name = "phone-vpn"
    return {
        "schema_version": 1, "collected_at": 1000,
        "source": "docker_cli", "source_status": "ok",
        "services": [{
            "name": "amnezia-awg", "service": "untrusted label",
            "state": "running", "health": "healthy",
            "published_ports": [{"port": 51820, "protocol": "udp"}],
            "private_key": "NEVER-EXPOSE-DOCKER",
        }],
        "managed": {"source_status": "ok", "instances": [{
            "name": name,
            "interface": "sg" + hashlib.sha256(name.encode()).hexdigest()[:11],
            "port": 51821, "subnet": "10.49.0.0/24",
            "client_count": 1, "state": "active",
            "private_key": "NEVER-EXPOSE-MANAGED",
            "profile": "NEVER-EXPOSE-PROFILE",
            "peer_address": "NEVER-EXPOSE-PEER",
        }]},
        "secret": "NEVER-EXPOSE-ROOT",
    }


class VpnStatusTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "vpn.json"

    def read(self, data: dict, *, now: int = 1001) -> dict:
        self.path.write_text(json.dumps(data))
        return read_vpn_status(self.path, now=now)

    def test_fixed_schema_excludes_keys_profiles_peers_and_raw_labels(self):
        result = self.read(snapshot())
        self.assertEqual(result["source_status"], "ok")
        self.assertEqual(result["managed"]["source_status"], "ok")
        self.assertEqual(result["services"][0]["service"], "AmneziaWG")
        self.assertEqual(result["managed"]["instances"][0]["client_count"], 1)
        serialized = json.dumps(result)
        self.assertNotIn("NEVER-EXPOSE", serialized)
        self.assertNotIn("private_key", serialized)
        self.assertNotIn("profile", serialized)
        self.assertNotIn("peer_address", serialized)

    def test_bad_managed_transaction_does_not_hide_amnezia(self):
        data = snapshot()
        data["managed"]["instances"] = [{
            "name": "phone-vpn", "interface": data["managed"]["instances"][0]["interface"],
            "port": None, "subnet": None, "client_count": None, "state": "error",
        }]
        result = self.read(data)
        self.assertEqual(result["source_status"], "ok")
        self.assertEqual(result["services"][0]["state"], "running")
        self.assertEqual(result["managed"]["instances"][0]["state"], "error")
        data["managed"]["instances"][0]["name"] = "bad\ncommand"
        result = self.read(data)
        self.assertEqual(result["source_status"], "ok")
        self.assertEqual(result["managed"]["source_status"], "error")
        self.assertEqual(result["managed"]["instances"], [])

    def test_docker_failure_does_not_hide_managed_and_both_age_independently(self):
        data = snapshot()
        data["source_status"] = "error"
        result = self.read(data)
        self.assertEqual(result["source_status"], "error")
        self.assertEqual(result["managed"]["source_status"], "ok")
        self.assertEqual(result["managed"]["instances"][0]["state"], "active")
        data["source_status"] = "ok"
        result = self.read(data, now=1100)
        self.assertEqual(result["source_status"], "stale")
        self.assertEqual(result["managed"]["source_status"], "stale")

    def test_legacy_snapshot_has_managed_unavailable_and_count_is_bounded(self):
        data = snapshot()
        del data["managed"]
        self.assertEqual(self.read(data)["managed"]["source_status"], "unavailable")
        data = snapshot()
        data["managed"]["instances"][0]["client_count"] = 254
        self.assertEqual(self.read(data)["managed"]["source_status"], "error")
        self.assertEqual(self.read(data)["source_status"], "ok")


if __name__ == "__main__":
    unittest.main()
