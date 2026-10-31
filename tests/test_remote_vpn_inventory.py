# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
"""Agent VPN snapshots are projected before storage and scoped to one server."""

import hashlib
import json
from pathlib import Path
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

from sovagrid_hub.http_api import HubApp, make_server
from sovagrid_hub.store import Store


PASSWORD = "a-long-vpn-inventory-test-password"


def snapshot():
    name = "sample-vpn"
    return {"schema_version": 1, "collected_at": 1000, "source": "docker_cli",
            "source_status": "ok", "services": [{"name": "amnezia-awg", "state": "running",
            "health": "healthy", "published_ports": [{"port": 51820, "protocol": "udp"}],
            "private_key": "NEVER-STORE-DOCKER"}],
            "managed": {"source_status": "ok", "instances": [{
                "name": name, "interface": "sg" + hashlib.sha256(name.encode()).hexdigest()[:11],
                "port": 51821, "subnet": "10.49.0.0/24", "client_count": 1,
                "state": "active", "profile": "NEVER-STORE-PROFILE"}]},
            "peer_address": "NEVER-STORE-PEER"}


class RemoteVpnInventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.temp.name) / "hub.sqlite")
        self.store.initialize("owner", PASSWORD)
        self.a = self.store.create_server("fixture-a")
        self.b = self.store.create_server("fixture-b")
        self.app = HubApp(self.store)
        self.http = make_server(self.app, 0)
        self.thread = threading.Thread(target=self.http.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.http.server_port}"
        self.owner = self.request("POST", "/api/v1/session", data={
            "username": "owner", "password": PASSWORD})[1]["token"]
        self.viewer = self.store.create_user("viewer", PASSWORD, "viewer")
        self.viewer_token = self.request("POST", "/api/v1/session", data={
            "username": "viewer", "password": PASSWORD})[1]["token"]
        self.store.save_server_access_policy("user", (self.viewer["id"],),
            {"revision": 0, "mode": "selected", "grants": [
                {"server_id": self.a["id"], "role": "viewer"}]}, session_token=self.owner)

    def tearDown(self):
        self.http.shutdown()
        self.http.server_close()
        self.thread.join(2)
        self.temp.cleanup()

    def request(self, method, path, token=None, data=None):
        headers = {"Authorization": "Bearer " + token} if token else {}
        body = None
        if data is not None:
            headers["Content-Type"] = "application/json"
            body = json.dumps(data).encode()
        request = urllib.request.Request(self.base + path, headers=headers, data=body, method=method)
        try:
            with urllib.request.urlopen(request) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as error:
            with error:
                return error.code, json.load(error)

    def test_agent_post_viewer_get_projection_acl_and_hub_receipt_time(self):
        path = f"/api/v1/servers/{self.a['id']}/vpn"
        self.assertEqual(self.request("GET", path, self.viewer_token)[1]["freshness"], "unavailable")
        self.assertEqual(self.request("POST", path, self.viewer_token, snapshot())[0], 401)
        status, posted = self.request("POST", path, self.a["agent_token"], snapshot())
        self.assertEqual(status, 202)
        self.assertTrue(posted["accepted"])
        status, result = self.request("GET", path, self.viewer_token)
        self.assertEqual(status, 200)
        self.assertEqual(result["received_at"], posted["received_at"])
        self.assertEqual(result["freshness"], "ok")  # Agent's old clock is irrelevant.
        self.assertEqual(result["vpn"]["source_status"], "ok")
        self.assertEqual(result["vpn"]["services"][0]["service"], "AmneziaWG")
        self.assertEqual(self.request("GET", f"/api/v1/servers/{self.b['id']}/vpn",
                                      self.viewer_token)[0], 403)
        self.assertEqual(self.request("GET", path, self.a["agent_token"])[0], 401)
        with self.store.connection() as db:
            stored = db.execute("SELECT projection_json FROM vpn_inventory WHERE server_id=?",
                                (self.a["id"],)).fetchone()[0]
            self.assertEqual(db.execute("SELECT COUNT(*) FROM vpn_inventory").fetchone()[0], 1)
        self.assertNotIn("NEVER-STORE", stored)
        self.assertNotIn("NEVER-STORE", json.dumps(result))

    def test_replacement_staleness_and_invalid_snapshot(self):
        path = f"/api/v1/servers/{self.a['id']}/vpn"
        self.store.put_vpn_inventory(self.a["id"], snapshot(),
                                     agent_token=self.a["agent_token"], now=2000)
        fresh = self.store.remote_vpn_inventory(self.a["id"],
                                                session_token=self.viewer_token, now=2001)
        self.assertEqual(fresh["vpn"]["managed"]["source_status"], "ok")
        stale = self.store.remote_vpn_inventory(self.a["id"],
                                                session_token=self.viewer_token, now=2091)
        self.assertEqual(stale["freshness"], "stale")
        self.assertEqual(stale["vpn"]["managed"]["source_status"], "stale")
        replacement = snapshot()
        replacement["source_status"] = "error"
        self.store.put_vpn_inventory(self.a["id"], replacement,
                                     agent_token=self.a["agent_token"], now=2100)
        latest = self.store.remote_vpn_inventory(self.a["id"],
                                                 session_token=self.viewer_token, now=2101)
        self.assertEqual(latest["vpn"]["source_status"], "error")
        self.assertEqual(latest["vpn"]["services"], [])
        with self.store.connection() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM vpn_inventory").fetchone()[0], 1)
        invalid = snapshot()
        invalid["schema_version"] = 2
        self.assertEqual(self.request("POST", path, self.a["agent_token"], invalid)[0], 422)


if __name__ == "__main__":
    unittest.main()
