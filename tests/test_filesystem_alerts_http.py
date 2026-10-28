# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Filesystem alert API enforces per-server roles, CAS and strict JSON."""

from __future__ import annotations

import json
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from sovagrid_hub.http_api import HubApp, make_server
from sovagrid_hub.store import Store
from tests.test_filesystem_alerts import filesystem, metric, rule


class FilesystemAlertHTTP(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(Path(self.temp.name) / "hub.sqlite")
        self.store.initialize("admin", "very-long-test-password")
        self.server_id = self.store.create_server("node")["id"]
        self.httpd = make_server(HubApp(self.store), 0)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.httpd.server_port}"

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)

    def request(self, method, path, body=None, token=None, *, origin=None, raw=False):
        headers = {}
        if token is not None:
            headers["Authorization"] = "Bearer " + token
        if origin is not None:
            headers["Origin"] = origin
        data = None
        if body is not None:
            data = body if raw else json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(self.base + path, data=data, headers=headers,
                                         method=method)
        try:
            with urllib.request.urlopen(request) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as error:
            with error:
                return error.code, json.load(error)

    def login(self, name):
        status, result = self.request("POST", "/api/v1/session", {
            "username": name, "password": "very-long-test-password"})
        self.assertEqual(status, 200)
        return result["token"]

    def test_cas_roles_origin_and_typed_inventory(self):
        path = f"/api/v1/servers/{self.server_id}/filesystems/alerts"
        self.assertEqual(self.request("GET", path)[0], 401)
        admin = self.login("admin")
        status, empty = self.request("GET", path, token=admin)
        self.assertEqual(status, 200)
        self.assertEqual(empty["server_id"], self.server_id)
        self.assertEqual(empty["rules"], [])
        self.assertEqual(empty["source_status"], "unavailable")
        self.assertEqual(self.request("GET", path + "?x=1", token=admin)[0], 400)
        now = int(time.time())
        self.store.ingest(self.server_id, metric(now, [filesystem()]), now=now)
        body = {"revision": 0, "hold_seconds": 60, "rules": [rule()]}
        self.assertEqual(self.request("PUT", path + "?x=1", body, admin)[0], 400)
        self.assertEqual(self.request("PUT", path, body, admin,
                                      origin="https://another.example")[0], 403)
        self.assertEqual(self.request("PUT", path,
                                      b'{"revision":0,"revision":0,"hold_seconds":60,"rules":[]}',
                                      admin, raw=True)[0], 400)
        status, saved = self.request("PUT", path, body, admin)
        self.assertEqual(status, 200)
        self.assertEqual(saved["revision"], 1)
        self.assertEqual(saved["observations"], [{"mountpoint": "/var/data", "metric": "space",
                                                   "status": "normal", "used_percent": 30.0}])
        self.assertEqual(self.request("PUT", path, body, admin)[0], 409)
        self.assertEqual(self.request("PUT", path, {**body, "revision": 1,
                                      "rules": [rule("/missing")]}, admin)[0], 409)
        self.assertEqual(self.request("POST", "/api/v1/users", {
            "username": "viewer", "password": "very-long-test-password",
            "role": "viewer"}, admin)[0], 201)
        viewer = self.login("viewer")
        self.assertEqual(self.request("GET", path, token=viewer)[0], 200)
        self.assertEqual(self.request("PUT", path, {**body, "revision": 1}, viewer)[0], 403)
        scoped = self.store.create_user("scoped", "very-long-test-password", "admin")
        scoped_token = self.login("scoped")
        self.store.save_server_access_policy("user", (scoped["id"],), {
            "revision": 0, "mode": "selected", "grants": []}, session_token=admin)
        self.assertEqual(self.request("GET", path, token=scoped_token)[0], 403)
        self.assertEqual(self.request("PUT", path, {**body, "revision": 1}, scoped_token)[0], 403)


if __name__ == "__main__":
    unittest.main()
