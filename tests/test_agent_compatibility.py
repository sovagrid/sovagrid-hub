# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""The original Hub proves its running bundle without an Agent side effect."""

from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from unittest import mock

from sovagrid_hub.http_api import HubApp, make_server
from sovagrid_hub.store import Store


DIGEST = "a" * 64


class AgentCompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(Path(self.temp.name) / "hub.sqlite")
        self.store.initialize("admin", "long-test-password")

    def start(self, digest):
        with mock.patch.dict(os.environ, {"SOVAGRID_BUNDLE_MANIFEST_SHA256": digest}):
            app = HubApp(self.store)
        server = make_server(app, 0)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()

        def close():
            server.shutdown()
            server.server_close()
            worker.join(timeout=2)

        self.addCleanup(close)
        return app, f"http://127.0.0.1:{server.server_port}"

    def request(self, base, method, path, *, body=None, token=None):
        headers = {}
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if token is not None:
            headers["Authorization"] = "Bearer " + token
        request = urllib.request.Request(base + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=3) as response:
                return response.status, json.load(response), response.headers.get("Location")
        except urllib.error.HTTPError as error:
            with error:
                return error.code, json.load(error), error.headers.get("Location")

    def admin_and_servers(self, base):
        status, login, _ = self.request(base, "POST", "/api/v1/session", body={
            "username": "admin", "password": "long-test-password"})
        self.assertEqual(status, 200)
        admin = login["token"]
        servers = []
        for name in ("one", "two"):
            status, created, _ = self.request(base, "POST", "/api/v1/servers", body={"name": name}, token=admin)
            self.assertEqual(status, 201)
            servers.append((created["id"], created["agent_token"]))
        return admin, servers

    def test_exact_agent_credential_reads_running_digest_without_leasing_job(self):
        app, base = self.start(DIGEST)
        admin, ((first_id, first_token), (second_id, second_token)) = self.admin_and_servers(base)
        first_path = f"/api/v1/servers/{first_id}/agent-compatibility"
        second_path = f"/api/v1/servers/{second_id}/agent-compatibility"
        expected = (200, {"protocol": 1, "bundle_manifest_sha256": DIGEST}, None)

        with mock.patch.object(self.store, "lease_job", side_effect=AssertionError("leased a job")):
            self.assertEqual(self.request(base, "GET", first_path, token=first_token), expected)
            self.assertEqual(self.request(base, "GET", second_path, token=second_token), expected)
        self.assertEqual(self.request(base, "GET", first_path, token=second_token)[0], 401)
        self.assertEqual(self.request(base, "GET", first_path, token=admin)[0], 401)
        self.assertEqual(self.request(base, "GET", first_path)[0], 401)
        self.assertEqual(self.request(base, "GET", first_path + "?debug=1", token=first_token)[0], 400)
        self.assertEqual(self.request(base, "GET", "/api/v1/servers/no-such-server/agent-compatibility",
                                      token=first_token)[0], 401)

        status, rotated, _ = self.request(base, "POST", f"/api/v1/servers/{first_id}/rotate-token",
                                          body={}, token=admin)
        self.assertEqual(status, 200)
        self.assertEqual(self.request(base, "GET", first_path, token=first_token)[0], 401)
        self.assertEqual(self.request(base, "GET", first_path, token=rotated["agent_token"]), expected)
        self.assertEqual(app.bundle_manifest_sha256, DIGEST)

    def test_missing_or_malformed_image_pin_fails_closed(self):
        for digest in ("", DIGEST.upper(), DIGEST + "\n", "0" * 63):
            with self.subTest(digest=digest):
                app, base = self.start(digest)
                _admin, ((server_id, agent_token), _) = self.admin_and_servers(base)
                self.assertIsNone(app.bundle_manifest_sha256)
                status, body, location = self.request(
                    base, "GET", f"/api/v1/servers/{server_id}/agent-compatibility", token=agent_token)
                self.assertEqual(status, 503)
                self.assertEqual(location, None)
                self.assertEqual(set(body), {"error"})


if __name__ == "__main__":
    unittest.main()
