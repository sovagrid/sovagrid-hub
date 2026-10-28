# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Role-checked, compare-and-swap HTTP policy for optional pressure alerts."""

from __future__ import annotations

import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from sovagrid_hub.http_api import HubApp, make_server
from sovagrid_hub.store import Store


class PressureSettingsHTTP(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(Path(self.temp.name) / "hub.sqlite")
        self.store.initialize("admin", "very-long-test-password")
        self.server = make_server(HubApp(self.store), 0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def request(self, method: str, path: str, body=None, token: str | None = None):
        headers = {}
        if token:
            headers["Authorization"] = "Bearer " + token
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(self.base + path, data=data, headers=headers,
                                         method=method)
        try:
            with urllib.request.urlopen(request) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as error:
            with error:
                return error.code, json.load(error)

    def login(self, username: str) -> str:
        status, result = self.request("POST", "/api/v1/session", {
            "username": username, "password": "very-long-test-password"})
        self.assertEqual(status, 200)
        return result["token"]

    def test_pressure_policy_is_separate_from_legacy_settings_and_admin_only(self) -> None:
        path = "/api/v1/monitoring/pressure-settings"
        admin = self.login("admin")
        self.assertEqual(self.request("GET", path)[0], 401)
        self.assertEqual(self.request("POST", path, {})[0], 401)
        status, initial = self.request("GET", path, token=admin)
        self.assertEqual(status, 200)
        settings = initial["settings"]
        self.assertEqual(settings["revision"], 0)
        self.assertTrue(all(value is None for value in settings["thresholds"].values()))
        self.assertEqual(self.request("GET", "/api/v1/monitoring/settings", token=admin)
                         [1]["settings"]["revision"], 0)

        self.assertEqual(self.request("POST", "/api/v1/users", {
            "username": "viewer", "password": "very-long-test-password", "role": "viewer"}, admin)[0], 201)
        viewer = self.login("viewer")
        self.assertEqual(self.request("GET", path, token=viewer)[0], 200)
        self.assertEqual(self.request("POST", path, settings, viewer)[0], 403)
        self.assertEqual(self.request("GET", path + "?extra=1", token=admin)[0], 400)

        updated = {**settings, "thresholds": {**settings["thresholds"],
                   "high_psi_memory_full": 25.5}, "hold_seconds": 120}
        self.assertEqual(self.request("POST", path, {**updated, "hold_seconds": 0}, admin)[0], 400)
        saved_status, saved = self.request("POST", path, updated, admin)
        self.assertEqual(saved_status, 200)
        self.assertEqual(saved["settings"]["revision"], 1)
        self.assertEqual(saved["settings"]["thresholds"]["high_psi_memory_full"], 25.5)
        self.assertEqual(self.request("POST", path, updated, admin)[0], 409)
        self.assertEqual(self.request("GET", "/api/v1/monitoring/settings", token=admin)
                         [1]["settings"]["revision"], 0)


if __name__ == "__main__":
    unittest.main()
