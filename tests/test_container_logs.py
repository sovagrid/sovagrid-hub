# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Admin-only, bounded and transient managed-container log job contract."""

from __future__ import annotations

import json
import sqlite3
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from types import SimpleNamespace

from sovagrid_hub.container_log_actions import build_command
from sovagrid_hub.http_api import HubApp, make_server
from sovagrid_hub.store import Store


IDENT = "a" * 64


def metric(*, ident=IDENT, truncated=False, include=True):
    now = int(time.time())
    snapshot = {"version": 1, "collected_at": now, "engines": [
        {"engine": "docker", "source_status": "ok", "reason": None,
         "truncated": truncated, "containers": [{
             "id": ident, "name": "sovagrid-hub-1", "image": "sovagrid-hub:local",
             "state": "running", "health": "healthy", "restarts": 0,
             "cpu_percent": 1.0, "memory_bytes": 1024,
         }]},
        {"engine": "podman", "source_status": "unavailable", "reason": "no_socket",
         "truncated": False, "containers": []},
    ]}
    return {"collected_at": now, "cpu_percent": 1, "memory_percent": 2,
            "disk_percent": 3, "network_rx_bytes": 4, "network_tx_bytes": 5,
            "load1": 0.1, "uptime_seconds": 60,
            "details": {"containers": snapshot} if include else {}}


class ContainerLogHTTPTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.temp.name) / "hub.sqlite")
        self.store.initialize("admin", "long-container-test-password")
        self.notified = []
        telegram = SimpleNamespace(enqueue_job_result=lambda job: self.notified.append(job))
        self.server = make_server(HubApp(self.store, telegram), 0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"
        self.admin = self.login("admin")
        created = self.store.create_server("container-host")
        self.sid, self.agent = created["id"], created["agent_token"]
        self.store.set_remote_commands(self.sid, True)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)
        self.temp.cleanup()

    def request(self, method, path, body=None, token=None, key=None):
        headers = {}
        data = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body).encode()
        if token is not None:
            headers["Authorization"] = "Bearer " + token
        if key is not None:
            headers["Idempotency-Key"] = key
        request = urllib.request.Request(self.base + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as error:
            with error:
                return error.code, json.load(error)

    def login(self, username):
        status, result = self.request("POST", "/api/v1/session",
                                      {"username": username, "password": "long-container-test-password"})
        self.assertEqual(status, 200)
        return result["token"]

    def test_admin_exact_inventory_and_transient_result(self):
        route = f"/api/v1/servers/{self.sid}/containers/logs"
        body = {"engine": "docker", "id": IDENT, "lines": 20}
        command = build_command(body)
        key = str(uuid.uuid4())
        self.assertEqual(self.request("POST", f"/api/v1/servers/{self.sid}/jobs",
                                      {"command": command}, self.admin)[0], 400)
        self.assertEqual(self.request("POST", route, body, self.admin, key)[0], 403)
        self.store.ingest(self.sid, metric())
        self.store.create_user("viewer", "long-container-test-password", "viewer")
        viewer = self.login("viewer")
        self.assertEqual(self.request("POST", route, body, viewer, key)[0], 403)
        self.assertEqual(self.request("POST", route, {**body, "id": "b" * 64}, self.admin, key)[0], 403)
        self.assertEqual(self.request("POST", route, body, self.admin)[0], 400)
        status, queued = self.request("POST", route, body, self.admin, key)
        self.assertEqual(status, 201)
        job_id = queued["job"]["id"]
        self.assertEqual(self.request("POST", route, body, self.admin, key)[0], 200)
        self.assertEqual(self.request("POST", route, body, self.admin, str(uuid.uuid4()))[0], 429)
        lease = self.request("GET", f"/api/v1/servers/{self.sid}/jobs/next", token=self.agent)[1]
        self.assertEqual(lease["job"]["command"], command)
        secret = "private app token=hidden\n"
        self.assertEqual(self.request("POST", f"/api/v1/servers/{self.sid}/jobs/{job_id}/result",
                                      {"state": "succeeded", "exit_code": 0, "output": secret},
                                      self.agent)[0], 200)
        shown = self.request("GET", f"/api/v1/jobs/{job_id}", token=self.admin)[1]["job"]
        self.assertEqual(shown["output"], secret)
        self.assertTrue(shown["transient_output"])
        self.assertEqual(self.request("GET", f"/api/v1/jobs/{job_id}", token=self.login("admin"))[0], 403)
        self.assertEqual(self.notified, [])
        with sqlite3.connect(self.store.path) as db:
            self.assertEqual(db.execute("SELECT command,output FROM jobs WHERE id=?", (job_id,)).fetchone(),
                             ("", ""))
            self.assertNotIn(secret, json.dumps(db.execute("SELECT details FROM audit_events").fetchall()))
        events = [item for item in self.store.audit_events() if item["action"] == "container_logs_requested"]
        self.assertEqual(len(events), 1)
        self.assertNotIn(IDENT, json.dumps(events))
        self.assertTrue(Store(self.store.path).job(job_id, self.admin)["output_expired"])
        self.store.ingest(self.sid, metric(include=False))
        self.assertEqual(self.request("POST", route, body, self.admin, str(uuid.uuid4()))[0], 403)

    def test_invalid_result_control_text_is_rejected_without_persistence(self):
        self.store.ingest(self.sid, metric())
        route = f"/api/v1/servers/{self.sid}/containers/logs"
        body = {"engine": "docker", "id": IDENT, "lines": 5}
        job = self.request("POST", route, body, self.admin, str(uuid.uuid4()))[1]["job"]
        self.request("GET", f"/api/v1/servers/{self.sid}/jobs/next", token=self.agent)
        self.request("POST", f"/api/v1/servers/{self.sid}/jobs/{job['id']}/result",
                     {"state": "succeeded", "exit_code": 0, "output": "secret\u001b[31m"}, self.agent)
        result = self.request("GET", f"/api/v1/jobs/{job['id']}", token=self.admin)[1]["job"]
        self.assertEqual(result["state"], "failed")
        self.assertEqual(result["output"], "Container log response was invalid")
        with sqlite3.connect(self.store.path) as db:
            self.assertEqual(db.execute("SELECT output FROM jobs WHERE id=?", (job["id"],)).fetchone()[0], "")


if __name__ == "__main__":
    unittest.main()
