# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
"""Process pages are bounded and transient to one admin session."""

import json
import hashlib
import sqlite3
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
import uuid
from pathlib import Path

from sovagrid_hub.http_api import HubApp, make_server
from sovagrid_hub.process_actions import build_process_command, validate_snapshot
from sovagrid_hub.store import Store


class ProcessInventoryHTTPTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.temp.name) / "hub.sqlite")
        self.store.initialize("admin", "a-long-process-test-password")
        self.http = make_server(HubApp(self.store), 0)
        self.worker = threading.Thread(target=self.http.serve_forever, daemon=True)
        self.worker.start()
        self.base = f"http://127.0.0.1:{self.http.server_port}"
        self.admin = self.login("admin")
        server = self.store.create_server("process-host")
        self.sid, self.agent = server["id"], server["agent_token"]
        self.store.set_remote_commands(self.sid, True)

    def tearDown(self):
        self.http.shutdown()
        self.http.server_close()
        self.worker.join(2)
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

    def login(self, name):
        status, body = self.request("POST", "/api/v1/session",
                                    {"username": name, "password": "a-long-process-test-password"})
        self.assertEqual(status, 200)
        return body["token"]

    def test_scoped_transient_page_never_reaches_sqlite(self):
        body = {"after_pid": 12, "limit": 2, "filter": "secret"}
        marker = build_process_command(body)
        route = f"/api/v1/servers/{self.sid}/processes/snapshot"
        self.assertEqual(self.request("POST", f"/api/v1/servers/{self.sid}/jobs",
                                      {"command": marker}, self.admin)[0], 400)
        self.assertEqual(self.request("POST", route, body, self.admin)[0], 400)
        self.store.create_user("viewer", "a-long-process-test-password", "viewer")
        viewer = self.login("viewer")
        key = str(uuid.uuid4())
        self.assertEqual(self.request("POST", route, body, viewer, key)[0], 403)
        status, queued = self.request("POST", route, body, self.admin, key)
        self.assertEqual(status, 201)
        job_id = queued["job"]["id"]
        self.assertEqual(self.request("POST", route, body, self.admin, key), (200, queued))
        leased = self.request("GET", f"/api/v1/servers/{self.sid}/jobs/next", token=self.agent)[1]["job"]
        self.assertEqual(leased["command"], marker)
        page = {"observed_at": int(time.time()), "after_pid": 12, "filter": "secret",
                "next_after_pid": 13, "has_more": False,
                "processes": [{"pid": 13, "name": "secret-worker", "rss_bytes": 4096}]}
        output = json.dumps(page)
        self.assertEqual(self.request("POST", f"/api/v1/servers/{self.sid}/jobs/{job_id}/result",
                                      {"state": "succeeded", "exit_code": 0, "output": output},
                                      self.agent)[0], 200)
        stored = self.request("GET", f"/api/v1/jobs/{job_id}", token=self.admin)[1]["job"]
        self.assertEqual(json.loads(stored["output"])["processes"], page["processes"])
        self.assertTrue(stored["transient_output"])
        self.assertEqual(self.request("GET", f"/api/v1/jobs/{job_id}", token=self.login("admin"))[0], 403)
        self.assertEqual(self.request("GET", f"/api/v1/jobs/{job_id}", token=viewer)[0], 403)
        self.assertEqual(self.request("GET", "/api/v1/jobs", token=self.admin)[1]["jobs"][0]["output"], "")
        with sqlite3.connect(self.store.path) as db:
            row = db.execute("SELECT command,output FROM jobs WHERE id=?", (job_id,)).fetchone()
            self.assertEqual(row, ("", ""))
            self.assertNotIn("secret-worker", json.dumps(db.execute(
                "SELECT details_json FROM metrics").fetchall()))
            self.assertNotIn("secret-worker", json.dumps(db.execute(
                "SELECT details FROM audit_events").fetchall()))
        restarted = Store(self.store.path)
        self.assertTrue(restarted.job(job_id, self.admin)["output_expired"])
        self.assertEqual(restarted.job(job_id, self.admin)["output"], "")

    def test_invalid_agent_result_becomes_generic_failure(self):
        body = {"after_pid": 0, "limit": 1}
        key = str(uuid.uuid4())
        route = f"/api/v1/servers/{self.sid}/processes/snapshot"
        job = self.request("POST", route, body, self.admin, key)[1]["job"]
        self.request("GET", f"/api/v1/servers/{self.sid}/jobs/next", token=self.agent)
        malformed = '{"observed_at":1,"observed_at":2,"private":"leak"}'
        self.request("POST", f"/api/v1/servers/{self.sid}/jobs/{job['id']}/result",
                     {"state": "succeeded", "exit_code": 0, "output": malformed}, self.agent)
        result = self.request("GET", f"/api/v1/jobs/{job['id']}", token=self.admin)[1]["job"]
        self.assertEqual(result["state"], "failed")
        self.assertEqual(result["output"], "Process inventory response was invalid")
        with sqlite3.connect(self.store.path) as db:
            self.assertEqual(db.execute("SELECT output FROM jobs WHERE id=?", (job["id"],)).fetchone()[0], "")
        with self.assertRaises(ValueError):
            validate_snapshot(malformed, 0, 1, hashlib.sha256(b"").hexdigest())
        mismatched = {"observed_at": int(time.time()), "after_pid": 0,
                      "filter": "secret", "next_after_pid": 1, "has_more": False,
                      "processes": [{"pid": 1, "name": "other", "rss_bytes": 0}]}
        with self.assertRaises(ValueError):
            validate_snapshot(json.dumps(mismatched), 0, 1,
                              hashlib.sha256(b"secret").hexdigest())


if __name__ == "__main__":
    unittest.main()
