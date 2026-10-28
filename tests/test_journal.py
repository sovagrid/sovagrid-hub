# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
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

from sovagrid_hub.http_api import HubApp, make_server
from sovagrid_hub.journal_actions import build_journal_command
from sovagrid_hub.store import InvalidMetric, Store, validate_details


class JournalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.temp.name) / "hub.db", offline_seconds=120)
        self.store.initialize("admin", "very-long-test-password")
        self.server = make_server(HubApp(self.store), 0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temp.cleanup()

    def request(self, method, path, data=None, token=None, key=None):
        headers = {}
        body = None
        if data is not None:
            body = json.dumps(data).encode()
            headers["Content-Type"] = "application/json"
        if token:
            headers["Authorization"] = "Bearer " + token
        if key:
            headers["Idempotency-Key"] = key
        request = urllib.request.Request(self.base + path, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as exc:
            with exc:
                return exc.code, json.load(exc)

    def admin(self):
        status, payload = self.request("POST", "/api/v1/session",
                                       {"username": "admin", "password": "very-long-test-password"})
        self.assertEqual(status, 200)
        return payload["token"]

    def metric(self, details):
        return {"collected_at": int(time.time()), "cpu_percent": 1, "memory_percent": 2,
                "disk_percent": 3, "network_rx_bytes": 4, "network_tx_bytes": 5,
                "load1": 0.1, "uptime_seconds": 60, "details": details}

    def test_strict_request_validation(self):
        self.assertEqual(build_journal_command({"unit": "ssh@x.service", "lines": 100}),
                         "/usr/local/bin/sovagrid-journal-read read ssh@x.service 100")
        for body in ({"unit": "ssh.service"}, {"unit": "ssh.service", "lines": True},
                     {"unit": "ssh.service", "lines": 101},
                     {"unit": "ssh.service;id", "lines": 20},
                     {"unit": "ssh.service", "lines": 20, "extra": "x"}):
            with self.subTest(body=body), self.assertRaises(ValueError):
                build_journal_command(body)
        for value in ([], ["ssh.service", "ssh.service"], ["bad"], ["x.service"] * 17):
            with self.subTest(value=value), self.assertRaises(InvalidMetric):
                validate_details({"journal_units": value})

    def test_journal_request_requires_admin_server_command_and_agent_allowlist(self):
        admin = self.admin()
        _, server = self.request("POST", "/api/v1/servers", {"name": "journal-test"}, admin)
        sid, agent = server["id"], server["agent_token"]
        route = f"/api/v1/servers/{sid}/journal"
        body = {"unit": "nginx.service", "lines": 20}
        key = str(uuid.uuid4())
        marker = build_journal_command(body)
        self.assertEqual(self.request("POST", f"/api/v1/servers/{sid}/jobs",
                                      {"command": marker}, admin)[0], 400)
        with self.assertRaisesRegex(ValueError, "dedicated endpoint"):
            self.store.request_command(sid, 1, 1, marker)
        self.assertEqual(self.request("POST", route, body, key=key)[0], 401)
        self.assertEqual(self.request("POST", route, body, admin, key)[0], 403)
        self.request("POST", f"/api/v1/servers/{sid}/commands", {"enabled": True}, admin)
        self.assertEqual(self.request("POST", route, body, admin, key)[0], 403)
        self.assertEqual(self.request("POST", f"/api/v1/servers/{sid}/metrics",
                                      self.metric({"journal_units": ["nginx.service"]}), agent)[0], 202)
        self.assertEqual(self.request("POST", route, {"unit": "ssh.service", "lines": 20}, admin, key)[0], 403)
        self.assertEqual(self.request("POST", route, {"unit": "nginx.service", "lines": 101}, admin, key)[0], 400)
        self.assertEqual(self.request("POST", route, body, admin)[0], 400)
        status, queued = self.request("POST", route, body, admin, key)
        self.assertEqual(status, 201)
        job_id = queued["job"]["id"]
        again = self.request("POST", route, body, admin, key)
        self.assertEqual(again[0], 200)
        self.assertEqual(again[1]["job"]["id"], job_id)
        status, delivered = self.request("GET", f"/api/v1/servers/{sid}/jobs/next", token=agent)
        self.assertEqual(status, 200)
        self.assertEqual(delivered["job"]["command"], build_journal_command(body))
        self.assertEqual(len([event for event in self.store.audit_events()
                              if event["action"] == "journal_requested"]), 1)
        self.assertNotIn("nginx.service", json.dumps([event for event in self.store.audit_events()
                                                      if event["action"] == "command_delivered"]))
        secret = "application wrote a temporary secret"
        self.assertEqual(self.request("POST", f"/api/v1/servers/{sid}/jobs/{job_id}/result",
                                      {"state": "succeeded", "exit_code": 0, "output": secret}, agent)[0], 200)
        self.assertEqual(self.request("GET", f"/api/v1/jobs/{job_id}", token=admin)[1]["job"]["output"], secret)
        second_admin = self.admin()
        self.assertEqual(self.request("GET", f"/api/v1/jobs/{job_id}", token=second_admin)[0], 403)
        self.assertEqual(next(job for job in self.store.jobs() if job["id"] == job_id)["output"], "")
        with sqlite3.connect(self.store.path) as db:
            self.assertEqual(db.execute("SELECT output FROM jobs WHERE id=?", (job_id,)).fetchone()[0], "")
        self.assertNotIn(secret, json.dumps(self.store.audit_events()))
        restarted = Store(self.store.path)
        vanished = restarted.job(job_id, admin)
        self.assertEqual(vanished["output"], "")
        self.assertTrue(vanished["output_expired"])
        with self.store._journal_lock:
            self.store._journal_outputs[job_id] = (time.monotonic() - 1, secret)
        self.store.prune_journal_outputs()
        self.assertNotIn(job_id, self.store._journal_outputs)
        expired = self.request("GET", f"/api/v1/jobs/{job_id}", token=admin)[1]["job"]
        self.assertTrue(expired["output_expired"])
        self.assertEqual(expired["output"], "")
        self.assertEqual(self.store.journal_units(sid, now=int(time.time()) + 121), [])
        self.assertEqual(self.request("POST", f"/api/v1/servers/{sid}/metrics", self.metric({}), agent)[0], 202)
        self.assertEqual(self.request("POST", route, body, admin, str(uuid.uuid4()))[0], 403)

    def test_journal_rate_limit_is_per_session_server_and_preserves_replay(self):
        admin = self.admin()
        _, server = self.request("POST", "/api/v1/servers", {"name": "rate-limit"}, admin)
        sid, agent = server["id"], server["agent_token"]
        self.request("POST", f"/api/v1/servers/{sid}/commands", {"enabled": True}, admin)
        self.request("POST", f"/api/v1/servers/{sid}/metrics",
                     self.metric({"journal_units": ["ssh.service"]}), agent)
        route = f"/api/v1/servers/{sid}/journal"
        body = {"unit": "ssh.service", "lines": 20}
        first_key = str(uuid.uuid4())
        status, first = self.request("POST", route, body, admin, first_key)
        self.assertEqual(status, 201)
        self.assertEqual(self.request("POST", route, body, admin, first_key)[0], 200)
        self.assertEqual(self.request("POST", route, body, admin, str(uuid.uuid4()))[0], 429)
        _, other_server = self.request("POST", "/api/v1/servers", {"name": "another-rate-limit"}, admin)
        other_sid = other_server["id"]
        self.request("POST", f"/api/v1/servers/{other_sid}/commands", {"enabled": True}, admin)
        self.request("POST", f"/api/v1/servers/{other_sid}/metrics",
                     self.metric({"journal_units": ["ssh.service"]}), other_server["agent_token"])
        self.assertEqual(self.request("POST", f"/api/v1/servers/{other_sid}/journal",
                                      body, admin, str(uuid.uuid4()))[0], 201)
        other_session = self.admin()
        self.assertEqual(self.request("POST", route, body, other_session,
                                      str(uuid.uuid4()))[0], 201)
        later, created = self.store.queue_web_job(
            sid, admin, build_journal_command(body), str(uuid.uuid4()),
            now=int(time.time()) + 21, audit_action="journal_requested",
            audit_details={"unit": body["unit"], "lines": body["lines"]})
        self.assertTrue(created)
        self.assertNotEqual(later["id"], first["job"]["id"])

    def test_logout_and_password_change_clear_transient_journal_text(self):
        admin = self.admin()
        _, server = self.request("POST", "/api/v1/servers", {"name": "privacy"}, admin)
        sid, agent = server["id"], server["agent_token"]
        self.request("POST", f"/api/v1/servers/{sid}/commands", {"enabled": True}, admin)
        self.request("POST", f"/api/v1/servers/{sid}/metrics",
                     self.metric({"journal_units": ["ssh.service"]}), agent)

        def complete(token):
            job = self.request("POST", f"/api/v1/servers/{sid}/journal",
                               {"unit": "ssh.service", "lines": 20}, token, str(uuid.uuid4()))[1]["job"]["id"]
            self.request("GET", f"/api/v1/servers/{sid}/jobs/next", token=agent)
            self.request("POST", f"/api/v1/servers/{sid}/jobs/{job}/result",
                         {"state": "succeeded", "exit_code": 0, "output": "private line"}, agent)
            return job

        first = complete(admin)
        self.assertIn(first, self.store._journal_outputs)
        self.assertEqual(self.request("DELETE", "/api/v1/session", token=admin)[0], 200)
        self.assertNotIn(first, self.store._journal_outputs)
        self.assertEqual(self.request("GET", f"/api/v1/jobs/{first}", token=admin)[0], 401)
        second = self.admin()
        self.assertEqual(self.request("GET", f"/api/v1/jobs/{first}", token=second)[0], 403)
        second_job = complete(second)
        self.assertIn(second_job, self.store._journal_outputs)
        changed = self.request("POST", "/api/v1/admin/password",
                               {"current_password": "very-long-test-password",
                                "new_password": "replacement-long-password"}, second)
        self.assertEqual(changed[0], 200)
        self.assertEqual(self.store._journal_outputs, {})


if __name__ == "__main__":
    unittest.main()
