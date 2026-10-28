# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
"""Optional server access must fail closed across direct routes and async work."""

import hashlib
import json
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from unittest import mock

from sovagrid_hub.http_api import HubApp, make_server
from sovagrid_hub.server_acl import AccessConflict
from sovagrid_hub.store import Store


PASSWORD = "a-long-server-acl-test-password"


class ServerACLTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.temp.name) / "hub.sqlite")
        self.store.initialize("owner", PASSWORD)
        self.app = HubApp(self.store)
        self.http = make_server(self.app, 0)
        self.thread = threading.Thread(target=self.http.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.http.server_port}"
        self.owner = self.login("owner")
        self.a = self.store.create_server("alpha")
        self.b = self.store.create_server("beta")
        self.store.set_remote_commands(self.a["id"], True)
        self.store.set_remote_commands(self.b["id"], True)
        self.user = self.store.create_user("operator", PASSWORD, "admin")
        self.token = self.login("operator")

    def tearDown(self):
        self.http.shutdown()
        self.http.server_close()
        self.thread.join(2)
        self.temp.cleanup()

    def request(self, method, path, token=None, data=None, headers=None):
        headers = dict(headers or {})
        if token:
            headers["Authorization"] = "Bearer " + token
        body = None
        if data is not None:
            headers["Content-Type"] = "application/json"
            body = json.dumps(data).encode()
        request = urllib.request.Request(self.base + path, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as error:
            with error:
                return error.code, json.load(error)

    def login(self, username):
        return self.request("POST", "/api/v1/session", data={"username": username, "password": PASSWORD})[1]["token"]

    def policy(self, user_id, mode, grants, revision=0):
        return self.request("PATCH", f"/api/v1/users/{user_id}/server-access", self.owner,
                            {"revision": revision, "mode": mode, "grants": grants})

    def test_legacy_all_then_selected_filters_lists_and_direct_paths(self):
        a, b = self.a["id"], self.b["id"]
        self.assertEqual(self.request("GET", "/api/v1/session/access", self.token),
                         (200, {"access": {"mode": "all", "revision": 0,
                                           "unrestricted_admin": True}}))
        initial = self.request("GET", "/api/v1/servers", self.token)[1]["servers"]
        self.assertEqual({row["id"] for row in initial}, {a, b})
        self.assertEqual({row["access_role"] for row in initial}, {"admin"})
        status, saved = self.policy(self.user["id"], "selected", [{"server_id": a, "role": "viewer"}])
        self.assertEqual(status, 200)
        self.assertEqual(saved["access"]["revision"], 1)
        self.assertEqual(self.request("GET", "/api/v1/session/access", self.token),
                         (200, {"access": {"mode": "selected", "revision": 1,
                                           "unrestricted_admin": False}}))
        visible = self.request("GET", "/api/v1/servers", self.token)[1]["servers"]
        self.assertEqual([(row["id"], row["access_role"]) for row in visible], [(a, "viewer")])
        for suffix in ("metrics", "maintenance", "checks", "amnezia/control",
                       "services/control?unit=ssh.service"):
            self.assertEqual(self.request("GET", f"/api/v1/servers/{a}/{suffix}", self.token)[0], 200)
            self.assertEqual(self.request("GET", f"/api/v1/servers/{b}/{suffix}", self.token)[0], 403)
        self.assertEqual(self.request("POST", f"/api/v1/servers/{a}/jobs", self.token,
                                      {"command": "whoami"})[0], 403)
        self.assertEqual(self.request("POST", f"/api/v1/servers/{a}/services/actions", self.token,
                                      {"action": "status", "unit": "ssh.service"},
                                      {"Idempotency-Key": str(uuid.uuid4())})[0], 403)
        self.assertEqual(self.request("GET", "/api/v1/jobs", self.token)[1]["jobs"], [])
        self.assertEqual(self.request("GET", "/api/v1/vpn", self.token)[0], 403)
        self.assertEqual(self.request("GET", "/api/v1/users", self.token)[0], 403)
        self.assertEqual(self.request("GET", "/api/v1/servers", self.owner)[0], 200)

    def test_revision_cas_and_revocation_cancel_queued_jobs_and_terminals(self):
        a = self.a["id"]
        key = str(uuid.uuid4())
        status, result = self.request("POST", f"/api/v1/servers/{a}/jobs", self.token,
                                      {"command": "whoami"}, {"Idempotency-Key": key})
        self.assertEqual(status, 201)
        job_id = result["job"]["id"]
        self.assertTrue(self.store.terminal_access_valid(
            hashlib.sha256(self.token.encode()).hexdigest(), a))
        self.assertEqual(self.policy(self.user["id"], "selected", [], revision=0)[0], 200)
        self.assertEqual(self.policy(self.user["id"], "all", [], revision=0)[0], 409)
        self.assertFalse(self.store.terminal_access_valid(
            hashlib.sha256(self.token.encode()).hexdigest(), a))
        self.assertIsNone(self.store.lease_job(a))
        self.assertEqual(self.store.job(job_id)["state"], "cancelled")
        self.assertEqual(self.request("GET", f"/api/v1/jobs/{job_id}", self.token)[0], 403)
        self.assertEqual(self.request("GET", "/api/v1/audit", self.token)[1]["events"], [])

    def test_bot_binding_scope_blocks_commands_alerts_and_direct_results(self):
        a, b = self.a["id"], self.b["id"]
        self.store.add_bot_user(41, 41, "admin")
        self.store.save_server_access_policy("bot", (41, 41), {"revision": 0, "mode": "selected",
            "grants": [{"server_id": a, "role": "operator"}]}, session_token=self.owner)
        self.assertTrue(self.store.bot_server_allowed(41, 41, a, "operator"))
        self.assertFalse(self.store.bot_server_allowed(41, 41, b, "viewer"))
        self.assertFalse(self.store.bot_server_allowed(41, 41, a, "admin"))
        self.assertFalse(self.store.bot_unrestricted(41, 41))
        self.assertEqual([(row["id"], row["access_role"]) for row in self.store.servers(bot=(41, 41))],
                         [(a, "operator")])
        with self.assertRaises(PermissionError):
            self.store.request_command(a, 41, 41, "whoami")
        with self.assertRaises(PermissionError):
            self.store.request_command(b, 41, 41, "whoami")
        policy = self.request("GET", "/api/v1/telegram/bindings/41/41/server-access", self.owner)
        self.assertEqual(policy[0], 200)
        self.assertEqual(policy[1]["access"]["revision"], 1)

    def test_server_summary_role_is_capped_by_account_role(self):
        viewer = self.store.create_user("viewer", PASSWORD, "viewer")
        token = self.login("viewer")
        self.policy(viewer["id"], "selected", [{"server_id": self.a["id"], "role": "admin"}])
        self.assertEqual(self.request("GET", "/api/v1/session/access", token)[1]["access"],
                         {"mode": "selected", "revision": 1, "unrestricted_admin": False})
        rows = self.request("GET", "/api/v1/servers", token)[1]["servers"]
        self.assertEqual([(row["id"], row["access_role"]) for row in rows],
                         [(self.a["id"], "viewer")])
        self.assertEqual(self.request("POST", f"/api/v1/servers/{self.a['id']}/services/actions",
                                      token, {"action": "status", "unit": "ssh.service"},
                                      {"Idempotency-Key": str(uuid.uuid4())})[0], 403)

    def test_incident_lists_and_acknowledgement_are_server_scoped(self):
        now = int(time.time())
        metric = {"collected_at": now, "cpu_percent": 97, "memory_percent": 10,
                  "disk_percent": 10, "network_rx_bytes": 1, "network_tx_bytes": 1,
                  "load1": 1, "uptime_seconds": 60}
        self.store.ingest(self.a["id"], metric, now=now)
        self.store.ingest(self.b["id"], metric, now=now)
        incidents = self.store.incidents()
        by_server = {item["server_id"]: item["id"] for item in incidents}
        self.policy(self.user["id"], "selected", [{"server_id": self.a["id"], "role": "operator"}])
        visible = self.request("GET", "/api/v1/incidents", self.token)[1]["incidents"]
        self.assertEqual({item["server_id"] for item in visible}, {self.a["id"]})
        self.assertEqual(self.request("POST", f"/api/v1/incidents/{by_server[self.b['id']]}/ack",
                                      self.token, {})[0], 403)
        self.assertEqual(self.request("POST", f"/api/v1/incidents/{by_server[self.a['id']]}/ack",
                                      self.token, {})[0], 200)

    def test_bot_outbox_rechecks_access_before_delivery(self):
        self.store.add_bot_user(42, 42, "viewer")
        now = int(time.time())
        self.store.ingest(self.b["id"], {"collected_at": now, "cpu_percent": 97,
            "memory_percent": 10, "disk_percent": 10, "network_rx_bytes": 1,
            "network_tx_bytes": 1, "load1": 1, "uptime_seconds": 60}, now=now)
        claimed = self.store.claim_incident_outbox(now=now)
        self.assertIsNotNone(claimed)
        self.store.save_server_access_policy("bot", (42, 42),
            {"revision": 0, "mode": "selected", "grants": []}, session_token=self.owner)
        self.assertFalse(self.store.incident_outbox_send_allowed(
            claimed["id"], claimed["lease_generation"], now=now))

    def test_concurrent_policy_cas_has_one_winner(self):
        a = self.a["id"]
        barrier = threading.Barrier(3)
        outcomes = []
        def write(mode):
            barrier.wait()
            try:
                self.store.save_server_access_policy("user", (self.user["id"],),
                    {"revision": 0, "mode": mode,
                     "grants": [{"server_id": a, "role": "viewer"}] if mode == "selected" else []},
                    session_token=self.owner)
                outcomes.append("ok")
            except AccessConflict:
                outcomes.append("conflict")
        threads = [threading.Thread(target=write, args=(mode,)) for mode in ("all", "selected")]
        for thread in threads: thread.start()
        barrier.wait()
        for thread in threads: thread.join(5)
        self.assertCountEqual(outcomes, ["ok", "conflict"])

    def test_policy_commit_wins_over_waiting_agent_lease(self):
        a = self.a["id"]
        queued = self.store.queue_web_job(a, self.token, "whoami")[0]
        policy_inside_write = threading.Event()
        release_policy = threading.Event()
        original = self.store._audit_account
        def hold_policy_audit(db, identity, action, *args, **kwargs):
            if action == "server_access_changed":
                policy_inside_write.set()
                self.assertTrue(release_policy.wait(2))
            return original(db, identity, action, *args, **kwargs)
        lease_result = []
        with mock.patch.object(self.store, "_audit_account", side_effect=hold_policy_audit):
            policy_thread = threading.Thread(target=lambda: self.store.save_server_access_policy(
                "user", (self.user["id"],), {"revision": 0, "mode": "selected", "grants": []},
                session_token=self.owner))
            policy_thread.start()
            self.assertTrue(policy_inside_write.wait(2))
            lease_thread = threading.Thread(target=lambda: lease_result.append(self.store.lease_job(a)))
            lease_thread.start()
            release_policy.set()
            policy_thread.join(5)
            lease_thread.join(5)
        self.assertEqual(lease_result, [None])
        self.assertEqual(self.store.job(queued["id"])["state"], "cancelled")


if __name__ == "__main__":
    unittest.main()
