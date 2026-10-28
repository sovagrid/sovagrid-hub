# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""The Hub lease gates jobs, but never asserts Agent-side idleness."""

from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
import uuid
from unittest import mock

from sovagrid_hub.agent_maintenance import MaintenanceLeaseBusy, MaintenanceLeaseInvalid
from sovagrid_hub.http_api import HubApp, make_server
from sovagrid_hub.store import Store


DIGEST = "a" * 64
EPOCH = "b" * 32


class AgentMaintenanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = Path(self.temp.name) / "hub.sqlite"
        self.store = Store(self.db)
        self.store.initialize("admin", "long-test-password")
        with mock.patch.dict(os.environ, {"SOVAGRID_BUNDLE_MANIFEST_SHA256": DIGEST}):
            self.app = HubApp(self.store)
        self.server = make_server(self.app, 0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"

        def close():
            self.server.shutdown()
            self.server.server_close()
            self.thread.join(timeout=2)

        self.addCleanup(close)
        self.admin = self.request("POST", "/api/v1/session", body={
            "username": "admin", "password": "long-test-password"})[1]["token"]
        created = self.request("POST", "/api/v1/servers", token=self.admin,
                               body={"name": "one"})[1]
        self.sid, self.agent = created["id"], created["agent_token"]
        self.path = f"/api/v1/servers/{self.sid}/agent-maintenance/lease"

    def request(self, method, path, *, token=None, body=None, key=None):
        headers = {}
        if token is not None:
            headers["Authorization"] = "Bearer " + token
        if key is not None:
            headers["Idempotency-Key"] = key
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(self.base + path, data=data,
                                         headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=3) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as error:
            with error:
                return error.code, json.load(error)

    def acquire(self, token=None):
        return self.request("POST", self.path, token=self.agent if token is None else token,
                            body={"bundle_manifest_sha256": DIGEST})

    def test_agent_scope_credential_bundle_and_explicit_release(self):
        self.assertEqual(self.acquire(token=self.admin)[0], 401)
        self.assertEqual(self.request("POST", self.path, token=self.agent,
                                      body={"bundle_manifest_sha256": "b" * 64})[0], 409)
        status, acquired = self.acquire()
        self.assertEqual(status, 201)
        self.assertEqual(acquired["scope"], "jobs_and_new_relays")
        self.assertEqual(acquired["hub_epoch"], self.app.agent_maintenance_epoch)
        self.assertIs(acquired["agent_idle_proven"], False)
        self.assertGreater(acquired["expires_at"], 0)
        lease_token = acquired["lease_token"]
        self.assertEqual(len(lease_token), 43)
        self.assertNotIn(lease_token.encode(), self.db.read_bytes())
        self.assertEqual(self.acquire()[0], 409)
        status, renewed = self.request("POST", self.path + "/renew", token=self.agent,
                                       body={"lease_token": lease_token})
        self.assertEqual(status, 200)
        self.assertEqual(renewed["scope"], "jobs_and_new_relays")
        self.assertIs(renewed["agent_idle_proven"], False)
        self.assertEqual(self.request("POST", self.path + "/release", token=self.agent,
                                      body={"lease_token": "z" * 43})[0], 409)
        self.assertEqual(self.request("POST", self.path + "/release", token=self.agent,
                                      body={"lease_token": lease_token}), (200, {"released": True}))
        self.assertEqual(self.acquire()[0], 201)
        actions = [event["action"] for event in self.store.audit_events()]
        self.assertIn("agent_maintenance_acquired", actions)
        self.assertIn("agent_maintenance_renewed", actions)
        self.assertIn("agent_maintenance_released", actions)

    def test_queued_delivered_and_pending_commands_prevent_lease(self):
        self.assertEqual(self.request("POST", f"/api/v1/servers/{self.sid}/commands",
                                      token=self.admin, body={"enabled": True})[0], 200)
        status, queued = self.request("POST", f"/api/v1/servers/{self.sid}/jobs",
                                      token=self.admin, body={"command": "id"})
        self.assertEqual(status, 201)
        self.assertEqual(self.acquire()[0], 409)
        status, leased = self.request("GET", f"/api/v1/servers/{self.sid}/jobs/next",
                                      token=self.agent)
        self.assertEqual(status, 200)
        self.assertEqual(leased["job"]["id"], queued["job"]["id"])
        self.assertEqual(self.acquire()[0], 409)
        self.assertEqual(self.request("POST", f"/api/v1/servers/{self.sid}/jobs/{leased['job']['id']}/result",
                                      token=self.agent, body={"state": "succeeded", "exit_code": 0,
                                                              "output": "ok"})[0], 200)
        with self.store.connection() as db:
            db.execute("""INSERT INTO pending_commands
                (code_hash,server_id,actor_user_id,chat_id,command,created_at,expires_at)
                VALUES (?,?,?,?,?,?,?)""",
                ("b" * 64, self.sid, 1, 1, "id", 1, 4_000_000_000))
        self.assertEqual(self.acquire()[0], 409)
        with self.store.connection() as db:
            db.execute("DELETE FROM pending_commands WHERE server_id=?", (self.sid,))
        self.assertEqual(self.acquire()[0], 201)

    def test_lease_blocks_web_jobs_and_new_relays(self):
        self.assertEqual(self.request("POST", f"/api/v1/servers/{self.sid}/commands",
                                      token=self.admin, body={"enabled": True})[0], 200)
        status, acquired = self.acquire()
        self.assertEqual(status, 201)
        status, _ = self.request("POST", f"/api/v1/servers/{self.sid}/jobs",
                                  token=self.admin, body={"command": "id"})
        self.assertEqual(status, 403)
        status, result = self.request("GET", f"/api/v1/servers/{self.sid}/jobs/next",
                                       token=self.agent)
        self.assertEqual((status, result), (200, {"job": None}))
        status, _ = self.request("POST", f"/api/v1/servers/{self.sid}/terminal/sessions",
                                  token=self.admin, key=str(uuid.uuid4()),
                                  body={"cols": 80, "rows": 24})
        self.assertEqual(status, 409)
        status, _ = self.request("POST", f"/api/v1/servers/{self.sid}/files/operations",
                                  token=self.admin, key=str(uuid.uuid4()),
                                  body={"action": "list", "root": "workspace", "path": ""})
        self.assertEqual(status, 409)
        self.assertEqual(self.request("POST", self.path + "/release", token=self.agent,
                                      body={"lease_token": acquired["lease_token"]})[0], 200)
        self.assertEqual(self.request("POST", f"/api/v1/servers/{self.sid}/jobs",
                                      token=self.admin, body={"command": "id"})[0], 201)

    def test_known_active_relay_prevents_lease(self):
        terminal, _ = self.app.terminals.create(self.sid, "owner", "key", 80, 24)
        self.assertEqual(self.acquire()[0], 409)
        self.app.terminals.close(self.sid, terminal["id"])
        operation, _ = self.app.files.create(self.sid, "owner", str(uuid.uuid4()),
                                             {"action": "list", "root": "workspace", "path": ""})
        self.assertEqual(self.acquire()[0], 409)
        self.app.files.close_operation(self.sid, operation["id"])
        self.assertEqual(self.acquire()[0], 201)

    def test_lease_and_credentials_are_isolated_per_server(self):
        second = self.request("POST", "/api/v1/servers", token=self.admin,
                              body={"name": "two"})[1]
        second_id, second_agent = second["id"], second["agent_token"]
        self.assertEqual(self.acquire(token=second_agent)[0], 401)
        first_lease = self.acquire()[1]
        second_path = f"/api/v1/servers/{second_id}/agent-maintenance/lease"
        self.assertEqual(self.request("POST", self.path + "/renew", token=second_agent,
                                      body={"lease_token": first_lease["lease_token"]})[0], 401)
        status, second_lease = self.request("POST", second_path, token=second_agent,
                                            body={"bundle_manifest_sha256": DIGEST})
        self.assertEqual(status, 201)
        self.assertEqual(self.request("POST", f"/api/v1/servers/{second_id}/commands",
                                      token=self.admin, body={"enabled": True})[0], 200)
        # A lease on the first server does not block another server once its
        # own lease has ended. Release using that server's exact credential.
        self.assertEqual(self.request("POST", second_path + "/release", token=second_agent,
                                      body={"lease_token": second_lease["lease_token"]})[0], 200)
        self.assertEqual(self.request("POST", f"/api/v1/servers/{second_id}/jobs",
                                      token=self.admin, body={"command": "id"})[0], 201)

    def test_expiry_cap_and_rotation_fail_closed(self):
        first = self.store.acquire_agent_maintenance_lease(self.sid, self.agent, DIGEST,
                                                            hub_epoch=EPOCH,
                                                            relays_active=False, now=1000)
        self.assertIsNotNone(first)
        self.assertEqual(first["expires_at"], 1120)
        with self.assertRaises(MaintenanceLeaseInvalid):
            self.store.renew_agent_maintenance_lease(
                self.sid, self.agent, first["lease_token"], hub_epoch="c" * 32,
                bundle_manifest_sha256=DIGEST, now=1010)
        with self.assertRaises(MaintenanceLeaseInvalid):
            self.store.renew_agent_maintenance_lease(
                self.sid, self.agent, first["lease_token"], hub_epoch=EPOCH,
                bundle_manifest_sha256="c" * 64, now=1010)
        renewed = self.store.renew_agent_maintenance_lease(
            self.sid, self.agent, first["lease_token"], hub_epoch=EPOCH,
            bundle_manifest_sha256=DIGEST, now=1110)
        self.assertEqual(renewed["expires_at"], 1230)
        for tick in (1210, 1310, 1410, 1510, 1610, 1710, 1810):
            self.store.renew_agent_maintenance_lease(
                self.sid, self.agent, first["lease_token"], hub_epoch=EPOCH,
                bundle_manifest_sha256=DIGEST, now=tick)
        renewed = self.store.renew_agent_maintenance_lease(
            self.sid, self.agent, first["lease_token"], hub_epoch=EPOCH,
            bundle_manifest_sha256=DIGEST, now=1890)
        self.assertEqual(renewed["expires_at"], 1900)
        with self.assertRaises(MaintenanceLeaseInvalid):
            self.store.renew_agent_maintenance_lease(self.sid, self.agent,
                                                     first["lease_token"], hub_epoch=EPOCH,
                                                     bundle_manifest_sha256=DIGEST, now=1900)
        second = self.store.acquire_agent_maintenance_lease(self.sid, self.agent, DIGEST,
                                                             hub_epoch=EPOCH,
                                                             relays_active=False, now=2000)
        self.assertIsNotNone(second)
        self.assertTrue(self.store.release_agent_maintenance_lease(
            self.sid, self.agent, second["lease_token"], now=2001))
        replacement = self.store.rotate_agent_token(self.sid, session_token=self.admin)
        self.assertIsNotNone(replacement)
        self.assertFalse(self.store.agent_maintenance_active(self.sid, now=2001))
        self.assertIsNone(self.store.renew_agent_maintenance_lease(
            self.sid, self.agent, second["lease_token"], hub_epoch=EPOCH,
            bundle_manifest_sha256=DIGEST, now=2001))
        self.assertIsNone(self.store.release_agent_maintenance_lease(
            self.sid, self.agent, second["lease_token"], now=2001))
        self.assertIsNotNone(self.store.acquire_agent_maintenance_lease(
            self.sid, replacement, DIGEST, hub_epoch=EPOCH,
            relays_active=False, now=2001))

    def test_token_rotation_waits_for_active_lease(self):
        status, acquired = self.acquire()
        self.assertEqual(status, 201)
        self.assertEqual(self.request("POST", f"/api/v1/servers/{self.sid}/rotate-token",
                                      token=self.admin, body={})[0], 409)
        self.assertTrue(self.store.agent_valid(self.sid, self.agent))
        self.assertEqual(self.request("POST", self.path + "/release", token=self.agent,
                                      body={"lease_token": acquired["lease_token"]})[0], 200)
        self.assertEqual(self.request("POST", f"/api/v1/servers/{self.sid}/rotate-token",
                                      token=self.admin, body={})[0], 200)
        self.assertFalse(self.store.agent_valid(self.sid, self.agent))

    def test_telegram_request_and_confirmation_cannot_enter_active_lease(self):
        self.assertEqual(self.request("POST", f"/api/v1/servers/{self.sid}/commands",
                                      token=self.admin, body={"enabled": True})[0], 200)
        self.store.add_bot_user(1, 1, "admin", session_token=self.admin)
        self.assertEqual(self.acquire()[0], 201)
        with self.assertRaises(MaintenanceLeaseBusy):
            self.store.request_command(self.sid, 1, 1, "id")
        # Simulate a pre-existing command imported during maintenance. Even
        # then confirmation must not turn it into a queued job.
        code = "known-code"
        with self.store.connection() as db:
            db.execute("""INSERT INTO pending_commands
                (code_hash,server_id,actor_user_id,chat_id,command,created_at,expires_at)
                VALUES (?,?,?,?,?,?,?)""",
                (hashlib.sha256(code.encode()).hexdigest(), self.sid, 1, 1,
                 "id", 1, 4_000_000_000))
        self.assertIsNone(self.store.confirm_command(code, 1, 1))
        with self.store.connection() as db:
            count = db.execute("SELECT COUNT(*) FROM jobs WHERE server_id=?", (self.sid,)).fetchone()[0]
        self.assertEqual(count, 0)

    def test_migration_restores_lease_table_without_erasing_jobs(self):
        with self.store.connection() as db:
            db.execute("DROP TABLE agent_maintenance_leases")
        self.store.migrate()
        status, acquired = self.acquire()
        self.assertEqual(status, 201)
        self.assertIs(acquired["agent_idle_proven"], False)


if __name__ == "__main__":
    unittest.main()
