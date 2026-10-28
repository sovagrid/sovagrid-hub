# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Structured service jobs must stay bound to one unit and one server."""

import hashlib
import json
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from sovagrid_hub.http_api import HubApp, make_server
from sovagrid_hub.service_actions import (build_service_command, control_status,
                                          is_service_command, protected_mutation_unit)
from sovagrid_hub.store import ServiceControlUnavailable, Store


class ServiceActionTests(unittest.TestCase):
    def test_protected_access_and_platform_units_keep_status_only(self):
        for unit in ("sovagrid-agent.service", "reverse-tunnel.service", "ssh.service",
                     "sshd@host.service", "docker.service", "systemd-networkd.service",
                     "awg-quick@awg0.service"):
            with self.subTest(unit=unit):
                self.assertTrue(protected_mutation_unit(unit))
                self.assertEqual(build_service_command({"action": "status", "unit": unit}),
                                 f"/usr/local/bin/sovagrid-service-ctl status {unit}")
        self.assertFalse(protected_mutation_unit("nginx.service"))

    def test_exact_command_and_status_projection(self):
        command = build_service_command({"action": "restart", "unit": "nginx.service"})
        self.assertEqual(command, "/usr/local/bin/sovagrid-service-ctl restart nginx.service")
        self.assertTrue(is_service_command(command))
        for body in ({"action": "restart", "unit": "nginx@.service"},
                     {"action": "enable", "unit": "nginx.service"},
                     {"action": "stop", "unit": "../ssh.service"},
                     {"action": "stop", "unit": "ssh.service", "shell": "id"}):
            with self.subTest(body=body), self.assertRaises(ValueError):
                build_service_command(body)
        self.assertFalse(is_service_command(command + "; id"))
        now = int(time.time())
        public = {"action": "status", "unit": "nginx.service", "result": "ok",
                  "load_state": "loaded", "active_state": "active", "sub_state": "running"}
        job = {"state": "succeeded", "exit_code": 0, "completed_at": now,
               "output": json.dumps(public)}
        self.assertEqual(control_status(job, now, "nginx.service")["active_state"], "active")
        for changed in (job | {"output": json.dumps(public | {"unit": "ssh.service"})},
                        job | {"output": json.dumps(public | {"private": "secret"})},
                        job | {"output": '{"action":"status","action":"restart"}'},
                        job | {"completed_at": now - 91}):
            self.assertEqual(control_status(changed, now, "nginx.service")["source_status"],
                             "unavailable")


class ServiceHttpTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.temp.name) / "hub.sqlite")
        self.store.initialize("admin", "long-test-password")
        self.server = make_server(HubApp(self.store), 0)
        self.worker = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.worker.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.worker.join(timeout=2)
        self.temp.cleanup()

    def request(self, method, path, body=None, token=None, request_key=None):
        headers = {}
        data = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body).encode()
        if token:
            headers["Authorization"] = "Bearer " + token
        if request_key:
            headers["Idempotency-Key"] = request_key
        request = urllib.request.Request(self.base + path, data=data, headers=headers,
                                         method=method)
        try:
            with urllib.request.urlopen(request) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as error:
            with error:
                return error.code, json.load(error)

    def test_unit_status_gates_mutation_and_replay(self):
        admin = self.request("POST", "/api/v1/session",
                             {"username": "admin", "password": "long-test-password"})[1]["token"]
        created = self.request("POST", "/api/v1/servers", {"name": "systemd-host"}, admin)[1]
        sid, agent = created["id"], created["agent_token"]
        self.request("POST", f"/api/v1/servers/{sid}/commands", {"enabled": True}, admin)
        control_path = f"/api/v1/servers/{sid}/services/control?unit=nginx.service"
        actions_path = f"/api/v1/servers/{sid}/services/actions"
        status = {"action": "status", "unit": "nginx.service"}
        restart = {"action": "restart", "unit": "nginx.service"}
        self.assertEqual(self.request("GET", control_path)[0], 401)
        self.assertEqual(self.request("GET", control_path, token=admin)[1]
                         ["control"]["source_status"], "unavailable")
        self.assertEqual(self.request("GET", control_path + "&unit=ssh.service",
                                      token=admin)[0], 400)
        self.assertEqual(self.request("POST", actions_path, restart, admin,
                                      "9ce5b5ad-ef2e-4371-ac49-c841d635d514")[0], 503)
        self.assertEqual(self.request("POST", actions_path, status, admin,
                                      "8756c00f-38bb-4dbf-b5b6-04541323d6b6")[0], 201)
        leased = self.request("GET", f"/api/v1/servers/{sid}/jobs/next", token=agent)[1]["job"]
        self.assertEqual(leased["command"], build_service_command(status))
        self.assertEqual(leased["timeout_seconds"], 60)
        public = {"action": "status", "unit": "nginx.service", "result": "ok",
                  "load_state": "loaded", "active_state": "active", "sub_state": "running"}
        self.request("POST", f"/api/v1/servers/{sid}/jobs/{leased['id']}/result",
                     {"state": "succeeded", "exit_code": 0, "output": json.dumps(public)}, agent)
        self.assertEqual(self.request("GET", control_path, token=admin)[1]
                         ["control"]["active_state"], "active")
        key = "5e51f768-8862-4bf8-aaf8-79a36147a945"
        first = self.request("POST", actions_path, restart, admin, key)
        self.assertEqual(first[0], 201)
        self.assertEqual(self.request("GET", control_path, token=admin)[1]
                         ["control"]["source_status"], "unavailable")
        self.assertEqual(self.request("POST", actions_path, restart, admin,
                                      "ed9410fb-41fb-4d69-8cc6-41ed49c0410b")[0], 503)
        self.assertEqual(self.request("POST", actions_path, restart, admin, key),
                         (200, first[1]))
        self.assertEqual(self.request("POST", actions_path,
                                      {"action": "stop", "unit": "ssh.service"}, admin,
                                      "a42fc812-52b8-4f91-8a82-a9845f66291f")[0], 403)
        self.assertEqual(self.request("POST", actions_path,
                                      {"action": "enable", "unit": "nginx.service"}, admin,
                                      "f7522cb0-94e4-498e-8bb9-6d0053873c50")[0], 400)

    def test_protected_mutation_is_rejected_before_status_gate_or_job(self):
        admin = self.request("POST", "/api/v1/session",
                             {"username": "admin", "password": "long-test-password"})[1]["token"]
        sid = self.request("POST", "/api/v1/servers", {"name": "systemd-host"}, admin)[1]["id"]
        self.request("POST", f"/api/v1/servers/{sid}/commands", {"enabled": True}, admin)
        path = f"/api/v1/servers/{sid}/services/actions"
        for unit in ("sovagrid-agent.service", "reverse-tunnel.service", "docker.service",
                     "systemd-networkd.service", "ssh@jump.service"):
            with self.subTest(unit=unit):
                self.assertEqual(self.request("POST", path, {"action": "restart", "unit": unit},
                                              admin, "d5307c9d-2884-4af2-b33e-8d50d975a7d1")[0], 403)
        self.assertEqual(self.request("POST", path, {"action": "status", "unit": "ssh.service"},
                                      admin, "a8e32249-aa2d-451b-a3c0-c3be8e06cc96")[0], 201)

    def test_generic_web_and_telegram_jobs_cannot_queue_service_marker(self):
        admin = self.request("POST", "/api/v1/session",
                             {"username": "admin", "password": "long-test-password"})[1]["token"]
        sid = self.request("POST", "/api/v1/servers", {"name": "systemd-host"}, admin)[1]["id"]
        self.request("POST", f"/api/v1/servers/{sid}/commands", {"enabled": True}, admin)
        self.store.add_bot_user(987654, 987654, "admin", session_token=admin)
        marker = "/usr/local/bin/sovagrid-service-ctl"
        commands = (
            f"{marker} restart nginx.service",
            f"{marker}\trestart nginx.service",
            f"sh -c '{marker} restart nginx.service'",
            f"echo {marker} restart nginx.service",
            "sovagrid-service-ctl restart nginx.service",
            "/usr/local/bin/sovagrid-vpn-ctl activate personal",
            "sh -c '/usr/local/bin/sovagrid-vpn-ctl activate personal'",
            "/usr/local/bin/sovagrid-amnezia-ctl status awg2",
            "echo sovagrid-amnezia-ctl status awg2",
        )
        for command in commands:
            with self.subTest(command=command):
                self.assertEqual(self.request("POST", f"/api/v1/servers/{sid}/jobs",
                                              {"command": command}, admin)[0], 400)
                with self.assertRaisesRegex(ValueError, "dedicated endpoint"):
                    self.store.request_command(sid, 987654, 987654, command)
                with self.assertRaisesRegex(ValueError, "dedicated endpoint"):
                    self.store.queue_web_job(sid, admin, command)
        # A pending Telegram command written by an older Hub must also be
        # rejected when its confirmation arrives after the upgrade.
        code = "legacy-confirmation"
        now = int(time.time())
        with self.store.connection() as db:
            db.execute("INSERT INTO pending_commands VALUES (?,?,?,?,?,?,?)",
                       (hashlib.sha256(code.encode()).hexdigest(), sid, 987654, 987654,
                        "/usr/local/bin/sovagrid-vpn-ctl activate personal", now, now + 60))
        self.assertIsNone(self.store.confirm_command(code, 987654, 987654, now=now))
        self.assertEqual(self.request("POST", f"/api/v1/servers/{sid}/services/actions",
                                      {"action": "status", "unit": "nginx.service"}, admin,
                                      "918fa4db-50f1-47a2-8e20-87d2e7ff0d53")[0], 201)

    def test_old_generic_marker_jobs_are_cancelled_at_lease_after_migration(self):
        admin = self.request("POST", "/api/v1/session",
                             {"username": "admin", "password": "long-test-password"})[1]["token"]
        created = self.request("POST", "/api/v1/servers", {"name": "legacy-host"}, admin)[1]
        sid = created["id"]
        self.request("POST", f"/api/v1/servers/{sid}/commands", {"enabled": True}, admin)
        legacy = (
            "/usr/local/bin/sovagrid-vpn-ctl activate personal",
            "/usr/local/bin/sovagrid-amnezia-ctl status awg2",
            "/usr/local/bin/sovagrid-service-ctl restart nginx.service",
        )
        ids = []
        for command in legacy:
            queued = self.store.queue_web_job(sid, admin, "echo old queued command")[0]
            ids.append(queued["id"])
            with self.store.connection() as db:
                db.execute("UPDATE jobs SET command=? WHERE id=?", (command, queued["id"]))
        ordinary = self.store.queue_web_job(sid, admin, "echo ordinary")[0]
        service = self.request("POST", f"/api/v1/servers/{sid}/services/actions",
                               {"action": "status", "unit": "nginx.service"}, admin,
                               "1248df33-1785-4db3-bfff-537493322951")[1]["job"]
        vpn = self.request("POST", f"/api/v1/servers/{sid}/vpn/actions",
                           {"action": "activate", "name": "personal"}, admin,
                           "2248df33-1785-4db3-bfff-537493322951")[1]["job"]
        amnezia = self.request("POST", f"/api/v1/servers/{sid}/amnezia/actions",
                               {"action": "status", "target": "awg2"}, admin,
                               "3248df33-1785-4db3-bfff-537493322951")[1]["job"]
        leased = []
        while job := self.store.lease_job(sid):
            leased.append(job)
        self.assertEqual({item["id"] for item in leased},
                         {ordinary["id"], service["id"], vpn["id"], amnezia["id"]})
        self.assertEqual({item["timeout_seconds"] for item in leased}, {15, 60, 105, 135})
        with self.store.connection() as db:
            rows = db.execute("SELECT id,state,control_kind FROM jobs WHERE id IN (?,?,?)", ids).fetchall()
        self.assertEqual({(row["state"], row["control_kind"]) for row in rows},
                         {("cancelled", "generic")})

    def test_existing_jobs_table_gets_safe_generic_default(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / "old.sqlite")
            store.initialize("admin", "long-test-password")
            with store.connection() as db:
                db.execute("ALTER TABLE jobs DROP COLUMN control_kind")
            store.migrate()
            with store.connection() as db:
                columns = {row["name"] for row in db.execute("PRAGMA table_info(jobs)")}
                default = db.execute("SELECT dflt_value FROM pragma_table_info('jobs') "
                                     "WHERE name='control_kind'").fetchone()[0]
            self.assertIn("control_kind", columns)
            self.assertEqual(default, "'generic'")

    def test_idempotency_does_not_replay_legacy_generic_as_structured(self):
        admin = self.request("POST", "/api/v1/session",
                             {"username": "admin", "password": "long-test-password"})[1]["token"]
        sid = self.request("POST", "/api/v1/servers", {"name": "legacy-key"}, admin)[1]["id"]
        self.request("POST", f"/api/v1/servers/{sid}/commands", {"enabled": True}, admin)
        key = "765beef8-a132-4fda-8b7b-ab37244b738f"
        legacy = self.store.queue_web_job(sid, admin, "echo legacy", key)[0]
        command = build_service_command({"action": "status", "unit": "nginx.service"})
        with self.store.connection() as db:
            db.execute("UPDATE jobs SET command=?,command_sha256=? WHERE id=?",
                       (command, hashlib.sha256(command.encode()).hexdigest(), legacy["id"]))
        self.assertEqual(self.request("POST", f"/api/v1/servers/{sid}/services/actions",
                                      {"action": "status", "unit": "nginx.service"}, admin,
                                      key)[0], 409)

    def test_failed_and_timed_out_mutations_require_a_new_completed_status(self):
        admin = self.request("POST", "/api/v1/session",
                             {"username": "admin", "password": "long-test-password"})[1]["token"]
        created = self.request("POST", "/api/v1/servers", {"name": "systemd-host"}, admin)[1]
        sid = created["id"]
        self.request("POST", f"/api/v1/servers/{sid}/commands", {"enabled": True}, admin)
        now = int(time.time()) - 20
        status = build_service_command({"action": "status", "unit": "nginx.service"})
        restart = build_service_command({"action": "restart", "unit": "nginx.service"})
        public = json.dumps({"action": "status", "unit": "nginx.service", "result": "ok",
                             "load_state": "loaded", "active_state": "active",
                             "sub_state": "running"})

        def complete_status(at):
            job = self.store.queue_web_job(sid, admin, status, now=at,
                                           allow_service_marker=True)[0]
            self.assertEqual(self.store.lease_job(sid, now=at)["id"], job["id"])
            self.store.finish_job(sid, job["id"], "succeeded", 0, public, now=at + 1)

        complete_status(now)
        for state in ("timed_out", "failed"):
            with self.subTest(state=state):
                mutation = self.store.queue_web_job(
                    sid, admin, restart, now=now + 2,
                    require_service_ready="nginx.service",
                    allow_service_marker=True)[0]
                self.assertIsNone(self.store.latest_service_control_job(
                    sid, "nginx.service", session_token=admin))
                with self.assertRaises(ServiceControlUnavailable):
                    self.store.queue_web_job(sid, admin, restart, now=now + 3,
                                             require_service_ready="nginx.service",
                                             allow_service_marker=True)
                self.assertEqual(self.store.lease_job(sid, now=now + 2)["id"],
                                 mutation["id"])
                self.store.finish_job(sid, mutation["id"], state, None,
                                      "Broker result uncertain", now=now + 3)
                with self.assertRaises(ServiceControlUnavailable):
                    self.store.queue_web_job(sid, admin, restart, now=now + 4,
                                             require_service_ready="nginx.service",
                                             allow_service_marker=True)
                complete_status(now + 5)
                now += 5

    def test_store_requires_matching_preflight_even_for_internal_control_caller(self):
        admin = self.request("POST", "/api/v1/session",
                             {"username": "admin", "password": "long-test-password"})[1]["token"]
        sid = self.request("POST", "/api/v1/servers", {"name": "preflight-host"}, admin)[1]["id"]
        self.request("POST", f"/api/v1/servers/{sid}/commands", {"enabled": True}, admin)
        service = build_service_command({"action": "restart", "unit": "nginx.service"})
        with self.assertRaisesRegex(ValueError, "matching status preflight"):
            self.store.queue_web_job(sid, admin, service, allow_service_marker=True)
        with self.assertRaisesRegex(ValueError, "matching status preflight"):
            self.store.queue_web_job(sid, admin, service,
                                     require_service_ready="other.service",
                                     allow_service_marker=True)
        with self.assertRaisesRegex(ValueError, "matching status preflight"):
            self.store.queue_web_job(sid, admin,
                                     "/usr/local/bin/sovagrid-amnezia-ctl revoke awg2 phone",
                                     allow_amnezia_marker=True)


if __name__ == "__main__":
    unittest.main()
