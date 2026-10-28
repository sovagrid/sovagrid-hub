# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
import hashlib
import json
import base64
import socket
import sqlite3
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from contextlib import closing
from pathlib import Path
from unittest import mock

from sovagrid_hub.http_api import HubApp, make_server
from sovagrid_hub.store import Store
from sovagrid_hub.telegram import TelegramBot


def metric(**overrides):
    result = {
        "collected_at": int(time.time()), "cpu_percent": 10, "memory_percent": 20,
        "disk_percent": 30, "network_rx_bytes": 100, "network_tx_bytes": 200,
        "load1": 0.5, "uptime_seconds": 3600,
    }
    result.update(overrides)
    return result


class HubIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp.name) / "hub.sqlite"
        self.store = Store(self.db_path, offline_seconds=5)
        self.store.initialize("admin", "very-long-test-password")
        self.app = HubApp(self.store)
        self.server = make_server(self.app, 0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temp.cleanup()

    def request(self, method, path, data=None, token=None, extra_headers=None):
        headers = dict(extra_headers or {})
        body = None
        if data is not None:
            headers["Content-Type"] = "application/json"
            body = json.dumps(data).encode()
        if token:
            headers["Authorization"] = "Bearer " + token
        request = urllib.request.Request(self.base + path, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as error:
            with error:
                return error.code, json.load(error)

    def admin_token(self):
        status, data = self.request("POST", "/api/v1/session", {"username": "admin", "password": "very-long-test-password"})
        self.assertEqual(status, 200)
        return data["token"]

    def test_login_limit_is_scoped_to_source_ip(self):
        bad = {"username": "admin", "password": "wrong"}
        first = {"X-SovaGrid-Client-IP": "198.51.100.11"}
        second = {"X-SovaGrid-Client-IP": "198.51.100.12"}
        for _ in range(5):
            self.assertEqual(self.request("POST", "/api/v1/session", bad, extra_headers=first)[0], 401)
        self.assertEqual(self.request("POST", "/api/v1/session", bad, extra_headers=first)[0], 429)
        self.assertEqual(self.request("POST", "/api/v1/session",
                                      {"username": "admin", "password": "very-long-test-password"},
                                      extra_headers=second)[0], 200)

    def test_admin_can_change_password_in_panel_and_revoke_all_sessions(self):
        first = self.admin_token()
        second = self.admin_token()
        _, server = self.request("POST", "/api/v1/servers", {"name": "password-test"}, first)
        sid = server["id"]
        self.request("POST", f"/api/v1/servers/{sid}/commands", {"enabled": True}, first)
        queued = self.request("POST", f"/api/v1/servers/{sid}/jobs", {"command": "echo never"}, first)[1]["job"]["id"]
        owner = hashlib.sha256(first.encode()).hexdigest()
        terminal, _ = self.app.terminals.create(sid, owner, "95051b07-c033-4f2a-b83f-ecb15db37d31", 80, 24)
        file_op, _ = self.app.files.create(sid, owner, "fb129cdc-c1e5-4bf2-959b-6c5f2290c5f2", {"action": "roots"})
        route = "/api/v1/admin/password"
        current = "very-long-test-password"
        new = "new-very-long-test-password"
        self.assertEqual(self.request("POST", route, {"current_password": current, "new_password": new})[0], 401)
        for invalid in ({"current_password": current},
                        {"current_password": current, "new_password": "short"},
                        {"current_password": current, "new_password": current},
                        {"current_password": current, "new_password": " " * 12}):
            self.assertEqual(self.request("POST", route, invalid, first)[0], 400)
        with mock.patch("sovagrid_hub.http_api.logging.info") as logs:
            changed = self.request("POST", route, {"current_password": current, "new_password": new}, second)
        self.assertEqual(changed, (200, {"changed": True, "sessions_revoked": True}))
        self.assertNotIn(current, str(logs.call_args_list))
        self.assertNotIn(new, str(logs.call_args_list))
        self.assertEqual(self.request("GET", "/api/v1/servers", token=first)[0], 401)
        self.assertEqual(self.request("GET", "/api/v1/servers", token=second)[0], 401)
        self.assertEqual(self.store.job(queued)["state"], "cancelled")
        self.assertEqual(self.app.terminals._sessions[terminal["id"]].state, "closed")
        self.assertEqual(self.app.terminals._sessions[terminal["id"]].reason, "session_revoked")
        self.assertNotIn(file_op["id"], self.app.files._operations)
        self.assertEqual(self.request("POST", "/api/v1/session",
                                      {"username": "admin", "password": current})[0], 401)
        self.assertEqual(self.request("POST", "/api/v1/session",
                                      {"username": "admin", "password": new})[0], 200)
        audit = json.dumps(self.store.audit_events())
        self.assertIn("password_changed", audit)
        self.assertNotIn(current, audit)
        self.assertNotIn(new, audit)

    def test_password_change_limits_wrong_current_password_by_session_and_ip(self):
        first = self.admin_token()
        second = self.admin_token()
        route = "/api/v1/admin/password"
        headers = {"X-SovaGrid-Client-IP": "198.51.100.41"}
        wrong = {"current_password": "wrong", "new_password": "some-other-valid-password"}
        for _ in range(5):
            self.assertEqual(self.request("POST", route, wrong, first, headers)[0], 403)
        self.assertEqual(self.request("POST", route, wrong, first, headers)[0], 429)
        self.assertEqual(self.request("POST", route, wrong, first,
                                      {"X-SovaGrid-Client-IP": "198.51.100.42"})[0], 429)
        self.assertEqual(self.request("POST", route, wrong, second, headers)[0], 429)
        self.assertEqual(self.request("POST", route,
                                      {"current_password": "very-long-test-password",
                                       "new_password": "some-other-valid-password"}, second,
                                      {"X-SovaGrid-Client-IP": "198.51.100.42"})[0], 200)

    def test_partial_body_times_out(self):
        with mock.patch("sovagrid_hub.http_api.READ_TIMEOUT_SECONDS", 0.2):
            with socket.create_connection(("127.0.0.1", self.server.server_port), timeout=2) as connection:
                connection.sendall(b"POST /api/v1/session HTTP/1.1\r\nHost: localhost\r\n"
                                   b"Content-Type: application/json\r\nContent-Length: 20\r\n"
                                   b"Connection: close\r\n\r\n{")
                self.assertIn(b" 408 ", connection.recv(4096))

    def test_slow_admin_body_cannot_grant_telegram_role_after_logout(self):
        token = self.admin_token()
        body = json.dumps({"user_id": 67890, "chat_id": 67890, "role": "admin"}).encode()
        checked = threading.Event()
        original = self.store.session_info

        def observed(value, *args, **kwargs):
            valid = original(value, *args, **kwargs)
            if value == token and valid:
                checked.set()
            return valid

        with mock.patch.object(self.store, "session_info", side_effect=observed):
            with socket.create_connection(("127.0.0.1", self.server.server_port), timeout=3) as connection:
                connection.sendall(
                    b"POST /api/v1/telegram/bindings HTTP/1.1\r\nHost: localhost\r\n"
                    + f"Authorization: Bearer {token}\r\n".encode()
                    + b"Content-Type: application/json\r\n"
                    + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
                    + body[:1])
                self.assertTrue(checked.wait(2), "Handler did not authenticate the partial request")
                self.store.logout(token)
                connection.sendall(body[1:])
                self.assertIn(b" 401 ", connection.recv(4096))
        self.assertIsNone(self.store.bot_role(67890, 67890))

    def test_slow_agent_body_cannot_report_after_token_rotation(self):
        admin = self.admin_token()
        _, created = self.request("POST", "/api/v1/servers", {"name": "rotating-agent"}, admin)
        server_id, token = created["id"], created["agent_token"]
        body = json.dumps(metric()).encode()
        checked = threading.Event()
        original = self.store.agent_valid

        def observed(sid, value):
            valid = original(sid, value)
            if sid == server_id and value == token and valid:
                checked.set()
            return valid

        with mock.patch.object(self.store, "agent_valid", side_effect=observed):
            with socket.create_connection(("127.0.0.1", self.server.server_port), timeout=3) as connection:
                connection.sendall(
                    f"POST /api/v1/servers/{server_id}/metrics HTTP/1.1\r\n".encode()
                    + b"Host: localhost\r\n"
                    + f"Authorization: Bearer {token}\r\n".encode()
                    + b"Content-Type: application/json\r\n"
                    + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
                    + body[:1])
                self.assertTrue(checked.wait(2), "Handler did not authenticate the partial request")
                self.store.rotate_agent_token(server_id)
                connection.sendall(body[1:])
                self.assertIn(b" 401 ", connection.recv(4096))
        self.assertIsNone(self.store.servers()[0]["last_seen"])

    def test_rotated_agent_cannot_lease_command_after_initial_bearer_check(self):
        admin = self.admin_token()
        _, server = self.request("POST", "/api/v1/servers", {"name": "lease-race"}, admin)
        sid, old_token = server["id"], server["agent_token"]
        self.assertEqual(self.request("POST", f"/api/v1/servers/{sid}/commands",
                                      {"enabled": True}, admin)[0], 200)
        queued = self.request("POST", f"/api/v1/servers/{sid}/jobs",
                              {"command": "printf guarded"}, admin)[1]["job"]["id"]
        original = self.store.agent_valid
        rotated = []

        def rotate_after_initial_check(server_id, token):
            valid = original(server_id, token)
            if server_id == sid and token == old_token and valid and not rotated:
                rotated.append(self.store.rotate_agent_token(sid))
            return valid

        with mock.patch.object(self.store, "agent_valid", side_effect=rotate_after_initial_check):
            self.assertEqual(self.request("GET", f"/api/v1/servers/{sid}/jobs/next",
                                          token=old_token)[0], 401)
        self.assertEqual(self.store.job(queued)["state"], "queued")
        self.assertEqual(self.request("GET", f"/api/v1/servers/{sid}/jobs/next",
                                      token=rotated[0])[1]["job"]["command"], "printf guarded")

    def test_rotation_after_lease_withholds_and_cancels_undisclosed_command(self):
        admin = self.admin_token()
        _, server = self.request("POST", "/api/v1/servers", {"name": "reply-race"}, admin)
        sid, old_token = server["id"], server["agent_token"]
        self.assertEqual(self.request("POST", f"/api/v1/servers/{sid}/commands",
                                      {"enabled": True}, admin)[0], 200)
        queued = self.request("POST", f"/api/v1/servers/{sid}/jobs",
                              {"command": "printf never-disclose"}, admin)[1]["job"]["id"]
        original = self.store.lease_job

        def rotate_after_lease(*args, **kwargs):
            job = original(*args, **kwargs)
            self.assertIsNotNone(job)
            self.store.rotate_agent_token(sid)
            return job

        with mock.patch.object(self.store, "lease_job", side_effect=rotate_after_lease):
            self.assertEqual(self.request("GET", f"/api/v1/servers/{sid}/jobs/next",
                                          token=old_token)[0], 401)
        self.assertEqual(self.store.job(queued)["state"], "cancelled")
        with self.store.connection() as db:
            self.assertEqual(db.execute("SELECT command FROM jobs WHERE id=?", (queued,)).fetchone()[0], "")
        self.assertNotIn("never-disclose", json.dumps(self.store.audit_events()))

    def test_monitoring_settings_live_persisted_and_conflict_safe(self):
        route = "/api/v1/monitoring/settings"
        admin = self.admin_token()
        self.assertEqual(self.request("GET", route)[0], 401)
        self.assertEqual(self.request("POST", route, {})[0], 401)
        self.assertEqual(self.request("GET", route, token=admin)[1]["settings"], {
            "high_cpu": 90.0, "high_memory": 90.0, "high_disk": 90.0,
            "offline_seconds": 5, "trigger_minutes": 0, "revision": 0})
        payload = {"high_cpu": 80, "high_memory": 85.5, "high_disk": 90,
                   "offline_seconds": 10, "trigger_minutes": 0, "revision": 0}
        for invalid in (
            {**payload, "high_cpu": True}, {**payload, "high_cpu": 10**400},
            {**payload, "high_memory": float("nan")},
            {**payload, "high_disk": 0}, {**payload, "offline_seconds": 9},
            {**payload, "offline_seconds": 10.5}, {**payload, "trigger_minutes": -1},
            {**payload, "trigger_minutes": True}, {**payload, "trigger_minutes": 1441},
            {**payload, "trigger_minutes": 1.5}, {**payload, "trigger_minutes": None},
            {**payload, "revision": True},
            {**payload, "unexpected": 1}, {key: value for key, value in payload.items() if key != "revision"},
        ):
            self.assertEqual(self.request("POST", route, invalid, admin)[0], 400)
        self.assertEqual(self.request("GET", route, token=admin)[1]["settings"]["revision"], 0)
        saved = self.request("POST", route, payload, admin)
        self.assertEqual(saved[0], 200)
        self.assertEqual(saved[1]["settings"]["revision"], 1)
        self.assertEqual(self.request("POST", route, payload, admin)[0], 409)
        self.assertEqual(self.store.monitoring_settings()["high_memory"], 85.5)

        _, created = self.request("POST", "/api/v1/servers", {"name": "live-settings"}, admin)
        sid, agent = created["id"], created["agent_token"]
        self.assertEqual(self.request("POST", f"/api/v1/servers/{sid}/metrics",
                                      metric(cpu_percent=84, memory_percent=86), agent)[0], 202)
        active = {item["kind"]: item for item in self.store.incidents(state="firing")}
        self.assertEqual(set(active), {"high_cpu", "high_memory"})
        self.assertEqual(active["high_cpu"]["threshold"], 80)
        seen = self.store.servers()[0]["last_seen"]
        self.assertEqual(self.store.sweep_offline(now=seen + 6), [])
        self.assertEqual(len(self.store.sweep_offline(now=seen + 11)), 1)
        self.assertIn("offline", {item["kind"] for item in self.store.incidents(state="firing")})

        updated = {**payload, "high_cpu": 95, "high_memory": 96,
                   "offline_seconds": 30, "revision": 1}
        self.assertEqual(self.request("POST", route, updated, admin)[0], 200)
        self.assertTrue(self.store.servers(now=seen + 11)[0]["online"])
        recovered = self.store.sweep_offline(now=seen + 11)
        self.assertEqual([(event["kind"], event["state"]) for event in recovered], [("offline", "resolved")])
        self.assertEqual(self.request("POST", f"/api/v1/servers/{sid}/metrics",
                                      metric(cpu_percent=84, memory_percent=86), agent)[0], 202)
        self.assertEqual(self.store.incidents(state="firing"), [])
        self.assertEqual(Store(self.db_path, offline_seconds=999,
                               thresholds={"high_cpu": 1}).monitoring_settings()["high_cpu"], 95)
        changed = [event for event in self.store.audit_events() if event["action"] == "monitoring_settings_changed"]
        self.assertEqual(len(changed), 2)

    def test_session_server_metrics_incident_and_logout(self):
        self.assertEqual(self.request("GET", "/api/v1/servers")[0], 401)
        self.assertEqual(self.request("POST", "/api/v1/session", {"username": "admin", "password": "wrong"})[0], 401)
        admin = self.admin_token()
        with mock.patch("sovagrid_hub.http_api.logging.info") as logs:
            self.request("GET", "/api/v1/servers", token=admin)
        self.assertNotIn(admin, str(logs.call_args_list))
        status, created = self.request("POST", "/api/v1/servers", {"name": "ubuntu-one"}, admin)
        self.assertEqual(status, 201)
        server_id = created["id"]
        agent = created["agent_token"]
        with closing(sqlite3.connect(self.db_path)) as db:
            stored = db.execute("SELECT agent_token_hash FROM servers WHERE id=?", (server_id,)).fetchone()[0]
            self.assertEqual(stored, hashlib.sha256(agent.encode()).hexdigest())
            self.assertNotIn(agent, self.db_path.read_bytes().decode("utf-8", errors="ignore"))
            self.assertNotIn(admin, self.db_path.read_bytes().decode("utf-8", errors="ignore"))
        sample = metric(cpu_percent=95)
        self.assertEqual(self.request("POST", f"/api/v1/servers/{server_id}/metrics", sample, "wrong")[0], 401)
        self.assertEqual(self.request("POST", f"/api/v1/servers/{server_id}/metrics", sample, agent)[0], 202)
        status, servers = self.request("GET", "/api/v1/servers", token=admin)
        self.assertEqual(status, 200)
        self.assertEqual(servers["servers"][0]["latest"]["cpu_percent"], 95)
        self.assertTrue(servers["servers"][0]["online"])
        status, history = self.request("GET", f"/api/v1/servers/{server_id}/metrics?limit=5", token=admin)
        self.assertEqual(status, 200)
        self.assertEqual(len(history["metrics"]), 1)
        status, incidents = self.request("GET", "/api/v1/incidents?state=firing", token=admin)
        self.assertEqual(status, 200)
        self.assertEqual(incidents["incidents"][0]["kind"], "high_cpu")
        incident_id = incidents["incidents"][0]["id"]
        self.assertEqual(self.request("POST", f"/api/v1/incidents/{incident_id}/ack", {}, admin)[0], 200)
        self.assertEqual(self.request("POST", f"/api/v1/servers/{server_id}/metrics", metric(cpu_percent=20), agent)[0], 202)
        status, resolved = self.request("GET", "/api/v1/incidents?state=resolved", token=admin)
        self.assertEqual(status, 200)
        self.assertEqual(resolved["incidents"][0]["kind"], "high_cpu")
        self.assertEqual(self.request("DELETE", "/api/v1/session", token=admin)[0], 200)
        self.assertEqual(self.request("GET", "/api/v1/servers", token=admin)[0], 401)

    def test_metric_validation_token_rotation_and_offline(self):
        admin = self.admin_token()
        _, created = self.request("POST", "/api/v1/servers", {"name": "host"}, admin)
        sid, agent = created["id"], created["agent_token"]
        self.assertEqual(self.request("POST", f"/api/v1/servers/{sid}/metrics", metric(cpu_percent=101), agent)[0], 422)
        self.assertEqual(self.request("POST", f"/api/v1/servers/{sid}/metrics", metric(network_rx_bytes=10**30), agent)[0], 422)
        self.assertEqual(self.request("POST", f"/api/v1/servers/{sid}/metrics", metric(), agent)[0], 202)
        self.assertEqual(len(self.store.sweep_offline(now=int(time.time()) + 6)), 1)
        self.assertEqual(len(self.store.sweep_offline(now=int(time.time()) + 6)), 0)
        _, rotated = self.request("POST", f"/api/v1/servers/{sid}/rotate-token", {}, admin)
        self.assertEqual(self.request("POST", f"/api/v1/servers/{sid}/metrics", metric(), agent)[0], 401)
        self.assertEqual(self.request("POST", f"/api/v1/servers/{sid}/metrics", metric(), rotated["agent_token"])[0], 202)
        self.assertEqual(len(self.store.incidents(state="firing")), 0)

    def test_failed_service_incident_waits_for_known_recovery(self):
        admin = self.admin_token()
        _, created = self.request("POST", "/api/v1/servers", {"name": "services-host"}, admin)
        sid, agent = created["id"], created["agent_token"]
        detail = {"services": {"failed_count": 2, "units": [
            {"name": "docker.service", "active": "failed", "sub": "failed"}]}}
        self.assertEqual(self.request("POST", f"/api/v1/servers/{sid}/metrics",
                                      metric(details=detail), agent)[0], 202)
        firing = self.store.incidents(state="firing")
        self.assertEqual([(row["kind"], row["current_value"]) for row in firing],
                         [("failed_services", 2.0)])
        self.assertEqual(self.request("POST", f"/api/v1/servers/{sid}/metrics",
                                      metric(details={}), agent)[0], 202)
        self.assertEqual(len(self.store.incidents(state="firing")), 1)
        self.assertEqual(self.request("POST", f"/api/v1/servers/{sid}/metrics",
                                      metric(details={"services": {"failed_count": 0, "units": []}}), agent)[0], 202)
        self.assertEqual(len(self.store.incidents(state="firing")), 0)
        self.assertEqual(self.store.incidents(state="resolved")[0]["kind"], "failed_services")

    def test_telegram_rbac_confirmation_and_agent_job(self):
        admin = self.admin_token()
        _, created = self.request("POST", "/api/v1/servers", {"name": "host"}, admin)
        sid, agent = created["id"], created["agent_token"]
        self.store.add_bot_user(100, 100, "viewer")
        self.store.add_bot_user(200, 200, "admin")
        sent = []
        bot = TelegramBot("fake-token", self.store)
        bot.send_message = lambda chat, text: sent.append((chat, text))
        update = lambda uid, text: {"message": {"chat": {"id": uid, "type": "private"}, "from": {"id": uid}, "text": text}}
        bot.process_update(update(100, f"/exec {sid} id"))
        self.assertEqual(sent, [])
        self.assertEqual(self.store.bot_role(100, 100), "viewer")
        self.store.add_bot_user(150, 150, "operator")
        bot.process_update(update(150, f"/exec {sid} id"))
        self.assertEqual(sent, [])
        self.assertEqual(self.request("POST", f"/api/v1/servers/{sid}/commands", {"enabled": True}, admin)[0], 200)
        bot.process_update(update(200, f"/exec {sid} printf hello"))
        code = sent[-1][1].split("/confirm ", 1)[1]
        self.assertIsNone(self.store.confirm_command(code, 100, 100))
        self.assertIsNone(self.store.confirm_command(code, 150, 150))
        self.assertIsNone(self.store.confirm_command(code, 200, 201))
        bot.process_update(update(200, "/confirm " + code))
        job_id = sent[-1][1].split()[-1]
        self.assertEqual(self.request("GET", f"/api/v1/servers/{sid}/jobs/next", token=agent)[1]["job"]["id"], job_id)
        self.assertIsNone(self.request("GET", f"/api/v1/servers/{sid}/jobs/next", token=agent)[1]["job"])
        status, result = self.request("POST", f"/api/v1/servers/{sid}/jobs/{job_id}/result",
                                      {"state": "succeeded", "exit_code": 0, "output": "hello"}, agent)
        self.assertEqual(status, 200)
        self.assertEqual(result["job"]["output"], "hello")
        bot.process_update(update(200, "/result " + job_id))
        self.assertIn("hello", sent[-1][1])
        audit = self.request("GET", "/api/v1/audit", token=admin)[1]["events"]
        self.assertTrue(any(event["action"] == "command_completed" for event in audit))
        self.assertNotIn("printf hello", json.dumps(audit))
        self.assertNotIn(agent, json.dumps(audit))
        self.assertNotIn(agent, json.dumps(self.request("GET", "/api/v1/servers", token=admin)[1]))
        self.assertEqual(self.request("GET", "/api/v1/jobs", token=agent)[0], 401)

    def test_telegram_checks_are_role_gated_and_hide_targets_even_in_names(self):
        created = self.store.create_server("checks-host")
        sid, token = created["id"], created["agent_token"]
        check_id = "8af0e77e-9d50-4dd8-a0b7-9a6d25d10001"
        secret = "private.example"
        expected_ip = "203.0.113.44"
        item = {"id": check_id, "name": f"Secret {secret}", "kind": "dns",
                "enabled": True, "host": secret, "record_type": "A",
                "expected_ip": expected_ip, "interval_seconds": 60, "timeout_seconds": 5}
        now = int(time.time())
        self.store.save_check_config(sid, {"revision": 0, "checks": [item]}, now=now)
        lease = self.store.claim_check(sid, token, {"protocol": 1}, now=now)["lease"]
        self.store.record_check_result(sid, check_id, token, {
            "lease_id": lease["id"], "config_revision": lease["config_revision"],
            "observed_at": now, "status": "up", "latency_ms": 3,
            "http_status": None, "tls_expires_at": None, "error_code": None}, now=now)
        self.store.add_bot_user(100, 100, "viewer")
        self.store.add_bot_user(150, 150, "operator")
        self.store.add_bot_user(200, 200, "admin")
        sent = []
        bot = TelegramBot("fake-token", self.store)
        bot.send_message = lambda chat, text: sent.append((chat, text))
        update = lambda uid, chat_id, kind, command: {
            "message": {"chat": {"id": chat_id, "type": kind},
                        "from": {"id": uid}, "text": command}}
        bot.process_update(update(999, 999, "private", "/checks"))
        bot.process_update(update(100, 100, "group", "/checks"))
        bot.process_update(update(100, 200, "private", "/checks"))
        self.assertEqual(sent, [])
        for uid in (100, 150, 200):
            bot.process_update(update(uid, uid, "private", "/checks"))
            self.assertEqual(sent[-1][0], uid)
            self.assertIn("DNS: доступна", sent[-1][1])
            self.assertIn(check_id[:8], sent[-1][1])
            self.assertNotIn(secret, sent[-1][1])
            self.assertNotIn(expected_ip, sent[-1][1])
            bot.process_update(update(uid, uid, "private", "/help"))
            self.assertIn("/checks", sent[-1][1])
        self.store.remove_bot_user(100, 100)
        before = len(sent)
        bot.process_update(update(100, 100, "private", "/checks"))
        self.assertEqual(len(sent), before)

    def test_telegram_vpn_private_chat_roles_and_redacted_inventory(self):
        path = Path(self.temp.name) / "vpn.json"
        snapshot = {"schema_version": 1, "source": "docker_cli", "source_status": "ok",
                    "collected_at": int(time.time()), "private_key": "must-never-leak",
                    "services": [{"name": "amnezia-awg2", "service": "untrusted label",
                                  "state": "running", "health": "healthy",
                                  "published_ports": [{"port": 42683, "protocol": "udp"}],
                                  "client_ip": "192.0.2.44", "environment": "must-never-leak"}]}
        path.write_text(json.dumps(snapshot))
        sent = []
        bot = TelegramBot("fake-token", self.store, vpn_status_path=str(path))
        bot.send_message = lambda chat, message: sent.append((chat, message))
        update = lambda uid, text, chat_type="private", chat_id=None: {
            "message": {"chat": {"id": uid if chat_id is None else chat_id, "type": chat_type},
                        "from": {"id": uid}, "text": text}}

        bot.process_update(update(999, "/vpn"))
        bot.process_update(update(100, "/vpn", "group"))
        self.assertEqual(sent, [])
        for user_id, role in ((100, "viewer"), (150, "operator"), (200, "admin")):
            self.store.add_bot_user(user_id, user_id, role)
            bot.process_update(update(user_id, "/vpn"))
            self.assertEqual(sent[-1][0], user_id)
            report = sent[-1][1]
            self.assertIn("AmneziaWG (awg2): running; Docker health: healthy", report)
            self.assertIn("не подтверждают работу VPN-подключения", report)
            self.assertNotIn("must-never-leak", report)
            self.assertNotIn("192.0.2.44", report)
            self.assertNotIn("untrusted label", report)
            bot.process_update(update(user_id, "/help"))
            self.assertIn("/vpn", sent[-1][1])
        before = len(sent)
        bot.process_update(update(100, "/vpn", chat_id=200))
        bot.process_update(update(999, "/vpn"))
        self.assertEqual(len(sent), before)

    def test_telegram_vpn_unavailable_stale_and_error_are_explicit(self):
        path = Path(self.temp.name) / "vpn.json"
        self.store.add_bot_user(100, 100, "viewer")
        sent = []
        bot = TelegramBot("fake-token", self.store, vpn_status_path=str(path))
        bot.send_message = lambda chat, message: sent.append(message)
        update = {"message": {"chat": {"id": 100, "type": "private"},
                              "from": {"id": 100}, "text": "/vpn"}}

        bot.process_update(update)
        self.assertIn("данные недоступны", sent[-1])
        self.assertIn("состояние неизвестно", sent[-1])
        self.assertIn("Управляемый WireGuard: данные недоступны", sent[-1])
        snapshot = {"schema_version": 1, "source": "docker_cli", "source_status": "ok",
                    "collected_at": int(time.time()) - 120,
                    "services": [{"name": "amnezia-awg", "state": "running", "health": "healthy",
                                  "published_ports": []}]}
        path.write_text(json.dumps(snapshot))
        bot.process_update(update)
        self.assertIn("данные устарели", sent[-1])
        self.assertNotIn("AmneziaWG: running", sent[-1])
        path.write_text("{malformed")
        bot.process_update(update)
        self.assertIn("ошибка мониторинга", sent[-1])
        with mock.patch("sovagrid_hub.telegram.read_vpn_status", side_effect=OSError("secret-path")):
            bot.process_update(update)
        self.assertIn("ошибка мониторинга", sent[-1])
        self.assertNotIn("secret-path", sent[-1])

    def test_telegram_vpn_managed_summary_excludes_peer_data(self):
        self.store.add_bot_user(100, 100, "viewer")
        sent = []
        bot = TelegramBot("fake-token", self.store)
        bot.send_message = lambda chat, message: sent.append(message)
        update = {"message": {"chat": {"id": 100, "type": "private"},
                              "from": {"id": 100}, "text": "/vpn"}}
        safe_snapshot = {"source_status": "unavailable", "services": [],
                         "managed": {"source_status": "ok", "instances": [{
                             "name": "personal", "state": "active", "client_count": 2,
                             "interface": "wg-sovagrid", "port": 51821,
                             "subnet": "10.77.0.0/24", "peer_key": "must-never-leak"}]}}
        with mock.patch("sovagrid_hub.telegram.read_vpn_status", return_value=safe_snapshot):
            bot.process_update(update)
        self.assertIn("personal: active; настроено клиентов: 2", sent[-1])
        self.assertIn("Amnezia/Docker: данные недоступны", sent[-1])
        for secret in ("10.77.0.0/24", "51821", "wg-sovagrid", "must-never-leak"):
            self.assertNotIn(secret, sent[-1])
        safe_snapshot["managed"]["instances"][0].update(state="error", client_count=None)
        with mock.patch("sovagrid_hub.telegram.read_vpn_status", return_value=safe_snapshot):
            bot.process_update(update)
        self.assertIn("personal: error; число клиентов неизвестно", sent[-1])
        self.assertNotIn("None", sent[-1])
        safe_snapshot["managed"]["source_status"] = "stale"
        with mock.patch("sovagrid_hub.telegram.read_vpn_status", return_value=safe_snapshot):
            bot.process_update(update)
        self.assertIn("Управляемый WireGuard: данные устарели", sent[-1])
        self.assertNotIn("personal: error", sent[-1])
        safe_snapshot["managed"]["source_status"] = "error"
        with mock.patch("sovagrid_hub.telegram.read_vpn_status", return_value=safe_snapshot):
            bot.process_update(update)
        self.assertIn("Управляемый WireGuard: ошибка мониторинга", sent[-1])
        self.assertNotIn("personal: error", sent[-1])

    def test_web_command_opt_in_audit_result_and_session_revocation(self):
        admin = self.admin_token()
        _, created = self.request("POST", "/api/v1/servers", {"name": "web-command-host"}, admin)
        sid, agent = created["id"], created["agent_token"]
        route = f"/api/v1/servers/{sid}/jobs"
        command = "printf web-panel-result"
        self.assertEqual(self.request("POST", route, {"command": command})[0], 401)
        self.assertEqual(self.request("POST", route, {"command": command}, agent)[0], 401)
        self.assertEqual(self.request("POST", route, {"command": command}, admin)[0], 403)
        self.assertEqual(self.request("POST", "/api/v1/servers/no-such-host/jobs", {"command": command}, admin)[0], 404)
        self.assertEqual(self.request("POST", f"/api/v1/servers/{sid}/commands", {"enabled": True}, admin)[0], 200)
        for invalid in ("", "  ", "a" * 2049, "a\x00b"):
            self.assertEqual(self.request("POST", route, {"command": invalid}, admin)[0], 400)
        self.assertEqual(self.request("POST", route, {"command": command, "timeout_seconds": 300}, admin)[0], 400)
        status, queued = self.request("POST", route, {"command": command}, admin)
        self.assertEqual(status, 201)
        job_id = queued["job"]["id"]
        self.assertEqual(queued["job"]["source"], "web")
        self.assertNotIn("command", queued["job"])
        listed = self.request("GET", "/api/v1/jobs", token=admin)[1]["jobs"]
        self.assertEqual(listed[0]["id"], job_id)
        self.assertNotIn(command, json.dumps(listed))
        self.assertEqual(self.request("GET", f"/api/v1/jobs/{job_id}", token=agent)[0], 401)
        self.assertEqual(self.request("GET", "/api/v1/jobs/not-found", token=admin)[0], 404)
        leased = self.request("GET", f"/api/v1/servers/{sid}/jobs/next", token=agent)[1]["job"]
        self.assertEqual(leased["id"], job_id)
        self.assertEqual(leased["command"], command)
        self.assertEqual(leased["timeout_seconds"], 15)
        self.assertEqual(leased["output_limit_bytes"], 8192)
        self.assertIsNone(self.request("GET", f"/api/v1/servers/{sid}/jobs/next", token=agent)[1]["job"])
        self.assertEqual(self.request("POST", f"/api/v1/servers/{sid}/jobs/{job_id}/result",
                                      {"state": "succeeded", "exit_code": 0, "output": "web-panel-result"}, agent)[0], 200)
        detail = self.request("GET", f"/api/v1/jobs/{job_id}", token=admin)[1]["job"]
        self.assertEqual(detail["state"], "succeeded")
        self.assertEqual(detail["output"], "web-panel-result")
        self.assertNotIn("command", detail)
        audit = self.request("GET", "/api/v1/audit", token=admin)[1]["events"]
        queue_events = [event for event in audit if event["action"] == "command_queued" and event["subject_id"] == job_id]
        self.assertEqual(len(queue_events), 1)
        self.assertEqual(json.loads(queue_events[0]["details"])["command_sha256"], hashlib.sha256(command.encode()).hexdigest())
        self.assertNotIn(command, json.dumps(audit))

        pending = self.request("POST", route, {"command": "printf never-execute"}, admin)[1]["job"]["id"]
        self.assertEqual(self.request("DELETE", "/api/v1/session", token=admin)[0], 200)
        self.assertIsNone(self.request("GET", f"/api/v1/servers/{sid}/jobs/next", token=agent)[1]["job"])
        self.assertEqual(self.store.job(pending)["state"], "cancelled")
        self.assertEqual(self.store.job(job_id)["state"], "succeeded")

    def test_web_command_idempotency_key_prevents_duplicate_execution(self):
        admin = self.admin_token()
        _, created = self.request("POST", "/api/v1/servers", {"name": "dedupe-host"}, admin)
        sid, agent = created["id"], created["agent_token"]
        self.request("POST", f"/api/v1/servers/{sid}/commands", {"enabled": True}, admin)
        route = f"/api/v1/servers/{sid}/jobs"
        key = "e7ba3975-dba2-47ce-82c7-303edb43f517"
        headers = {"Idempotency-Key": key}
        self.assertEqual(self.request("POST", route, {"command": "id"}, admin,
                                      {"Idempotency-Key": "not-a-uuid"})[0], 400)
        status, first = self.request("POST", route, {"command": "id"}, admin, headers)
        self.assertEqual(status, 201)
        status, again = self.request("POST", route, {"command": "id"}, admin, headers)
        self.assertEqual(status, 200)
        self.assertEqual(again, first)
        self.assertEqual(self.request("POST", route, {"command": "uptime"}, admin, headers)[0], 409)
        self.assertEqual(self.request("GET", f"/api/v1/servers/{sid}/jobs/next", token=agent)[1]["job"]["id"],
                         first["job"]["id"])
        self.assertEqual(self.request("POST", route, {"command": "id"}, admin, headers)[1]["job"]["id"],
                         first["job"]["id"])
        with closing(sqlite3.connect(self.db_path)) as db:
            self.assertEqual(db.execute("SELECT command FROM jobs WHERE id=?", (first["job"]["id"],)).fetchone()[0], "")
        self.assertIsNone(self.request("GET", f"/api/v1/servers/{sid}/jobs/next", token=agent)[1]["job"])
        audit = self.request("GET", "/api/v1/audit", token=admin)[1]["events"]
        self.assertEqual(len([event for event in audit if event["action"] == "command_queued"]), 1)

    def test_vpn_actions_require_admin_opt_in_and_exact_schema(self):
        admin = self.admin_token()
        _, created = self.request("POST", "/api/v1/servers", {"name": "vpn-host"}, admin)
        sid, agent = created["id"], created["agent_token"]
        route = f"/api/v1/servers/{sid}/vpn/actions"
        header = {"Idempotency-Key": "2df23ee0-aac6-42c0-9466-77f5627c248f"}
        create = {"action": "create", "name": "personal", "port": 51820,
                  "subnet": "10.49.0.0/24", "endpoint": "vpn.example.com"}
        self.assertEqual(self.request("POST", route, create, extra_headers=header)[0], 401)
        self.assertEqual(self.request("POST", route, create, agent, header)[0], 401)
        self.assertEqual(self.request("POST", route, create, admin, header)[0], 403)
        self.assertEqual(self.request("POST", f"/api/v1/servers/no-such-server/vpn/actions",
                                      create, admin, header)[0], 404)
        self.assertEqual(self.request("POST", f"/api/v1/servers/{sid}/commands",
                                      {"enabled": True}, admin)[0], 200)
        self.assertEqual(self.request("POST", route, create, admin)[0], 400)
        self.assertEqual(self.request("POST", route, create, admin,
                                      {"Idempotency-Key": "not-a-uuid"})[0], 400)
        invalid = [
            {**create, "action": "export-client", "output": "/tmp/profile"},
            {**create, "action": "recover"},
            {**create, "command": "id"},
            {**create, "name": "a; id"},
            {**create, "name": "../etc"},
            {**create, "port": True},
            {**create, "port": "51820"},
            {**create, "port": 80},
            {**create, "subnet": "8.8.8.0/24"},
            {**create, "subnet": "10.49.0.1/24"},
            {**create, "subnet": "10.49.0.0/23"},
            {**create, "endpoint": "vpn.example.com; id"},
            {**create, "endpoint": "$(id).example.com"},
            {"action": "add-client", "name": "personal", "client": "bob; id"},
            {"action": "remove", "name": "personal", "confirm_name": "other"},
            {"action": "activate", "name": "personal", "port": 51820},
            {"action": "sealed-export", "name": "personal", "client": "phone_1", "public_key": "bad"},
            {"action": "sealed-export", "name": "personal", "client": "phone_1", "public_key": "A" * 87},
            {"action": "sealed-export", "name": "personal", "client": "phone_1",
             "public_key": base64.urlsafe_b64encode(b"\x04" + b"\x00" * 64).decode().rstrip("="),
             "route": "unsafe"},
            {"action": "sealed-export", "name": "personal", "client": "phone_1",
             "public_key": base64.urlsafe_b64encode(b"\x04" + b"\x00" * 64).decode().rstrip("=") + ";id"},
        ]
        for value in invalid:
            with self.subTest(value=value):
                self.assertEqual(self.request("POST", route, value, admin, header)[0], 400)
        self.assertEqual(self.request("GET", "/api/v1/jobs", token=admin)[1]["jobs"], [])

    def test_vpn_actions_queue_fixed_broker_commands_once_and_audit(self):
        admin = self.admin_token()
        _, created = self.request("POST", "/api/v1/servers", {"name": "vpn-actions"}, admin)
        sid, agent = created["id"], created["agent_token"]
        self.request("POST", f"/api/v1/servers/{sid}/commands", {"enabled": True}, admin)
        route = f"/api/v1/servers/{sid}/vpn/actions"
        public_key = base64.urlsafe_b64encode(b"\x04" + b"\x00" * 64).decode().rstrip("=")
        cases = [
            ({"action": "create", "name": "personal", "port": 51821,
              "subnet": "10.49.0.0/24", "endpoint": "VPN.Example.COM"},
             "/usr/local/bin/sovagrid-vpn-ctl create personal --port 51821 --subnet 10.49.0.0/24 --endpoint vpn.example.com"),
            ({"action": "activate", "name": "personal"},
             "/usr/local/bin/sovagrid-vpn-ctl activate personal"),
            ({"action": "add-client", "name": "personal", "client": "phone_1"},
             "/usr/local/bin/sovagrid-vpn-ctl add-client personal phone_1"),
            ({"action": "revoke-client", "name": "personal", "client": "phone_1"},
             "/usr/local/bin/sovagrid-vpn-ctl revoke-client personal phone_1"),
            ({"action": "sealed-export", "name": "personal", "client": "phone_1", "public_key": public_key},
             f"/usr/local/bin/sovagrid-vpn-ctl sealed-export personal phone_1 {public_key}"),
            ({"action": "sealed-export", "name": "personal", "client": "phone_1",
              "public_key": public_key, "route": "full"},
             f"/usr/local/bin/sovagrid-vpn-ctl sealed-export personal phone_1 {public_key} --route full"),
            ({"action": "remove", "name": "personal", "confirm_name": "personal"},
             "/usr/local/bin/sovagrid-vpn-ctl remove personal --confirm-name personal"),
        ]
        for index, (payload, expected_command) in enumerate(cases):
            with self.subTest(action=payload["action"]):
                header = {"Idempotency-Key": f"ed9abe93-dd34-4d2b-853e-{index:012d}"}
                status, first = self.request("POST", route, payload, admin, header)
                self.assertEqual(status, 201)
                job_id = first["job"]["id"]
                self.assertEqual(first["job"]["state"], "queued")
                self.assertNotIn("command", first["job"])
                self.assertEqual(self.request("POST", route, payload, admin, header), (200, first))
                leased = self.request("GET", f"/api/v1/servers/{sid}/jobs/next", token=agent)[1]["job"]
                self.assertEqual(leased["id"], job_id)
                self.assertEqual(leased["command"], expected_command)
                self.assertEqual(leased["timeout_seconds"], 105)
                self.assertNotIn("sudo", leased["command"])
                self.assertEqual(self.request("POST", route, payload, admin, header)[1]["job"]["id"], job_id)
                with closing(sqlite3.connect(self.db_path)) as db:
                    self.assertEqual(db.execute("SELECT command FROM jobs WHERE id=?", (job_id,)).fetchone()[0], "")
        self.assertIsNone(self.request("GET", f"/api/v1/servers/{sid}/jobs/next", token=agent)[1]["job"])
        audit = self.request("GET", "/api/v1/audit", token=admin)[1]["events"]
        self.assertEqual(len([event for event in audit if event["action"] == "command_queued"]), len(cases))
        self.assertNotIn("PrivateKey", json.dumps(audit))

    def test_vpn_action_idempotency_conflict_across_commands_and_servers(self):
        admin = self.admin_token()
        first = self.request("POST", "/api/v1/servers", {"name": "vpn-one"}, admin)[1]
        second = self.request("POST", "/api/v1/servers", {"name": "vpn-two"}, admin)[1]
        for sid in (first["id"], second["id"]):
            self.request("POST", f"/api/v1/servers/{sid}/commands", {"enabled": True}, admin)
        route = f"/api/v1/servers/{first['id']}/vpn/actions"
        key = {"Idempotency-Key": "8ee9543d-654c-4590-bfc8-4f63044dcbf0"}
        payload = {"action": "activate", "name": "personal"}
        self.assertEqual(self.request("POST", route, payload, admin, key)[0], 201)
        self.assertEqual(self.request("POST", route, {"action": "activate", "name": "another"},
                                      admin, key)[0], 409)
        self.assertEqual(self.request("POST", f"/api/v1/servers/{second['id']}/vpn/actions",
                                      payload, admin, key)[0], 409)
        self.assertEqual(len(self.request("GET", "/api/v1/jobs", token=admin)[1]["jobs"]), 1)

    def test_vpn_timeout_requires_exact_canonical_broker_command(self):
        admin = self.admin_token()
        created = self.request("POST", "/api/v1/servers", {"name": "vpn-timeout"}, admin)[1]
        sid, agent = created["id"], created["agent_token"]
        self.request("POST", f"/api/v1/servers/{sid}/commands", {"enabled": True}, admin)
        route = f"/api/v1/servers/{sid}/jobs"
        for command in (
            "/usr/local/bin/sovagrid-vpn-ctl activate personal; id",
            "/usr/local/bin/sovagrid-vpn-ctl export-client personal phone --output /tmp/profile",
            "/usr/local/bin/sovagrid-vpn-ctl sealed-export personal phone badkey",
            "/usr/local/bin/sovagrid-vpn-ctl sealed-export personal phone badkey --route full",
            "/usr/local/bin/sovagrid-vpn-ctl create personal --port 051821 --subnet 10.49.0.0/24 --endpoint vpn.example.com",
        ):
            self.assertEqual(self.request("POST", route, {"command": command}, admin)[0], 400)
        self.assertEqual(self.request("POST", route, {"command": "echo ordinary"}, admin)[0], 201)
        leased = self.request("GET", f"/api/v1/servers/{sid}/jobs/next", token=agent)[1]["job"]
        self.assertEqual(leased["timeout_seconds"], 15)

    def test_interactive_terminal_relay_auth_order_and_no_persistent_bytes(self):
        admin = self.admin_token()
        other_login = self.admin_token()
        created = self.request("POST", "/api/v1/servers", {"name": "terminal-host"}, admin)[1]
        sid, agent = created["id"], created["agent_token"]
        route = f"/api/v1/servers/{sid}/terminal/sessions"
        key = {"Idempotency-Key": "43f98809-35b7-4ccb-a1f3-c0df94e5391c"}
        self.assertEqual(self.request("POST", route, {"cols": 80, "rows": 24}, admin, key)[0], 403)
        self.request("POST", f"/api/v1/servers/{sid}/commands", {"enabled": True}, admin)
        status, response = self.request("POST", route, {"cols": 80, "rows": 24}, admin, key)
        self.assertEqual(status, 201)
        terminal_id = response["session"]["id"]
        self.assertEqual(self.request("POST", route, {"cols": 80, "rows": 24}, admin, key), (200, response))
        self.assertEqual(self.request("POST", route, {"cols": 81, "rows": 24}, admin, key)[0], 409)
        self.assertEqual(self.request("POST", route, {"cols": 80, "rows": 24}, admin,
                                      {"Idempotency-Key": "46fd3282-b8d0-413b-9f92-6d3bea0317ba"})[0], 429)
        base = f"{route}/{terminal_id}"
        self.assertEqual(self.request("GET", base + "/events?after=99", token=other_login)[0], 403)
        self.assertEqual(self.request("GET", base + "/events?after=99")[0], 401)
        leased = self.request("GET", f"/api/v1/servers/{sid}/terminal/next", token=agent)[1]["session"]
        self.assertEqual(leased, {"id": terminal_id, "cols": 80, "rows": 24})
        self.assertEqual(self.request("POST", base + "/ready", {}, agent), (200, {"state": "active"}))
        encoded_input = base64.urlsafe_b64encode(b"echo secret-marker\n").decode().rstrip("=")
        encoded_output = base64.urlsafe_b64encode(b"hello\x1b[31m\n").decode().rstrip("=")
        self.assertEqual(self.request("POST", base + "/input", {"seq": 1, "data": encoded_input}, admin)[0], 202)
        self.assertEqual(self.request("POST", base + "/input", {"seq": 1, "data": encoded_input}, admin)[0], 200)
        self.assertEqual(self.request("POST", base + "/input", {"seq": 1, "data": "eA"}, admin)[0], 409)
        self.assertEqual(self.request("POST", base + "/resize", {"seq": 2, "cols": 100, "rows": 30}, admin)[0], 202)
        controls = self.request("GET", base + "/controls?after=0", token=agent)[1]
        self.assertEqual([event["type"] for event in controls["events"]], ["input", "resize"])
        self.assertEqual(controls["next_after"], 2)
        self.assertEqual(self.request("POST", base + "/output", {"seq": 1, "data": encoded_output}, agent)[0], 202)
        self.assertEqual(self.request("POST", base + "/output", {"seq": 1, "data": encoded_output}, agent)[0], 200)
        output = self.request("GET", base + "/events?after=0", token=admin)[1]
        self.assertEqual(output["events"], [{"seq": 1, "type": "output", "data": encoded_output}])
        self.assertEqual(output["next_after"], 1)
        self.assertEqual(self.request("POST", base + "/exit", {"exit_code": None}, agent)[0], 200)
        closed = self.request("GET", base + "/events?after=1", token=admin)[1]
        self.assertEqual((closed["state"], closed["reason"]), ("closed", "process_exit"))
        self.assertEqual(self.request("DELETE", base, token=admin), (200, {"closed": True}))
        with closing(sqlite3.connect(self.db_path)) as db:
            for table in ("jobs", "audit_events"):
                self.assertNotIn("secret-marker", str(db.execute(f"SELECT * FROM {table}").fetchall()))

    def test_interactive_terminal_revocation_closes_agent_controls(self):
        admin = self.admin_token()
        created = self.request("POST", "/api/v1/servers", {"name": "revoked-pty"}, admin)[1]
        sid, agent = created["id"], created["agent_token"]
        self.request("POST", f"/api/v1/servers/{sid}/commands", {"enabled": True}, admin)
        route = f"/api/v1/servers/{sid}/terminal/sessions"
        session = self.request("POST", route, {"cols": 80, "rows": 24}, admin,
                               {"Idempotency-Key": "602912c9-5132-472b-96ec-770c536f77e4"})[1]["session"]
        base = f"{route}/{session['id']}"
        self.request("GET", f"/api/v1/servers/{sid}/terminal/next", token=agent)
        self.request("POST", base + "/ready", {}, agent)
        self.request("DELETE", "/api/v1/session", token=admin)
        control = self.request("GET", base + "/controls?after=0", token=agent)[1]
        self.assertEqual((control["state"], control["reason"]), ("closed", "session_revoked"))
        self.assertEqual(self.request("POST", base + "/input", {"seq": 1, "data": "eA"}, admin)[0], 401)

    def test_terminal_events_do_not_disclose_output_after_logout_during_response(self):
        admin = self.admin_token()
        created = self.request("POST", "/api/v1/servers", {"name": "logout-race"}, admin)[1]
        sid, agent = created["id"], created["agent_token"]
        self.request("POST", f"/api/v1/servers/{sid}/commands", {"enabled": True}, admin)
        route = f"/api/v1/servers/{sid}/terminal/sessions"
        terminal_id = self.request("POST", route, {"cols": 80, "rows": 24}, admin,
                                   {"Idempotency-Key": "12275536-ecbf-46f6-85e8-908802a8e6f1"})[1]["session"]["id"]
        base = f"{route}/{terminal_id}"
        self.request("GET", f"/api/v1/servers/{sid}/terminal/next", token=agent)
        self.request("POST", base + "/ready", {}, agent)
        self.request("POST", base + "/output", {"seq": 1, "data": "c2VjcmV0"}, agent)
        returned, release = threading.Event(), threading.Event()
        original = self.app.terminals.events

        def pause_after_events(*args):
            result = original(*args)
            returned.set()
            release.wait(2)
            return result

        results = []
        with mock.patch.object(self.app.terminals, "events", side_effect=pause_after_events):
            worker = threading.Thread(target=lambda: results.append(self.request("GET", base + "/events?after=0", token=admin)))
            worker.start()
            try:
                self.assertTrue(returned.wait(2))
                self.request("DELETE", "/api/v1/session", token=admin)
            finally:
                release.set()
                worker.join(2)
        self.assertFalse(worker.is_alive())
        self.assertEqual(results[0][0], 401)
        self.assertNotIn("secret", str(results[0]))

    def test_terminal_controls_do_not_disclose_input_after_agent_rotation(self):
        admin = self.admin_token()
        created = self.request("POST", "/api/v1/servers", {"name": "rotation-race"}, admin)[1]
        sid, agent = created["id"], created["agent_token"]
        self.request("POST", f"/api/v1/servers/{sid}/commands", {"enabled": True}, admin)
        route = f"/api/v1/servers/{sid}/terminal/sessions"
        terminal_id = self.request("POST", route, {"cols": 80, "rows": 24}, admin,
                                   {"Idempotency-Key": "f8dd6ddb-599e-480e-a90f-ec2d01975871"})[1]["session"]["id"]
        base = f"{route}/{terminal_id}"
        self.request("GET", f"/api/v1/servers/{sid}/terminal/next", token=agent)
        self.request("POST", base + "/ready", {}, agent)
        self.request("POST", base + "/input", {"seq": 1, "data": "c2VjcmV0"}, admin)
        returned, release = threading.Event(), threading.Event()
        original = self.app.terminals.controls

        def pause_after_controls(*args):
            result = original(*args)
            returned.set()
            release.wait(2)
            return result

        results = []
        with mock.patch.object(self.app.terminals, "controls", side_effect=pause_after_controls):
            worker = threading.Thread(target=lambda: results.append(self.request("GET", base + "/controls?after=0", token=agent)))
            worker.start()
            try:
                self.assertTrue(returned.wait(2))
                self.request("POST", f"/api/v1/servers/{sid}/rotate-token", {}, admin)
            finally:
                release.set()
                worker.join(2)
        self.assertFalse(worker.is_alive())
        self.assertEqual(results[0][0], 401)
        self.assertNotIn("secret", str(results[0]))

    def test_vpn_inventory_is_admin_only_and_redacted(self):
        path = Path(self.temp.name) / "vpn.json"
        self.app.vpn_status_path = str(path)
        self.assertEqual(self.request("GET", "/api/v1/vpn")[0], 401)
        admin = self.admin_token()
        self.assertEqual(self.request("GET", "/api/v1/vpn", token=admin)[1]["vpn"]["source_status"], "unavailable")
        snapshot = {"schema_version": 1, "collected_at": int(time.time()), "source": "docker_cli",
                    "source_status": "ok", "secret": "must-never-leak", "services": [
                        {"name": "amnezia-awg2", "service": "untrusted label", "state": "running",
                         "health": "healthy", "published_ports": [{"port": 42683, "protocol": "udp"}],
                         "environment": "must-never-leak"}]}
        path.write_text(json.dumps(snapshot))
        result = self.request("GET", "/api/v1/vpn", token=admin)[1]["vpn"]
        self.assertEqual(result["source_status"], "ok")
        self.assertEqual(result["services"][0]["service"], "AmneziaWG (awg2)")
        self.assertNotIn("must-never-leak", json.dumps(result))
        snapshot["collected_at"] -= 120
        path.write_text(json.dumps(snapshot))
        self.assertEqual(self.request("GET", "/api/v1/vpn", token=admin)[1]["vpn"]["source_status"], "stale")
        path.write_text("{malformed")
        self.assertEqual(self.request("GET", "/api/v1/vpn", token=admin)[1]["vpn"]["source_status"], "error")

    def test_web_queued_job_does_not_survive_expired_or_changed_admin_session(self):
        admin = self.admin_token()
        _, created = self.request("POST", "/api/v1/servers", {"name": "host"}, admin)
        sid, agent = created["id"], created["agent_token"]
        self.store.set_remote_commands(sid, True)
        queued, _ = self.store.queue_web_job(sid, admin, "true", now=int(time.time()))
        with self.store.connection() as db:
            db.execute("UPDATE sessions SET expires_at=0")
        self.assertIsNone(self.store.lease_job(sid))
        self.assertEqual(self.store.job(queued["id"])["state"], "cancelled")
        self.assertEqual(self.request("GET", f"/api/v1/servers/{sid}/jobs/next", token=agent)[1]["job"], None)
        second = self.admin_token()
        queued, _ = self.store.queue_web_job(sid, second, "true")
        self.assertTrue(self.store.change_password("admin", "very-long-test-password", "new-very-long-test-password"))
        self.assertEqual(self.store.job(queued["id"])["state"], "cancelled")
        self.assertIsNone(self.store.lease_job(sid))

    def test_command_expiry_and_opt_in(self):
        created = self.store.create_server("host")
        sid = created["id"]
        self.store.add_bot_user(1, 1, "admin")
        with self.assertRaises(PermissionError):
            self.store.request_command(sid, 1, 1, "id")
        self.store.set_remote_commands(sid, True)
        code = self.store.request_command(sid, 1, 1, "id", now=100)
        self.assertIsNone(self.store.confirm_command(code, 1, 1, now=161))
        code = self.store.request_command(sid, 1, 1, "id", now=200)
        job = self.store.confirm_command(code, 1, 1, now=201)
        self.assertIsNotNone(job)
        self.assertIsNone(self.store.confirm_command(code, 1, 1, now=202))
        self.store.set_remote_commands(sid, False)
        self.assertIsNone(self.store.lease_job(sid))

    def test_admin_demotion_and_removal_cancel_pending_and_queued(self):
        sid = self.store.create_server("host")["id"]
        self.store.set_remote_commands(sid, True)
        self.store.add_bot_user(10, 10, "admin")
        pending = self.store.request_command(sid, 10, 10, "id")
        queued = self.store.confirm_command(self.store.request_command(sid, 10, 10, "true"), 10, 10)
        self.store.add_bot_user(10, 10, "viewer")
        self.assertIsNone(self.store.confirm_command(pending, 10, 10))
        self.assertIsNone(self.store.lease_job(sid))
        self.assertEqual(next(item for item in self.store.jobs() if item["id"] == queued["id"])["state"], "cancelled")
        with self.assertRaises(PermissionError):
            self.store.request_command(sid, 10, 10, "id")
        self.store.add_bot_user(10, 10, "admin")
        pending = self.store.request_command(sid, 10, 10, "id")
        queued = self.store.confirm_command(self.store.request_command(sid, 10, 10, "true"), 10, 10)
        self.store.remove_bot_user(10, 10)
        self.assertIsNone(self.store.confirm_command(pending, 10, 10))
        self.assertIsNone(self.store.lease_job(sid))
        self.assertEqual(next(item for item in self.store.jobs() if item["id"] == queued["id"])["state"], "cancelled")
        self.store.add_bot_user(10, 10, "admin")
        delivered = self.store.confirm_command(self.store.request_command(sid, 10, 10, "true"), 10, 10)
        self.assertEqual(self.store.lease_job(sid)["id"], delivered["id"])
        self.store.remove_bot_user(10, 10)
        self.assertEqual(next(item for item in self.store.jobs() if item["id"] == delivered["id"])["state"], "delivered")

    def test_detailed_metrics_round_trip_and_reject_unbounded_data(self):
        admin = self.admin_token()
        _, created = self.request("POST", "/api/v1/servers", {"name": "detailed"}, admin)
        sid, agent = created["id"], created["agent_token"]
        details = {
            "swap": {"total_bytes": 1000, "free_bytes": 600, "used_percent": 40},
            "filesystems": [{"mountpoint": "/", "fstype": "ext4", "total_bytes": 1000,
                             "available_bytes": 400, "used_percent": 60, "inodes_total": 100,
                             "inodes_available": 30, "inodes_used_percent": 70}],
            "interfaces": [{"name": "eth0", "rx_bytes": 100, "tx_bytes": 200,
                            "rx_errors": 1, "tx_errors": 2}],
            "load5": 0.4, "load15": 0.2,
            "processes": {"running": 2, "blocked": 1},
            "disk_io": [{"device": "sda", "read_bytes": 1024, "write_bytes": 2048}],
            "cpu_times": {"iowait_percent": 3.5, "steal_percent": 1.25},
            "pressure": {"cpu": {"some": {"avg10": 1.5, "avg60": 1.0, "avg300": 0.5, "total_us": 12345}},
                         "io": {"some": {"avg10": 2.0, "avg60": 1.0, "avg300": 0.5, "total_us": 200},
                                "full": {"avg10": 0.1, "avg60": 0.2, "avg300": 0.3, "total_us": 20}}},
            "services": {"failed_count": 1, "units": [
                {"name": "docker.service", "active": "failed", "sub": "failed"}]},
        }
        self.assertEqual(self.request("POST", f"/api/v1/servers/{sid}/metrics", metric(details=details), agent),
                         (202, {"accepted": True, "metric_details": ["pressure", "cpu_times"]}))
        latest = self.request("GET", "/api/v1/servers", token=admin)[1]["servers"][0]["latest"]
        self.assertEqual(latest["details"]["filesystems"][0]["inodes_used_percent"], 70)
        history = self.request("GET", f"/api/v1/servers/{sid}/metrics", token=admin)[1]["metrics"]
        self.assertEqual(history[0]["details"]["disk_io"][0]["read_bytes"], 1024)
        self.assertEqual(history[0]["details"]["services"]["units"][0]["active"], "failed")
        self.assertEqual(history[0]["details"]["pressure"]["io"]["full"]["total_us"], 20)
        self.assertEqual(history[0]["details"]["cpu_times"]["steal_percent"], 1.25)
        self.assertEqual(self.request("POST", f"/api/v1/servers/{sid}/metrics", metric(details={"logs": "secret"}), agent)[0], 422)
        oversized = details | {"interfaces": [details["interfaces"][0] | {"name": f"eth{n}"} for n in range(17)]}
        self.assertEqual(self.request("POST", f"/api/v1/servers/{sid}/metrics", metric(details=oversized), agent)[0], 422)
        unsafe = details | {"services": {"failed_count": 1, "units": [
            {"name": "../token.service", "active": "failed", "sub": "failed"}]}}
        self.assertEqual(self.request("POST", f"/api/v1/servers/{sid}/metrics", metric(details=unsafe), agent)[0], 422)
        self.assertEqual(len(self.store.history(sid)), 1)

    def test_top_processes_are_admin_only_bounded_and_not_persisted(self):
        admin = self.admin_token()
        _, created = self.request("POST", "/api/v1/servers", {"name": "processes"}, admin)
        sid, agent = created["id"], created["agent_token"]
        top = [{"pid": 42, "name": "python3", "rss_bytes": 409600},
               {"pid": 7, "name": "sshd", "rss_bytes": 81920}]
        route = f"/api/v1/servers/{sid}/metrics"
        self.assertEqual(self.request("POST", route, metric(details={"top_processes": top}), agent)[0], 202)
        self.assertEqual(self.request("GET", "/api/v1/servers")[0], 401)
        self.assertEqual(self.request("GET", "/api/v1/servers", token=agent)[0], 401)
        latest = self.request("GET", "/api/v1/servers", token=admin)[1]["servers"][0]["latest"]
        self.assertEqual(latest["details"]["top_processes"], top)
        self.assertNotIn("top_processes", self.request("GET", route, token=admin)[1]["metrics"][0]["details"])
        with self.store.connection() as db:
            stored = db.execute("SELECT details_json FROM metrics WHERE server_id=?", (sid,)).fetchone()[0]
        self.assertNotIn("top_processes", stored)
        self.assertNotIn("top_processes", Store(self.db_path).servers()[0]["latest"]["details"])
        self.assertNotIn("top_processes", self.store.servers(now=int(time.time()) + 100)[0]["latest"]["details"])

        bad_items = [
            {**top[0], "pid": True}, {**top[0], "pid": 0},
            {**top[0], "name": "../secret"}, {**top[0], "name": "x" * 17},
            {**top[0], "rss_bytes": -1}, {**top[0], "rss_bytes": 1.5},
            {**top[0], "argv": "secret"},
        ]
        invalid_lists = [[item] for item in bad_items]
        invalid_lists += [[top[0], top[0]], [top[0]] * 11]
        for items in invalid_lists:
            with self.subTest(items=items):
                self.assertEqual(self.request("POST", route, metric(details={"top_processes": items}), agent)[0], 422)
        self.assertEqual(len(self.store.history(sid)), 1)
        self.assertEqual(self.store.servers()[0]["latest"]["details"]["top_processes"], top)

        # An older Agent's next report clears the transient list without a DB migration.
        self.assertEqual(self.request("POST", route, metric(details={}), agent)[0], 202)
        self.assertNotIn("top_processes", self.store.servers()[0]["latest"]["details"])

    def test_old_database_details_migration(self):
        old = Path(self.temp.name) / "old.sqlite"
        with closing(sqlite3.connect(old)) as db:
            db.execute("CREATE TABLE servers (id TEXT PRIMARY KEY, name TEXT, created_at INTEGER, last_seen INTEGER, remote_commands_enabled INTEGER)")
            db.execute("CREATE TABLE metrics (id INTEGER PRIMARY KEY, server_id TEXT, collected_at INTEGER, received_at INTEGER, cpu_percent REAL, memory_percent REAL, disk_percent REAL, network_rx_bytes INTEGER, network_tx_bytes INTEGER, load1 REAL, uptime_seconds INTEGER, memory_total_bytes INTEGER, memory_available_bytes INTEGER, disk_total_bytes INTEGER, disk_available_bytes INTEGER)")
            db.execute("CREATE TABLE jobs (id TEXT PRIMARY KEY, server_id TEXT, actor_user_id INTEGER, chat_id INTEGER, command TEXT, state TEXT, created_at INTEGER, delivered_at INTEGER, completed_at INTEGER, exit_code INTEGER, output TEXT)")
            db.execute("INSERT INTO servers VALUES ('old-server', 'old', 1, 1, 0)")
            db.execute("INSERT INTO metrics (server_id, collected_at, received_at, cpu_percent, memory_percent, disk_percent, network_rx_bytes, network_tx_bytes, load1, uptime_seconds) VALUES ('old-server', 1, 1, 10, 20, 30, 100, 200, 0.5, 60)")
            db.execute("INSERT INTO jobs VALUES ('old-job', 'old-server', 11, 11, 'true', 'succeeded', 1, 2, 3, 0, '')")
            db.commit()
        migrated = Store(old)
        migrated.migrate()
        with closing(sqlite3.connect(old)) as db:
            columns = {row[1] for row in db.execute("PRAGMA table_info(metrics)")}
            job_columns = {row[1] for row in db.execute("PRAGMA table_info(jobs)")}
        self.assertIn("details_json", columns)
        self.assertIn("source", job_columns)
        self.assertIn("session_token_hash", job_columns)
        self.assertIn("idempotency_key", job_columns)
        self.assertIn("command_sha256", job_columns)
        self.assertEqual(migrated.monitoring_settings(), {
            "high_cpu": 90.0, "high_memory": 90.0, "high_disk": 90.0,
            "offline_seconds": 120, "trigger_minutes": 0, "revision": 0})
        self.assertEqual(migrated.job("old-job")["source"], "telegram")
        self.assertEqual(migrated.servers()[0]["latest"]["details"], {})
        self.assertEqual(migrated.history("old-server")[0]["details"], {})

    def test_migration_preserves_web_idempotency_after_scrubbing_command(self):
        admin = self.admin_token()
        _, created = self.request("POST", "/api/v1/servers", {"name": "migration-host"}, admin)
        sid = created["id"]
        self.store.set_remote_commands(sid, True)
        key = "dfe44888-7150-430a-8ac6-9a67b7f08513"
        job, _ = self.store.queue_web_job(sid, admin, "whoami", key)
        with closing(sqlite3.connect(self.db_path)) as db:
            db.execute("UPDATE jobs SET state='succeeded', command_sha256=NULL WHERE id=?", (job["id"],))
            db.commit()
        self.store.migrate()
        with closing(sqlite3.connect(self.db_path)) as db:
            command, digest = db.execute(
                "SELECT command, command_sha256 FROM jobs WHERE id=?", (job["id"],)).fetchone()
        self.assertEqual(command, "")
        self.assertEqual(digest, hashlib.sha256(b"whoami").hexdigest())
        replay, created_new = self.store.queue_web_job(sid, admin, "whoami", key)
        self.assertFalse(created_new)
        self.assertEqual(replay["id"], job["id"])


if __name__ == "__main__":
    unittest.main()
