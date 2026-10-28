# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Accounts cannot retain another user's authority after role/password changes."""

import hashlib
import json
import socket
import sqlite3
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
import uuid
from contextlib import contextmanager
from pathlib import Path
from unittest import mock

from sovagrid_hub.auth import AuthorizationError, UserConflict, USER_FIELDS
from sovagrid_hub.http_api import HubApp, make_server
from sovagrid_hub.store import Store


PASSWORD = "a-long-account-test-password"


class AccountTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "accounts.sqlite"
        self.store = Store(self.path)
        self.store.initialize("owner", PASSWORD)
        self.app = HubApp(self.store)
        self.server = make_server(self.app, 0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"
        self.owner = self.login("owner")

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
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

    def login(self, username, password=PASSWORD):
        status, body = self.request("POST", "/api/v1/session", data={"username": username, "password": password})
        self.assertEqual(status, 200)
        self.assertEqual(set(body["user"]), set(USER_FIELDS))
        self.assertEqual(body["user"]["username"], username)
        return body["token"]

    def create(self, username, role):
        status, body = self.request("POST", "/api/v1/users", self.owner,
                                    {"username": username, "password": PASSWORD, "role": role})
        self.assertEqual(status, 201)
        return body["user"], self.login(username)

    def server_with_incident(self):
        server = self.store.create_server("account-host")
        now = int(time.time())
        self.store.ingest(server["id"], {"collected_at": now, "cpu_percent": 96,
            "memory_percent": 20, "disk_percent": 30, "network_rx_bytes": 1,
            "network_tx_bytes": 2, "load1": 0.5, "uptime_seconds": 30}, now=now)
        self.store.set_remote_commands(server["id"], True)
        return server, self.store.incidents()[0]["id"]

    def test_public_identity_and_user_records_never_include_credentials(self):
        _, viewer = self.create("наблюдатель", "viewer")
        identity = self.request("GET", "/api/v1/session", viewer)
        self.assertEqual(identity[0], 200)
        self.assertEqual(identity[1]["user"]["role"], "viewer")
        self.assertEqual(set(identity[1]), {"user", "expires_at"})
        users = self.request("GET", "/api/v1/users", self.owner)[1]["users"]
        self.assertEqual(len(users), 2)
        for user in users:
            self.assertEqual(set(user), set(USER_FIELDS))
        serialized = json.dumps(users)
        for forbidden in (PASSWORD, "password_hash", "salt", "token_hash"):
            self.assertNotIn(forbidden, serialized)
        self.assertEqual(self.request("GET", "/api/v1/session")[0], 401)
        with self.store.connection() as db:
            db.execute("UPDATE sessions SET expires_at=0 WHERE token_hash=?",
                       (hashlib.sha256(viewer.encode()).hexdigest(),))
        self.assertEqual(self.request("GET", "/api/v1/session", viewer)[0], 401)

    def test_role_matrix_blocks_commands_files_secrets_and_account_management(self):
        server, incident = self.server_with_incident()
        sid = server["id"]
        job, _ = self.store.queue_web_job(sid, self.owner, "echo private-command")
        self.store.lease_job(sid)
        self.store.finish_job(sid, job["id"], "succeeded", 0, "PRIVATE_JOB_OUTPUT")
        for role in ("viewer", "operator"):
            _, token = self.create(role, role)
            for path in ("/api/v1/servers", "/api/v1/incidents", "/api/v1/vpn",
                         "/api/v1/monitoring/settings", f"/api/v1/servers/{sid}/metrics",
                         f"/api/v1/servers/{sid}/maintenance", f"/api/v1/servers/{sid}/amnezia/control"):
                with self.subTest(role=role, read=path):
                    self.assertEqual(self.request("GET", path, token)[0], 200)
            for path in ("/api/v1/users", "/api/v1/jobs", f"/api/v1/jobs/{job['id']}",
                         "/api/v1/audit", "/api/v1/telegram",
                         f"/api/v1/servers/{sid}/files/operations/unknown",
                         f"/api/v1/servers/{sid}/terminal/sessions/unknown/events"):
                with self.subTest(role=role, secret=path):
                    status, body = self.request("GET", path, token)
                    self.assertEqual(status, 403)
                    self.assertNotIn("PRIVATE_JOB_OUTPUT", json.dumps(body))
            for path in ("/api/v1/users", "/api/v1/servers", "/api/v1/monitoring/settings",
                         "/api/v1/telegram/token", "/api/v1/telegram/bindings",
                         f"/api/v1/servers/{sid}/commands", f"/api/v1/servers/{sid}/jobs",
                         f"/api/v1/servers/{sid}/journal", f"/api/v1/servers/{sid}/vpn/actions",
                         f"/api/v1/servers/{sid}/amnezia/actions", f"/api/v1/servers/{sid}/maintenance",
                         f"/api/v1/servers/{sid}/rotate-token", f"/api/v1/servers/{sid}/files/operations",
                         f"/api/v1/servers/{sid}/terminal/sessions"):
                with self.subTest(role=role, write=path):
                    self.assertEqual(self.request("POST", path, token, {})[0], 403)
            self.assertEqual(self.request("PATCH", "/api/v1/users/unknown", token, {"revision": 1, "role": "admin"})[0], 403)
            self.assertEqual(self.request("DELETE", "/api/v1/users/unknown?revision=1", token)[0], 403)
            self.assertEqual(self.request("POST", f"/api/v1/incidents/{incident}/ack", token, {})[0],
                             200 if role == "operator" else 403)
            self.assertEqual(self.request("DELETE", "/api/v1/session", token), (200, {"revoked": True}))

    def test_last_admin_revision_guard_and_noop_update_contract(self):
        owner = self.request("GET", "/api/v1/session", self.owner)[1]["user"]
        path = "/api/v1/users/" + owner["id"]
        for data in ({"revision": owner["revision"], "role": "viewer"},
                     {"revision": owner["revision"], "enabled": False}):
            self.assertEqual(self.request("PATCH", path, self.owner, data)[0], 409)
        self.assertEqual(self.request("DELETE", path + "?revision=1", self.owner)[0], 409)
        self.assertEqual(self.request("GET", "/api/v1/session", self.owner)[0], 200)
        noop = self.request("PATCH", path, self.owner, {"revision": 1, "role": "admin"})
        self.assertEqual(noop[0], 200)
        self.assertEqual(noop[1]["user"]["revision"], 2)
        self.assertFalse(noop[1]["sessions_revoked"])
        self.assertEqual(self.request("PATCH", path, self.owner, {"revision": 1, "enabled": True})[0], 409)
        for revision in ("0", "1&revision=2", "true", "9223372036854775808"):
            self.assertEqual(self.request("DELETE", path + "?revision=" + revision, self.owner)[0], 400)
        self.assertEqual(self.request("POST", "/api/v1/users", self.owner,
            {"username": "owner", "password": PASSWORD, "role": "viewer"})[0], 409)

    def test_demotion_closes_only_target_sessions_files_and_queued_jobs(self):
        target, token = self.create("second-admin", "admin")
        server, _ = self.server_with_incident()
        sid = server["id"]
        own_job, _ = self.store.queue_web_job(sid, self.owner, "echo owner")
        target_job, _ = self.store.queue_web_job(sid, token, "echo target")
        other_server = self.store.create_server("another-host")["id"]
        self.store.set_remote_commands(other_server, True)
        owner_hash, target_hash = (hashlib.sha256(value.encode()).hexdigest() for value in (self.owner, token))
        terminal, _ = self.app.terminals.create(sid, target_hash, str(uuid.uuid4()), 80, 24)
        own_terminal, _ = self.app.terminals.create(other_server, owner_hash, str(uuid.uuid4()), 80, 24)
        operation, _ = self.app.files.create(sid, target_hash, str(uuid.uuid4()), {"action": "roots"})
        own_operation, _ = self.app.files.create(sid, owner_hash, str(uuid.uuid4()), {"action": "roots"})
        status, body = self.request("PATCH", "/api/v1/users/" + target["id"], self.owner,
                                    {"revision": target["revision"], "role": "viewer"})
        self.assertEqual(status, 200)
        self.assertTrue(body["sessions_revoked"])
        self.assertNotIn("_revoked_hashes", body)
        self.assertEqual(self.request("GET", "/api/v1/session", token)[0], 401)
        self.assertEqual(self.request("GET", "/api/v1/session", self.owner)[0], 200)
        self.assertEqual(self.store.job(target_job["id"])["state"], "cancelled")
        self.assertEqual(self.store.job(own_job["id"])["state"], "queued")
        self.assertEqual(self.app.terminals._sessions[terminal["id"]].state, "closed")
        self.assertNotEqual(self.app.terminals._sessions[own_terminal["id"]].state, "closed")
        self.assertNotIn(operation["id"], self.app.files._operations)
        self.assertIn(own_operation["id"], self.app.files._operations)
        self.assertEqual(self.request("GET", "/api/v1/session", self.login("second-admin"))[1]["user"]["role"], "viewer")

    def test_password_change_is_session_bound_and_reset_does_not_revoke_other_users(self):
        target, token = self.create("viewer", "viewer")
        second = self.login("viewer")
        new_password = "a-new-long-account-password"
        for route in ("/api/v1/session/password", "/api/v1/admin/password"):
            with self.subTest(route=route):
                result = self.request("POST", route, token,
                    {"current_password": PASSWORD, "new_password": new_password})
                self.assertEqual(result, (200, {"changed": True, "sessions_revoked": True}))
                self.assertEqual(self.request("GET", "/api/v1/session", second)[0], 401)
                self.assertEqual(self.request("GET", "/api/v1/session", self.owner)[0], 200)
                token = self.login("viewer", new_password)
                target = self.request("GET", "/api/v1/session", token)[1]["user"]
                status, reset = self.request("POST", "/api/v1/users/" + target["id"] + "/password",
                    self.owner, {"revision": target["revision"], "password": PASSWORD})
                self.assertEqual(status, 200)
                self.assertEqual(reset["user"]["revision"], target["revision"] + 1)
                self.assertEqual(self.request("GET", "/api/v1/session", token)[0], 401)
                token = second = self.login("viewer")
        audit = json.dumps(self.store.audit_events())
        self.assertNotIn(PASSWORD, audit)
        self.assertNotIn(new_password, audit)
        actors = [row for row in self.store.audit_events() if row["action"] == "password_changed"]
        self.assertTrue(all(row["actor"].startswith("hub:") for row in actors))
        self.assertTrue(all("actor_username" in json.loads(row["details"]) for row in actors))

    def test_disabled_deleted_accounts_cannot_login_and_old_revision_cannot_delete(self):
        user, token = self.create("disabled", "operator")
        path = "/api/v1/users/" + user["id"]
        disabled = self.request("PATCH", path, self.owner, {"revision": 1, "enabled": False})
        self.assertEqual(disabled[0], 200)
        self.assertFalse(disabled[1]["user"]["enabled"])
        self.assertEqual(self.request("POST", "/api/v1/session", data={"username": "disabled", "password": PASSWORD})[0], 401)
        self.assertEqual(self.request("GET", "/api/v1/session", token)[0], 401)
        self.assertEqual(self.request("DELETE", path + "?revision=1", self.owner)[0], 409)
        self.assertEqual(self.request("DELETE", path + "?revision=2", self.owner), (200, {"removed": True}))
        self.assertEqual(self.request("DELETE", path + "?revision=2", self.owner)[0], 404)
        self.assertEqual(self.request("GET", "/api/v1/session", self.owner)[0], 200)

    def test_concurrent_last_admin_updates_cannot_remove_both_administrators(self):
        owner = self.store.session_info(self.owner)["user"]
        second, token = self.create("concurrent-admin", "admin")
        barrier = threading.Barrier(2)
        outcomes = []

        def demote(user, bearer):
            # Independent Store objects have independent Python locks, so
            # the safeguard must rely on the SQLite write transaction.
            store = Store(self.path)
            barrier.wait(3)
            try:
                store.update_user(user["id"], {"revision": 1, "role": "viewer"}, session_token=bearer)
                outcomes.append("changed")
            except UserConflict:
                outcomes.append("last-admin")

        workers = [threading.Thread(target=demote, args=pair) for pair in ((owner, self.owner), (second, token))]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(5)
            self.assertFalse(worker.is_alive())
        self.assertEqual(sorted(outcomes), ["changed", "last-admin"])
        with self.store.connection() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM hub_users WHERE role='admin' AND enabled=1").fetchone()[0], 1)

    def test_store_mutations_recheck_role_and_trusted_cli_none_still_works(self):
        _, token = self.create("reader", "viewer")
        server, incident = self.server_with_incident()
        sid = server["id"]
        settings = self.store.monitoring_settings()
        operations = (
            lambda: self.store.create_server("forbidden", session_token=token),
            lambda: self.store.rotate_agent_token(sid, session_token=token),
            lambda: self.store.set_remote_commands(sid, False, session_token=token),
            lambda: self.store.save_monitoring_settings(settings, session_token=token),
            lambda: self.store.create_maintenance(sid, {"ends_at": int(time.time()) + 120, "reason": "test"}, session_token=token),
            lambda: self.store.cancel_maintenance(sid, "unknown", session_token=token),
            lambda: self.store.acknowledge(incident, session_token=token),
            lambda: self.store.queue_web_job(sid, token, "whoami"),
            lambda: self.store.add_bot_user(101, 101, "viewer", session_token=token),
        )
        for operation in operations:
            with self.subTest(operation=operation):
                with self.assertRaises(AuthorizationError):
                    operation()
        self.assertIsNotNone(self.store.create_server("trusted-cli"))
        self.assertTrue(self.store.set_remote_commands(sid, False))

    def test_file_revocation_does_not_close_another_administrators_operations(self):
        server, _ = self.server_with_incident()
        sid = server["id"]
        unaffected_hash = hashlib.sha256(self.owner.encode()).hexdigest()
        original_access = self.store.terminal_access_valid
        for index, (method, revoke_on_check) in enumerate((("GET", 1), ("GET", 2), ("DELETE", 1))):
            with self.subTest(method=method, revoke_on_check=revoke_on_check):
                user, token = self.create("racing-admin-" + str(index), "admin")
                revoked_hash = hashlib.sha256(token.encode()).hexdigest()
                revoked_operation, _ = self.app.files.create(sid, revoked_hash,
                    str(uuid.uuid4()), {"action": "roots"})
                unaffected_operation, _ = self.app.files.create(sid, unaffected_hash,
                    str(uuid.uuid4()), {"action": "roots"})
                calls = 0

                def demote_between_authentication_and_access(owner_hash, server_id):
                    nonlocal calls
                    if owner_hash == revoked_hash:
                        calls += 1
                        if calls == revoke_on_check:
                            self.app.close_revoked(self.store.update_user(user["id"],
                                {"revision": user["revision"], "role": "viewer"}, session_token=self.owner))
                    return original_access(owner_hash, server_id)

                with mock.patch.object(self.store, "terminal_access_valid",
                                       side_effect=demote_between_authentication_and_access):
                    status, _ = self.request(method,
                        f"/api/v1/servers/{sid}/files/operations/{revoked_operation['id']}", token)
                self.assertEqual(status, 403)
                self.assertEqual(calls, revoke_on_check)
                status, body = self.request("GET",
                    f"/api/v1/servers/{sid}/files/operations/{unaffected_operation['id']}", self.owner)
                self.assertEqual(status, 200)
                self.assertEqual(body["operation"]["id"], unaffected_operation["id"])
                self.app.files.close_operation(sid, unaffected_operation["id"])

    def test_claim_and_long_poll_access_join_current_role_even_without_explicit_revocation(self):
        target, token = self.create("lease-admin", "admin")
        server, _ = self.server_with_incident()
        sid = server["id"]
        job, _ = self.store.queue_web_job(sid, token, "echo cannot-claim")
        owner = hashlib.sha256(token.encode()).hexdigest()
        terminal, _ = self.app.terminals.create(sid, owner, str(uuid.uuid4()), 80, 24)
        operation, _ = self.app.files.create(sid, owner, str(uuid.uuid4()), {"action": "roots"})
        # Simulate another administrator's committed role change while a
        # worker still has the old in-memory owner hash and bearer token.
        with self.store.connection() as db:
            db.execute("UPDATE hub_users SET role='viewer' WHERE id=?", (target["id"],))
        self.assertTrue(self.store.session_valid(token))
        self.assertFalse(self.store.terminal_access_valid(owner, sid))
        self.assertIsNone(self.store.lease_job(sid))
        self.assertEqual(self.store.job(job["id"])["state"], "cancelled")
        with self.assertRaises(AuthorizationError):
            self.store.queue_web_job(sid, token, "whoami")
        self.assertIsNone(self.request("GET", f"/api/v1/servers/{sid}/terminal/next", server["agent_token"])[1]["session"])
        self.assertEqual(self.app.terminals._sessions[terminal["id"]].state, "closed")
        self.assertIsNone(self.request("GET", f"/api/v1/servers/{sid}/files/next", server["agent_token"])[1]["operation"])
        self.assertEqual(self.app.files._operations[operation["id"]]["state"], "failed")
        self.assertEqual(self.app.files._operations[operation["id"]]["result"], {"code": "disabled"})

    def test_password_validation_rejects_invalid_unicode_and_types_but_accepts_emoji(self):
        target, token = self.create("unicode", "viewer")
        for password in (True, [], "x" * 12 + "\ud800"):
            with self.subTest(password_type=type(password).__name__):
                self.assertEqual(self.request("POST", "/api/v1/users", self.owner,
                    {"username": "bad-unicode", "password": password, "role": "viewer"})[0], 400)
                self.assertEqual(self.request("POST", "/api/v1/users/" + target["id"] + "/password", self.owner,
                    {"revision": 1, "password": password})[0], 400)
                self.assertEqual(self.request("POST", "/api/v1/session", data=
                    {"username": "unicode", "password": password})[0], 400)
        self.assertEqual(self.request("POST", "/api/v1/session/password", token,
            {"current_password": PASSWORD + "\ud800", "new_password": "another-long-password"})[0], 400)
        self.assertEqual(self.request("POST", "/api/v1/session/password", token,
            {"current_password": PASSWORD, "new_password": PASSWORD + "\ud800"})[0], 400)
        emoji_password = "password-with-valid-emoji-\U0001f989"
        self.assertEqual(self.request("POST", "/api/v1/session/password", token,
            {"current_password": PASSWORD, "new_password": emoji_password})[0], 200)
        self.assertIsNotNone(self.login("unicode", emoji_password))

    def test_partial_body_cannot_create_account_or_server_after_demotion(self):
        for route, payload in (("/api/v1/users", {"username": "late", "password": PASSWORD, "role": "admin"}),
                               ("/api/v1/servers", {"name": "late-host"})):
            target, token = self.create("slow-" + route.rsplit("/", 1)[-1], "admin")
            checked = threading.Event()
            original = self.store.session_info

            def observe(value, *args, **kwargs):
                info = original(value, *args, **kwargs)
                if value == token and info:
                    checked.set()
                return info

            body = json.dumps(payload).encode()
            with mock.patch.object(self.store, "session_info", side_effect=observe):
                with socket.create_connection(("127.0.0.1", self.server.server_port), timeout=3) as connection:
                    connection.sendall(f"POST {route} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode() + body[:1])
                    self.assertTrue(checked.wait(2))
                    self.assertEqual(self.request("PATCH", "/api/v1/users/" + target["id"], self.owner,
                        {"revision": 1, "role": "viewer"})[0], 200)
                    connection.sendall(body[1:])
                    self.assertIn(b" 401 ", connection.recv(4096))
        self.assertNotIn("late", [user["username"] for user in self.store.users()])
        self.assertNotIn("late-host", [server["name"] for server in self.store.servers()])

    def test_revocation_between_body_check_and_sql_write_cannot_create_server(self):
        target, token = self.create("write-race", "admin")
        original = self.store.create_server

        def revoked(*args, **kwargs):
            self.store.update_user(target["id"], {"revision": 1, "role": "viewer"}, session_token=self.owner)
            return original(*args, **kwargs)

        with mock.patch.object(self.store, "create_server", side_effect=revoked):
            self.assertEqual(self.request("POST", "/api/v1/servers", token, {"name": "not-created"})[0], 401)
        self.assertNotIn("not-created", [server["name"] for server in self.store.servers()])


class LegacyAccountMigrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "legacy.sqlite"
        self.store = Store(self.path)
        self.store.initialize("legacy-owner", PASSWORD)
        self.token = self.store.login("legacy-owner", PASSWORD)[0]
        with self.store.connection() as db:
            row = db.execute("SELECT username,salt,password_hash FROM hub_users").fetchone()
            db.execute("CREATE TABLE admin(username TEXT PRIMARY KEY,salt BLOB,password_hash BLOB)")
            db.execute("INSERT INTO admin VALUES (?,?,?)", tuple(row))
            db.execute("CREATE TABLE legacy_sessions(token_hash TEXT PRIMARY KEY,expires_at INTEGER)")
            db.execute("INSERT INTO legacy_sessions SELECT token_hash,expires_at FROM sessions")
            db.execute("DROP TABLE sessions")
            db.execute("ALTER TABLE legacy_sessions RENAME TO sessions")
            db.execute("DROP TABLE hub_users")

    def tearDown(self):
        self.temp.cleanup()

    def test_migrate_preserves_legacy_credentials_sessions_and_stable_identity(self):
        self.store.migrate()
        identity = self.store.session_info(self.token)["user"]
        self.assertEqual(identity["username"], "legacy-owner")
        self.assertEqual(identity["role"], "admin")
        self.store.migrate()
        self.assertEqual(self.store.session_info(self.token)["user"]["id"], identity["id"])
        self.assertIsNotNone(self.store.login("legacy-owner", PASSWORD))
        with self.store.connection() as db:
            self.assertIsNone(db.execute("SELECT name FROM sqlite_master WHERE name='admin'").fetchone())
            self.assertEqual(db.execute("PRAGMA foreign_key_check").fetchall(), [])

    def test_interrupted_identity_migration_keeps_legacy_schema_and_retries_safely(self):
        real_connection = self.store.connection

        class Interrupted:
            def __init__(self, db):
                self.db = db

            def execute(self, sql, *args):
                if sql == "ALTER TABLE migrated_sessions RENAME TO sessions":
                    raise RuntimeError("migration interrupted")
                return self.db.execute(sql, *args)

        @contextmanager
        def interrupt():
            with real_connection() as db:
                yield Interrupted(db)

        with mock.patch.object(self.store, "connection", interrupt):
            with self.assertRaisesRegex(RuntimeError, "migration interrupted"):
                self.store.migrate()
        with real_connection() as db:
            self.assertIsNotNone(db.execute("SELECT name FROM sqlite_master WHERE name='admin'").fetchone())
            self.assertIsNone(db.execute("SELECT name FROM sqlite_master WHERE name='hub_users'").fetchone())
            self.assertEqual(len(db.execute("SELECT * FROM sessions").fetchall()), 1)
        self.store.migrate()
        self.assertEqual(self.store.session_info(self.token)["user"]["role"], "admin")


if __name__ == "__main__":
    unittest.main()
