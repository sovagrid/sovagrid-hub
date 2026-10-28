# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Remote feature changes cannot outlive their account, identity or revision."""
import hashlib
import json
import threading
import unittest
import uuid
from unittest import mock

from sovagrid_hub.agent_management import MAX_MANAGEMENT_SERVERS, MAX_REVISION, migrate_agent_management
from sovagrid_hub.auth import AuthenticationError, AuthorizationError
from sovagrid_hub.enrollment import EnrollmentError
from sovagrid_hub.http_api import HubApp, make_server
from test_enrollment import EnrollmentFixture, PASSWORD, metric
import test_enrollment as enrollment_tests

FIELDS = {"server_id", "enrollment_id", "agent_token_sha256", "enabled", "revision"}


class ManagementFixture(EnrollmentFixture):
    def activate(self):
        self.register()
        self.store.ingest(self.sid, metric(), agent_token=self.bearer)

    def save(self, enabled=True, revision=0, **changes):
        payload = {"enrollment_id": self.identifier, "agent_token_sha256": self.payload["agent_token_sha256"],
                   "expected_revision": revision, "enabled": enabled}
        payload.update(changes)
        return self.store.save_agent_management(self.sid, payload, session_token=self.owner)


class AgentManagementStoreTests(ManagementFixture, unittest.TestCase):
    def test_revision_cas_and_legacy_writer_share_one_counter(self):
        self.activate()
        first = self.store.agent_management(self.sid, session_token=self.owner)
        self.assertEqual(set(first), FIELDS)
        self.assertEqual(first, {"server_id": self.sid, "enrollment_id": self.identifier,
                                "agent_token_sha256": self.payload["agent_token_sha256"], "enabled": False, "revision": 0})
        self.assertEqual(self.save(False), {**first, "changed": False})
        enabled = self.save()
        self.assertEqual((enabled["enabled"], enabled["changed"], enabled["revision"]), (True, True, 1))
        self.assertEqual(self.save(True, 1), {**enabled, "changed": False})
        with self.assertRaises(EnrollmentError) as stale:
            self.save(False)
        self.assertEqual(stale.exception.status, 409)
        self.assertTrue(self.store.server_commands_enabled(self.sid))
        self.assertTrue(self.store.set_remote_commands(self.sid, False, session_token=self.owner))
        self.assertTrue(self.store.set_remote_commands(self.sid, False, session_token=self.owner))
        self.assertEqual(self.store.agent_management(self.sid, session_token=self.owner)["revision"], 2)
        with self.assertRaises(EnrollmentError):
            self.save(True, 1)
        self.assertEqual(self.save(True, 2)["revision"], 3)

    def test_identity_active_registration_and_credential_rotation_are_required(self):
        self.register()
        with self.assertRaises(EnrollmentError) as pending:
            self.store.agent_management(self.sid)
        self.assertEqual(pending.exception.status, 409)
        self.store.ingest(self.sid, metric(), agent_token=self.bearer)
        for changes in ({"enrollment_id": str(uuid.uuid4())}, {"agent_token_sha256": "0" * 64}):
            with self.subTest(changes=changes), self.assertRaises(EnrollmentError):
                self.save(**changes)
        self.assertFalse(self.store.server_commands_enabled(self.sid))
        self.store.rotate_agent_token(self.sid)
        with self.assertRaises(EnrollmentError):
            self.store.agent_management(self.sid)
        with self.assertRaises(EnrollmentError):
            self.save()
        legacy = self.store.create_server("legacy")
        with self.assertRaises(EnrollmentError) as missing:
            self.store.agent_management(legacy["id"])
        self.assertEqual(missing.exception.status, 404)

    def test_strict_payload_rejects_noncanonical_or_unbounded_values_without_writes(self):
        self.activate()
        invalid = [{"enabled": 1}, {"enabled": "true"}, {"expected_revision": True}, {"expected_revision": -1},
                   {"expected_revision": MAX_REVISION + 1}, {"expected_revision": 0.0},
                   {"enrollment_id": self.identifier.replace("-", "")}, {"enrollment_id": "not-an-id"},
                   {"agent_token_sha256": "A" * 64}, {"agent_token_sha256": None}, {"extra": "no"}]
        for changes in invalid:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.save(**changes)
        self.assertEqual(self.store.agent_management(self.sid)["revision"], 0)
        self.assertFalse(self.store.server_commands_enabled(self.sid))
        with self.store.connection() as db:
            db.execute("UPDATE servers SET management_revision=? WHERE id=?", (MAX_REVISION, self.sid))
        with self.assertRaises(EnrollmentError):
            self.save(revision=MAX_REVISION)
        self.assertFalse(self.store.server_commands_enabled(self.sid))

    def test_current_role_is_rechecked_by_all_store_entry_points(self):
        self.activate()
        for role in ("viewer", "operator"):
            self.store.create_user(role, PASSWORD, role, session_token=self.owner)
            token = self.store.login(role, PASSWORD)[0]
            for callback in (lambda: self.store.agent_management(self.sid, session_token=token),
                             lambda: self.store.agent_management_servers(session_token=token),
                             lambda: self.store.save_agent_management(self.sid, {
                                 "enrollment_id": self.identifier, "agent_token_sha256": self.payload["agent_token_sha256"],
                                 "expected_revision": 0, "enabled": True}, session_token=token)):
                with self.assertRaises(AuthorizationError):
                    callback()
        user = self.store.create_user("other-admin", PASSWORD, "admin", session_token=self.owner)
        token = self.store.login("other-admin", PASSWORD)[0]
        self.store.update_user(user["id"], {"revision": user["revision"], "enabled": False}, session_token=self.owner)
        with self.assertRaises(AuthenticationError):
            self.store.agent_management(self.sid, session_token=token)

    def test_concurrent_writers_with_the_same_revision_have_only_one_winner(self):
        self.activate()
        barrier = threading.Barrier(2)
        results = []
        def writer():
            try:
                barrier.wait(3)
                results.append(self.save()["revision"])
            except EnrollmentError as error:
                results.append(error.status)
        threads = [threading.Thread(target=writer) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(5)
            self.assertFalse(thread.is_alive())
        self.assertCountEqual(results, [1, 409])
        self.assertTrue(self.store.server_commands_enabled(self.sid))
        self.assertEqual(self.store.agent_management(self.sid)["revision"], 1)

    def test_disable_cancels_queued_work_and_audit_contains_no_credential(self):
        self.activate()
        self.save()
        job, _ = self.store.queue_web_job(self.sid, self.owner, "printf should-not-execute", idempotency_key=str(uuid.uuid4()))
        with self.store.connection() as db:
            db.execute("INSERT INTO pending_commands VALUES (?,?,1,1,'pending command',1,2)", ("temporary-confirmation", self.sid))
        disabled = self.save(False, 1)
        self.assertEqual((disabled["revision"], disabled["changed"]), (2, True))
        self.assertEqual(self.store.job(job["id"])["state"], "cancelled")
        with self.store.connection() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM pending_commands WHERE server_id=?", (self.sid,)).fetchone()[0], 0)
        events = self.store.audit_events()
        text = json.dumps(events)
        for value in (self.bearer, self.payload["agent_token_sha256"], "printf should-not-execute", "pending command"):
            self.assertNotIn(value, text)
        details = json.loads(events[0]["details"])
        self.assertEqual({k: details[k] for k in ("enabled", "changed", "revision")},
                         {"enabled": False, "changed": True, "revision": 2})

    def test_picker_is_bounded_sorted_and_contains_only_active_matching_agents(self):
        self.activate()
        with self.store.connection() as db:
            for index in range(MAX_MANAGEMENT_SERVERS + 1):
                sid, eid = str(uuid.uuid4()), str(uuid.uuid4())
                value = hashlib.sha256(str(index).encode()).hexdigest()
                name = f"bounded-{index:03}"
                db.execute("INSERT INTO servers(id,name,agent_token_hash,created_at,last_seen) VALUES (?,?,?,1,1)", (sid, name, value))
                db.execute("""INSERT INTO agent_enrollments(id,server_id,name,request_hash,registered_token_hash,created_at)
                              VALUES (?,?,?,?,?,1)""", (eid, sid, name, "0" * 64, value))
            for kind in ("pending", "cancelled", "rotated"):
                sid, eid = str(uuid.uuid4()), str(uuid.uuid4())
                db.execute("INSERT INTO servers(id,name,agent_token_hash,created_at,last_seen) VALUES (?,?,?,1,?)",
                           (sid, "000-excluded-" + kind, "0" * 64, None if kind == "pending" else 1))
                db.execute("""INSERT INTO agent_enrollments(id,server_id,name,request_hash,registered_token_hash,created_at,cancelled_at)
                              VALUES (?,?,?,?,?,1,?)""", (eid, sid, "000-excluded-" + kind, "0" * 64,
                                                         "1" * 64 if kind == "rotated" else "0" * 64,
                                                         1 if kind == "cancelled" else None))
        value = self.store.agent_management_servers(session_token=self.owner)
        self.assertEqual(set(value), {"servers", "truncated"})
        self.assertTrue(value["truncated"])
        self.assertEqual(len(value["servers"]), MAX_MANAGEMENT_SERVERS)
        self.assertTrue(all(set(row) == {"id", "name"} for row in value["servers"]))
        self.assertEqual(value["servers"], sorted(value["servers"], key=lambda row: (row["name"], row["id"])))
        self.assertFalse(any("excluded-" in row["name"] for row in value["servers"]))

    def test_migration_is_additive_and_repeatable_for_an_existing_server(self):
        legacy = self.store.create_server("legacy")
        with self.store.connection() as db:
            db.execute("ALTER TABLE servers DROP COLUMN management_revision")
        def interrupted(db):
            migrate_agent_management(db)
            raise RuntimeError("interrupted management migration")
        with mock.patch("sovagrid_hub.store.migrate_agent_management", side_effect=interrupted):
            with self.assertRaisesRegex(RuntimeError, "interrupted management migration"):
                self.store.migrate()
        with self.store.connection() as db:
            self.assertNotIn("management_revision", {row["name"] for row in db.execute("PRAGMA table_info(servers)")})
        self.store.migrate()
        self.store.migrate()
        self.assertTrue(self.store.agent_valid(legacy["id"], legacy["agent_token"]))
        self.assertTrue(self.store.session_valid(self.owner))
        with self.store.connection() as db:
            self.assertEqual(db.execute("SELECT management_revision FROM servers WHERE id=?", (legacy["id"],)).fetchone()[0], 0)


class AgentManagementHTTPTests(ManagementFixture, unittest.TestCase):
    request = enrollment_tests.EnrollmentHTTPTests.request
    account = enrollment_tests.EnrollmentHTTPTests.account

    def setUp(self):
        super().setUp()
        self.app = HubApp(self.store)
        self.server = make_server(self.app, 0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"
        self.activate()
        self.route = "/api/v1/servers/" + self.sid + "/agent-management"
        self.change = {"enrollment_id": self.identifier, "agent_token_sha256": self.payload["agent_token_sha256"],
                       "expected_revision": 0, "enabled": True}

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)
        super().tearDown()

    def test_admin_contract_roles_and_disable_closes_only_selected_relays(self):
        status, current = self.request("GET", self.route, self.owner)
        self.assertEqual(status, 200)
        self.assertEqual(set(current), FIELDS)
        self.assertEqual(self.request("GET", "/api/v1/agent-management", self.owner),
                         (200, {"servers": [{"id": self.sid, "name": self.payload["name"]}], "truncated": False}))
        for role in ("viewer", "operator"):
            _, token = self.account(role, role)
            self.assertEqual(self.request("GET", self.route, token)[0], 403)
            self.assertEqual(self.request("GET", "/api/v1/agent-management", token)[0], 403)
            self.assertEqual(self.request("POST", self.route, token, self.change)[0], 403)
        self.assertEqual(self.request("GET", self.route, self.bearer)[0], 401)
        self.assertEqual(self.request("POST", self.route, self.owner, self.change)[0], 200)
        owner_hash = hashlib.sha256(self.owner.encode()).hexdigest()
        terminal, _ = self.server.RequestHandlerClass.app.terminals.create(self.sid, owner_hash, str(uuid.uuid4()), 80, 24)
        operation, _ = self.server.RequestHandlerClass.app.files.create(self.sid, owner_hash, str(uuid.uuid4()), {"action": "roots"})
        other = self.store.create_server("unrelated")
        untouched, _ = self.server.RequestHandlerClass.app.terminals.create(other["id"], owner_hash, str(uuid.uuid4()), 80, 24)
        status, result = self.request("POST", self.route, self.owner, {**self.change, "expected_revision": 1, "enabled": False})
        self.assertEqual((status, result["revision"], result["changed"]), (200, 2, True))
        app = self.server.RequestHandlerClass.app
        self.assertEqual(app.terminals._sessions[terminal["id"]].reason, "permission_revoked")
        self.assertEqual(app.terminals._sessions[untouched["id"]].state, "pending")
        self.assertNotIn(operation["id"], app.files._operations)
        self.assertEqual(self.request("POST", self.route, self.owner, self.change)[0], 409)

    def test_strict_http_inputs_and_late_session_revocation(self):
        self.assertEqual(self.request("POST", self.route, self.owner, raw=b" " * 4097)[0], 413)
        raw = json.dumps(self.change)[:-1] + ',"enabled":false}'
        self.assertEqual(self.request("POST", self.route, self.owner, raw=raw.encode())[0], 400)
        self.assertEqual(self.request("GET", self.route + "?extra=1", self.owner)[0], 400)
        self.assertEqual(self.request("GET", "/api/v1/agent-management?extra=1", self.owner)[0], 400)
        self.assertEqual(self.request("POST", self.route + "?extra=1", self.owner, self.change)[0], 400)
        self.assertEqual(self.request("GET", "/api/v1/servers/invalid/agent-management", self.owner)[0], 400)
        user, token = self.account("revoked-writer")
        original = self.store.save_agent_management
        def revoke(*args, **kwargs):
            self.store.update_user(user["id"], {"revision": user["revision"], "enabled": False}, session_token=self.owner)
            return original(*args, **kwargs)
        with mock.patch.object(self.store, "save_agent_management", side_effect=revoke):
            self.assertEqual(self.request("POST", self.route, token, self.change)[0], 401)
        self.assertFalse(self.store.server_commands_enabled(self.sid))

    def test_get_rechecks_authority_inside_its_read_transaction(self):
        for endpoint, method in ((self.route, "agent_management"), ("/api/v1/agent-management", "agent_management_servers")):
            user, token = self.account("reader-" + method)
            original = getattr(self.store, method)
            def revoke(*args, **kwargs):
                self.store.update_user(user["id"], {"revision": user["revision"], "enabled": False}, session_token=self.owner)
                return original(*args, **kwargs)
            with mock.patch.object(self.store, method, side_effect=revoke):
                self.assertEqual(self.request("GET", endpoint, token)[0], 401)


if __name__ == "__main__":
    unittest.main()
