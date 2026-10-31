# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Reviewed external Agent updates stay behind admin, root broker and CAS."""

import json
from pathlib import Path
import subprocess
import tempfile
import threading
from types import SimpleNamespace
import unittest
import urllib.error
import urllib.request
from unittest import mock

from sovagrid_hub.backup import BackupError
from sovagrid_hub.backup_broker import BackupBroker, _external_execute, _request
from sovagrid_hub.backup_client import BackupClientError, ExternalAgentUpdateBrokerClient
from sovagrid_hub.external_agent_control import (SCRIPT, FUTURE_METADATA, METADATA,
                                                  LIVE_GATES, valid_result)
from sovagrid_hub.http_api import HubApp, make_server
from sovagrid_hub.store import Store


ARCHIVE = "a" * 64
CURRENT = "b" * 64
EXTERNAL = "c" * 64
REVIEW = "d" * 64
REQUEST_ID = "12345678-1234-4234-8234-1234567890ab"
STATUS = {"protocol": 1, "hub_only": True, "current_hub_manifest_sha256": CURRENT,
          "external_agent_manifest_sha256": EXTERNAL, "idle_endpoint_present": True,
          "live_idle_ack_verified": False}
PREVIEW = {"protocol": 1, "current_hub_manifest_sha256": CURRENT,
           "candidate_manifest_sha256": CURRENT,
           "external_agent_manifest_sha256": EXTERNAL,
           "external_agent_preserved": True, "tunnel_active": True,
           "source_paths_to_change": [{"path": "/opt/sovagrid-agent/sovagrid_agent/agent.py",
                                       "operation": "replace"}],
           "future_metadata_paths": FUTURE_METADATA,
           "original_hub_compatibility": "verified_same_bundle",
           "apply_supported": True,
           "apply_blockers": ["EXTERNAL_AGENT_PREFLIGHT_REQUIRED"],
           "explicit_review_required": True}
PREFLIGHT = {**PREVIEW, "apply_blockers": [], "candidate_agent_file_count": 12,
             "archive_sha256": ARCHIVE, "baseline_sha256": "e" * 64,
             "enrollment_sha256": "f" * 64, "review_sha256": REVIEW,
             "metadata_paths_to_change": METADATA, "live_gates_pending": LIVE_GATES}
APPLIED = {"protocol": 1, "applied": True,
           "external_agent_manifest_sha256": CURRENT, "review_sha256": REVIEW}
OPERATION = {"format": 1, "request_id": REQUEST_ID, "phase": "accepted",
             "created_at": 1790000000, "updated_at": 1790000000, "error": None}


class BrokerTests(unittest.TestCase):
    def test_exact_socket_grammar_rejects_paths_flags_and_duplicate_keys(self):
        valid = ({"action": "external_status"},
                 {"action": "external_preview", "archive_sha256": ARCHIVE,
                  "current_hub_manifest_sha256": CURRENT},
                 {"action": "external_preflight", "archive_sha256": ARCHIVE,
                  "current_hub_manifest_sha256": CURRENT},
                 {"action": "external_apply", "request_id": REQUEST_ID,
                  "archive_sha256": ARCHIVE,
                  "current_hub_manifest_sha256": CURRENT,
                  "external_agent_manifest_sha256": EXTERNAL,
                  "review_sha256": REVIEW},
                 {"action": "external_operation_status", "request_id": REQUEST_ID},
                 {"action": "external_operation_list"})
        for payload in valid:
            with self.subTest(payload=payload):
                self.assertEqual(_request((json.dumps(payload) + "\n").encode()), payload)
        for payload in ({"action": "external_status", "path": "../../secrets"},
                        {**valid[1], "url": "https://example.com"},
                        {**valid[3], "review_sha256": "A" * 64},
                        {**valid[3], "command": "sh"}):
            with self.subTest(payload=payload), self.assertRaisesRegex(BackupError,
                                                                        "INVALID_REQUEST"):
                _request((json.dumps(payload) + "\n").encode())
        with self.assertRaisesRegex(BackupError, "INVALID_REQUEST"):
            _request(('{"action":"external_status","action":"external_apply"}\n').encode())

    def test_root_command_is_fixed_and_replies_are_metadata_only(self):
        self.assertEqual(SCRIPT,
                         "/opt/sovagrid-src/sovagrid-blueprint/deploy/external_agent_update.py")
        payload = {"action": "external_preflight", "archive_sha256": ARCHIVE,
                   "current_hub_manifest_sha256": CURRENT}
        with mock.patch("sovagrid_hub.backup_broker.subprocess.run", return_value=
                        subprocess.CompletedProcess([], 0, (json.dumps(PREFLIGHT) + "\n").encode(),
                                                    b"private host detail")) as run:
            self.assertEqual(_external_execute(payload), {"ok": True, "result": PREFLIGHT})
        self.assertEqual(run.call_args.args[0],
                         ["/usr/bin/python3", "-B", "-I", SCRIPT, "preflight", ARCHIVE, CURRENT])
        self.assertEqual(run.call_args.kwargs["stderr"], subprocess.DEVNULL)
        self.assertEqual(run.call_args.kwargs["stdin"], subprocess.DEVNULL)
        self.assertEqual(run.call_args.kwargs["env"], {"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
        for value in ({**PREFLIGHT, "private_key": "secret"},
                      {**PREFLIGHT, "source_paths_to_change": [{"path": "/etc/shadow",
                                                                 "operation": "replace"}]},
                      {**PREFLIGHT, "review_sha256": "bad"}):
            with self.subTest(value=value), mock.patch(
                    "sovagrid_hub.backup_broker.subprocess.run", return_value=
                    subprocess.CompletedProcess([], 0, (json.dumps(value) + "\n").encode(), b"")):
                with self.assertRaisesRegex(BackupError, "EXTERNAL_UNAVAILABLE"):
                    _external_execute(payload)
        with mock.patch("sovagrid_hub.backup_broker.subprocess.run", return_value=
                        subprocess.CompletedProcess([], 40, b"", b"private host detail")):
            with self.assertRaisesRegex(BackupError, "EXTERNAL_REFUSED"):
                _external_execute(payload)
        with mock.patch("sovagrid_hub.backup_broker.subprocess.run") as run:
            with self.assertRaisesRegex(BackupError, "EXTERNAL_UNAVAILABLE"):
                _external_execute({"action": "external_apply", "request_id": REQUEST_ID,
                                   "archive_sha256": ARCHIVE,
                                   "current_hub_manifest_sha256": CURRENT,
                                   "external_agent_manifest_sha256": EXTERNAL,
                                   "review_sha256": REVIEW})
            run.assert_not_called()
        self.assertFalse(valid_result("external_status", {**STATUS, "token": "secret"}))

    def test_durable_dispatch_uses_injected_store_not_backup_subprocess(self):
        with tempfile.TemporaryDirectory() as directory:
            manager = SimpleNamespace(layout=SimpleNamespace(backups=Path(directory)))
            operations = mock.Mock()
            operations.apply.return_value = OPERATION
            operations.status.return_value = OPERATION
            operations.list.return_value = [OPERATION]
            broker = BackupBroker(manager=manager,
                                  requests=Path(directory) / ".broker-requests",
                                  restores=mock.Mock(), public_web=mock.Mock(),
                                  local_web=mock.Mock(), external_operations=operations)
            with mock.patch("sovagrid_hub.backup_broker.subprocess.run") as run:
                self.assertEqual(broker.execute({"action": "external_apply",
                    "request_id": REQUEST_ID, "archive_sha256": ARCHIVE,
                    "current_hub_manifest_sha256": CURRENT,
                    "external_agent_manifest_sha256": EXTERNAL,
                    "review_sha256": REVIEW}), {"ok": True, "operation": OPERATION})
                self.assertEqual(broker.execute({"action": "external_operation_status",
                    "request_id": REQUEST_ID}), {"ok": True, "operation": OPERATION})
                self.assertEqual(broker.execute({"action": "external_operation_list"}),
                                 {"ok": True, "operations": [OPERATION]})
                run.assert_not_called()
            operations.apply.assert_called_once_with(REQUEST_ID, ARCHIVE, CURRENT,
                                                      EXTERNAL, REVIEW)


class ClientTests(unittest.TestCase):
    def test_untrusted_socket_reply_and_exact_cas(self):
        client = ExternalAgentUpdateBrokerClient()
        with mock.patch.object(client, "_request", return_value={"ok": True, "result": STATUS}) as request:
            self.assertEqual(client.status(), STATUS)
            request.assert_called_once_with({"action": "external_status"}, timeout_seconds=195)
        with mock.patch.object(client, "_request", return_value={"ok": True, "result": PREFLIGHT}):
            self.assertEqual(client.preflight(ARCHIVE, CURRENT), PREFLIGHT)
        with mock.patch.object(client, "_request", return_value=
                               {"ok": True, "result": {**PREFLIGHT, "archive_sha256": "0" * 64}}):
            with self.assertRaisesRegex(BackupClientError, "EXTERNAL_UNAVAILABLE"):
                client.preflight(ARCHIVE, CURRENT)
        with mock.patch.object(client, "_request", return_value={"ok": True, "operation":
                                                                  {**OPERATION, "request_id":
                                                                   "87654321-4321-4321-8321-ba0987654321"}}):
            with self.assertRaisesRegex(BackupClientError, "EXTERNAL_UNAVAILABLE"):
                client.apply(REQUEST_ID, ARCHIVE, CURRENT, EXTERNAL, REVIEW)
        with mock.patch.object(client, "_request") as request:
            with self.assertRaisesRegex(BackupClientError, "INVALID_REQUEST"):
                client.apply(REQUEST_ID, ARCHIVE, CURRENT, EXTERNAL, "A" * 64)
            request.assert_not_called()

    def test_uncertain_socket_result_is_never_retryable_by_client(self):
        client = ExternalAgentUpdateBrokerClient()
        with mock.patch.object(client, "_request", side_effect=BackupClientError(
                503, "Backup broker unavailable; result may be uncertain")) as request:
            with self.assertRaisesRegex(BackupClientError, "EXTERNAL_UNCERTAIN"):
                client.apply(REQUEST_ID, ARCHIVE, CURRENT, EXTERNAL, REVIEW)
            self.assertEqual(request.call_count, 1)

    def test_durable_operation_client_rejects_mismatched_or_secret_records(self):
        client = ExternalAgentUpdateBrokerClient()
        with mock.patch.object(client, "_request", return_value={"ok": True,
                                                                  "operation": OPERATION}) as request:
            self.assertEqual(client.apply(REQUEST_ID, ARCHIVE, CURRENT, EXTERNAL, REVIEW), OPERATION)
            self.assertEqual(request.call_args.kwargs["timeout_seconds"], 30)
            self.assertEqual(client.operation_status(REQUEST_ID), OPERATION)
        with mock.patch.object(client, "_request", return_value={"ok": True,
                                                                  "operations": [OPERATION]}):
            self.assertEqual(client.operations(), {"operations": [OPERATION]})
        for value in ({"ok": True, "operation": {**OPERATION, "secret": "value"}},
                      {"ok": True, "operation": {**OPERATION, "request_id":
                                                   "87654321-4321-4321-8321-ba0987654321"}}):
            with self.subTest(value=value), mock.patch.object(client, "_request", return_value=value):
                with self.assertRaisesRegex(BackupClientError, "EXTERNAL_UNAVAILABLE"):
                    client.operation_status(REQUEST_ID)


class ApiTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.store = Store(Path(temporary.name) / "hub.sqlite")
        self.store.initialize("admin", "external-agent-admin-password-long")
        self.external = mock.Mock()
        self.external.status.return_value = STATUS
        self.external.preview.return_value = PREVIEW
        self.external.preflight.return_value = PREFLIGHT
        self.external.apply.return_value = OPERATION
        self.external.operation_status.return_value = OPERATION
        self.external.operations.return_value = {"operations": [OPERATION]}
        self.app = HubApp(self.store, external_agent_update=self.external)
        self.server = make_server(self.app, 0)
        self.worker = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.worker.start()
        self.addCleanup(self._shutdown)
        self.base = f"http://127.0.0.1:{self.server.server_port}"
        self.admin = self.request("POST", "/api/v1/session", {"username": "admin",
                             "password": "external-agent-admin-password-long"})[1]["token"]

    def _shutdown(self):
        self.server.shutdown()
        self.server.server_close()
        self.worker.join(2)

    def request(self, method, path, body=None, *, token=None, origin=None, raw=None):
        headers = {}
        if token:
            headers["Authorization"] = "Bearer " + token
        if origin:
            headers["Origin"] = origin
        data = None
        if body is not None or raw is not None:
            data = json.dumps(body).encode() if raw is None else raw
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(self.base + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=4) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as error:
            with error:
                return error.code, json.load(error)

    def test_admin_origin_exact_review_and_audit(self):
        route = "/api/v1/external-agent-update"
        preview = {"archive_sha256": ARCHIVE, "current_hub_manifest_sha256": CURRENT}
        apply = {**preview, "request_id": REQUEST_ID,
                 "external_agent_manifest_sha256": EXTERNAL,
                 "review_sha256": REVIEW, "confirmed": True}
        self.assertEqual(self.request("GET", route)[0], 401)
        selected = self.store.create_user("selected", "external-agent-admin-password-long", "admin")
        selected_token = self.request("POST", "/api/v1/session", {"username": "selected",
                        "password": "external-agent-admin-password-long"})[1]["token"]
        self.store.save_server_access_policy("user", (selected["id"],),
             {"revision": 0, "mode": "selected", "grants": []}, session_token=self.admin)
        self.assertEqual(self.request("GET", route, token=selected_token)[0], 403)
        self.assertEqual(self.request("POST", route + "/apply", apply,
                                      token=selected_token)[0], 403)
        self.assertEqual(self.request("GET", route, token=self.admin), (200, STATUS))
        self.assertEqual(self.request("GET", route + "/operations", token=self.admin),
                         (200, {"operations": [OPERATION]}))
        self.assertEqual(self.request("GET", route + "/operations/" + REQUEST_ID,
                                      token=self.admin), (200, OPERATION))
        self.assertEqual(self.request("POST", route + "/preview", preview, token=self.admin,
                                      origin="https://elsewhere.example")[0], 403)
        self.assertEqual(self.request("POST", route + "/preview", preview, token=self.admin,
                                      origin=self.base), (200, PREVIEW))
        self.assertEqual(self.request("POST", route + "/preflight", preview,
                                      token=self.admin), (200, PREFLIGHT))
        self.assertEqual(self.request("POST", route + "/apply", apply,
                                      token=self.admin, origin=self.base), (200, OPERATION))
        self.external.apply.assert_called_once_with(REQUEST_ID, ARCHIVE, CURRENT, EXTERNAL, REVIEW)
        events = self.request("GET", "/api/v1/audit", token=self.admin)[1]["events"]
        matches = [event for event in events if event["action"] ==
                   "external_agent_update_apply_requested"]
        self.assertEqual(len(matches), 1)
        self.assertEqual(json.loads(matches[0]["details"]), {
            "actor_username": "admin", "archive_sha256": ARCHIVE,
            "current_hub_manifest_sha256": CURRENT,
            "external_agent_manifest_sha256": EXTERNAL, "review_sha256": REVIEW})
        self.assertEqual(matches[0]["subject_id"], REQUEST_ID)

    def test_bad_or_uncertain_apply_is_not_retried(self):
        route = "/api/v1/external-agent-update/apply"
        valid = {"request_id": REQUEST_ID, "archive_sha256": ARCHIVE,
                 "current_hub_manifest_sha256": CURRENT,
                 "external_agent_manifest_sha256": EXTERNAL, "review_sha256": REVIEW,
                 "confirmed": True}
        for body in ({**valid, "confirmed": False}, {**valid, "review_sha256": "bad"},
                     {**valid, "command": "sh"}):
            with self.subTest(body=body):
                self.assertEqual(self.request("POST", route, body, token=self.admin)[0], 400)
        raw = ('{"archive_sha256":"' + ARCHIVE + '","archive_sha256":"' + ARCHIVE + '"}').encode()
        self.assertEqual(self.request("POST", route, token=self.admin, raw=raw)[0], 400)
        self.external.apply.assert_not_called()
        self.external.apply.side_effect = BackupClientError(503, "EXTERNAL_UNCERTAIN")
        self.assertEqual(self.request("POST", route, valid, token=self.admin),
                         (503, {"error": "EXTERNAL_UNCERTAIN"}))
        self.external.apply.assert_called_once()

    def test_busy_apply_and_revoked_session_do_not_disclose_result(self):
        route = "/api/v1/external-agent-update/apply"
        body = {"request_id": REQUEST_ID, "archive_sha256": ARCHIVE,
                "current_hub_manifest_sha256": CURRENT,
                "external_agent_manifest_sha256": EXTERNAL, "review_sha256": REVIEW,
                "confirmed": True}
        self.assertTrue(self.app.external_agent_update_lock.acquire(blocking=False))
        try:
            self.assertEqual(self.request("POST", route, body, token=self.admin),
                             (409, {"error": "EXTERNAL_BUSY"}))
        finally:
            self.app.external_agent_update_lock.release()
        self.external.apply.assert_not_called()

        def revoke(*_args):
            self.store.logout(self.admin)
            return OPERATION

        self.external.apply.side_effect = revoke
        self.assertEqual(self.request("POST", route, body, token=self.admin),
                         (401, {"error": "Unauthorized"}))
        self.external.apply.assert_called_once()


if __name__ == "__main__":
    unittest.main()
