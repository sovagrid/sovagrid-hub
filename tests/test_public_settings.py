# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Public Web control is a bounded admin action with replay after lost HTTP."""

import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
import uuid
from unittest import mock

from sovagrid_hub.backup import HubBackups, Layout
from sovagrid_hub.backup_broker import BackupBroker, _request, handle
from sovagrid_hub.http_api import HubApp, make_server
from sovagrid_hub.public_settings import (
    MAX_JOURNAL, PublicSettingsClient, PublicSettingsError, PublicSettingsExecutor,
    _canonical,
    SCRIPT, validate_config, validate_reply)
from sovagrid_hub.store import Store


PASSWORD = "public-settings-test-password-long"
CONFIG = {"mode": "ip", "address": "8.8.8.8", "acme_environment": "production",
          "panel_path": "/sovagrid/monitoring/", "root_behavior": "untouched"}
SOURCE = "a" * 64
STATE = "b" * 64
REQUEST_ID = "a98b3201-7a73-4dc0-81f6-77e4ee9723bd"
PREVIEW = {"protocol": 1, "ok": True, "config": CONFIG,
           "expected_state_sha256": None, "source_manifest_sha256": SOURCE,
           "changed": True, "url": "https://8.8.8.8", "certificate_verified": False}
APPLIED = {**PREVIEW, "expected_state_sha256": STATE,
           "certificate_verified": True, "enabled": True}
STATUS = {"protocol": 1, "ok": True, "enabled": True, "config": CONFIG,
          "expected_state_sha256": STATE}


class PublicContractTests(unittest.TestCase):
    def test_longest_valid_address_and_path_fit_result_journal(self):
        address = ".".join(("a" * 63, "b" * 63, "c" * 63, "d" * 61))
        config = validate_config({**CONFIG, "mode": "dns", "address": address,
                                  "panel_path": "/" + "a" * 30 + "/" + "b" * 30 + "/" + "c" * 30 + "/"})
        result = {**APPLIED, "config": config, "url": "https://" + address}
        record = {"format": 1, "request_id": REQUEST_ID, "request_sha256": SOURCE,
                  "phase": "complete", "result": result}
        self.assertEqual(len(address), 253)
        self.assertLessEqual(len(_canonical(record)), MAX_JOURNAL)

    def test_config_and_broker_grammar(self):
        self.assertEqual(validate_config(CONFIG), CONFIG)
        for config in ({**CONFIG, "panel_path": "/api/"},
                       {**CONFIG, "panel_path": "/admin//"},
                       {**CONFIG, "root_behavior": "proxy"},
                       {**CONFIG, "address": "127.0.0.1"},
                       {**CONFIG, "extra": "value"}):
            with self.assertRaises(PublicSettingsError):
                validate_config(config)
        accepted = {"action": "public_apply", "config": CONFIG,
                    "expected_state_sha256": None,
                    "source_manifest_sha256": SOURCE, "request_id": REQUEST_ID}
        self.assertEqual(_request((json.dumps(accepted) + "\n").encode()), accepted)
        for payload in ({**accepted, "request_id": "../etc/shadow"},
                        {**accepted, "script": "/bin/sh"},
                        {**accepted, "config": {**CONFIG, "panel_path": "/api/"}},
                        {"action": "public_status", "command": "apply"}):
            with self.assertRaisesRegex(Exception, "INVALID_REQUEST"):
                _request((json.dumps(payload) + "\n").encode())

    def test_exact_helper_replies(self):
        self.assertEqual(validate_reply("status", STATUS), STATUS)
        self.assertEqual(validate_reply("preview", PREVIEW, config=CONFIG), PREVIEW)
        self.assertEqual(validate_reply("apply", APPLIED, config=CONFIG, source_sha=SOURCE), APPLIED)
        for action, reply in (("status", {**STATUS, "unexpected": "secret"}),
                              ("preview", {**PREVIEW, "source_manifest_sha256": "bad"}),
                              ("apply", {**APPLIED, "certificate_verified": False}),
                              ("apply", {**APPLIED, "config": {**CONFIG, "panel_path": "/wrong/"}})):
            with self.assertRaisesRegex(PublicSettingsError, "UNAVAILABLE"):
                validate_reply(action, reply, config=CONFIG, source_sha=SOURCE)
        with self.assertRaisesRegex(PublicSettingsError, "STATE_CHANGED"):
            validate_reply("apply", {"protocol": 1, "ok": False,
                                     "error": {"code": "STATE_CHANGED", "message": "stale"}},
                           config=CONFIG, source_sha=SOURCE)

    def test_command_pins_helper_and_suppresses_stderr(self):
        process = mock.Mock()
        process.communicate.return_value = ((json.dumps(PREVIEW) + "\n").encode(), b"")
        process.returncode = 0
        with mock.patch("sovagrid_hub.public_settings.subprocess.Popen", return_value=process) as popen:
            result = PublicSettingsExecutor()._command("preview", {"config": CONFIG})
        self.assertEqual(result, PREVIEW)
        self.assertEqual(popen.call_args.args[0], ["/usr/bin/python3", "-B", "-I",
                                                   str(SCRIPT), "preview"])
        self.assertEqual(popen.call_args.kwargs["stderr"], subprocess.DEVNULL)
        self.assertEqual(json.loads(process.communicate.call_args.args[0]), {"config": CONFIG})
        with self.assertRaisesRegex(PublicSettingsError, "UNAVAILABLE"):
            PublicSettingsExecutor(script=Path("/tmp/other.py"))._command("status", {})


class PublicJournalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.executor = PublicSettingsExecutor(requests=Path(self.temp.name) / "requests",
                                               uid=os.getuid())
        self.payload = {"config": CONFIG, "expected_state_sha256": None,
                        "source_manifest_sha256": SOURCE, "request_id": REQUEST_ID}

    def test_replay_does_not_apply_twice_and_rejects_reused_key(self):
        with mock.patch.object(self.executor, "_command", return_value=APPLIED) as command:
            self.assertEqual(self.executor.execute("apply", self.payload), APPLIED)
            self.assertEqual(self.executor.execute("apply", self.payload), APPLIED)
        command.assert_called_once_with("apply", self.payload)
        with self.assertRaisesRegex(PublicSettingsError, "KEY_REUSED"):
            self.executor.execute("apply", {**self.payload, "config":
                                            {**CONFIG, "panel_path": "/other/"}})

    def test_legacy_format_one_apply_journal_still_replays(self):
        import hashlib
        self.executor._journal_directory()
        digest = hashlib.sha256(_canonical({key: item for key, item in self.payload.items()
                                            if key != "request_id"})).hexdigest()
        self.executor._write({"format": 1, "request_id": REQUEST_ID,
                              "request_sha256": digest, "phase": "complete",
                              "result": APPLIED}, create=True)
        with mock.patch.object(self.executor, "_command") as command:
            self.assertEqual(self.executor.execute("apply", self.payload), APPLIED)
        command.assert_not_called()

    def test_unknown_outcome_stays_pending_and_status_recovers(self):
        with mock.patch.object(self.executor, "_command",
                               side_effect=PublicSettingsError("UNCERTAIN")) as command:
            with self.assertRaisesRegex(PublicSettingsError, "UNCERTAIN"):
                self.executor.execute("apply", self.payload)
            with self.assertRaisesRegex(PublicSettingsError, "UNCERTAIN"):
                self.executor.execute("apply", self.payload)
        command.assert_called_once()
        with mock.patch.object(self.executor, "_command", return_value=STATUS) as command:
            self.assertEqual(self.executor.execute("status", {}), STATUS)
        command.assert_called_once_with("status", {})

    def test_lost_socket_reply_then_status_and_idempotent_replay(self):
        root = Path(self.temp.name)
        data = root / "hub"
        data.mkdir()
        layout = Layout(parent=root, data=data, backups=root / "backups",
                        external_token=root / "bot.token")
        manager = HubBackups(layout=layout, require_root=False)
        broker = BackupBroker(manager=manager, requests=layout.backups / ".broker-requests",
                              public_web=self.executor)
        caller, server = socket.socketpair()
        try:
            caller.sendall((json.dumps({"action": "public_apply", **self.payload}) + "\n").encode())
            caller.close()  # Hub/Web can disappear when the helper restarts Web.
            with mock.patch("sovagrid_hub.backup_broker._peer_uid", return_value=10001), \
                    mock.patch.object(self.executor, "_command", return_value=APPLIED) as command:
                handle(server, broker)
                self.assertEqual(self.executor.execute("apply", self.payload), APPLIED)
            command.assert_called_once()
            with mock.patch.object(self.executor, "_command", return_value=STATUS):
                self.assertEqual(self.executor.execute("status", {}), STATUS)
        finally:
            caller.close()
            server.close()


class PublicApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(Path(self.temp.name) / "hub.sqlite")
        self.store.initialize("admin", PASSWORD)
        self.public = mock.Mock(spec=PublicSettingsClient)
        self.public.status.return_value = STATUS
        self.public.preview.return_value = PREVIEW
        self.public.apply.return_value = APPLIED
        self.server = make_server(HubApp(self.store, public_web=self.public), 0)
        self.worker = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.worker.start()
        self.addCleanup(self._shutdown)
        self.base = f"http://127.0.0.1:{self.server.server_port}"
        self.admin = self.request("POST", "/api/v1/session",
                                  {"username": "admin", "password": PASSWORD})[1]["token"]

    def _shutdown(self):
        self.server.shutdown()
        self.server.server_close()
        self.worker.join(2)

    def request(self, method, path, body=None, *, token=None, origin=None):
        headers = {}
        if token:
            headers["Authorization"] = "Bearer " + token
        if origin:
            headers["Origin"] = origin
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(self.base + path, data=data,
                                         headers=headers, method=method)
        try:
            with urllib.request.urlopen(request) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as error:
            with error:
                return error.code, json.load(error)

    def test_admin_acl_audit_origin_and_cas_contract(self):
        route = "/api/v1/public-web"
        self.assertEqual(self.request("GET", route)[0], 401)
        selected = self.store.create_user("selected", PASSWORD, "admin")
        selected_token = self.request("POST", "/api/v1/session",
                                      {"username": "selected", "password": PASSWORD})[1]["token"]
        self.store.save_server_access_policy("user", (selected["id"],),
                                             {"revision": 0, "mode": "selected", "grants": []},
                                             session_token=self.admin)
        self.assertEqual(self.request("GET", route, token=selected_token)[0], 403)
        self.assertEqual(self.request("GET", route, token=self.admin), (200, STATUS))
        self.assertEqual(self.request("GET", route + "?extra=1", token=self.admin)[0], 400)
        self.assertEqual(self.request("POST", route + "/preview", {"config": CONFIG},
                                      token=self.admin, origin="https://evil.example")[0], 403)
        self.assertEqual(self.request("POST", route + "/preview", {"config": CONFIG},
                                      token=self.admin, origin=self.base), (200, PREVIEW))
        self.assertEqual(self.request("POST", route + "/apply", {
            "config": CONFIG, "expected_state_sha256": None,
            "source_manifest_sha256": SOURCE, "request_id": REQUEST_ID},
            token=self.admin), (200, APPLIED))
        self.public.apply.assert_called_once_with(CONFIG, None, SOURCE, REQUEST_ID)
        self.assertEqual(self.request("POST", route + "/apply", {
            "config": CONFIG, "expected_state_sha256": "bad",
            "source_manifest_sha256": SOURCE, "request_id": REQUEST_ID},
            token=self.admin)[0], 400)
        events = self.request("GET", "/api/v1/audit", token=self.admin)[1]["events"]
        self.assertTrue(any(item["action"] == "public_web_apply_requested" and
                            item["subject_id"] == REQUEST_ID for item in events))
        self.assertFalse(any("8.8.8.8" in json.dumps(item) for item in events))

    def test_revoked_session_cannot_receive_long_apply_result(self):
        def revoke(*_args):
            self.store.logout(self.admin)
            return APPLIED
        self.public.apply.side_effect = revoke
        result = self.request("POST", "/api/v1/public-web/apply", {
            "config": CONFIG, "expected_state_sha256": None,
            "source_manifest_sha256": SOURCE, "request_id": str(uuid.uuid4())},
            token=self.admin)
        self.assertEqual(result[0], 401)
        self.assertEqual(result[1], {"error": "Unauthorized"})


if __name__ == "__main__":
    unittest.main()
