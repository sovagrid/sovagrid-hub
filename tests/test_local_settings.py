# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Local-only panel settings, discovery, and public transition contracts."""

import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
import uuid
from unittest import mock

from sovagrid_hub.backup import BackupError, HubBackups, Layout
from sovagrid_hub.backup_broker import BackupBroker, _request, handle
from sovagrid_hub.http_api import HubApp, make_server
from sovagrid_hub.local_settings import (
    LocalSettingsClient, LocalSettingsExecutor, PublicSettingsError,
    validate_config, validate_reply)
from sovagrid_hub.public_settings import PublicSettingsClient, PublicSettingsClientError
from sovagrid_hub.store import Store


PASSWORD = "local-settings-test-password-long"
CONFIG = {"panel_path": "/home/control/", "root_behavior": "untouched"}
SOURCE = "a" * 64
STATE = "b" * 64
REQUEST_ID = "a98b3201-7a73-4dc0-81f6-77e4ee9723bd"
PREVIEW = {"protocol": 1, "ok": True, "config": CONFIG,
           "expected_state_sha256": None, "source_manifest_sha256": SOURCE,
           "changed": True, "url": "http://127.0.0.1:8766",
           "certificate_verified": False}
APPLIED = {**PREVIEW, "expected_state_sha256": STATE, "enabled": True}
STATUS = {"protocol": 1, "ok": True, "enabled": True,
          "config": CONFIG, "expected_state_sha256": STATE}
DISABLED = {"protocol": 1, "ok": True, "enabled": False, "changed": True,
            "expected_state_sha256": None}
PUBLIC_DISABLED = {"protocol": 1, "ok": True, "enabled": False,
                   "config": None, "expected_state_sha256": None}


class LocalContractTests(unittest.TestCase):
    def test_exact_request_and_reply_schemas(self):
        self.assertEqual(validate_config(CONFIG), CONFIG)
        for config in ({**CONFIG, "panel_path": "/api/"},
                       {**CONFIG, "panel_path": "../home/"},
                       {**CONFIG, "root_behavior": "wildcard"},
                       {**CONFIG, "extra": True}):
            with self.assertRaises(PublicSettingsError):
                validate_config(config)
        for action, value in (("status", STATUS), ("preview", PREVIEW),
                              ("apply", APPLIED), ("disable", DISABLED)):
            self.assertEqual(validate_reply(action, value, config=CONFIG,
                                            source_sha=SOURCE), value)
        for action, value in (("status", {**STATUS, "secret": "x"}),
                              ("preview", {**PREVIEW, "url": "https://wrong.example"}),
                              ("apply", {**APPLIED, "certificate_verified": True}),
                              ("disable", {**DISABLED, "expected_state_sha256": STATE})):
            with self.assertRaisesRegex(PublicSettingsError, "UNAVAILABLE"):
                validate_reply(action, value, config=CONFIG, source_sha=SOURCE)
        accepted = {"action": "local_disable", "expected_state_sha256": STATE,
                    "request_id": REQUEST_ID}
        self.assertEqual(_request((json.dumps(accepted) + "\n").encode()), accepted)
        for value in ({**accepted, "request_id": "bad"},
                      {**accepted, "command": "rm -rf /"},
                      {"action": "local_apply", "config": CONFIG,
                       "expected_state_sha256": None,
                       "source_manifest_sha256": SOURCE,
                       "request_id": "bad"}):
            with self.assertRaisesRegex(BackupError, "INVALID_REQUEST"):
                _request((json.dumps(value) + "\n").encode())

    def test_public_active_has_distinct_http_conflict(self):
        self.assertEqual(LocalSettingsClient()._error_status("PUBLIC_ACTIVE"),
                         (409, "Public HTTPS is active; change the panel path in Public Web settings"))
        self.assertEqual(PublicSettingsClient()._error_status("LOCAL_ACTIVE"),
                         (409, "Local-only panel is active; disable it before enabling public HTTPS"))


class LocalJournalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.executor = LocalSettingsExecutor(requests=Path(self.temp.name) / "requests",
                                              uid=os.getuid())
        self.apply = {"config": CONFIG, "expected_state_sha256": None,
                      "source_manifest_sha256": SOURCE, "request_id": REQUEST_ID}

    def test_apply_and_disable_each_replay_once(self):
        disabled_id = str(uuid.uuid4())
        disable = {"expected_state_sha256": STATE, "request_id": disabled_id}
        with mock.patch.object(self.executor, "_command", side_effect=[APPLIED, DISABLED]) as command:
            self.assertEqual(self.executor.execute("apply", self.apply), APPLIED)
            self.assertEqual(self.executor.execute("apply", self.apply), APPLIED)
            self.assertEqual(self.executor.execute("disable", disable), DISABLED)
            self.assertEqual(self.executor.execute("disable", disable), DISABLED)
        self.assertEqual(command.call_count, 2)
        with self.assertRaisesRegex(PublicSettingsError, "KEY_REUSED"):
            self.executor.execute("disable", {**disable, "request_id": REQUEST_ID})
        with self.assertRaisesRegex(PublicSettingsError, "KEY_REUSED"):
            self.executor.execute("disable", {**disable, "expected_state_sha256": None})

    def test_uncertain_disable_never_reexecutes(self):
        request = {"expected_state_sha256": STATE, "request_id": REQUEST_ID}
        with mock.patch.object(self.executor, "_command",
                               side_effect=PublicSettingsError("UNCERTAIN")) as command:
            with self.assertRaisesRegex(PublicSettingsError, "UNCERTAIN"):
                self.executor.execute("disable", request)
            with self.assertRaisesRegex(PublicSettingsError, "UNCERTAIN"):
                self.executor.execute("disable", request)
        command.assert_called_once()

    def test_lost_socket_reply_replays_disable_and_status(self):
        root = Path(self.temp.name)
        data = root / "hub"
        data.mkdir()
        layout = Layout(parent=root, data=data, backups=root / "backups",
                        external_token=root / "bot.token")
        broker = BackupBroker(manager=HubBackups(layout=layout, require_root=False),
                              requests=layout.backups / ".broker-requests",
                              local_web=self.executor)
        payload = {"expected_state_sha256": STATE, "request_id": REQUEST_ID}
        caller, server = socket.socketpair()
        try:
            caller.sendall((json.dumps({"action": "local_disable", **payload}) + "\n").encode())
            caller.close()
            with mock.patch("sovagrid_hub.backup_broker._peer_uid", return_value=10001), \
                    mock.patch.object(self.executor, "_command", return_value=DISABLED) as command:
                handle(server, broker)
                self.assertEqual(self.executor.execute("disable", payload), DISABLED)
            command.assert_called_once()
            disabled_status = {"protocol": 1, "ok": True, "enabled": False,
                               "config": None, "expected_state_sha256": None}
            with mock.patch.object(self.executor, "_command", return_value=disabled_status):
                self.assertEqual(self.executor.execute("status", {}), disabled_status)
        finally:
            caller.close()
            server.close()


class LocalApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(Path(self.temp.name) / "hub.sqlite")
        self.store.initialize("admin", PASSWORD)
        self.public = mock.Mock(spec=PublicSettingsClient)
        self.public.status.return_value = PUBLIC_DISABLED
        self.local = mock.Mock(spec=LocalSettingsClient)
        self.local.status.return_value = STATUS
        self.local.preview.return_value = PREVIEW
        self.local.apply.return_value = APPLIED
        self.local.disable.return_value = DISABLED
        self.app = HubApp(self.store, public_web=self.public, local_web=self.local)
        self.server = make_server(self.app, 0)
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

    def test_discovery_is_not_ready_until_async_verified_and_healthz_stays_fast(self):
        gate = threading.Event()
        self.public.status.side_effect = lambda: (gate.wait(2), PUBLIC_DISABLED)[1]
        start = time.monotonic()
        self.assertEqual(self.request("GET", "/api/v1/panel-location"),
                         (503, {"error": "Panel location is not ready"}))
        self.assertLess(time.monotonic() - start, 0.5)
        self.assertEqual(self.request("GET", "/healthz"), (200, {"ok": True}))
        gate.set()
        for _ in range(50):
            status, result = self.request("GET", "/api/v1/panel-location")
            if status == 200:
                break
            time.sleep(0.02)
        self.assertEqual((status, result), (200, {"panel_path": CONFIG["panel_path"]}))

    def test_discovery_refuses_conflicting_public_and_local_states(self):
        self.public.status.return_value = {"protocol": 1, "ok": True, "enabled": True,
                                           "config": {"mode": "ip", "address": "8.8.8.8",
                                                      "acme_environment": "production",
                                                      "panel_path": "/public/control/",
                                                      "root_behavior": "untouched"},
                                           "expected_state_sha256": STATE}
        self.assertEqual(self.request("GET", "/api/v1/panel-location")[0], 503)
        for _ in range(50):
            if self.local.status.called:
                break
            time.sleep(0.02)
        self.assertTrue(self.local.status.called)
        self.assertEqual(self.request("GET", "/api/v1/panel-location"),
                         (503, {"error": "Panel location is not ready"}))

    def test_discovery_invalidates_expired_and_failed_cache(self):
        self.app._set_panel_location("/old/control/")
        self.app._panel_location_next_refresh = 0
        gate = threading.Event()
        self.public.status.side_effect = lambda: (gate.wait(2), PUBLIC_DISABLED)[1]
        self.assertEqual(self.request("GET", "/api/v1/panel-location"),
                         (503, {"error": "Panel location is not ready"}))
        gate.set()
        for _ in range(50):
            status, payload = self.request("GET", "/api/v1/panel-location")
            if status == 200:
                break
            time.sleep(0.02)
        self.assertEqual((status, payload), (200, {"panel_path": CONFIG["panel_path"]}))
        self.app._panel_location_next_refresh = 0
        self.public.status.side_effect = PublicSettingsClientError(503, "unavailable")
        self.assertEqual(self.request("GET", "/api/v1/panel-location")[0], 503)
        time.sleep(0.05)
        self.assertEqual(self.request("GET", "/api/v1/panel-location")[0], 503)

    def test_admin_acl_origin_audit_apply_and_disable(self):
        self.assertEqual(self.request("GET", "/api/v1/local-web")[0], 401)
        selected = self.store.create_user("selected", PASSWORD, "admin")
        selected_token = self.request("POST", "/api/v1/session",
                                      {"username": "selected", "password": PASSWORD})[1]["token"]
        self.store.save_server_access_policy("user", (selected["id"],),
                                             {"revision": 0, "mode": "selected", "grants": []},
                                             session_token=self.admin)
        self.assertEqual(self.request("GET", "/api/v1/local-web", token=selected_token)[0], 403)
        self.assertEqual(self.request("GET", "/api/v1/local-web", token=self.admin), (200, STATUS))
        self.assertEqual(self.request("POST", "/api/v1/local-web/preview", {"config": CONFIG},
                                      token=self.admin, origin="https://other.example")[0], 403)
        self.assertEqual(self.request("POST", "/api/v1/local-web/preview", {"config": CONFIG},
                                      token=self.admin, origin=self.base), (200, PREVIEW))
        apply = {"config": CONFIG, "expected_state_sha256": None,
                 "source_manifest_sha256": SOURCE, "request_id": REQUEST_ID}
        self.assertEqual(self.request("POST", "/api/v1/local-web/apply", apply,
                                      token=self.admin), (200, APPLIED))
        self.local.apply.assert_called_once_with(CONFIG, None, SOURCE, REQUEST_ID)
        self.assertEqual(self.request("GET", "/api/v1/panel-location"),
                         (200, {"panel_path": CONFIG["panel_path"]}))
        disable_id = str(uuid.uuid4())
        self.assertEqual(self.request("POST", "/api/v1/local-web/disable",
                                      {"expected_state_sha256": STATE,
                                       "request_id": disable_id}, token=self.admin),
                         (200, DISABLED))
        self.local.disable.assert_called_once_with(STATE, disable_id)
        self.assertEqual(self.request("GET", "/api/v1/panel-location"),
                         (200, {"panel_path": "/sovagrid/monitoring/"}))
        events = self.request("GET", "/api/v1/audit", token=self.admin)[1]["events"]
        self.assertTrue(any(item["action"] == "local_web_disable_requested" and
                            item["subject_id"] == disable_id for item in events))
        self.assertFalse(any("/home/control/" in json.dumps(item) for item in events))

    def test_revoked_admin_cannot_receive_disable_result(self):
        def revoke(*_args):
            self.store.logout(self.admin)
            return DISABLED
        self.local.disable.side_effect = revoke
        status, payload = self.request("POST", "/api/v1/local-web/disable",
                                       {"expected_state_sha256": STATE,
                                        "request_id": str(uuid.uuid4())}, token=self.admin)
        self.assertEqual((status, payload), (401, {"error": "Unauthorized"}))
        self.assertEqual(self.request("GET", "/api/v1/panel-location"),
                         (200, {"panel_path": "/sovagrid/monitoring/"}))


if __name__ == "__main__":
    unittest.main()
