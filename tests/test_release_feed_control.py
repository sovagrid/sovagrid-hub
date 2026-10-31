# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Signed update controls keep browser requests behind the host broker."""

import json
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from unittest import mock

from sovagrid_hub.backup import BackupError
from sovagrid_hub.backup_broker import FEED_SCRIPT, _feed_execute, _request
from sovagrid_hub.backup_client import BackupClientError, ReleaseFeedBrokerClient
from sovagrid_hub.http_api import HubApp, make_server
from sovagrid_hub.store import Store


PASSWORD = "release-feed-admin-test-password-long"
REVISION = "a" * 64
STATUS = {
    "format": 1, "channel": "stable", "enabled": False, "key_id": None,
    "available_keys": {"sovagrid-2026-10": "b" * 64},
    "timer_installed": True, "timer_enabled": False, "timer_active": False,
    "manual_candidate_active": False, "installed_manifest_sha256": "c" * 64,
    "ledger": {"format": 1, "highest_sequence": 0, "highest_version": "0.0.0",
               "highest_issued_at": 0, "last_seen_at": 0},
    "state_revision": REVISION,
}
ENABLED = {**STATUS, "enabled": True, "key_id": "sovagrid-2026-10",
           "timer_enabled": True, "timer_active": True, "state_revision": "d" * 64}


class FeedBrokerGrammarTests(unittest.TestCase):
    def test_only_fixed_actions_and_a_single_reviewed_revision_cross_socket(self):
        for payload in ({"action": "feed_status"},
                        {"action": "feed_enable", "expected_state": REVISION},
                        {"action": "feed_disable", "expected_state": REVISION}):
            raw = (json.dumps(payload) + "\n").encode()
            self.assertEqual(_request(raw), payload)
        for payload in ({"action": "feed_status", "command": "enable"},
                        {"action": "feed_enable", "expected_state": REVISION,
                         "url": "https://elsewhere.example"},
                        {"action": "feed_enable", "expected_state": "A" * 64},
                        {"action": "feed_disable", "expected_state": "../state"},
                        {"action": "feed_enable", "key_id": "sovagrid-2026-10",
                         "expected_state": REVISION}):
            with self.subTest(payload=payload), self.assertRaisesRegex(
                    BackupError, "INVALID_REQUEST"):
                _request((json.dumps(payload) + "\n").encode())
        with self.assertRaisesRegex(BackupError, "INVALID_REQUEST"):
            _request(('{"action":"feed_enable","action":"feed_disable",'
                      '"expected_state":"' + REVISION + '"}\n').encode())

    def test_host_command_is_fixed_and_replies_must_be_bounded_metadata(self):
        self.assertEqual(str(FEED_SCRIPT),
                         "/opt/sovagrid-src/sovagrid-blueprint/deploy/release_feed.py")
        status_reply = subprocess.CompletedProcess([], 0,
            stdout=(json.dumps(STATUS) + "\n").encode(), stderr=b"private host detail")
        with mock.patch("sovagrid_hub.backup_broker.subprocess.run",
                        return_value=status_reply) as run:
            self.assertEqual(_feed_execute({"action": "feed_status"}),
                             {"ok": True, "status": STATUS})
        self.assertEqual(run.call_args.args[0],
                         ["/usr/bin/python3", "-B", "-I", str(FEED_SCRIPT), "status"])
        self.assertEqual(run.call_args.kwargs["stderr"], subprocess.DEVNULL)
        self.assertEqual(run.call_args.kwargs["stdin"], subprocess.DEVNULL)
        self.assertLessEqual(run.call_args.kwargs["timeout"], 100)
        for raw in ((json.dumps({**STATUS, "private_key": "secret"}) + "\n").encode(),
                    (json.dumps({**STATUS, "state_revision": "bad"}) + "\n").encode(),
                    b"{\"format\":1}\nprivate extra line\n"):
            with self.subTest(raw=raw[:40]), mock.patch(
                    "sovagrid_hub.backup_broker.subprocess.run",
                    return_value=subprocess.CompletedProcess([], 0, raw, b"secret")):
                with self.assertRaisesRegex(BackupError, "FEED_UNAVAILABLE"):
                    _feed_execute({"action": "feed_status"})

    def test_enable_uses_reviewed_revision_and_refusals_have_stable_codes(self):
        applied = subprocess.CompletedProcess([], 0,
            b"SG_RELEASE_FEED:ENABLED:sovagrid-2026-10\n", b"")
        status_reply = subprocess.CompletedProcess([], 0,
            (json.dumps(ENABLED) + "\n").encode(), b"")
        with mock.patch("sovagrid_hub.backup_broker.subprocess.run",
                        side_effect=[applied, status_reply]) as run:
            self.assertEqual(_feed_execute({"action": "feed_enable",
                                             "expected_state": REVISION}),
                             {"ok": True, "status": ENABLED})
        self.assertEqual(run.call_args_list[0].args[0],
                         ["/usr/bin/python3", "-B", "-I", str(FEED_SCRIPT),
                          "enable", "--expected-state", REVISION])
        self.assertEqual(run.call_args_list[1].args[0][-1], "status")
        for code, expected in (("STATE_CHANGED", "FEED_STATE_CHANGED"),
                               ("HUB_ONLY_UNSUPPORTED", "FEED_HUB_ONLY_UNSUPPORTED"),
                               ("UNCONFIGURED_TRUST", "FEED_UNCONFIGURED_TRUST"),
                               ("INVALID_SIGNATURE", "FEED_UNAVAILABLE")):
            refusal = subprocess.CompletedProcess([], 40,
                f"SG_RELEASE_FEED_REFUSE:{code}\n".encode(), b"private host detail")
            with self.subTest(code=code), mock.patch(
                    "sovagrid_hub.backup_broker.subprocess.run",
                    return_value=refusal):
                with self.assertRaisesRegex(BackupError, expected):
                    _feed_execute({"action": "feed_enable",
                                   "expected_state": REVISION})


class FeedClientTests(unittest.TestCase):
    def test_unavailable_socket_uses_stable_feed_error(self):
        with tempfile.TemporaryDirectory() as directory:
            client = ReleaseFeedBrokerClient(str(Path(directory) / "missing.sock"))
            with self.assertRaises(BackupClientError) as failure:
                client.status()
        self.assertEqual(failure.exception.status, 503)
        self.assertEqual(str(failure.exception), "FEED_UNAVAILABLE")

    def test_status_shape_and_cas_are_checked_on_untrusted_socket_reply(self):
        client = ReleaseFeedBrokerClient()
        with mock.patch.object(client, "_request",
                               return_value={"ok": True, "status": STATUS}) as request:
            self.assertEqual(client.status(), STATUS)
            request.assert_called_once_with({"action": "feed_status"},
                                            timeout_seconds=75)
        for altered in ({**STATUS, "private_token": "secret"},
                        {**STATUS, "ledger": {**STATUS["ledger"],
                                              "highest_sequence": True}},
                        {**STATUS, "available_keys":
                          {"sovagrid-2026-10": "not a fingerprint"}}):
            with self.subTest(altered=altered), mock.patch.object(
                    client, "_request", return_value={"ok": True, "status": altered}):
                with self.assertRaises(BackupClientError) as failure:
                    client.status()
                self.assertEqual(failure.exception.status, 503)
        with mock.patch.object(client, "_request") as request:
            for invalid in ("", "A" * 64, "../state"):
                with self.subTest(invalid=invalid), self.assertRaises(BackupClientError) as failure:
                    client.enable(invalid)
                self.assertEqual(failure.exception.status, 400)
            request.assert_not_called()


class FeedApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(Path(self.temp.name) / "hub.sqlite")
        self.store.initialize("admin", PASSWORD)
        self.feed = mock.Mock()
        self.feed.status.return_value = STATUS
        self.feed.enable.return_value = ENABLED
        self.feed.disable.return_value = STATUS
        self.server = make_server(HubApp(self.store, release_feed=self.feed), 0)
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
        request = urllib.request.Request(self.base + path, data=data,
                                         headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=4) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as error:
            with error:
                return error.code, json.load(error)

    def test_unrestricted_admin_cas_origin_and_audit(self):
        route = "/api/v1/release-feed"
        self.assertEqual(self.request("GET", route)[0], 401)
        selected = self.store.create_user("selected", PASSWORD, "admin")
        selected_token = self.request("POST", "/api/v1/session",
                                      {"username": "selected", "password": PASSWORD})[1]["token"]
        self.store.save_server_access_policy("user", (selected["id"],),
                                             {"revision": 0, "mode": "selected", "grants": []},
                                             session_token=self.admin)
        self.assertEqual(self.request("GET", route, token=selected_token)[0], 403)
        self.assertEqual(self.request("POST", route + "/enable",
                                      {"expected_state": REVISION},
                                      token=selected_token)[0], 403)
        self.assertEqual(self.request("GET", route, token=self.admin), (200, STATUS))
        self.assertEqual(self.request("GET", route + "?unexpected=1",
                                      token=self.admin)[0], 400)
        self.assertEqual(self.request("POST", route + "/enable",
                                      {"expected_state": REVISION},
                                      token=self.admin,
                                      origin="https://elsewhere.example")[0], 403)
        self.assertEqual(self.request("POST", route + "/enable",
                                      {"expected_state": REVISION},
                                      token=self.admin, origin=self.base), (200, ENABLED))
        self.feed.enable.assert_called_once_with(REVISION)
        self.assertEqual(self.request("POST", route + "/disable",
                                      {"expected_state": ENABLED["state_revision"]},
                                      token=self.admin), (200, STATUS))
        self.feed.disable.assert_called_once_with(ENABLED["state_revision"])
        events = self.request("GET", "/api/v1/audit", token=self.admin)[1]["events"]
        for action, revision in (("release_feed_enable_requested", REVISION),
                                 ("release_feed_disable_requested",
                                  ENABLED["state_revision"])):
            matching = [item for item in events if item["action"] == action]
            self.assertEqual(len(matching), 1)
            self.assertEqual(json.loads(matching[0]["details"]),
                             {"actor_username": "admin", "expected_state": revision})
            self.assertIsNone(matching[0]["subject_id"])

    def test_bad_or_replayed_review_is_rejected_before_broker(self):
        route = "/api/v1/release-feed/enable"
        for body in ({}, {"expected_state": "bad"},
                     {"expected_state": REVISION, "key_id": "sovagrid-2026-10"}):
            with self.subTest(body=body):
                self.assertEqual(self.request("POST", route, body, token=self.admin)[0], 400)
        raw = ('{"expected_state":"' + REVISION + '",'
               '"expected_state":"' + REVISION + '"}').encode()
        self.assertEqual(self.request("POST", route, token=self.admin, raw=raw)[0], 400)
        self.feed.enable.assert_not_called()

    def test_revoked_admin_cannot_receive_broker_result(self):
        def revoke(_revision):
            self.store.logout(self.admin)
            return ENABLED
        self.feed.enable.side_effect = revoke
        status, body = self.request("POST", "/api/v1/release-feed/enable",
                                    {"expected_state": REVISION}, token=self.admin)
        self.assertEqual((status, body), (401, {"error": "Unauthorized"}))

    def test_review_conflicts_have_actionable_codes_without_host_output(self):
        for status, code in ((409, "STATE_CHANGED"), (409, "HUB_ONLY_UNSUPPORTED"),
                             (503, "UNCONFIGURED_TRUST"), (503, "FEED_UNAVAILABLE"),
                             (503, "TIMER_UNAVAILABLE")):
            with self.subTest(code=code):
                self.feed.enable.side_effect = BackupClientError(status, code)
                self.assertEqual(self.request("POST", "/api/v1/release-feed/enable",
                                              {"expected_state": REVISION},
                                              token=self.admin), (status, {"error": code}))


if __name__ == "__main__":
    unittest.main()
