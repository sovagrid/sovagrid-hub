# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""SSH root grants are local, short-lived and one-use."""

import hashlib
import io
import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from sovagrid_hub.http_api import HubApp, make_server
from sovagrid_hub.__main__ import main as hub_main
from sovagrid_hub.store import Store


PASSWORD = "a-long-local-password"


class SSHGrantTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "hub.sqlite"
        self.store = Store(self.path)
        self.store.initialize("local-admin", PASSWORD)

    def tearDown(self):
        self.temp.cleanup()

    def issue(self, now=None):
        with (mock.patch("sovagrid_hub.auth.os.getpid", return_value=1),
              mock.patch("sovagrid_hub.auth.os.getuid", return_value=10001),
              mock.patch("sovagrid_hub.auth.os.geteuid", return_value=10001)):
            return self.store.issue_ssh_grant(now)

    def test_running_hub_child_or_wrong_uid_cannot_mint_and_grant_is_hashed(self):
        with mock.patch("sovagrid_hub.auth.os.geteuid", return_value=10001):
            with self.assertRaises(PermissionError):
                self.store.issue_ssh_grant()
        with (mock.patch("sovagrid_hub.auth.os.getpid", return_value=1),
              mock.patch("sovagrid_hub.auth.os.getuid", return_value=0),
              mock.patch("sovagrid_hub.auth.os.geteuid", return_value=0)):
            with self.assertRaises(PermissionError):
                self.store.issue_ssh_grant()
        grant = self.issue()
        self.assertEqual(set(grant), {"protocol", "grant", "expires_at", "username"})
        self.assertEqual(grant["username"], "local-admin")
        with self.store.connection() as db:
            rows = db.execute("SELECT * FROM ssh_grants").fetchall()
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["grant_hash"], hashlib.sha256(grant["grant"].encode()).hexdigest())
        self.assertNotIn(grant["grant"], json.dumps(self.store.audit_events()))

    def test_redeem_mints_short_admin_session_and_replay_fails(self):
        grant = self.issue(now=1000)["grant"]
        token, expires = self.store.redeem_ssh_grant(grant, now=1010)
        self.assertEqual(expires, 1010 + 3600)
        self.assertEqual(self.store.session_info(token, now=1011)["user"]["role"], "admin")
        self.assertIsNone(self.store.redeem_ssh_grant(grant, now=1011))
        self.assertIsNone(self.store.session_info(token, now=expires))
        with self.store.connection() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM ssh_grants").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM sessions").fetchone()[0], 1)
        audit = json.dumps(self.store.audit_events())
        self.assertNotIn(grant, audit)
        self.assertNotIn(token, audit)

    def test_grant_expires_after_60_seconds(self):
        grant = self.issue(now=1000)
        self.assertEqual(grant["expires_at"], 1060)
        self.assertIsNone(self.store.redeem_ssh_grant(grant["grant"], now=1060))
        self.assertIsNone(self.store.redeem_ssh_grant(grant["grant"], now=1059))

    def test_account_revision_or_disabled_state_invalidates_unredeemed_grant(self):
        owner = self.store.users()[0]
        self.store.create_user("other-admin", PASSWORD, "admin")
        grant = self.issue()["grant"]
        self.store.reset_user_password(owner["id"], 1, "another-long-password")
        self.assertIsNone(self.store.redeem_ssh_grant(grant))
        owner = self.store.users()[0] if self.store.users()[0]["username"] == "local-admin" else self.store.users()[1]
        grant = self.issue()["grant"]
        self.store.update_user(owner["id"], {"revision": owner["revision"], "enabled": False})
        self.assertIsNone(self.store.redeem_ssh_grant(grant))

    def test_demotion_invalidates_grant_even_when_account_stays_enabled(self):
        owner = self.store.users()[0]
        self.store.create_user("other-admin", PASSWORD, "admin")
        grant = self.issue()["grant"]
        self.store.update_user(owner["id"], {"revision": 1, "role": "viewer"})
        self.assertIsNone(self.store.redeem_ssh_grant(grant))

    def test_concurrent_redeemers_receive_at_most_one_session(self):
        grant = self.issue()["grant"]
        barrier = threading.Barrier(2)
        results = []

        def redeem():
            other_store = Store(self.path)
            barrier.wait(3)
            results.append(other_store.redeem_ssh_grant(grant))

        workers = [threading.Thread(target=redeem) for _ in range(2)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(5)
            self.assertFalse(worker.is_alive())
        self.assertEqual(sum(result is not None for result in results), 1)

    def test_redeem_rate_limit_and_input_bounds(self):
        app = HubApp(self.store)
        for bad in (None, "", "x" * 42, "x" * 44, "a" * 42 + "="):
            self.assertEqual(app.redeem_ssh_grant(bad, "192.0.2.55")[0], "invalid")
        self.assertEqual(app.redeem_ssh_grant("x" * 43, "192.0.2.55")[0], "rate_limited")
        grant = self.issue()["grant"]
        self.assertEqual(app.redeem_ssh_grant(grant, "192.0.2.55")[0], "rate_limited")
        self.assertEqual(app.redeem_ssh_grant(grant, "192.0.2.56")[0], "ok")

    def test_cli_requires_one_shot_identity_and_emits_only_grant_json(self):
        out, err = io.StringIO(), io.StringIO()
        with (redirect_stdout(out), redirect_stderr(err),
              mock.patch("sovagrid_hub.__main__.os.getpid", return_value=2),
              mock.patch("sovagrid_hub.__main__.os.getuid", return_value=10001),
              mock.patch("sovagrid_hub.__main__.os.geteuid", return_value=10001)):
            with self.assertRaises(SystemExit) as exit_code:
                hub_main(["--db", str(self.path), "ssh-grant"])
        self.assertEqual(exit_code.exception.code, 2)
        self.assertEqual(out.getvalue(), "")
        self.assertIn("one-shot", err.getvalue())
        out = io.StringIO()
        with (redirect_stdout(out),
              mock.patch("sovagrid_hub.__main__.os.getpid", return_value=1),
              mock.patch("sovagrid_hub.__main__.os.getuid", return_value=10001),
              mock.patch("sovagrid_hub.__main__.os.geteuid", return_value=10001)):
            hub_main(["--db", str(self.path), "ssh-grant"])
        grant = json.loads(out.getvalue())
        self.assertEqual(grant["protocol"], 1)
        self.assertIsNotNone(self.store.redeem_ssh_grant(grant["grant"]))


class SSHGrantHTTPTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "hub.sqlite"
        self.store = Store(self.path)
        self.store.initialize("local-admin", PASSWORD)
        self.server = make_server(HubApp(self.store), 0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)
        self.temp.cleanup()

    def issue(self):
        with (mock.patch("sovagrid_hub.auth.os.getpid", return_value=1),
              mock.patch("sovagrid_hub.auth.os.getuid", return_value=10001),
              mock.patch("sovagrid_hub.auth.os.geteuid", return_value=10001)):
            return self.store.issue_ssh_grant()

    def request(self, path, data, *, content_type="application/json"):
        body = data if isinstance(data, bytes) else json.dumps(data).encode()
        req = urllib.request.Request(self.base + path, data=body,
                                     headers={"Content-Type": content_type}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=3) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as error:
            with error:
                return error.code, json.load(error)

    def test_http_redeem_and_replay_without_password(self):
        grant = self.issue()["grant"]
        status, body = self.request("/api/v1/session/ssh-grant", {"grant": grant})
        self.assertEqual(status, 200)
        self.assertEqual(body["user"]["role"], "admin")
        self.assertEqual(body["user"]["username"], "local-admin")
        self.assertEqual(self.store.session_info(body["token"])["user"]["role"], "admin")
        self.assertEqual(self.request("/api/v1/session/ssh-grant", {"grant": grant})[0], 401)
        self.assertNotIn(grant, json.dumps(self.store.audit_events()))

    def test_http_rejects_query_duplicate_keys_and_foreign_content_type(self):
        grant = self.issue()["grant"]
        self.assertEqual(self.request("/api/v1/session/ssh-grant?grant=x", {"grant": grant})[0], 400)
        self.assertEqual(self.request("/api/v1/session/ssh-grant", b'{"grant":"x","grant":"y"}')[0], 400)
        self.assertEqual(self.request("/api/v1/session/ssh-grant", {"grant": grant}, content_type="text/plain")[0], 415)
        self.assertEqual(self.request("/api/v1/session/ssh-grant", {"grant": grant})[0], 200)


if __name__ == "__main__":
    unittest.main()
