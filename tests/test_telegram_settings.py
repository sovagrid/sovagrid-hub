# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
import json
import logging
import os
import sqlite3
import stat
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

from sovagrid_hub.http_api import HubApp, make_server
from sovagrid_hub.store import Store
from sovagrid_hub.telegram import TelegramBot
from sovagrid_hub.telegram_runtime import (TOKEN_NAME, TelegramActivationError,
                                           TelegramRuntime)


TOKEN = "123456789:" + "A" * 35
NEXT_TOKEN = "123456789:" + "B" * 35


class FakeBot:
    instances = []

    def __init__(self, token, store):
        self.token = token
        self.store = store
        self.stop = threading.Event()
        self.polling_started = False
        self.last_success_at = None
        self.last_error = None
        self.notifications = []
        self.instances.append(self)

    def start(self, poll=True):
        self.polling_started = poll

    def close(self):
        self.stop.set()

    def enqueue(self, events):
        self.notifications.extend(events)

    def enqueue_job_result(self, job):
        self.notifications.append(job)

    def enqueue_pairing_result(self, chat_id, role):
        self.notifications.append((chat_id, role))


class TelegramSettingsTests(unittest.TestCase):
    def setUp(self):
        FakeBot.instances.clear()
        self.temp = tempfile.TemporaryDirectory()
        self.data = Path(self.temp.name)
        self.db = self.data / "hub.sqlite"
        self.store = Store(self.db)
        self.store.initialize("admin", "long-test-password")
        self.verifications = []
        self.runtime = TelegramRuntime(self.store, self.db, poll=True, bot_factory=FakeBot,
                                       verifier=self.verifications.append)
        self.runtime.start()
        self.server = make_server(HubApp(self.store, self.runtime), 0)
        self.worker = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.worker.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.worker.join(timeout=2)
        self.runtime.close()
        self.temp.cleanup()

    def request(self, method, path, body=None, token=None):
        headers = {}
        data = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body).encode()
        if token:
            headers["Authorization"] = "Bearer " + token
        request = urllib.request.Request(self.base + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as error:
            with error:
                return error.code, json.load(error)

    def admin(self):
        return self.request("POST", "/api/v1/session",
                            {"username": "admin", "password": "long-test-password"})[1]["token"]

    def test_managed_token_is_verified_atomic_private_and_hot_swapped(self):
        admin = self.admin()
        path = self.data / TOKEN_NAME
        self.assertEqual(self.request("GET", "/api/v1/telegram")[0], 401)
        initial = self.request("GET", "/api/v1/telegram", token=admin)[1]["telegram"]
        self.assertEqual(initial["mode"], "managed")
        self.assertFalse(initial["configured"])
        self.assertIsNone(initial["error"])
        self.assertEqual(self.request("POST", "/api/v1/telegram/token", {"token": TOKEN})[0], 401)
        self.assertEqual(self.request("POST", "/api/v1/telegram/token", {"token": "bad"}, admin)[0], 400)
        self.assertFalse(path.exists())

        with mock.patch("sovagrid_hub.http_api.logging.info") as logs:
            saved = self.request("POST", "/api/v1/telegram/token", {"token": TOKEN}, admin)
        self.assertEqual(saved[0], 200)
        self.assertEqual(self.verifications, [TOKEN])
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(path.read_text(), TOKEN + "\n")
        self.assertTrue(saved[1]["telegram"]["configured"])
        self.assertTrue(saved[1]["telegram"]["polling"])
        self.assertFalse(saved[1]["telegram"]["connected"])
        self.assertNotIn(TOKEN, json.dumps(saved[1]))
        self.assertNotIn(TOKEN, str(logs.call_args_list))
        self.assertNotIn(TOKEN, self.db.read_bytes().decode(errors="ignore"))
        self.assertEqual(FakeBot.instances[-1].token, TOKEN)
        FakeBot.instances[-1].last_success_at = time.time()
        self.assertTrue(self.request("GET", "/api/v1/telegram", token=admin)[1]
                        ["telegram"]["connected"])

        self.runtime.verifier = lambda _: "SovaGridTestBot"
        replaced = self.request("POST", "/api/v1/telegram/token", {"token": NEXT_TOKEN}, admin)
        self.assertEqual(replaced[0], 200)
        self.assertEqual(replaced[1]["telegram"]["bot_username"], "SovaGridTestBot")
        self.assertTrue(FakeBot.instances[0].stop.is_set())
        self.assertEqual(path.read_text(), NEXT_TOKEN + "\n")
        self.assertEqual(list(self.data.glob(".telegram-bot-token.*")), [])
        self.assertEqual(self.store.audit_events()[0]["action"], "telegram_token_saved")
        self.assertNotIn(TOKEN, json.dumps(self.store.audit_events()))
        self.assertNotIn(NEXT_TOKEN, json.dumps(self.store.audit_events()))

        self.runtime.close()
        second = TelegramRuntime(self.store, self.db, bot_factory=FakeBot,
                                 verifier=lambda _: self.fail("Startup must not contact getMe"))
        second.start()
        self.assertEqual(FakeBot.instances[-1].token, NEXT_TOKEN)
        self.assertTrue(second.status()["configured"])
        self.assertEqual(second.status()["bot_username"], "SovaGridTestBot")
        second.close()
        removed = self.request("DELETE", "/api/v1/telegram/token", token=admin)
        self.assertEqual(removed[0], 200)
        self.assertFalse(path.exists())
        self.assertFalse(removed[1]["telegram"]["configured"])

    def test_verification_failure_keeps_previous_token_and_does_not_leak(self):
        admin = self.admin()
        self.request("POST", "/api/v1/telegram/token", {"token": TOKEN}, admin)
        old_bot = FakeBot.instances[-1]
        self.runtime.verifier = lambda _: (_ for _ in ()).throw(
            TelegramActivationError("BotFather token was rejected", 422))
        rejected = self.request("POST", "/api/v1/telegram/token", {"token": NEXT_TOKEN}, admin)
        self.assertEqual(rejected, (422, {"error": "BotFather token was rejected"}))
        self.assertEqual((self.data / TOKEN_NAME).read_text(), TOKEN + "\n")
        self.assertFalse(old_bot.stop.is_set())
        self.runtime.verifier = lambda _: (_ for _ in ()).throw(
            TelegramActivationError("Telegram validation is unavailable", 503))
        unavailable = self.request("POST", "/api/v1/telegram/token", {"token": NEXT_TOKEN}, admin)
        self.assertEqual(unavailable, (503, {"error": "Telegram validation is unavailable"}))
        self.assertNotIn(NEXT_TOKEN, json.dumps(unavailable))

    def test_token_verification_cannot_persist_after_admin_logout(self):
        admin = self.admin()
        verifying = threading.Event()
        release = threading.Event()
        responses = []

        def slow_verify(_token):
            verifying.set()
            self.assertTrue(release.wait(3))
            return "SovaGridTestBot"

        self.runtime.verifier = slow_verify
        worker = threading.Thread(target=lambda: responses.append(
            self.request("POST", "/api/v1/telegram/token", {"token": TOKEN}, admin)))
        worker.start()
        try:
            self.assertTrue(verifying.wait(2), "BotFather verification did not start")
            self.store.logout(admin)
        finally:
            release.set()
            worker.join(timeout=3)
        self.assertFalse(worker.is_alive())
        self.assertEqual(responses, [(401, {"error": "Unauthorized"})])
        self.assertFalse((self.data / TOKEN_NAME).exists())
        self.assertFalse(self.runtime.status()["configured"])

    def test_telegram_role_mutation_checks_session_inside_transaction(self):
        admin = self.admin()
        self.store.logout(admin)
        with self.assertRaises(PermissionError):
            self.store.add_bot_user(4321, 4321, "admin", session_token=admin)
        self.assertIsNone(self.store.bot_role(4321, 4321))

    def test_getme_verifier_exposes_only_public_username(self):
        with mock.patch("sovagrid_hub.telegram.TelegramBot._call",
                        return_value={"ok": True, "result": {"id": 123456789,
                                                              "username": "SovaGridTestBot"}}):
            self.assertEqual(self.runtime._verify_token(TOKEN), "SovaGridTestBot")
        secret_url = f"https://api.telegram.org/bot{TOKEN}/getMe"
        with mock.patch("sovagrid_hub.telegram.TelegramBot._call",
                        side_effect=urllib.error.HTTPError(secret_url, 401, "denied", {}, None)):
            with self.assertRaises(TelegramActivationError) as error:
                self.runtime._verify_token(TOKEN)
        self.assertEqual(error.exception.status, 422)
        self.assertNotIn(TOKEN, str(error.exception))

    def test_external_token_is_read_only_and_bindings_are_admin_only(self):
        admin = self.admin()
        external = self.data / "legacy-bot.token"
        external.write_text(TOKEN + "\n")
        external.chmod(0o640)
        self.runtime.close()
        self.runtime = TelegramRuntime(self.store, self.db, external, bot_factory=FakeBot,
                                       verifier=lambda _: self.fail("External token cannot be replaced"))
        self.runtime.start()
        self.server.RequestHandlerClass.app.telegram = self.runtime
        info = self.request("GET", "/api/v1/telegram", token=admin)[1]["telegram"]
        self.assertEqual(info["mode"], "managed_externally")
        self.assertTrue(info["configured"])
        self.assertEqual(self.request("POST", "/api/v1/telegram/token", {"token": NEXT_TOKEN}, admin)[0], 409)
        self.assertEqual(self.request("DELETE", "/api/v1/telegram/token", token=admin)[0], 409)
        self.assertEqual(external.read_text(), TOKEN + "\n")

        binding = {"user_id": 123456789, "chat_id": 123456789, "role": "admin"}
        self.assertEqual(self.request("POST", "/api/v1/telegram/bindings", binding)[0], 401)
        self.assertEqual(self.request("POST", "/api/v1/telegram/bindings", binding, admin),
                         (200, {"binding": binding}))
        self.assertEqual(self.request("GET", "/api/v1/telegram", token=admin)[1]
                         ["telegram"]["bindings"], [{**binding, "first_name": "",
                                                     "last_name": "", "username": ""}])
        self.assertEqual(self.request("POST", "/api/v1/telegram/bindings",
                                      {**binding, "role": "viewer"}, admin)[0], 200)
        self.assertEqual(self.store.bot_role(123456789, 123456789), "viewer")
        for invalid in ({**binding, "user_id": True}, {**binding, "chat_id": -1},
                        {**binding, "chat_id": 111}, {**binding, "role": "root"},
                        {**binding, "secret": "x"}):
            self.assertEqual(self.request("POST", "/api/v1/telegram/bindings", invalid, admin)[0], 400)
        self.assertEqual(self.request("DELETE", "/api/v1/telegram/bindings/123456789/123456789")[0], 401)
        self.assertEqual(self.request("DELETE", "/api/v1/telegram/bindings/123456789/123456789",
                                      token=admin), (200, {"removed": True}))
        self.assertEqual(self.request("DELETE", "/api/v1/telegram/bindings/123456789/123456789",
                                      token=admin), (200, {"removed": False}))

    def test_symlink_is_never_overwritten(self):
        admin = self.admin()
        target = self.data / "do-not-change"
        target.write_text("preserve")
        (self.data / TOKEN_NAME).symlink_to(target)
        status, result = self.request("POST", "/api/v1/telegram/token", {"token": TOKEN}, admin)
        self.assertEqual(status, 503)
        self.assertEqual(target.read_text(), "preserve")
        self.assertNotIn(TOKEN, json.dumps(result))

    def test_dangling_symlink_is_reported_as_unsafe(self):
        (self.data / TOKEN_NAME).symlink_to(self.data / "missing")
        runtime = TelegramRuntime(self.store, self.db, bot_factory=FakeBot,
                                  verifier=lambda _: self.fail("No verification at startup"))
        runtime.start()
        self.assertFalse(runtime.status()["configured"])
        self.assertEqual(runtime.status()["error"], "Stored Telegram token could not be loaded")
        runtime.close()

    def test_stopped_bot_ignores_a_late_private_update(self):
        self.store.add_bot_user(123456789, 123456789, "admin")
        bot = TelegramBot(TOKEN, self.store)
        bot.send_message = mock.Mock()
        bot.stop.set()
        bot.process_update({"message": {"chat": {"id": 123456789, "type": "private"},
                                        "from": {"id": 123456789}, "text": "/status"}})
        bot.send_message.assert_not_called()

    def test_private_self_pairing_approval_and_replay_rejection(self):
        admin = self.admin()
        self.assertEqual(self.request("POST", "/api/v1/telegram/token", {"token": TOKEN}, admin)[0], 200)
        bot = TelegramBot(TOKEN, self.store)
        sent = []
        bot.send_message = lambda chat_id, message: sent.append((chat_id, message))
        update = lambda uid, chat, kind, text: {
            "message": {"chat": {"id": chat, "type": kind},
                        "from": {"id": uid, "first_name": "Alice", "last_name": "Server",
                                 "username": "alice_server"}, "text": text}}
        bot.process_update(update(111, 111, "group", "/start"))
        bot.process_update(update(111, 222, "private", "/connect"))
        self.assertEqual(self.store.pending_bot_pairings(), [])
        self.assertEqual(sent, [])

        bot.process_update(update(111, 111, "private", "/start"))
        self.assertIn("запрос отправлен", sent[-1][1])
        bot.process_update(update(111, 111, "private", "/exec host id"))
        self.assertEqual(len(sent), 1)
        pending = self.request("GET", "/api/v1/telegram", token=admin)[1]["telegram"]["pending_requests"]
        self.assertEqual(len(pending), 1)
        self.assertEqual({k: pending[0][k] for k in ("user_id", "chat_id", "first_name", "username")},
                         {"user_id": 111, "chat_id": 111, "first_name": "Alice", "username": "alice_server"})
        self.assertEqual(self.request("POST", "/api/v1/telegram/requests/111/111/approve",
                                      {"role": "operator"})[0], 401)
        self.assertEqual(self.request("POST", "/api/v1/telegram/requests/111/111/approve",
                                      {"role": "owner"}, admin)[0], 400)
        approved = self.request("POST", "/api/v1/telegram/requests/111/111/approve",
                                {"role": "operator"}, admin)
        self.assertEqual(approved[0], 200)
        self.assertEqual(approved[1]["telegram"]["pending_requests"], [])
        self.assertEqual(approved[1]["telegram"]["bindings"][0]["first_name"], "Alice")
        self.assertEqual(self.store.bot_role(111, 111), "operator")
        self.assertEqual(self.request("POST", "/api/v1/telegram/requests/111/111/approve",
                                      {"role": "admin"}, admin)[0], 404)
        self.assertEqual(FakeBot.instances[-1].notifications[-1], (111, "operator"))

        bot.process_update(update(222, 222, "private", "/connect"))
        self.assertEqual(self.request("POST", "/api/v1/telegram/requests/222/222/reject",
                                      {}, admin)[0], 200)
        self.assertEqual(self.request("POST", "/api/v1/telegram/requests/222/222/reject",
                                      {}, admin)[0], 404)
        self.assertEqual(self.store.request_bot_pairing(222, 222), "rejected")

    def test_pairing_expiry_rejection_cooldown_and_capacity(self):
        self.assertEqual(self.store.request_bot_pairing(101, 101, now=1000), "created")
        self.assertEqual(self.store.request_bot_pairing(101, 101, now=1001), "pending")
        self.assertEqual(len(self.store.pending_bot_pairings(now=1000 + 7 * 86400)), 1)
        self.assertEqual(self.store.pending_bot_pairings(now=1001 + 7 * 86400), [])
        self.assertEqual(self.store.request_bot_pairing(101, 101, now=1002 + 7 * 86400), "created")
        self.assertTrue(self.store.reject_bot_pairing(101, 101, now=1003 + 7 * 86400))
        self.assertEqual(self.store.request_bot_pairing(101, 101, now=1004 + 7 * 86400), "rejected")
        self.assertEqual(self.store.request_bot_pairing(101, 101, now=1004 + 8 * 86400), "created")
        for user_id in range(1000, 1099):
            self.assertEqual(self.store.request_bot_pairing(user_id, user_id, now=1004 + 8 * 86400), "created")
        self.assertEqual(self.store.request_bot_pairing(2000, 2000, now=1004 + 8 * 86400), "full")

    def test_existing_bot_bindings_survive_schema_migration(self):
        old_db = self.data / "old-hub.sqlite"
        old_store = Store(old_db)
        old_store.initialize("admin", "long-test-password")
        with sqlite3.connect(old_db) as db:
            db.execute("DROP TABLE bot_users")
            db.execute("""CREATE TABLE bot_users (
                       user_id INTEGER NOT NULL, chat_id INTEGER NOT NULL,
                       role TEXT NOT NULL CHECK(role IN ('viewer','operator','admin')),
                       PRIMARY KEY(user_id, chat_id))""")
            db.execute("INSERT INTO bot_users VALUES (123, 123, 'admin')")
        old_store.migrate()
        self.assertEqual(old_store.bot_bindings(), [{"user_id": 123, "chat_id": 123,
                                                    "role": "admin", "first_name": "",
                                                    "last_name": "", "username": ""}])
        self.assertEqual(old_store.request_bot_pairing(123, 123), "bound")

    def test_update_cursor_survives_restart_and_isolated_token_rotation(self):
        first = TelegramBot(TOKEN, self.store)
        self.assertEqual(first.offset, 0)
        self.assertTrue(self.store.claim_telegram_update(TOKEN, 42))
        self.assertFalse(self.store.claim_telegram_update(TOKEN, 42))
        self.assertFalse(self.store.claim_telegram_update(TOKEN, 41))
        restarted = TelegramBot(TOKEN, self.store)
        self.assertEqual(restarted.offset, 43)
        rotated = TelegramBot(NEXT_TOKEN, self.store)
        self.assertEqual(rotated.offset, 0)
        self.assertTrue(self.store.claim_telegram_update(NEXT_TOKEN, 1))
        self.assertEqual(TelegramBot(NEXT_TOKEN, self.store).offset, 2)
        self.assertEqual(TelegramBot(TOKEN, self.store).offset, 43)
        self.assertNotIn(TOKEN, self.db.read_bytes().decode(errors="ignore"))
        self.assertNotIn(NEXT_TOKEN, self.db.read_bytes().decode(errors="ignore"))
        self.assertTrue(self.store.claim_telegram_update(TOKEN, 77, now=1000))
        self.assertEqual(self.store.telegram_update_offset(TOKEN, now=1000 + 48 * 3600 + 1), 0)
        self.assertTrue(self.store.claim_telegram_update(TOKEN, 1, now=1000 + 48 * 3600 + 1))


if __name__ == "__main__":
    unittest.main()
