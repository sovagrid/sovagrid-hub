# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
import json
import sqlite3
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from sovagrid_hub.http_api import HubApp, make_server
from sovagrid_hub.store import MaintenanceConflict, Store
from sovagrid_hub.telegram import TelegramBot


def metric(now, cpu=10):
    return {"collected_at": now, "cpu_percent": cpu, "memory_percent": 20,
            "disk_percent": 30, "network_rx_bytes": 100, "network_tx_bytes": 200,
            "load1": 0.5, "uptime_seconds": 3600}


class MaintenanceStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "hub.sqlite"
        self.store = Store(self.path, offline_seconds=120)
        self.store.initialize("admin", "very-long-test-password")
        self.sid = self.store.create_server("server-one")["id"]
        self.now = int(time.time())

    def tearDown(self):
        self.temp.cleanup()

    def window(self, ends=60, now=None):
        now = self.now if now is None else now
        return self.store.create_maintenance(
            self.sid, {"ends_at": now + ends, "reason": "Обновление Ubuntu"}, now=now)

    def test_firing_and_recovery_within_window_stay_visible_without_alert(self):
        window = self.window()
        self.assertEqual(self.store.ingest(self.sid, metric(self.now + 1, 96), now=self.now + 1), [])
        incident = self.store.incidents(state="firing")[0]
        self.assertEqual(incident["kind"], "high_cpu")
        self.assertEqual(self.store.servers(now=self.now + 2)[0]["maintenance"]["id"], window["id"])
        self.assertEqual(self.store.ingest(self.sid, metric(self.now + 2), now=self.now + 2), [])
        self.assertEqual(self.store.incidents(state="firing"), [])
        self.assertEqual(self.store.incidents(state="resolved")[0]["id"], incident["id"])
        self.assertEqual(self.store.sweep_offline(now=self.now + 60), [])
        self.assertIsNone(self.store.servers(now=self.now + 60)[0]["maintenance"])

    def test_existing_problem_gets_one_reminder_after_window(self):
        before = self.store.ingest(self.sid, metric(self.now, 97), now=self.now)
        self.assertEqual([(e["kind"], e["state"]) for e in before], [("high_cpu", "firing")])
        self.window(now=self.now + 1)
        self.assertEqual(self.store.ingest(self.sid, metric(self.now + 2, 97), now=self.now + 2), [])
        self.assertEqual(self.store.sweep_offline(now=self.now + 60), [])
        after = self.store.sweep_offline(now=self.now + 61)
        self.assertEqual([(e["id"], e["state"]) for e in after], [(before[0]["id"], "firing")])
        self.assertEqual(self.store.sweep_offline(now=self.now + 62), [])
        recovered = self.store.ingest(self.sid, metric(self.now + 63), now=self.now + 63)
        self.assertEqual([(e["id"], e["state"]) for e in recovered], [(before[0]["id"], "resolved")])

    def test_first_recovery_sample_after_expiry_does_not_raise_false_alarm(self):
        self.window()
        self.assertEqual(self.store.ingest(self.sid, metric(self.now + 1, 99), now=self.now + 1), [])
        self.assertEqual(self.store.ingest(self.sid, metric(self.now + 61), now=self.now + 61), [])
        self.assertEqual(self.store.sweep_offline(now=self.now + 62), [])

    def test_preexisting_incident_recovery_during_window_stays_silent(self):
        first = self.store.ingest(self.sid, metric(self.now, 96), now=self.now)
        self.assertEqual(len(first), 1)
        self.window(now=self.now + 1)
        self.assertEqual(self.store.ingest(self.sid, metric(self.now + 2), now=self.now + 2), [])
        self.assertEqual(self.store.sweep_offline(now=self.now + 61), [])
        self.assertEqual(self.store.incidents(state="resolved")[0]["id"], first[0]["id"])

    def test_other_server_alerts_continue_during_window(self):
        other = self.store.create_server("server-two")["id"]
        self.window()
        events = self.store.ingest(other, metric(self.now + 1, 98), now=self.now + 1)
        self.assertEqual([(e["server_id"], e["kind"]) for e in events], [(other, "high_cpu")])

    def test_offline_during_maintenance_is_reported_once_after_expiry(self):
        self.store = Store(self.path, offline_seconds=5)
        self.store.ingest(self.sid, metric(self.now), now=self.now)
        self.window()
        self.assertEqual(self.store.sweep_offline(now=self.now + 6), [])
        self.assertIn("offline", {item["kind"] for item in self.store.incidents(state="firing")})
        events = self.store.sweep_offline(now=self.now + 60)
        self.assertEqual([(e["kind"], e["state"]) for e in events], [("offline", "firing")])
        self.assertEqual(self.store.sweep_offline(now=self.now + 61), [])

    def test_cancel_releases_pending_once_and_keeps_audit(self):
        self.window()
        self.store.ingest(self.sid, metric(self.now + 1, 95), now=self.now + 1)
        window = self.store.maintenance_windows(self.sid, now=self.now + 2)[0]
        result, events = self.store.cancel_maintenance(self.sid, window["id"], now=self.now + 2)
        self.assertEqual(result["status"], "cancelled")
        self.assertEqual([(e["kind"], e["state"]) for e in events], [("high_cpu", "firing")])
        self.assertEqual(self.store.sweep_offline(now=self.now + 3), [])
        with self.assertRaises(MaintenanceConflict):
            self.store.cancel_maintenance(self.sid, window["id"], now=self.now + 3)
        actions = [event["action"] for event in self.store.audit_events()]
        self.assertIn("maintenance_started", actions)
        self.assertIn("maintenance_cancelled", actions)

    def test_immediate_cancel_reminder_is_not_suppressed_by_its_own_window(self):
        self.store.ingest(self.sid, metric(self.now, 96), now=self.now)
        window = self.window()
        _, reminders = self.store.cancel_maintenance(self.sid, window["id"], now=self.now)
        self.assertEqual(len(reminders), 1)
        self.assertTrue(self.store.alert_delivery_allowed(reminders[0], now=self.now))
        self.window(now=self.now)
        self.assertFalse(self.store.alert_delivery_allowed(reminders[0], now=self.now))

    def test_migration_preserves_pending_alert_across_restart(self):
        with sqlite3.connect(self.path) as db:
            db.execute("DROP TABLE maintenance_deferred")
            db.execute("DROP TABLE maintenance_windows")
        self.store.migrate()
        self.store.migrate()
        self.window()
        self.store.ingest(self.sid, metric(self.now + 1, 95), now=self.now + 1)
        restarted = Store(self.path, offline_seconds=120)
        restarted.migrate()
        self.assertEqual(len(restarted.maintenance_windows(self.sid, now=self.now + 1)), 1)
        self.assertEqual([e["kind"] for e in restarted.sweep_offline(now=self.now + 60)], ["high_cpu"])

    def test_concurrent_create_and_expiry_sweep_are_single_claim(self):
        created, conflicts = [], []

        def create():
            try:
                created.append(self.window())
            except MaintenanceConflict:
                conflicts.append(True)

        threads = [threading.Thread(target=create) for _ in range(6)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual((len(created), len(conflicts)), (1, 5))
        self.store.ingest(self.sid, metric(self.now + 1, 95), now=self.now + 1)
        results = []
        threads = [threading.Thread(target=lambda: results.append(self.store.sweep_offline(now=self.now + 60)))
                   for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(sum(len(batch) for batch in results), 1)

    def test_telegram_outbox_drops_old_alert_and_sends_one_reminder(self):
        self.store.add_bot_user(123, 123, "viewer")
        old = self.store.ingest(self.sid, metric(self.now - 62, 96), now=self.now - 62)
        bot = TelegramBot("123:ABC", self.store)
        sent = []
        bot.send_message = lambda chat, message: sent.append((chat, message))
        self.assertEqual(self.store.incident_outbox_pending_count(), 1)
        self.window(now=self.now - 61)
        self.assertFalse(self.store.alert_delivery_allowed(old[0], now=self.now - 60))
        self.assertFalse(self.store.alert_delivery_allowed(old[0], now=self.now))
        self.assertEqual(self.store.incident_outbox_pending_count(), 0)
        reminder = self.store.sweep_offline(now=self.now)
        self.assertEqual(len(reminder), 1)
        self.assertTrue(self.store.alert_delivery_allowed(reminder[0], now=self.now))
        self.assertTrue(bot.deliver_incident_once(now=self.now))
        self.assertFalse(bot.deliver_incident_once(now=self.now))
        self.assertEqual(len(sent), 1)
        self.assertIn("Тревога", sent[0][1])


class MaintenanceAPITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.temp.name) / "hub.sqlite")
        self.store.initialize("admin", "very-long-test-password")
        self.server = make_server(HubApp(self.store), 0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temp.cleanup()

    def request(self, method, path, data=None, token=None):
        headers, body = {}, None
        if token:
            headers["Authorization"] = "Bearer " + token
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

    def test_admin_only_validation_conflict_and_audit(self):
        admin = self.request("POST", "/api/v1/session", {"username": "admin", "password": "very-long-test-password"})[1]["token"]
        server = self.request("POST", "/api/v1/servers", {"name": "api-host"}, admin)[1]
        sid, agent = server["id"], server["agent_token"]
        route = f"/api/v1/servers/{sid}/maintenance"
        now = int(time.time())
        body = {"ends_at": now + 3600, "reason": "Замена диска"}
        for method, path, payload in (("GET", route, None), ("POST", route, body),
                                      ("DELETE", route + "/anything", None)):
            self.assertEqual(self.request(method, path, payload)[0], 401)
            self.assertEqual(self.request(method, path, payload, agent)[0], 401)
        self.assertEqual(self.request("GET", "/api/v1/servers/unknown/maintenance", token=admin)[0], 404)
        self.assertEqual(self.request("POST", "/api/v1/servers/unknown/maintenance", body, admin)[0], 404)
        self.assertEqual(self.request("POST", route, token=admin)[0], 415)
        for bad in ({}, {**body, "extra": 1}, {**body, "ends_at": True},
                    {**body, "ends_at": now + 30}, {**body, "ends_at": now + 8 * 86400},
                    {**body, "reason": " "}, {**body, "reason": "line\nbreak"},
                    {**body, "reason": "A" * 201}):
            self.assertEqual(self.request("POST", route, bad, admin)[0], 400)
        status, created = self.request("POST", route, body, admin)
        self.assertEqual(status, 201)
        window = created["window"]
        self.assertEqual(window["status"], "active")
        self.assertEqual(self.request("POST", route, body, admin)[0], 409)
        self.assertEqual(self.request("GET", route, token=admin)[1]["windows"][0]["id"], window["id"])
        self.assertEqual(self.request("GET", "/api/v1/servers", token=admin)[1]["servers"][0]["maintenance"]["id"], window["id"])
        self.assertEqual(self.request("DELETE", route + "/wrong", token=admin)[0], 404)
        self.assertEqual(self.request("DELETE", route + "/" + window["id"], token=admin)[0], 200)
        self.assertEqual(self.request("DELETE", route + "/" + window["id"], token=admin)[0], 409)
        audit = self.request("GET", "/api/v1/audit", token=admin)[1]["events"]
        self.assertIn("maintenance_started", [item["action"] for item in audit])
        self.assertIn("maintenance_cancelled", [item["action"] for item in audit])
