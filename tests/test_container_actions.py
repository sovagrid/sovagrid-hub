# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Container jobs remain bound to one exact Docker ID across migrations/retries."""

from __future__ import annotations

import hashlib
import json
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
import uuid
from pathlib import Path

from sovagrid_hub.container_actions import (MARKER, build_command, control_status,
                                            parse_command, protected_inventory, result)
from sovagrid_hub.http_api import HubApp, make_server
from sovagrid_hub.store import Store


IDENT = "a" * 64
OTHER = "b" * 64
PASSWORD = "a-long-container-test-password"


def metric(*, ident=IDENT, name="worker", image="docker.io/library/nginx:stable",
           truncated=False, include=True):
    now = int(time.time())
    snapshot = {"version": 1, "collected_at": now, "engines": [
        {"engine": "docker", "source_status": "ok", "reason": None,
         "truncated": truncated, "containers": [{"id": ident, "name": name,
             "image": image, "state": "running", "health": "healthy",
             "restarts": 0, "cpu_percent": 1.0, "memory_bytes": 1024}]},
        {"engine": "podman", "source_status": "unavailable", "reason": "no_socket",
         "truncated": False, "containers": []},
    ]}
    return {"collected_at": now, "cpu_percent": 1, "memory_percent": 2,
            "disk_percent": 3, "network_rx_bytes": 4, "network_tx_bytes": 5,
            "load1": 0.1, "uptime_seconds": 60,
            "details": {"containers": snapshot} if include else {}}


class ContainerActionContractTests(unittest.TestCase):
    def test_exact_command_result_and_protected_inventory(self):
        command = build_command({"action": "restart", "engine": "docker", "id": IDENT})
        self.assertEqual(command, f"{MARKER} restart docker {IDENT}")
        self.assertEqual(parse_command(command), ("restart", "docker", IDENT))
        for malformed in (command + "; id", command.replace(" docker ", " podman "),
                          command.replace(IDENT, "a" * 12), command.replace("restart", "exec"),
                          command.replace(" ", "  ", 1)):
            with self.subTest(malformed=malformed), self.assertRaises(ValueError):
                parse_command(malformed)
        public = {"action": "status", "id": IDENT, "result": "ok", "state": "running"}
        now = int(time.time())
        self.assertEqual(control_status({"state": "succeeded", "exit_code": 0,
                                         "completed_at": now, "output": json.dumps(public)},
                                        now, IDENT)["state"], "running")
        for bad in (public | {"id": OTHER}, public | {"secret": "bad"},
                    public | {"result": []}, public | {"state": {}},
                    '{"action":"status","action":"stop","id":"' + IDENT +
                    '","result":"ok","state":"running"}'):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                result(json.dumps(bad) if isinstance(bad, dict) else bad, "status", IDENT)
        self.assertFalse(protected_inventory("worker", "docker.io/library/nginx:stable"))
        for name, image in (("sovagrid-hub-1", "nginx:stable"),
                            ("worker", "ghcr.io/amneziavpn/awg:latest"),
                            ("ssh-gateway", "nginx:stable")):
            self.assertTrue(protected_inventory(name, image))

    def test_migration_preserves_rows_rowids_keys_and_rejects_old_marker(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / "hub.sqlite")
            store.initialize("admin", PASSWORD)
            admin = store.login("admin", PASSWORD)[0]
            server = store.create_server("old-host")
            sid = server["id"]
            store.set_remote_commands(sid, True)
            old = store.queue_web_job(sid, admin, "echo old", str(uuid.uuid4()))[0]
            known = store.queue_web_job(sid, admin, "echo known", str(uuid.uuid4()))[0]
            with store.connection() as db:
                db.execute("DROP TABLE container_control_jobs")
                db.execute("""CREATE TABLE jobs_old (
                    id TEXT PRIMARY KEY, server_id TEXT NOT NULL REFERENCES servers(id),
                    actor_user_id INTEGER NOT NULL, chat_id INTEGER NOT NULL,
                    source TEXT NOT NULL DEFAULT 'telegram' CHECK(source IN ('telegram','web')),
                    session_token_hash TEXT, idempotency_key TEXT, command_sha256 TEXT,
                    control_kind TEXT NOT NULL DEFAULT 'generic'
                        CHECK(control_kind IN ('generic','vpn','amnezia','service')),
                    command TEXT NOT NULL, state TEXT NOT NULL, created_at INTEGER NOT NULL,
                    delivered_at INTEGER, completed_at INTEGER, exit_code INTEGER, output TEXT
                )""")
                columns = ("id,server_id,actor_user_id,chat_id,source,session_token_hash,"
                           "idempotency_key,command_sha256,control_kind,command,state,created_at,"
                           "delivered_at,completed_at,exit_code,output")
                db.execute(f"INSERT INTO jobs_old(rowid,{columns}) SELECT rowid,{columns} FROM jobs")
                old_rows = {row["id"]: row["rowid"] for row in db.execute("SELECT rowid,id FROM jobs")}
                db.execute("DROP TABLE jobs")
                db.execute("ALTER TABLE jobs_old RENAME TO jobs")
                db.execute("CREATE INDEX jobs_server_state ON jobs(server_id,state,created_at)")
                db.execute("""CREATE UNIQUE INDEX web_job_request_key
                    ON jobs(session_token_hash,idempotency_key) WHERE idempotency_key IS NOT NULL""")
                db.execute("UPDATE jobs SET command=? WHERE id=?",
                           (f"{MARKER} stop docker {IDENT}", old["id"]))
            store.migrate()
            store.migrate()  # restart-safe and idempotent
            with store.connection() as db:
                self.assertEqual({row["id"]: row["rowid"] for row in
                                  db.execute("SELECT rowid,id FROM jobs")}, old_rows)
                self.assertIn("'container'", db.execute("SELECT sql FROM sqlite_master "
                            "WHERE name='jobs'").fetchone()[0])
                self.assertIsNotNone(db.execute("SELECT 1 FROM jobs WHERE id=?", (known["id"],)).fetchone())
                self.assertEqual(db.execute("PRAGMA foreign_key_check").fetchall(), [])
            leased = store.lease_job(sid)
            self.assertEqual(leased["id"], known["id"])
            with store.connection() as db:
                state = db.execute("SELECT state FROM jobs WHERE id=?", (old["id"],)).fetchone()[0]
            self.assertEqual(state, "cancelled")

    def test_container_kind_without_matching_sidecar_is_cancelled_at_lease(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / "hub.sqlite")
            store.initialize("admin", PASSWORD)
            admin = store.login("admin", PASSWORD)[0]
            sid = store.create_server("host")["id"]
            store.set_remote_commands(sid, True)
            job = store.queue_web_job(sid, admin, "echo legacy")[0]
            command = build_command({"action": "stop", "engine": "docker", "id": IDENT})
            with store.connection() as db:
                db.execute("UPDATE jobs SET command=?,command_sha256=?,control_kind='container' WHERE id=?",
                           (command, hashlib.sha256(command.encode()).hexdigest(), job["id"]))
            self.assertIsNone(store.lease_job(sid))
            with store.connection() as db:
                self.assertEqual(db.execute("SELECT state FROM jobs WHERE id=?",
                                            (job["id"],)).fetchone()[0], "cancelled")


class ContainerActionHTTPTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.temp.name) / "hub.sqlite")
        self.store.initialize("admin", PASSWORD)
        self.server = make_server(HubApp(self.store), 0)
        self.worker = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.worker.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"
        self.admin = self.request("POST", "/api/v1/session",
                                  {"username": "admin", "password": PASSWORD})[1]["token"]
        created = self.store.create_server("container-host")
        self.sid, self.agent = created["id"], created["agent_token"]
        self.store.set_remote_commands(self.sid, True)
        self.actions = f"/api/v1/servers/{self.sid}/containers/actions"
        self.control = f"/api/v1/servers/{self.sid}/containers/control?engine=docker&id={IDENT}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.worker.join(timeout=2)
        self.temp.cleanup()

    def request(self, method, path, body=None, token=None, key=None):
        headers = {}
        data = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body).encode()
        if token is not None:
            headers["Authorization"] = "Bearer " + token
        if key is not None:
            headers["Idempotency-Key"] = key
        req = urllib.request.Request(self.base + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as error:
            with error:
                return error.code, json.load(error)

    def post_action(self, action, *, ident=IDENT, key=None):
        return self.request("POST", self.actions,
                            {"action": action, "engine": "docker", "id": ident},
                            self.admin, key or str(uuid.uuid4()))

    def finish(self, job, action, *, ident=IDENT, broker_result="ok", state="running",
               job_state="succeeded", exit_code=0):
        public = {"action": action, "id": ident, "result": broker_result, "state": state}
        return self.store.finish_job(self.sid, job["id"], job_state, exit_code,
                                     json.dumps(public))

    def test_admin_inventory_status_preflight_replay_and_uncertain_result(self):
        self.assertEqual(self.request("GET", self.control, token=self.admin)[1]
                         ["control"]["source_status"], "unavailable")
        self.assertEqual(self.post_action("stop")[0], 503)
        self.assertEqual(self.post_action("status")[0], 503)
        self.store.ingest(self.sid, metric())
        status = self.post_action("status")
        self.assertEqual(status[0], 201)
        leased = self.store.lease_job(self.sid)
        self.assertEqual(leased["command"], f"{MARKER} status docker {IDENT}")
        self.assertEqual(leased["timeout_seconds"], 40)
        self.finish(leased, "status")
        self.assertEqual(self.request("GET", self.control, token=self.admin)[1]
                         ["control"]["state"], "running")
        key = str(uuid.uuid4())
        stop = self.post_action("stop", key=key)
        self.assertEqual(stop[0], 201)
        self.assertEqual(self.post_action("stop", key=key), (200, stop[1]))
        self.assertEqual(self.request("GET", self.control, token=self.admin)[1]
                         ["control"]["source_status"], "unavailable")
        self.assertEqual(self.post_action("stop")[0], 503)
        leased = self.store.lease_job(self.sid)
        self.assertEqual(leased["command"], f"{MARKER} stop docker {IDENT}")
        self.finish(leased, "stop", broker_result="uncertain", state=None,
                    job_state="timed_out", exit_code=None)
        self.assertEqual(self.post_action("stop")[0], 503)
        self.assertEqual(self.request("GET", self.control, token=self.admin)[1]
                         ["control"]["source_status"], "unavailable")

    def test_unverifiable_mutation_reply_is_uncertain_and_blocks_retries(self):
        self.store.ingest(self.sid, metric())
        status = self.post_action("status")[1]["job"]
        leased = self.store.lease_job(self.sid)
        self.assertEqual(leased["id"], status["id"])
        self.finish(leased, "status")
        restart = self.post_action("restart")[1]["job"]
        leased = self.store.lease_job(self.sid)
        self.assertEqual(leased["id"], restart["id"])
        bad = self.store.finish_job(self.sid, leased["id"], "succeeded", 0,
                                    json.dumps({"action": "restart", "id": IDENT,
                                                "result": "ok", "state": "exited"}))
        self.assertEqual(bad["state"], "timed_out")
        self.assertEqual(bad["output"], "Container action outcome uncertain")
        self.assertEqual(self.post_action("restart")[0], 503)

    def test_generic_markers_protected_targets_and_malformed_result_fail_closed(self):
        self.store.ingest(self.sid, metric())
        for command in (f"{MARKER} restart docker {IDENT}",
                        f"sh -c '{MARKER} restart docker {IDENT}'",
                        f"echo sovagrid-container-action-ctl restart docker {IDENT}"):
            with self.subTest(command=command):
                self.assertEqual(self.request("POST", f"/api/v1/servers/{self.sid}/jobs",
                                              {"command": command}, self.admin)[0], 400)
        status = self.post_action("status")[1]["job"]
        leased = self.store.lease_job(self.sid)
        self.assertEqual(leased["id"], status["id"])
        self.store.finish_job(self.sid, leased["id"], "succeeded", 0,
                              '{"action":"status","id":"' + IDENT +
                              '","result":"ok","state":"running","secret":"bad"}')
        self.assertEqual(self.request("GET", self.control, token=self.admin)[1]
                         ["control"]["source_status"], "unavailable")
        self.assertEqual(self.post_action("stop")[0], 503)
        self.store.ingest(self.sid, metric(name="sovagrid-hub-1"))
        self.assertEqual(self.post_action("status")[0], 403)
        self.store.ingest(self.sid, metric(truncated=True))
        self.assertEqual(self.post_action("status")[0], 503)
        self.store.ingest(self.sid, metric(include=False))
        self.assertEqual(self.post_action("status")[0], 503)
        viewer = self.store.create_user("viewer", PASSWORD, "viewer")
        viewer_token = self.store.login("viewer", PASSWORD)[0]
        self.assertEqual(self.request("POST", self.actions,
                                      {"action": "status", "engine": "docker", "id": IDENT},
                                      viewer_token, str(uuid.uuid4()))[0], 403)


if __name__ == "__main__":
    unittest.main()
