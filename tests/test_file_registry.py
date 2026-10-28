# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
import base64
import hashlib
import json
import sqlite3
import tempfile
import threading
import time
import unittest
import uuid
import urllib.error
import urllib.request
from pathlib import Path

from sovagrid_hub.files import (FileRegistry, FileRelayError, MAX_BINARY_BYTES,
                                MAX_DOWNLOAD_BYTES, validate_request, validate_result)
from sovagrid_hub.http_api import HubApp, make_server
from sovagrid_hub.store import Store


def post(base, method, path, token="", body=None, key=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    if key:
        headers["Idempotency-Key"] = key
    request = urllib.request.Request(base + path, method=method, headers=headers,
                                     data=json.dumps(body).encode() if body is not None else None)
    try:
        with urllib.request.urlopen(request, timeout=12) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        with error:
            return error.code, json.load(error)


class FileHTTPTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = Path(self.temp.name) / "hub.sqlite"
        self.store = Store(self.db)
        self.store.initialize("admin", "long-password-for-test")
        self.app = HubApp(self.store)
        self.server = make_server(self.app, 0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"
        self.admin = post(self.base, "POST", "/api/v1/session", body={
            "username": "admin", "password": "long-password-for-test"})[1]["token"]
        created = post(self.base, "POST", "/api/v1/servers", self.admin, {"name": "files-test"})[1]
        self.sid, self.agent = created["id"], created["agent_token"]
        self.path = f"/api/v1/servers/{self.sid}/files"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)
        self.temp.cleanup()

    def test_auth_permissions_exact_server_and_no_sqlite_content(self):
        key = str(uuid.uuid4())
        request = {"action": "write", "root": "workspace", "path": "secret.txt",
                   "etag": "a" * 64, "content": base64.urlsafe_b64encode(b"VERY_PRIVATE_CONTENT").decode().rstrip("=")}
        self.assertEqual(post(self.base, "POST", self.path + "/operations", self.admin, request, key)[0], 403)
        self.assertEqual(post(self.base, "POST", f"/api/v1/servers/{self.sid}/commands", self.admin,
                              {"enabled": True})[0], 200)
        self.assertEqual(post(self.base, "POST", self.path + "/operations", "wrong", request, key)[0], 401)
        status, created = post(self.base, "POST", self.path + "/operations", self.admin, request, key)
        self.assertEqual(status, 201)
        op = created["operation"]["id"]
        self.assertEqual(post(self.base, "POST", self.path + "/operations", self.admin, request, key)[0], 200)
        self.assertEqual(post(self.base, "GET", self.path + "/next", "wrong")[0], 401)
        status, leased = post(self.base, "GET", self.path + "/next", self.agent)
        self.assertEqual(status, 200)
        self.assertEqual(leased["operation"]["id"], op)
        self.assertEqual(leased["operation"]["request"]["content"], request["content"])
        other = post(self.base, "POST", "/api/v1/servers", self.admin, {"name": "other"})[1]
        self.assertEqual(post(self.base, "POST", f"/api/v1/servers/{other['id']}/commands", self.admin,
                              {"enabled": True})[0], 200)
        self.assertEqual(post(self.base, "POST", f"/api/v1/servers/{other['id']}/files/operations/{op}/result",
                              other["agent_token"], {"state": "failed", "code": "denied"})[0], 404)
        self.assertEqual(post(self.base, "POST", self.path + f"/operations/{op}/result", self.agent,
                              {"state": "succeeded", "value": {"etag": "b" * 64, "size": 20}})[0], 200)
        self.assertEqual(post(self.base, "GET", self.path + f"/operations/{op}", self.admin)[1]["operation"]["state"], "succeeded")
        raw = self.db.read_bytes()
        self.assertNotIn(b"VERY_PRIVATE_CONTENT", raw)
        self.assertNotIn(request["content"].encode(), raw)
        self.assertNotIn(b"secret.txt", raw)
        self.assertEqual(post(self.base, "POST", f"/api/v1/servers/{self.sid}/commands", self.admin,
                              {"enabled": False})[0], 200)
        self.assertEqual(post(self.base, "GET", self.path + f"/operations/{op}", self.admin)[0], 403)

    def test_read_result_bound_and_revoked_session(self):
        post(self.base, "POST", f"/api/v1/servers/{self.sid}/commands", self.admin, {"enabled": True})
        key = str(uuid.uuid4())
        request = {"action": "read", "root": "workspace", "path": "note.txt"}
        op = post(self.base, "POST", self.path + "/operations", self.admin, request, key)[1]["operation"]["id"]
        post(self.base, "GET", self.path + "/next", self.agent)
        excessive = base64.urlsafe_b64encode(b"x" * 8193).decode().rstrip("=")
        self.assertEqual(post(self.base, "POST", self.path + f"/operations/{op}/result", self.agent,
                              {"state": "succeeded", "value": {"etag": "a" * 64,
                                                                    "size": 8193, "content": excessive}})[0], 400)
        self.assertEqual(post(self.base, "POST", self.path + f"/operations/{op}/result", self.agent,
                              {"state": "succeeded", "value": {"etag": "a" * 64,
                                                                    "size": 4, "content": "dGVzdA"}})[0], 200)
        self.assertEqual(post(self.base, "DELETE", "/api/v1/session", self.admin)[0], 200)
        self.assertEqual(post(self.base, "GET", self.path + f"/operations/{op}", self.admin)[0], 401)
        self.assertEqual(len(self.app.files._operations), 0)

    def test_binary_chunk_large_body_private_result_and_release(self):
        self.assertEqual(post(self.base, "POST", "/api/v1/session", body={
            "username": "admin", "password": "x" * 70000})[0], 413)
        post(self.base, "POST", f"/api/v1/servers/{self.sid}/commands", self.admin, {"enabled": True})
        data = bytes(range(256)) * 256
        encoded = base64.urlsafe_b64encode(data).decode().rstrip("=")
        request = {"action": "upload_chunk", "root": "workspace", "path": "archive.bin",
                   "upload_id": str(uuid.uuid4()), "offset": 0, "content": encoded}
        status, created = post(self.base, "POST", self.path + "/operations", self.admin,
                               request, str(uuid.uuid4()))
        self.assertEqual(status, 201)
        operation_id = created["operation"]["id"]
        leased = post(self.base, "GET", self.path + "/next", self.agent)[1]["operation"]
        self.assertEqual(leased["request"]["content"], encoded)
        self.assertEqual(post(self.base, "POST", self.path + f"/operations/{operation_id}/result",
                              self.agent, {"state": "succeeded", "value": {"received": 65536,
                                                                          "size": 65536}})[0], 200)
        self.assertNotIn("content", self.app.files._operations[operation_id]["request"])
        self.assertNotIn(encoded.encode(), self.db.read_bytes())
        self.assertEqual(post(self.base, "DELETE", self.path + f"/operations/{operation_id}",
                              self.admin)[0], 200)
        self.assertEqual(post(self.base, "GET", self.path + f"/operations/{operation_id}", self.admin)[0], 404)

    def test_binary_protocol_rejects_overflow_and_malformed_results(self):
        common = {"root": "workspace", "path": "file.bin"}
        download_size = MAX_BINARY_BYTES + 1
        self.assertEqual(validate_request({"action": "binary_chunk", **common,
                                           "etag": "a" * 64, "offset": MAX_BINARY_BYTES})["offset"],
                         MAX_BINARY_BYTES)
        self.assertEqual(validate_result("binary_info", {"size": download_size,
                                                         "etag": "a" * 64,
                                                         "sha256": "b" * 64})["size"],
                         download_size)
        for request in (
            {"action": "binary_chunk", **common, "etag": "a" * 64, "offset": 1},
            {"action": "binary_chunk", **common, "etag": "a" * 64, "offset": MAX_DOWNLOAD_BYTES},
            {"action": "upload_begin", **common, "size": 4 * 1024 * 1024 + 1,
             "sha256": "a" * 64, "etag": None},
            {"action": "upload_chunk", **common, "upload_id": str(uuid.uuid4()),
             "offset": 0, "content": base64.urlsafe_b64encode(b"x" * 65537).decode().rstrip("=")},
        ):
            with self.subTest(request=request["action"]), self.assertRaises(FileRelayError):
                validate_request(request)
        with self.assertRaises(FileRelayError):
            validate_result("binary_chunk", {"content": "ZA", "offset": 0, "size": 2,
                                             "etag": "a" * 64})
        with self.assertRaises(FileRelayError):
            validate_result("binary_info", {"size": MAX_DOWNLOAD_BYTES + 1,
                                            "etag": "a" * 64, "sha256": "b" * 64})


class FileWaiterTests(unittest.TestCase):
    def test_one_waiter_per_server_and_global_cap(self):
        registry = FileRegistry()
        results = []
        worker = threading.Thread(target=lambda: results.append(registry.next_agent("server-A", lambda _: True)))
        worker.start()
        deadline = time.monotonic() + 1
        while "server-A" not in registry._next_waiting and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertIn("server-A", registry._next_waiting)
        with self.assertRaises(FileRelayError) as duplicate:
            registry.next_agent("server-A", lambda _: True)
        self.assertEqual(duplicate.exception.status, 429)
        with registry._condition:
            registry._next_waiting.update(f"other-{index}" for index in range(15))
        with self.assertRaises(FileRelayError) as saturated:
            registry.next_agent("server-B", lambda _: True)
        self.assertEqual(saturated.exception.status, 429)
        with registry._condition:
            registry._next_waiting.difference_update(f"other-{index}" for index in range(15))
        registry.create("server-A", "owner", str(uuid.uuid4()), {"action": "roots"})
        worker.join(2)
        self.assertFalse(worker.is_alive())
        self.assertEqual(results[0]["request"], {"action": "roots"})
        self.assertNotIn("server-A", registry._next_waiting)


if __name__ == "__main__":
    unittest.main()
