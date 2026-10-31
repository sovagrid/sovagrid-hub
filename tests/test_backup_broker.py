# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""The Web backup route cannot turn a lost reply into a second snapshot."""

import hashlib
import http.client
import io
import json
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from sovagrid_hub.backup import BackupError, HubBackups, Layout
from sovagrid_hub.backup_broker import (BackupBroker, _request, handle,
                                        _host_command_cancellable, _host_execute,
                                        _stream_send)
from sovagrid_hub.backup_client import (BackupBrokerClient, BackupClientError,
                                        HostBackupBrokerClient, _restore,
                                        _host_portable_operation)
from sovagrid_hub.backup_restore import RestoreOrchestrator
from sovagrid_hub.http_api import HubApp, make_server
from sovagrid_hub.store import Store


PASSWORD = "backup-broker-test-password-long"
RESTORE_ID = "c68244a2-8cf1-43e3-a5ae-aa5791bac657"
HOST_REQUEST_ID = "a" * 32
HOST_ARCHIVE_ID = "b" * 32
HOST_MANIFEST = "c" * 64
HOST_OPERATION = {"ok": True, "protocol": "sovagrid-host-backup-operation-v1",
                  "request_id": HOST_REQUEST_ID, "phase": "accepted", "archive": None,
                  "error": None, "created_at": "2026-10-27T00:00:00+00:00"}
HOST_ARCHIVE = {"id": HOST_ARCHIVE_ID, "created_at": "2026-10-27T00:00:00+00:00",
                "layout": "full", "bytes": 1024, "files": 5}
HOST_RECEIPT = {
    "protocol": "sovagrid-portable-host-receipt-v1",
    "host_archive_id": HOST_ARCHIVE_ID,
    "host_archive_sha256": "d" * 64,
    "source_manifest_sha256": HOST_MANIFEST,
    "images_sha256": "e" * 64,
    "images": {"hub": "sha256:" + "1" * 64, "web": "sha256:" + "2" * 64},
    "container_ids": {"hub": "3" * 64, "web": "4" * 64},
    "exported_configs": {"hub": "sha256:" + "5" * 64,
                         "web": "sha256:" + "6" * 64},
    "rootfs_sha256": {"hub": "7" * 64, "web": "8" * 64},
    "active_units": [], "unit_hashes": {},
}
HOST_PORTABLE = {**HOST_OPERATION, "phase": "complete", "archive": HOST_ARCHIVE,
                 "image_receipt": HOST_RECEIPT}


def restore_record(target_id, *, phase="complete", hub_running=True):
    return {"ok": phase == "complete", "protocol": 1, "request_id": RESTORE_ID,
            "target_id": target_id, "phase": phase,
            "safety_id": "b888c6d8-d3ab-4441-9f45-47c90b279487",
            "plan_id": "fb46864a-d25c-40af-bacb-ad5a4266fb0b",
            "hub_running": hub_running,
            "error": None if phase == "complete" else "RESTORE_RECOVERY_REQUIRED",
            "created_at": 1793000000}


class BackupBrokerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        parent = root / "sovagrid"
        parent.mkdir(mode=0o700)
        data = parent / "hub"
        data.mkdir(mode=0o700)
        self.layout = Layout(parent=parent, data=data, backups=parent / "backups",
                             external_token=root / "bot.token")
        Store(data / "hub.sqlite").initialize("admin", PASSWORD)
        self.manager = HubBackups(layout=self.layout, require_root=False)
        self.broker = BackupBroker(manager=self.manager,
                                   requests=self.layout.backups / ".broker-requests")

    def test_reservation_replay_and_rate_limit(self):
        key = str(uuid.uuid4())
        first = self.broker.execute({"action": "create", "request_key": key})
        self.assertTrue(first["created"])
        self.assertTrue(first["backup"]["verified"])
        self.assertEqual(self.broker.execute({"action": "list"})["ids"],
                         [first["backup"]["id"]])
        again = self.broker.execute({"action": "create", "request_key": key})
        self.assertEqual(again["backup"], first["backup"])
        self.assertFalse(again["created"])
        self.assertEqual(self.broker.execute({"action": "verify", "id": first["backup"]["id"]})
                         ["backup"], first["backup"])
        with self.assertRaisesRegex(BackupError, "CREATE_RATE_LIMITED"):
            self.broker.execute({"action": "create", "request_key": str(uuid.uuid4())})

    def test_failed_create_can_retry_only_the_reserved_identity(self):
        key = str(uuid.uuid4())
        original = self.manager.create
        with mock.patch.object(self.manager, "create", side_effect=BackupError("SNAPSHOT_FAILED")):
            with self.assertRaisesRegex(BackupError, "SNAPSHOT_FAILED"):
                self.broker.execute({"action": "create", "request_key": key})
        reserved = json.loads((self.broker.requests / key).read_text())["backup_id"]
        with mock.patch.object(self.manager, "create", wraps=original) as create:
            result = self.broker.execute({"action": "create", "request_key": key})
        self.assertEqual(create.call_args.kwargs, {"identity": reserved})
        self.assertEqual(result["backup"]["id"], reserved)
        self.assertTrue(result["created"])
        self.assertTrue((self.layout.backups / reserved).exists())

    def test_client_and_broker_unix_socket_round_trip(self):
        path = str(Path(self.temp.name) / "control.sock")
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(listener.close)
        listener.bind(path)
        listener.listen(1)
        listener.settimeout(5)

        def serve_three():
            for _ in range(3):
                connection, _ = listener.accept()
                with connection:
                    handle(connection, self.broker)

        worker = threading.Thread(target=serve_three, daemon=True)
        client = BackupBrokerClient(path)
        with mock.patch("sovagrid_hub.backup_broker._peer_uid", return_value=10001):
            worker.start()
            key = str(uuid.uuid4())
            backup, created = client.create(key)
            self.assertTrue(created)
            self.assertEqual(set(backup), {"id", "created_at", "database_bytes",
                                           "telegram_token_included", "verified"})
            self.assertEqual(client.verify(backup["id"]), backup)
            self.assertEqual(client.list(), {"ids": [backup["id"]]})
        worker.join(5)
        self.assertFalse(worker.is_alive())

    def test_socket_rejects_wrong_uid_and_bad_requests_without_copying(self):
        for uid, payload in ((0, b'{"action":"list"}\n'),
                             (10001, b'{"action":"create","request_key":"bad"}\n'),
                             (10001, b'{"action":"list","action":"create"}\n')):
            with self.subTest(uid=uid, payload=payload):
                caller, server = socket.socketpair()
                try:
                    caller.sendall(payload)
                    with mock.patch("sovagrid_hub.backup_broker._peer_uid", return_value=uid):
                        handle(server, self.broker)
                    response = json.loads(caller.recv(4096))
                    self.assertFalse(response["ok"])
                finally:
                    caller.close()
                    server.close()
        self.assertFalse(self.layout.backups.exists())
        for payload in (b'{"action":"verify","id":"../hub.sqlite"}\n',
                        b'{"action":"list"}\ntrailing', b'{}'):
            with self.assertRaises(BackupError):
                _request(payload)

    def test_restore_request_grammar_and_failed_status_validation(self):
        target = str(uuid.uuid4())
        accepted = (
            {"action": "restore_list"},
            {"action": "restore_status", "request_id": RESTORE_ID},
            {"action": "restore_recover", "request_id": RESTORE_ID},
            {"action": "restore_apply", "request_id": RESTORE_ID, "target_id": target},
        )
        for payload in accepted:
            self.assertEqual(_request((json.dumps(payload) + "\n").encode()), payload)
        for payload in ({"action": "restore_apply", "request_id": RESTORE_ID,
                         "target_id": RESTORE_ID},
                        {"action": "restore_apply", "request_id": "../x", "target_id": target},
                        {"action": "restore_recover", "request_id": RESTORE_ID,
                         "target_id": target}):
            with self.assertRaisesRegex(BackupError, "INVALID_REQUEST"):
                _request((json.dumps(payload) + "\n").encode())
        failure = restore_record(target, phase="recovery_required", hub_running=False)
        self.assertEqual(_restore(failure, request_id=RESTORE_ID), failure)
        with self.assertRaises(BackupClientError):
            _restore({**failure, "target_id": "../etc/shadow"})
        with self.assertRaises(BackupClientError):
            _restore({**failure, "ok": True})

    def test_host_request_grammar_and_pinned_argv(self):
        accepted = (
            {"action": "host_plan"}, {"action": "host_archives"},
            {"action": "host_operations"},
            {"action": "host_verify", "id": HOST_ARCHIVE_ID},
            {"action": "host_status", "request_id": HOST_REQUEST_ID},
            {"action": "host_recover", "request_id": HOST_REQUEST_ID},
            {"action": "host_start", "request_id": HOST_REQUEST_ID,
             "expected_manifest_sha256": HOST_MANIFEST},
        )
        for payload in accepted:
            self.assertEqual(_request((json.dumps(payload) + "\n").encode()), payload)
        for payload in (
                {"action": "host_start", "request_id": "../bad",
                 "expected_manifest_sha256": HOST_MANIFEST},
                {"action": "host_start", "request_id": HOST_REQUEST_ID,
                 "expected_manifest_sha256": "bad"},
                {"action": "host_recover", "request_id": HOST_REQUEST_ID,
                 "extra": "command"},
                {"action": "host_verify", "id": []},
                {"action": ["host_start"]}):
            with self.assertRaisesRegex(BackupError, "INVALID_REQUEST"):
                _request((json.dumps(payload) + "\n").encode())
        with mock.patch("sovagrid_hub.backup_broker.subprocess.run") as run:
            run.return_value.returncode = 0
            run.return_value.stdout = (json.dumps(HOST_OPERATION) + "\n").encode()
            self.assertEqual(_host_execute(accepted[-1]), HOST_OPERATION)
            argv = run.call_args.args[0]
            self.assertEqual(argv, ["/usr/bin/python3", "-B", "-I",
                                    "/opt/sovagrid-src/sovagrid-blueprint/deploy/host_backup_orchestrator.py",
                                    "start", HOST_REQUEST_ID, HOST_MANIFEST])
            self.assertNotIn("shell", run.call_args.kwargs)

    def test_host_client_refuses_malformed_metadata_and_accepts_operation(self):
        client = HostBackupBrokerClient("/unused.sock")
        plan = {"ok": True, "manifest_sha256": HOST_MANIFEST,
                "plan": {"layout": "full", "active_units": [],
                         "running_containers": ["hub", "web", "ssh-gateway"],
                         "offline_ready": False}}
        with mock.patch.object(client, "_request", return_value=plan) as request:
            self.assertEqual(client.plan(), {key: plan[key] for key in ("plan", "manifest_sha256")})
            request.assert_called_once_with({"action": "host_plan"}, timeout_seconds=180)
        with mock.patch.object(client, "_request", return_value={**plan, "plan": {
                **plan["plan"], "running_containers": ["hub", "web"]}}):
            self.assertEqual(client.plan()["plan"]["running_containers"], ["hub", "web"])
        for containers in (["hub", "web", "ssh-gateway", "foreign"],
                           ["hub", "hub"], ["hub", "foreign"]):
            with self.subTest(containers=containers), \
                 mock.patch.object(client, "_request", return_value={**plan, "plan": {
                     **plan["plan"], "running_containers": containers}}), \
                 self.assertRaises(BackupClientError):
                client.plan()
        with mock.patch.object(client, "_request", return_value={**plan, "plan": {
                **plan["plan"], "active_units": [[]]}}):
            with self.assertRaises(BackupClientError):
                client.plan()
        with mock.patch.object(client, "_request", return_value=HOST_OPERATION):
            self.assertEqual(client.start(HOST_REQUEST_ID, HOST_MANIFEST), HOST_OPERATION)
        with mock.patch.object(client, "_request", return_value={**HOST_OPERATION,
                                                                  "request_id": "d" * 32}):
            with self.assertRaises(BackupClientError):
                client.operation_status(HOST_REQUEST_ID)

    def test_portable_request_grammar_pinned_helpers_and_receipt_shape(self):
        accepted = (
            {"action": "host_portable_start", "request_id": HOST_REQUEST_ID,
             "expected_manifest_sha256": HOST_MANIFEST},
            {"action": "host_portable_status", "request_id": HOST_REQUEST_ID},
            {"action": "host_portable_verify", "request_id": HOST_REQUEST_ID},
            {"action": "host_portable_stream", "request_id": HOST_REQUEST_ID,
             "part": "images"},
        )
        for payload in accepted:
            self.assertEqual(_request((json.dumps(payload) + "\n").encode()), payload)
        for payload in ({"action": "host_portable_stream", "request_id": "../bad",
                         "part": "images"},
                        {"action": "host_portable_stream", "request_id": HOST_REQUEST_ID,
                         "part": "../../etc/shadow"},
                        {"action": "host_portable_stream", "request_id": HOST_REQUEST_ID,
                         "part": "images", "path": "/etc/shadow"}):
            with self.assertRaisesRegex(BackupError, "INVALID_REQUEST"):
                _request((json.dumps(payload) + "\n").encode())
        with mock.patch("sovagrid_hub.backup_broker._host_command",
                        return_value=HOST_OPERATION) as command:
            self.assertEqual(_host_execute(accepted[0]), HOST_OPERATION)
            command.assert_called_once_with(
                mock.ANY, "start-portable", HOST_REQUEST_ID, HOST_MANIFEST)
        with mock.patch("sovagrid_hub.backup_broker._host_command",
                        side_effect=(HOST_PORTABLE, {
                            "ok": True, "protocol": "sovagrid-host-images-v1",
                            "id": HOST_ARCHIVE_ID, "verified": True,
                            "image_count": 2, "bytes": 2048,
                            "apply_available": False, "receipt": HOST_RECEIPT,
                            "platforms": {}})) as command:
            result = _host_execute(accepted[2])
            self.assertEqual(result["receipt"], HOST_RECEIPT)
            self.assertEqual(result["images_bytes"], 2048)
            self.assertEqual(command.call_args_list[1].args[1:],
                             ("verify-portable", HOST_ARCHIVE_ID))
        self.assertEqual(_host_portable_operation(HOST_PORTABLE), HOST_PORTABLE)
        with self.assertRaises(BackupClientError):
            _host_portable_operation({**HOST_PORTABLE,
                                      "image_receipt": {**HOST_RECEIPT,
                                                        "host_archive_id": "../bad"}})
        for invalid_config in ("5" * 64, "SHA256:" + "5" * 64,
                               "sha256:" + "5" * 63, "sha256:" + "g" * 64):
            with self.subTest(invalid_config=invalid_config):
                with self.assertRaises(BackupClientError):
                    _host_portable_operation({
                        **HOST_PORTABLE,
                        "image_receipt": {
                            **HOST_RECEIPT,
                            "exported_configs": {
                                **HOST_RECEIPT["exported_configs"],
                                "hub": invalid_config,
                            },
                        },
                    })

    def test_portable_stream_verifies_digest_before_header_and_stays_bounded(self):
        data = b"portable-host-archive-test\n" * 40
        path = Path(self.temp.name) / "host.tar.gz"
        path.write_bytes(data)
        archive = {**HOST_ARCHIVE, "bytes": len(data)}
        receipt = {**HOST_RECEIPT,
                   "host_archive_sha256": hashlib.sha256(data).hexdigest()}
        checked = {"ok": True, "request_id": HOST_REQUEST_ID, "archive": archive,
                   "images_bytes": 2048, "receipt": receipt}
        for corrupt in (False, True):
            caller, server = socket.socketpair()
            try:
                def opened(*_args, **_kwargs):
                    fd = os.open(path, os.O_RDONLY)
                    return fd, os.fstat(fd)
                selected = {**checked, "receipt": {**receipt,
                            "host_archive_sha256": "0" * 64}} if corrupt else checked
                with mock.patch("sovagrid_hub.backup_broker._host_command",
                                return_value=HOST_PORTABLE), \
                     mock.patch("sovagrid_hub.backup_broker._host_verify_portable",
                                return_value=selected), \
                     mock.patch("sovagrid_hub.backup_broker._stream_open", side_effect=opened):
                    worker = threading.Thread(target=_stream_send,
                                              args=(server, {"request_id": HOST_REQUEST_ID,
                                                             "part": "archive"}), daemon=True)
                    worker.start()
                    with caller.makefile("rb") as reader:
                        header = json.loads(reader.readline(1025))
                        if corrupt:
                            self.assertEqual(header, {"ok": False,
                                                      "error": "HOST_UNAVAILABLE"})
                        else:
                            self.assertEqual(header["bytes"], len(data))
                            self.assertEqual(reader.read(len(data)), data)
                    worker.join(3)
                    self.assertFalse(worker.is_alive())
            finally:
                caller.close()
                server.close()

    def test_portable_client_streams_exact_bytes_over_broker_socket(self):
        data = b"portable-images-test\n" * 100
        image = Path(self.temp.name) / "images.tar"
        image.write_bytes(data)
        receipt = {**HOST_RECEIPT, "images_sha256": hashlib.sha256(data).hexdigest()}
        checked = {"ok": True, "request_id": HOST_REQUEST_ID,
                   "archive": HOST_ARCHIVE, "images_bytes": len(data),
                   "receipt": receipt}
        path = str(Path(self.temp.name) / "portable.sock")
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(path)
        listener.listen(1)

        def opened(*_args, **_kwargs):
            fd = os.open(image, os.O_RDONLY)
            return fd, os.fstat(fd)

        def serve():
            connection, _ = listener.accept()
            with connection:
                handle(connection, self.broker)

        try:
            with mock.patch("sovagrid_hub.backup_broker._peer_uid", return_value=10001), \
                 mock.patch("sovagrid_hub.backup_broker._host_command",
                            return_value=HOST_PORTABLE), \
                 mock.patch("sovagrid_hub.backup_broker._host_verify_portable",
                            return_value=checked), \
                 mock.patch("sovagrid_hub.backup_broker._stream_open", side_effect=opened):
                worker = threading.Thread(target=serve, daemon=True)
                worker.start()
                client = HostBackupBrokerClient(path)
                with client.open_portable_stream(HOST_REQUEST_ID, "images") as stream:
                    self.assertEqual(stream.size, len(data))
                    self.assertEqual(stream.sha256, hashlib.sha256(data).hexdigest())
                    copied = bytearray()
                    while block := stream.read(31):
                        copied.extend(block)
                self.assertEqual(bytes(copied), data)
                worker.join(3)
                self.assertFalse(worker.is_alive())
        finally:
            listener.close()

    def test_stream_capacity_does_not_block_control_request(self):
        children = {101, 102}
        payload = {"action": "host_portable_stream", "request_id": HOST_REQUEST_ID,
                   "part": "archive"}
        caller, server = socket.socketpair()
        try:
            caller.sendall((json.dumps(payload) + "\n").encode())
            with mock.patch("sovagrid_hub.backup_broker._peer_uid", return_value=10001), \
                 mock.patch("sovagrid_hub.backup_broker._reap_streams"):
                handle(server, self.broker, stream_children=children,
                       listener=mock.Mock(spec=socket.socket))
            self.assertEqual(json.loads(caller.recv(1024))["error"], "HOST_STREAM_BUSY")
        finally:
            caller.close()
            server.close()
        caller, server = socket.socketpair()
        try:
            caller.sendall(b'{"action":"list"}\n')
            with mock.patch("sovagrid_hub.backup_broker._peer_uid", return_value=10001), \
                 mock.patch.object(self.broker, "execute", return_value={"ok": True, "ids": []}):
                handle(server, self.broker, stream_children=children,
                       listener=mock.Mock(spec=socket.socket))
            self.assertEqual(json.loads(caller.recv(1024)), {"ok": True, "ids": []})
        finally:
            caller.close()
            server.close()

    def test_abandoned_portable_header_closes_broker_and_kills_helper(self):
        path = str(Path(self.temp.name) / "abandoned.sock")
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(path)
        listener.listen(1)
        ready = threading.Event()
        ended = []

        def serve():
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(4)
                connection.recv(1024)
                ready.set()
                ended.append(connection.recv(1))

        browser, browser_peer = socket.socketpair()
        try:
            server = threading.Thread(target=serve, daemon=True)
            server.start()
            errors = []

            def fetch():
                try:
                    HostBackupBrokerClient(path).open_portable_stream(
                        HOST_REQUEST_ID, "archive", cancel_socket=browser)
                except BackupClientError as exc:
                    errors.append(exc.status)

            client = threading.Thread(target=fetch, daemon=True)
            client.start()
            self.assertTrue(ready.wait(2))
            browser_peer.close()
            client.join(3)
            server.join(3)
            self.assertFalse(client.is_alive())
            self.assertFalse(server.is_alive())
            self.assertEqual(errors, [499])
            self.assertEqual(ended, [b""])
        finally:
            browser.close()
            browser_peer.close()
            listener.close()

        caller, broker = socket.socketpair()
        try:
            timer = threading.Timer(0.1, caller.close)
            timer.start()
            started = time.monotonic()
            with self.assertRaisesRegex(BackupError, "HOST_UNAVAILABLE"):
                _host_command_cancellable(
                    [sys.executable, "-c", "import time; time.sleep(30)"],
                    30, broker)
            self.assertLess(time.monotonic() - started, 3)
            timer.join(2)
        finally:
            caller.close()
            broker.close()

    def test_web_restore_space_guard_precedes_any_docker_stop(self):
        target = self.manager.create()["id"]
        fake = mock.Mock(spec=RestoreOrchestrator)
        fake._path.return_value = Path(self.temp.name) / "missing-journal"
        fake.apply.return_value = restore_record(target)
        self.broker.restores = fake
        low = SimpleNamespace(f_bavail=0, f_blocks=100, f_frsize=4096)
        payload = {"action": "restore_apply", "request_id": RESTORE_ID,
                   "target_id": target}
        with mock.patch("sovagrid_hub.backup_broker.os.statvfs", return_value=low):
            with self.assertRaisesRegex(BackupError, "INSUFFICIENT_SPACE"):
                self.broker.execute(payload)
        fake.apply.assert_not_called()
        self.assertFalse(fake._path.return_value.exists())
        self.assertEqual(self.broker.execute(payload), fake.apply.return_value)
        fake.apply.assert_called_once_with(target, RESTORE_ID)

    def test_web_restore_replay_skips_space_guard_and_lost_socket_reply_does_not_repeat(self):
        target = self.manager.create()["id"]
        fake = mock.Mock(spec=RestoreOrchestrator)
        journal = Path(self.temp.name) / "existing-journal"
        journal.write_text("reserved")
        fake._path.return_value = journal
        fake.apply.return_value = restore_record(target)
        self.broker.restores = fake
        payload = {"action": "restore_apply", "request_id": RESTORE_ID,
                   "target_id": target}
        low = SimpleNamespace(f_bavail=0, f_blocks=100, f_frsize=4096)
        caller, server = socket.socketpair()
        try:
            caller.sendall((json.dumps(payload) + "\n").encode())
            caller.close()
            with mock.patch("sovagrid_hub.backup_broker._peer_uid", return_value=10001), \
                    mock.patch("sovagrid_hub.backup_broker.os.statvfs", return_value=low):
                handle(server, self.broker)
            fake.apply.assert_called_once_with(target, RESTORE_ID)
        finally:
            caller.close()
            server.close()


class BackupApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(Path(self.temp.name) / "hub.sqlite")
        self.store.initialize("admin", PASSWORD)
        self.backup = mock.Mock(spec=BackupBrokerClient)
        self.backup.list.return_value = {"ids": []}
        self.backup.verify.return_value = {"id": "f829d8d8-8bc7-42d1-8b33-9f6741561c47",
                                           "created_at": 1793000000, "database_bytes": 8192,
                                           "telegram_token_included": False, "verified": True}
        self.backup.create.return_value = (self.backup.verify.return_value, True)
        self.backup.restore_status.return_value = restore_record(self.backup.verify.return_value["id"],
                                                                  phase="recovery_required",
                                                                  hub_running=False)
        self.backup.restore_list.return_value = {"restores": [self.backup.restore_status.return_value]}
        self.backup.restore_apply.return_value = restore_record(self.backup.verify.return_value["id"])
        self.backup.restore_recover.return_value = self.backup.restore_status.return_value
        self.host_backup = mock.Mock(spec=HostBackupBrokerClient)
        self.host_backup.plan.return_value = {
            "manifest_sha256": HOST_MANIFEST,
            "plan": {"layout": "full", "active_units": [], "running_containers": [],
                     "offline_ready": True}}
        self.host_backup.archives.return_value = {"archives": [HOST_ARCHIVE]}
        self.host_backup.verify_archive.return_value = {"archive": HOST_ARCHIVE, "verified": True}
        self.host_backup.operations.return_value = {"operations": [HOST_OPERATION]}
        self.host_backup.operation_status.return_value = HOST_OPERATION
        self.host_backup.start.return_value = HOST_OPERATION
        self.host_backup.portable_capabilities.return_value = {
            "supported": True, "download": True}
        self.host_backup.start_portable.return_value = HOST_OPERATION
        self.host_backup.portable_status.return_value = HOST_PORTABLE
        self.host_backup.verify_portable.return_value = {
            "ok": True, "request_id": HOST_REQUEST_ID, "archive": HOST_ARCHIVE,
            "images_bytes": 2048, "receipt": HOST_RECEIPT}
        self.host_backup.recover.return_value = {**HOST_OPERATION, "phase": "recovered",
                                                 "error": "INTERRUPTED"}
        self.app = HubApp(self.store, backups=self.backup, host_backups=self.host_backup)
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

    def request(self, method, path, data=None, token=None, key=None):
        headers = {}
        raw = None
        if token:
            headers["Authorization"] = "Bearer " + token
        if key:
            headers["Idempotency-Key"] = key
        if data is not None:
            headers["Content-Type"] = "application/json"
            raw = json.dumps(data).encode()
        request = urllib.request.Request(self.base + path, data=raw,
                                         headers=headers, method=method)
        try:
            with urllib.request.urlopen(request) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as error:
            with error:
                return error.code, json.load(error)

    def test_global_admin_and_idempotency_contract(self):
        ident = self.backup.verify.return_value["id"]
        route = "/api/v1/backups"
        self.assertEqual(self.request("GET", route)[0], 401)
        selected = self.store.create_user("selected", PASSWORD, "admin")
        selected_token = self.request("POST", "/api/v1/session",
                                      {"username": "selected", "password": PASSWORD})[1]["token"]
        self.store.save_server_access_policy("user", (selected["id"],),
                                             {"revision": 0, "mode": "selected", "grants": []},
                                             session_token=self.admin)
        self.assertEqual(self.request("GET", route, token=selected_token)[0], 403)
        self.assertEqual(self.request("GET", route, token=self.admin), (200, {"ids": []}))
        self.assertEqual(self.request("GET", f"{route}/{ident}", token=self.admin)[1]["backup"],
                         self.backup.verify.return_value)
        self.assertEqual(self.request("GET", f"{route}/../hub.sqlite", token=self.admin)[0], 404)
        self.assertEqual(self.request("POST", route, {}, self.admin)[0], 400)
        key = str(uuid.uuid4())
        self.assertEqual(self.request("POST", route, {"action": "create"}, self.admin, key)[0], 400)
        self.assertEqual(self.request("POST", route, {}, self.admin, key)[0], 201)
        events = self.request("GET", "/api/v1/audit", token=self.admin)[1]["events"]
        self.assertTrue(any(event["action"] == "backup_create_requested" and
                            event["subject_id"] == key for event in events))
        self.backup.create.return_value = (self.backup.verify.return_value, False)
        self.assertEqual(self.request("POST", route, {}, self.admin, key)[0], 200)
        self.assertEqual(self.backup.create.call_args_list[-1].args, (key,))
        self.assertEqual(self.backup.list.call_count, 1)

    def test_backend_unavailable_is_clean_503(self):
        self.backup.list.side_effect = BackupClientError(503, "Backup broker unavailable")
        self.assertEqual(self.request("GET", "/api/v1/backups", token=self.admin),
                         (503, {"error": "Backup broker unavailable"}))

    def test_web_restore_requires_global_admin_and_persists_request_audit(self):
        target = self.backup.verify.return_value["id"]
        status_path = "/api/v1/backups/restores/" + RESTORE_ID
        self.assertEqual(self.request("GET", "/api/v1/backups/restores")[0], 401)
        selected = self.store.create_user("selected-restore", PASSWORD, "admin")
        selected_token = self.request("POST", "/api/v1/session",
                                      {"username": "selected-restore", "password": PASSWORD})[1]["token"]
        self.store.save_server_access_policy("user", (selected["id"],),
                                             {"revision": 0, "mode": "selected", "grants": []},
                                             session_token=self.admin)
        self.assertEqual(self.request("GET", status_path, token=selected_token)[0], 403)
        self.assertEqual(self.request("POST", "/api/v1/backups/restore",
                                      {"backup_id": target, "request_id": RESTORE_ID},
                                      selected_token)[0], 403)
        self.assertEqual(self.request("GET", "/api/v1/backups/restores", token=self.admin),
                         (200, self.backup.restore_list.return_value))
        self.assertEqual(self.request("GET", status_path, token=self.admin),
                         (200, self.backup.restore_status.return_value))
        self.assertEqual(self.request("GET", status_path + "?extra=1", token=self.admin)[0], 400)
        self.assertEqual(self.request("POST", "/api/v1/backups/restore",
                                      {"backup_id": "../bad", "request_id": RESTORE_ID},
                                      self.admin)[0], 400)
        self.assertEqual(self.request("POST", "/api/v1/backups/restore",
                                      {"backup_id": target, "request_id": RESTORE_ID,
                                       "unexpected": 1}, self.admin)[0], 400)
        self.assertEqual(self.request("POST", "/api/v1/backups/restore",
                                      {"backup_id": target, "request_id": RESTORE_ID},
                                      self.admin), (200, self.backup.restore_apply.return_value))
        self.backup.restore_apply.assert_called_once_with(target, RESTORE_ID)
        events = self.request("GET", "/api/v1/audit", token=self.admin)[1]["events"]
        self.assertTrue(any(item["action"] == "backup_restore_requested" and
                            item["subject_id"] == RESTORE_ID for item in events))
        self.assertEqual(self.request("POST", status_path + "/recover", {}, self.admin),
                         (202, self.backup.restore_recover.return_value))
        events = self.request("GET", "/api/v1/audit", token=self.admin)[1]["events"]
        self.assertTrue(any(item["action"] == "backup_restore_recovery_requested" and
                            item["subject_id"] == RESTORE_ID for item in events))

    def test_host_backup_routes_require_unrestricted_admin_and_audit(self):
        base = "/api/v1/host-backups"
        self.assertEqual(self.request("GET", base + "/plan")[0], 401)
        for role in ("operator", "viewer"):
            self.store.create_user("host-" + role, PASSWORD, role)
            token = self.request("POST", "/api/v1/session",
                                 {"username": "host-" + role, "password": PASSWORD})[1]["token"]
            self.assertEqual(self.request("GET", base + "/plan", token=token)[0], 403)
            self.assertEqual(self.request("POST", base + "/operations",
                                          {"request_id": HOST_REQUEST_ID,
                                           "expected_manifest_sha256": HOST_MANIFEST},
                                          token)[0], 403)
        selected = self.store.create_user("host-selected", PASSWORD, "admin")
        selected_token = self.request("POST", "/api/v1/session",
                                      {"username": "host-selected", "password": PASSWORD})[1]["token"]
        self.store.save_server_access_policy("user", (selected["id"],),
                                             {"revision": 0, "mode": "selected", "grants": []},
                                             session_token=self.admin)
        self.assertEqual(self.request("GET", base + "/plan", token=selected_token)[0], 403)
        self.assertEqual(self.request("GET", base + "/plan", token=self.admin),
                         (200, self.host_backup.plan.return_value))
        self.assertEqual(self.request("GET", base + "/archives", token=self.admin),
                         (200, self.host_backup.archives.return_value))
        self.assertEqual(self.request("GET", base + "/archives/" + HOST_ARCHIVE_ID + "/verify",
                                      token=self.admin),
                         (200, self.host_backup.verify_archive.return_value))
        self.assertEqual(self.request("GET", base + "/operations", token=self.admin),
                         (200, self.host_backup.operations.return_value))
        self.assertEqual(self.request("GET", base + "/operations/" + HOST_REQUEST_ID,
                                      token=self.admin), (200, HOST_OPERATION))
        self.assertEqual(self.request("GET", base + "/operations?extra=1", token=self.admin)[0], 400)
        payload = {"request_id": HOST_REQUEST_ID,
                   "expected_manifest_sha256": HOST_MANIFEST}
        self.assertEqual(self.request("POST", base + "/operations", payload,
                                      selected_token)[0], 403)
        self.assertEqual(self.request("POST", base + "/operations", {**payload,
                                                                     "unexpected": 1},
                                      self.admin)[0], 400)
        self.assertEqual(self.request("POST", base + "/operations", payload,
                                      self.admin), (202, HOST_OPERATION))
        self.host_backup.start.assert_called_once_with(HOST_REQUEST_ID, HOST_MANIFEST)
        self.assertEqual(self.request("POST", base + "/operations/" + HOST_REQUEST_ID +
                                      "/recover", {}, self.admin),
                         (200, self.host_backup.recover.return_value))
        events = self.request("GET", "/api/v1/audit", token=self.admin)[1]["events"]
        self.assertTrue(any(item["action"] == "host_backup_create_requested" and
                            item["subject_id"] == HOST_REQUEST_ID for item in events))
        self.assertTrue(any(item["action"] == "host_backup_recovery_requested" and
                            item["subject_id"] == HOST_REQUEST_ID for item in events))

    def test_portable_web_grants_are_admin_only_one_use_and_stream_attachments(self):
        base = "/api/v1/host-backups"
        portable = base + "/operations/" + HOST_REQUEST_ID + "/portable"
        grant = portable + "/download-grants/archive"
        download = portable + "/download/archive"
        self.assertEqual(self.request("GET", base + "/portable/capabilities")[0], 401)
        self.assertEqual(self.request("GET", base + "/portable/capabilities",
                                      token=self.admin),
                         (200, {"supported": True, "download": True}))
        self.assertEqual(self.request("GET", portable, token=self.admin), (200, HOST_PORTABLE))
        self.assertEqual(self.request("GET", portable + "/verify", token=self.admin),
                         (200, self.host_backup.verify_portable.return_value))
        selected = self.store.create_user("portable-selected", PASSWORD, "admin")
        selected_token = self.request("POST", "/api/v1/session",
                                      {"username": "portable-selected", "password": PASSWORD})[1]["token"]
        self.store.save_server_access_policy("user", (selected["id"],),
                                             {"revision": 0, "mode": "selected", "grants": []},
                                             session_token=self.admin)
        self.assertEqual(self.request("POST", grant, {}, selected_token)[0], 403)
        self.assertEqual(self.request("POST", base + "/portable/operations",
                                      {"request_id": HOST_REQUEST_ID,
                                       "expected_manifest_sha256": HOST_MANIFEST},
                                      self.admin), (202, HOST_OPERATION))
        self.host_backup.start_portable.assert_called_once_with(HOST_REQUEST_ID, HOST_MANIFEST)
        self.assertEqual(self.request("POST", grant, {"unexpected": True}, self.admin)[0], 400)
        request = urllib.request.Request(
            self.base + grant, data=b"{}", method="POST",
            headers={"Authorization": "Bearer " + self.admin,
                     "Content-Type": "application/json"})
        with urllib.request.urlopen(request) as response:
            self.assertEqual(response.status, 200)
            self.assertEqual(json.load(response), {"request_id": HOST_REQUEST_ID,
                                                   "part": "archive",
                                                   "expires_in_seconds": 60})
            cookie = response.headers["Set-Cookie"].split(";", 1)[0]
            self.assertIn("HttpOnly", response.headers["Set-Cookie"])
            self.assertIn("SameSite=Strict", response.headers["Set-Cookie"])
        self.assertEqual(self.request("GET", download)[0], 401)
        wrong = urllib.request.Request(self.base + portable + "/download/images",
                                       headers={"Cookie": cookie})
        with self.assertRaises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(wrong)
        self.assertEqual(error.exception.code, 401)
        error.exception.close()
        # A wrong part consumes the grant, so a later correct use cannot race it.
        with self.assertRaises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(urllib.request.Request(self.base + download,
                                                          headers={"Cookie": cookie}))
        self.assertEqual(error.exception.code, 401)
        error.exception.close()
        with urllib.request.urlopen(request) as response:
            cookie = response.headers["Set-Cookie"].split(";", 1)[0]
            response.read()

        class Stream:
            size = 7
            sha256 = hashlib.sha256(b"payload").hexdigest()
            remaining = 0

            def __enter__(self):
                self.reader = io.BytesIO(b"payload")
                return self

            def __exit__(self, *_args):
                self.reader.close()

            def read(self):
                return self.reader.read(4)

        self.host_backup.open_portable_stream.return_value = Stream()
        with urllib.request.urlopen(urllib.request.Request(self.base + download,
                                                          headers={"Cookie": cookie})) as response:
            self.assertEqual(response.status, 200)
            self.assertEqual(response.read(), b"payload")
            self.assertEqual(response.headers["Cache-Control"], "no-store")
            self.assertEqual(response.headers["X-SovaGrid-SHA256"], Stream.sha256)
            self.assertIn("attachment", response.headers["Content-Disposition"])
        with self.assertRaises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(urllib.request.Request(self.base + download,
                                                          headers={"Cookie": cookie}))
        self.assertEqual(error.exception.code, 401)
        error.exception.close()
        with urllib.request.urlopen(request) as response:
            cookie = response.headers["Set-Cookie"].split(";", 1)[0]
            response.read()
        with self.app.host_download_lock:
            key, record = next(iter(self.app.host_download_grants.items()))
            self.app.host_download_grants[key] = (time.monotonic() - 1, *record[1:])
        with self.assertRaises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(urllib.request.Request(self.base + download,
                                                          headers={"Cookie": cookie}))
        self.assertEqual(error.exception.code, 401)
        error.exception.close()
        events = self.request("GET", "/api/v1/audit", token=self.admin)[1]["events"]
        self.assertTrue(any(item["action"] == "host_backup_download_granted" and
                            item["subject_id"] == HOST_REQUEST_ID for item in events))
        self.assertTrue(any(item["action"] == "host_backup_download_started" and
                            item["subject_id"] == HOST_REQUEST_ID for item in events))

    def test_portable_download_grant_dies_with_session(self):
        route = ("/api/v1/host-backups/operations/" + HOST_REQUEST_ID +
                 "/portable/download-grants/receipt")
        request = urllib.request.Request(
            self.base + route, data=b"{}", method="POST",
            headers={"Authorization": "Bearer " + self.admin,
                     "Content-Type": "application/json"})
        with urllib.request.urlopen(request) as response:
            cookie = response.headers["Set-Cookie"].split(";", 1)[0]
            response.read()
        self.assertEqual(self.request("DELETE", "/api/v1/session", token=self.admin),
                         (200, {"revoked": True}))
        path = route.replace("download-grants", "download")
        with self.assertRaises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(urllib.request.Request(self.base + path,
                                                          headers={"Cookie": cookie}))
        self.assertEqual(error.exception.code, 401)
        error.exception.close()
        self.host_backup.open_portable_stream.assert_not_called()

    def test_portable_download_rechecks_access_after_broker_wait(self):
        route = ("/api/v1/host-backups/operations/" + HOST_REQUEST_ID +
                 "/portable/download-grants/archive")
        download = route.replace("download-grants", "download")

        for mode in ("logout", "downgrade"):
            with self.subTest(mode=mode):
                user = self.store.create_user("download-" + mode, PASSWORD, "admin")
                token = self.request("POST", "/api/v1/session",
                                     {"username": user["username"],
                                      "password": PASSWORD})[1]["token"]
                request = urllib.request.Request(
                    self.base + route, data=b"{}", method="POST",
                    headers={"Authorization": "Bearer " + token,
                             "Content-Type": "application/json"})
                with urllib.request.urlopen(request) as response:
                    cookie = response.headers["Set-Cookie"].split(";", 1)[0]
                    response.read()

                class Stream:
                    size = 7
                    sha256 = hashlib.sha256(b"payload").hexdigest()
                    closed = False

                    def __enter__(self):
                        return self

                    def __exit__(self, *_args):
                        self.closed = True

                stream = Stream()

                def opened(*_args, **_kwargs):
                    if mode == "logout":
                        self.store.logout(token)
                    else:
                        self.store.update_user(user["id"],
                                               {"revision": user["revision"],
                                                "role": "viewer"},
                                               session_token=self.admin)
                    return stream

                self.host_backup.open_portable_stream.side_effect = opened
                with self.assertRaises(urllib.error.HTTPError) as error:
                    urllib.request.urlopen(urllib.request.Request(
                        self.base + download, headers={"Cookie": cookie}))
                self.assertEqual(error.exception.code, 401)
                error.exception.close()
                self.assertTrue(stream.closed)
                self.assertFalse(self.store.unrestricted_admin(token))
                self.host_backup.open_portable_stream.side_effect = None

    def test_portable_download_stops_after_session_revoked_midstream(self):
        route = ("/api/v1/host-backups/operations/" + HOST_REQUEST_ID +
                 "/portable/download-grants/archive")
        user = self.store.create_user("download-midstream", PASSWORD, "admin")
        token = self.request("POST", "/api/v1/session",
                             {"username": user["username"],
                              "password": PASSWORD})[1]["token"]
        request = urllib.request.Request(
            self.base + route, data=b"{}", method="POST",
            headers={"Authorization": "Bearer " + token,
                     "Content-Type": "application/json"})
        with urllib.request.urlopen(request) as response:
            cookie = response.headers["Set-Cookie"].split(";", 1)[0]
            response.read()

        class Stream:
            size = 10 * 131072
            sha256 = "a" * 64

            def __init__(self):
                self.remaining = self.size
                self.reads = 0
                self.closed = False

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                self.closed = True

            def read(self):
                if self.remaining == 0:
                    return b""
                if self.reads == 8:
                    self_store.logout(token)
                self.reads += 1
                self.remaining -= 131072
                return b"a" * 131072

        self_store = self.store
        stream = Stream()
        self.host_backup.open_portable_stream.return_value = stream
        download = route.replace("download-grants", "download")
        with urllib.request.urlopen(urllib.request.Request(
                self.base + download, headers={"Cookie": cookie})) as response:
            self.assertEqual(response.status, 200)
            with self.assertRaises(http.client.IncompleteRead) as error:
                response.read()
        self.assertEqual(len(error.exception.partial), 8 * 131072)
        self.assertTrue(stream.closed)
        self.assertFalse(self.store.unrestricted_admin(token))
