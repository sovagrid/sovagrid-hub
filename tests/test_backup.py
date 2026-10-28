# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
import json
import hashlib
import os
from pathlib import Path
import sqlite3
import stat
import tempfile
import time
import unittest
from unittest import mock

from sovagrid_hub.backup import BackupError, HubBackups, Layout, main
from sovagrid_hub.service_actions import status_command as service_status_command
from sovagrid_hub.store import Store


TOKEN = "123456789:" + "A" * 35
OTHER_TOKEN = "123456789:" + "B" * 35


class HubBackupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        parent = root / "sovagrid"
        parent.mkdir(mode=0o700)
        data = parent / "hub"
        data.mkdir(mode=0o700)
        external_dir = root / "legacy"
        external_dir.mkdir(mode=0o700)
        self.layout = Layout(parent=parent, data=data, backups=parent / "backups",
                             external_token=external_dir / "bot.token")
        self.store = Store(data / "hub.sqlite")
        self.store.initialize("admin", "long-test-password")
        self.manager = HubBackups(layout=self.layout, require_root=False)

    def tearDown(self):
        self.temp.cleanup()

    def _token(self, *, external=False, value=TOKEN):
        path = (self.layout.external_token if external else
                self.layout.data / "telegram-bot-token")
        path.write_text(value + "\n")
        path.chmod(0o640 if external else 0o600)
        self.store.set_telegram_bot_info(value, None)
        return path

    def _exchange_for_test(self, left, right):
        # Production requires Linux renameat2(RENAME_EXCHANGE). The temporary
        # unit-test tree is isolated and may run on macOS.
        temporary = left.parent / ".unit-test-exchange"
        left.rename(temporary)
        right.rename(left)
        temporary.rename(right)

    def test_wal_snapshot_is_consistent_private_and_verifiable(self):
        writer = sqlite3.connect(self.layout.data / "hub.sqlite")
        try:
            writer.execute("CREATE TABLE backup_marker (value TEXT NOT NULL)")
            writer.execute("INSERT INTO backup_marker VALUES ('committed in WAL')")
            writer.commit()
            self.assertTrue((self.layout.data / "hub.sqlite-wal").exists())
            created = self.manager.create()
        finally:
            writer.close()
        identity = created["id"]
        snapshot = self.layout.backups / identity
        self.assertEqual(self.manager.list(), {"ids": [identity]})
        self.assertTrue(self.manager.verify(identity)["verified"])
        self.assertFalse(created["telegram_token_included"])
        self.assertEqual(stat.S_IMODE(snapshot.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((snapshot / "hub.sqlite").stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE((snapshot / "manifest.json").stat().st_mode), 0o600)
        self.assertEqual(set(path.name for path in snapshot.iterdir()),
                         {"hub.sqlite", "manifest.json"})
        with sqlite3.connect(snapshot / "hub.sqlite") as db:
            self.assertEqual(db.execute("SELECT value FROM backup_marker").fetchone(),
                             ("committed in WAL",))

    def test_managed_token_is_included_without_disclosure_and_tamper_is_detected(self):
        self._token()
        created = self.manager.create()
        identity = created["id"]
        snapshot = self.layout.backups / identity
        metadata = json.loads((snapshot / "manifest.json").read_text())
        self.assertEqual(metadata["telegram_token"]["source"], "managed")
        self.assertTrue(self.manager.verify(identity)["verified"])
        self.assertNotIn(TOKEN, json.dumps(created))
        self.assertNotIn(TOKEN, json.dumps(self.manager.verify(identity)))
        token_file = snapshot / "managed-telegram-bot-token"
        self.assertEqual(stat.S_IMODE(token_file.stat().st_mode), 0o600)
        token_file.write_text(OTHER_TOKEN + "\n")
        with self.assertRaisesRegex(BackupError, "HASH_MISMATCH"):
            self.manager.verify(identity)

    def test_external_token_source_survives_in_manifest(self):
        self._token(external=True)
        created = self.manager.create()
        snapshot = self.layout.backups / created["id"]
        metadata = json.loads((snapshot / "manifest.json").read_text())
        self.assertEqual(metadata["telegram_token"]["source"], "external")
        self.assertTrue((snapshot / "external-telegram-bot-token").exists())
        self.assertTrue(self.manager.verify(created["id"])["verified"])

    def test_refuses_mode_drift_and_cleans_failed_snapshot(self):
        database = self.layout.data / "hub.sqlite"
        database.chmod(0o644)
        with self.assertRaisesRegex(BackupError, "UNSAFE_FILE"):
            self.manager.create()
        database.chmod(0o600)
        self._token(value=TOKEN)
        self.store.set_telegram_bot_info(OTHER_TOKEN, None)
        with self.assertRaisesRegex(BackupError, "TOKEN_DATABASE_MISMATCH"):
            self.manager.create()
        self.assertEqual(list(self.layout.backups.iterdir()), [])
        self.assertFalse(list(self.layout.data.glob(".backup-*")))

    def test_refuses_symlinked_database_and_extra_snapshot_file(self):
        database = self.layout.data / "hub.sqlite"
        moved = self.layout.data / "original.sqlite"
        database.rename(moved)
        database.symlink_to(moved)
        with self.assertRaisesRegex(BackupError, "UNSAFE_FILE"):
            self.manager.create()
        database.unlink()
        moved.rename(database)
        created = self.manager.create()
        extra = self.layout.backups / created["id"] / "unexpected"
        extra.write_text("x")
        with self.assertRaisesRegex(BackupError, "UNEXPECTED_SNAPSHOT_FILE"):
            self.manager.verify(created["id"])

    def test_published_copy_is_independent_of_worker_open_file(self):
        descriptors = []
        original = self.manager._snapshot_worker

        def retain_source(stage):
            original(stage)
            descriptors.append(os.open(stage / "hub.sqlite", os.O_WRONLY))

        try:
            with mock.patch.object(self.manager, "_snapshot_worker", retain_source):
                created = self.manager.create()
            os.pwrite(descriptors[0], b"broken", 0)
            self.assertTrue(self.manager.verify(created["id"])["verified"])
        finally:
            for descriptor in descriptors:
                os.close(descriptor)

    def test_worker_refuses_token_drift_against_parent_snapshot(self):
        stage = self.layout.data / ".backup-test"
        stage.mkdir(mode=0o700)
        self._token()
        with self.assertRaisesRegex(BackupError, "TOKEN_CHANGED"):
            self.manager._snapshot_worker(stage, self.layout.data,
                                          ("managed", (OTHER_TOKEN + "\n").encode()))

    def test_invalid_identity_and_restore_command_are_rejected(self):
        self.manager.create()
        with self.assertRaisesRegex(BackupError, "INVALID_ID"):
            self.manager.verify("../hub.sqlite")
        with mock.patch("builtins.print") as printed:
            self.assertEqual(main(["restore", "some-id"]), 2)
        self.assertIn("INVALID_ARGUMENTS", printed.call_args.args[0])

    def test_offline_restore_keeps_safety_snapshot_and_can_undo(self):
        self._token(value=TOKEN)
        original = self.manager.create()["id"]
        with sqlite3.connect(self.layout.data / "hub.sqlite") as db:
            db.execute("CREATE TABLE restore_marker (value TEXT NOT NULL)")
            db.execute("INSERT INTO restore_marker VALUES ('newer state')")
        with mock.patch("sovagrid_hub.backup._exchange_directories",
                        side_effect=self._exchange_for_test):
            plan = self.manager.plan_restore(original)
            self.assertEqual(self.manager.verify(plan["safety_id"])["verified"], True)
            self.assertIn(original, self.manager.list()["ids"])
            applied = self.manager.apply_restore(plan["plan_id"])
            self.assertTrue(applied["restored"])
            self.assertTrue(Path(applied["recovery_directory"]).is_dir())
            self.assertEqual((self.layout.data / "telegram-bot-token").read_text(),
                             TOKEN + "\n")
            undone = self.manager.undo_restore(plan["plan_id"])
            self.assertTrue(undone["restored_previous_data"])
            self.assertFalse(undone["cleanup_pending"])
        self.assertEqual((self.layout.data / "telegram-bot-token").read_text(),
                         TOKEN + "\n")
        with sqlite3.connect(self.layout.data / "hub.sqlite") as db:
            self.assertEqual(db.execute("SELECT value FROM restore_marker").fetchone(),
                             ("newer state",))
        self.assertIn(original, self.manager.list()["ids"])
        self.assertIn(plan["safety_id"], self.manager.list()["ids"])

    def test_restore_refuses_source_drift_after_review(self):
        target = self.manager.create()["id"]
        plan = self.manager.plan_restore(target)
        with sqlite3.connect(self.layout.data / "hub.sqlite") as db:
            db.execute("CREATE TABLE changed_after_review (id INTEGER)")
        with self.assertRaisesRegex(BackupError, "RESTORE_SOURCE_CHANGED"):
            self.manager.apply_restore(plan["plan_id"])
        self.assertFalse((self.layout.parent / (".restore-" + plan["plan_id"])).exists())

    def test_restore_refuses_external_token_and_tampered_target(self):
        self._token(external=True)
        external = self.manager.create()["id"]
        with self.assertRaisesRegex(BackupError, "EXTERNAL_TOKEN_RESTORE_UNSUPPORTED"):
            self.manager.plan_restore(external)
        self.layout.external_token.unlink()
        self.store.clear_telegram_bot_info()
        target = self.manager.create()["id"]
        plan = self.manager.plan_restore(target)
        (self.layout.backups / target / "hub.sqlite").write_bytes(b"tampered")
        with self.assertRaisesRegex(BackupError, "HASH_MISMATCH"):
            self.manager.apply_restore(plan["plan_id"])

    def test_restore_refuses_different_managed_telegram_token(self):
        self._token(value=TOKEN)
        target = self.manager.create()["id"]
        self._token(value=OTHER_TOKEN)
        with self.assertRaisesRegex(BackupError, "TOKEN_CHANGE_RESTORE_UNSUPPORTED"):
            self.manager.plan_restore(target)

    def test_restore_refuses_existing_recovery_directory(self):
        target = self.manager.create()["id"]
        plan = self.manager.plan_restore(target)
        recovery = self.layout.parent / (".restore-" + plan["plan_id"])
        recovery.mkdir()
        with self.assertRaisesRegex(BackupError, "RESTORE_RECOVERY_EXISTS"):
            self.manager.apply_restore(plan["plan_id"])

    def test_finalize_keeps_safety_snapshot_and_removes_old_directory(self):
        target = self.manager.create()["id"]
        plan = self.manager.plan_restore(target)
        with mock.patch("sovagrid_hub.backup._exchange_directories",
                        side_effect=self._exchange_for_test):
            applied = self.manager.apply_restore(plan["plan_id"])
        result = self.manager.finalize_restore(plan["plan_id"])
        self.assertTrue(result["finalized"])
        self.assertFalse(Path(applied["recovery_directory"]).exists())
        self.assertTrue(self.manager.verify(plan["safety_id"])["verified"])
        with self.assertRaisesRegex(BackupError, "FILE_UNAVAILABLE"):
            self.manager.finalize_restore(plan["plan_id"])

    def test_restore_neutralizes_replay_and_carries_forward_telegram_cursor(self):
        self._token()
        server = self.store.create_server("monitored")
        sid = server["id"]
        now = int(time.time())
        digest = hashlib.sha256(TOKEN.encode()).hexdigest()
        with sqlite3.connect(self.layout.data / "hub.sqlite") as db:
            user = db.execute("SELECT id FROM hub_users LIMIT 1").fetchone()[0]
            db.execute("INSERT INTO sessions VALUES (?,?,?)", ("a" * 64, now + 3600, user))
            db.execute("INSERT INTO ssh_grants VALUES (?,?,?,?)",
                       ("b" * 64, user, 1, now + 60))
            db.execute("""INSERT INTO jobs
                       (id,server_id,actor_user_id,chat_id,command,state,created_at)
                       VALUES (?,?,?,?,?,?,?)""",
                       ("queued-job", sid, 0, 0, "echo replay", "queued", now))
            db.execute("""INSERT INTO jobs
                       (id,server_id,actor_user_id,chat_id,command,state,created_at,delivered_at)
                       VALUES (?,?,?,?,?,?,?,?)""",
                       ("delivered-job", sid, 0, 0, "", "delivered", now, now))
            db.execute("""INSERT INTO jobs
                       (id,server_id,actor_user_id,chat_id,source,command_sha256,
                        command,state,created_at,completed_at,exit_code,output)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                       ("old-service-status", sid, 0, 0, "web",
                        hashlib.sha256(service_status_command("nginx.service").encode()).hexdigest(),
                        "", "succeeded", now, now, 0,
                        json.dumps({"action": "status", "unit": "nginx.service", "result": "ok",
                                    "load_state": "loaded", "active_state": "active",
                                    "sub_state": "running"})))
            db.execute("""INSERT INTO pending_commands
                       VALUES (?,?,?,?,?,?,?)""",
                       ("c" * 64, sid, 1, 1, "echo replay", now, now + 60))
            db.execute("""INSERT INTO bot_pairing_requests
                       VALUES (?,?,?,?,?,?,?,?)""",
                       (123, 123, "", "", "", now, "pending", None))
            db.execute("""INSERT INTO incidents
                       (id,server_id,kind,state,opened_at,updated_at)
                       VALUES (?,?,?,?,?,?)""",
                       ("old-alert", sid, "offline", "firing", now, now))
            db.execute("""INSERT INTO incident_outbox
                       (incident_id,chat_id,event_type,event_at,next_attempt_at)
                       VALUES (?,?,?,?,?)""",
                       ("old-alert", 123, "firing", now, now))
            db.execute("INSERT INTO maintenance_deferred VALUES (?,?,?)",
                       ("old-alert", sid, now))
            db.execute("INSERT INTO telegram_update_cursors VALUES (?,?,?)",
                       (digest, 10, now - 100000))
        target = self.manager.create()["id"]
        with sqlite3.connect(self.layout.data / "hub.sqlite") as db:
            db.execute("UPDATE telegram_update_cursors SET next_offset=25 WHERE token_hash=?",
                       (digest,))
        plan = self.manager.plan_restore(target)
        with mock.patch("sovagrid_hub.backup._exchange_directories",
                        side_effect=self._exchange_for_test):
            self.manager.apply_restore(plan["plan_id"])
        with sqlite3.connect(self.layout.data / "hub.sqlite") as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM sessions").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM ssh_grants").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT state,command FROM jobs WHERE id='queued-job'").fetchone(),
                             ("cancelled", ""))
            self.assertEqual(db.execute("SELECT state,exit_code FROM jobs WHERE id='delivered-job'").fetchone(),
                             ("timed_out", None))
            self.assertEqual(db.execute("SELECT state,output FROM jobs WHERE id='old-service-status'").fetchone(),
                             ("cancelled", ""))
            self.assertEqual(db.execute("SELECT COUNT(*) FROM pending_commands").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM bot_pairing_requests WHERE state='pending'").fetchone()[0], 0)
            self.assertIsNotNone(db.execute(
                "SELECT dropped_at FROM incident_outbox WHERE incident_id='old-alert'").fetchone()[0])
            self.assertEqual(db.execute("SELECT COUNT(*) FROM maintenance_deferred").fetchone()[0], 0)
            cursor = db.execute("SELECT next_offset,updated_at FROM telegram_update_cursors WHERE token_hash=?",
                                (digest,)).fetchone()
            self.assertEqual(cursor[0], 25)
            self.assertGreaterEqual(cursor[1], now)


if __name__ == "__main__":
    unittest.main()
