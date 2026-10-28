# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""A lost SSH result cannot repeat an offline Hub data exchange."""

from __future__ import annotations

from contextlib import nullcontext
import json
import os
from pathlib import Path
import shutil
import tempfile
import threading
import unittest

from sovagrid_hub.backup import BackupError, HubBackups, Layout
from sovagrid_hub.backup_restore import RestoreOrchestrator


TARGET = "11111111-1111-4111-8111-111111111111"
REQUEST = "22222222-2222-4222-8222-222222222222"
PLAN = "33333333-3333-4333-8333-333333333333"
SAFETY = "44444444-4444-4444-8444-444444444444"
CONTAINER = "a" * 64


class FakeManager:
    def __init__(self, root: Path):
        self.layout = Layout(root, root / "hub", root / "backups", root / "bot.token")
        self.layout.data.mkdir()
        self.layout.backups.mkdir()
        self.root_uid, self.root_gid = os.geteuid(), os.getegid()
        self.calls = []
        self.source = "old"
        self.fail_apply = False
        self.fail_undo = False
        self.runner = None

    def _restore_lock(self):
        self.calls.append("lock")
        return nullcontext()

    def _backups(self, *, create: bool):
        assert self.layout.backups.is_dir()

    def verify(self, identity):
        assert identity in (TARGET, SAFETY)
        self.calls.append("verify")
        return {"id": identity, "verified": True}

    def _require_offline(self):
        if self.runner.running:
            raise BackupError("HUB_NOT_STOPPED")

    def plan_restore(self, identity):
        assert identity == TARGET
        self._require_offline()
        self.calls.append("plan")
        self._plan_path(PLAN).write_text("test plan")
        return {"plan_id": PLAN, "safety_id": SAFETY}

    def apply_restore(self, identity):
        assert identity == PLAN
        self._require_offline()
        self.calls.append("apply")
        if self.fail_apply:
            raise BackupError("RESTORE_SOURCE_CHANGED")
        self.source = "restored"
        stage = self.layout.parent / (".restore-" + PLAN)
        stage.mkdir()
        (stage / "old").write_text("old")
        return {"restored": True}

    def _plan_path(self, identity):
        assert identity == PLAN
        return self.layout.backups / (".restore-plan-" + identity + ".json")

    def _read_plan(self, identity):
        assert identity == PLAN
        return {"target_id": TARGET, "safety_id": SAFETY,
                "source_files": {"state": "old"},
                "restored_files": {"state": "restored"}}

    def _fingerprint_directory(self, path):
        assert path == self.layout.parent / (".restore-" + PLAN)
        return {"state": "old"} if (path / "old").read_text() == "old" else {}

    def _source_fingerprint(self):
        return {"state": self.source}

    def undo_restore(self, identity):
        assert identity == PLAN
        self._require_offline()
        self.calls.append("undo")
        if self.fail_undo:
            raise BackupError("RESTORE_DATA_DRIFT")
        self.source = "old"
        self.runner.fail_health = False
        self._plan_path(PLAN).unlink(missing_ok=True)
        shutil.rmtree(self.layout.parent / (".restore-" + PLAN), ignore_errors=True)
        return {"restored_previous_data": True}

    def finalize_restore(self, identity):
        assert identity == PLAN
        self.calls.append("finalize")
        self._plan_path(PLAN).unlink(missing_ok=True)
        shutil.rmtree(self.layout.parent / (".restore-" + PLAN), ignore_errors=True)
        return {"finalized": True}

    def create(self):
        self.calls.append("safety")
        return {"id": "77777777-7777-4777-8777-777777777777"}


class FakeRunner:
    def __init__(self, manager):
        self.manager = manager
        manager.runner = self
        self.calls = []
        self.running = True
        self.fail_health = False

    def __call__(self, args, **_kwargs):
        self.calls.append(tuple(args))
        if args[:3] == ["docker", "container", "ls"]:
            value = CONTAINER + "\n"
        elif args[:3] == ["docker", "inspect", "--format"]:
            if args[3] == "{{json .Mounts}}":
                value = json.dumps([{"Type": "bind", "Source": str(self.manager.layout.data),
                                     "Destination": "/data"}])
            elif args[3] == "{{json .State}}":
                value = json.dumps({"Running": self.running, "Paused": False,
                                    "Restarting": False,
                                    "Health": {"Status": "unhealthy" if self.fail_health
                                               else "healthy"}})
            else:
                raise AssertionError(args)
        elif args[:3] == ["docker", "container", "stop"]:
            self.running = False
            value = CONTAINER
        elif args[:3] == ["docker", "container", "start"]:
            self.running = True
            value = CONTAINER
        elif args[:2] == ["docker", "exec"]:
            info = self.manager.layout.data.stat()
            value = f"{info.st_dev}:{info.st_ino}\n"
        else:
            raise AssertionError(args)
        return type("Result", (), {"returncode": 0, "stdout": value})()


class Clock:
    def __init__(self):
        self.value = 0

    def monotonic(self):
        return self.value

    def sleep(self, seconds):
        self.value += seconds


class RestoreOrchestratorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.manager = FakeManager(Path(self.temp.name))
        self.runner = FakeRunner(self.manager)
        self.clock = Clock()
        self.restore = RestoreOrchestrator(manager=self.manager, runner=self.runner,
                                           monotonic=self.clock.monotonic,
                                           sleep=self.clock.sleep)

    def test_confirmed_restore_is_journaled_and_same_key_never_repeats(self):
        first = self.restore.apply(TARGET, REQUEST)
        self.assertEqual(first, {"ok": True, "protocol": 1, "request_id": REQUEST,
                                 "target_id": TARGET, "phase": "complete",
                                 "safety_id": SAFETY, "plan_id": PLAN,
                                 "hub_running": True, "error": None,
                                 "created_at": first["created_at"]})
        self.assertEqual(self.manager.calls.count("plan"), 1)
        self.assertEqual(self.manager.calls.count("apply"), 1)
        self.assertEqual(self.manager.calls.count("finalize"), 1)
        self.assertEqual(self.restore.status(REQUEST), first)
        self.assertEqual(self.restore.apply(TARGET, REQUEST), first)
        self.assertEqual(self.manager.calls.count("apply"), 1)
        listed = self.restore.list()
        self.assertEqual(len(listed["restores"]), 1)
        self.assertEqual(listed["restores"][0]["request_id"], REQUEST)
        self.assertIsNone(listed["restores"][0]["hub_running"])
        self.assertEqual(self.manager.source, "restored")

    def test_apply_failure_restarts_untouched_original_without_repeat(self):
        self.manager.fail_apply = True
        result = self.restore.apply(TARGET, REQUEST)
        self.assertEqual(result["phase"], "failed_recovered")
        self.assertEqual(result["error"], "RESTORE_SOURCE_CHANGED")
        self.assertTrue(result["hub_running"])
        self.assertEqual(self.manager.source, "old")
        self.assertEqual(self.restore.apply(TARGET, REQUEST), result)
        self.assertEqual(self.manager.calls.count("apply"), 1)

    def test_failed_restarted_restore_undoes_only_unchanged_data(self):
        self.runner.fail_health = False
        original_start = self.restore._start
        starts = 0
        def fail_first(identity):
            nonlocal starts
            starts += 1
            if starts == 1:
                self.runner.fail_health = True
            return original_start(identity)
        self.restore._start = fail_first
        result = self.restore.apply(TARGET, REQUEST)
        self.assertEqual(result["phase"], "failed_recovered")
        self.assertEqual(result["error"], "HUB_RESTART_FAILED")
        self.assertEqual(self.manager.calls.count("undo"), 1)
        self.assertEqual(self.manager.source, "old")
        self.assertTrue(self.runner.running)

    def test_unsafe_undo_leaves_hub_stopped_and_readable_after_gui_crash(self):
        self.manager.fail_undo = True
        original_start = self.restore._start
        starts = 0
        def fail_first(identity):
            nonlocal starts
            starts += 1
            if starts == 1:
                self.runner.fail_health = True
            return original_start(identity)
        self.restore._start = fail_first
        result = self.restore.apply(TARGET, REQUEST)
        self.assertEqual(result["phase"], "recovery_required")
        self.assertEqual(result["error"], "RESTORE_RECOVERY_REQUIRED")
        self.assertFalse(result["hub_running"])
        self.assertEqual(self.manager.calls.count("undo"), 1)
        self.assertEqual(self.restore.list()["restores"][0]["request_id"], REQUEST)
        self.assertEqual(self.restore.status(REQUEST), result)
        with self.assertRaisesRegex(BackupError, "RESTORE_BUSY"):
            self.restore.apply(TARGET, "55555555-5555-4555-8555-555555555555")

    def test_incomplete_key_and_changed_target_cannot_repeat_restore(self):
        self.restore.apply(TARGET, REQUEST)
        record = self.restore._read(REQUEST)
        self.restore._advance(record, "applying")
        before = list(self.manager.calls)
        self.assertEqual(self.restore.apply(TARGET, REQUEST)["phase"], "applying")
        self.assertEqual(before, self.manager.calls[:-1])  # only the outer lock is acquired
        with self.assertRaisesRegex(BackupError, "RESTORE_KEY_REUSED"):
            self.restore.apply("66666666-6666-4666-8666-666666666666", REQUEST)

    def test_journal_tampering_fails_closed_and_no_second_restore_starts(self):
        self.restore.apply(TARGET, REQUEST)
        path = self.restore._path(REQUEST)
        raw = json.loads(path.read_text())
        raw["target_id"] = TARGET + "; touch /tmp/unexpected"
        path.write_text(json.dumps(raw))
        with self.assertRaisesRegex(BackupError, "INVALID_RESTORE_JOURNAL"):
            self.restore.status(REQUEST)
        with self.assertRaisesRegex(BackupError, "INVALID_RESTORE_JOURNAL"):
            self.restore.list()
        with self.assertRaisesRegex(BackupError, "INVALID_RESTORE_JOURNAL"):
            self.restore.apply(TARGET, REQUEST)
        self.assertEqual(self.manager.calls.count("apply"), 1)

    def test_nested_restore_lock_reuses_outer_holder_on_same_thread(self):
        # The production lock path is intentionally not created in a unit test.
        manager = object.__new__(HubBackups)
        manager.require_root = True
        manager._restore_lock_depth = 1
        manager._restore_lock_owner = threading.get_ident()
        with manager._restore_lock():
            self.assertEqual(manager._restore_lock_depth, 2)
        self.assertEqual(manager._restore_lock_depth, 1)

    def test_recover_after_crash_before_exchange_starts_original(self):
        identity = self.restore._managed_container()
        now = 1793000000
        record = {"format": 1, "request_id": REQUEST, "target_id": TARGET,
                  "container_id": identity, "created_at": now,
                  "updated_at": now, "phase": "planning", "safety_id": None,
                  "plan_id": None, "source_files": None, "error": None}
        self.restore._write(record, create=True)
        self.runner.running = False
        result = self.restore.recover(REQUEST)
        self.assertEqual(result["phase"], "failed_recovered")
        self.assertEqual(result["error"], "RESTORE_INTERRUPTED")
        self.assertTrue(result["hub_running"])
        self.assertEqual(self.manager.calls.count("apply"), 0)
        self.assertEqual(self.restore.recover(REQUEST), result)

    def test_recover_after_crash_during_apply_undoes_exact_exchanged_data(self):
        self.restore.apply(TARGET, REQUEST)
        # Recreate the exact state just after exchange and before Docker start.
        self.manager._plan_path(PLAN).write_text("test plan")
        stage = self.manager.layout.parent / (".restore-" + PLAN)
        stage.mkdir()
        (stage / "old").write_text("old")
        self.manager.source = "restored"
        self.runner.running = False
        record = self.restore._read(REQUEST)
        self.restore._advance(record, "applying")
        result = self.restore.recover(REQUEST)
        self.assertEqual(result["phase"], "failed_recovered")
        self.assertEqual(self.manager.calls.count("undo"), 1)
        self.assertEqual(self.manager.source, "old")
        self.assertTrue(result["hub_running"])
        self.assertEqual(self.restore.recover(REQUEST), result)

    def test_recover_changed_but_valid_post_start_data_uses_new_safety_copy(self):
        self.restore.apply(TARGET, REQUEST)
        self.manager._plan_path(PLAN).write_text("test plan")
        stage = self.manager.layout.parent / (".restore-" + PLAN)
        stage.mkdir()
        (stage / "old").write_text("old")
        self.manager.source = "restored-with-wal"
        self.runner.running = False
        record = self.restore._read(REQUEST)
        self.restore._advance(record, "starting")
        result = self.restore.recover(REQUEST)
        self.assertEqual(result["phase"], "complete")
        self.assertEqual(self.manager.calls.count("safety"), 1)
        self.assertTrue(result["hub_running"])
        self.assertEqual(self.restore.recover(REQUEST), result)

    def test_recover_refuses_changed_retained_old_directory(self):
        self.restore.apply(TARGET, REQUEST)
        self.manager._plan_path(PLAN).write_text("test plan")
        stage = self.manager.layout.parent / (".restore-" + PLAN)
        stage.mkdir()
        (stage / "old").write_text("tampered")
        self.manager.source = "restored"
        self.runner.running = False
        record = self.restore._read(REQUEST)
        self.restore._advance(record, "applying")
        result = self.restore.recover(REQUEST)
        self.assertEqual(result["phase"], "recovery_required")
        self.assertFalse(result["hub_running"])
        self.assertEqual(self.manager.calls.count("undo"), 0)

    def test_completed_restore_keeps_healthy_hub_up_if_last_journal_write_fails(self):
        original = self.restore._write
        failed = False
        def write(record, *, create=False):
            nonlocal failed
            if record["phase"] == "complete" and not failed:
                failed = True
                raise OSError("journal disk error")
            return original(record, create=create)
        self.restore._write = write
        result = self.restore.apply(TARGET, REQUEST)
        self.assertEqual(result["phase"], "complete")
        self.assertTrue(result["hub_running"])
        self.assertEqual(self.manager.calls.count("undo"), 0)
        self.assertEqual(sum(call[:3] == ("docker", "container", "stop")
                             for call in self.runner.calls), 1)


if __name__ == "__main__":
    unittest.main()
