# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Root SSH entry point for a bounded, journaled Hub-data restore.

The Web Hub cannot orchestrate replacement of its own database. This host
command holds the update/backup lock while it stops only the managed Hub
container, creates an offline safety copy, swaps the data, checks a restart,
and retains an explicit journal if recovery needs an administrator.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import time
from typing import Callable

from .backup import (BackupError, HubBackups, _canonical_id, _fsync_dir,
                     _json_bytes, _read_file)


PROTOCOL = 1
MAX_JOURNALS = 1000
LIST_LIMIT = 100
MAX_RECORD = 4096
CONTAINER_ID = re.compile(r"[0-9a-f]{64}\Z")
JOURNAL_NAME = re.compile(
    r"\.restore-request-([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\.json\Z")
TEMP_NAME = re.compile(
    r"\.restore-request-[0-9a-f-]{36}\.[0-9a-f]{24}\.tmp\Z")
PHASES = frozenset(("pending", "stopping", "stopped", "planning", "planned",
                    "applying", "applied", "starting", "started", "finalizing",
                    "complete", "failed_recovered", "recovery_required"))
TERMINAL = frozenset(("complete", "failed_recovered"))


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise BackupError("INVALID_RESTORE_JOURNAL")
        result[key] = value
    return result


def _code(error: BaseException) -> str:
    value = str(error) if isinstance(error, BackupError) else "RESTORE_FAILED"
    return value if re.fullmatch(r"[A-Z][A-Z0-9_]{2,63}", value) else "RESTORE_FAILED"


class RestoreOrchestrator:
    def __init__(self, *, manager: HubBackups | None = None,
                 runner: Callable = subprocess.run,
                 monotonic: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep):
        self.manager = manager or HubBackups()
        self.runner, self.monotonic, self.sleep = runner, monotonic, sleep

    def _path(self, request_id: str) -> Path:
        if not _canonical_id(request_id):
            raise BackupError("INVALID_ID")
        return self.manager.layout.backups / (".restore-request-" + request_id + ".json")

    def _read(self, request_id: str) -> dict:
        raw = _read_file(self._path(request_id), self.manager.root_uid,
                         self.manager.root_gid, 0o600, MAX_RECORD)
        try:
            value = json.loads(raw, object_pairs_hook=_unique)
        except (ValueError, UnicodeError) as exc:
            raise BackupError("INVALID_RESTORE_JOURNAL") from exc
        if (not isinstance(value, dict) or set(value) !=
                {"format", "request_id", "target_id", "container_id", "created_at",
                 "updated_at", "phase", "safety_id", "plan_id", "source_files", "error"} or
                type(value["format"]) is not int or value["format"] != PROTOCOL or
                value["request_id"] != request_id or
                not _canonical_id(value["target_id"]) or
                not isinstance(value["container_id"], str) or
                CONTAINER_ID.fullmatch(value["container_id"]) is None or
                type(value["created_at"]) is not int or
                not 1 <= value["created_at"] <= 253402300799 or
                type(value["updated_at"]) is not int or
                value["updated_at"] < value["created_at"] or
                not isinstance(value["phase"], str) or value["phase"] not in PHASES or
                (value["safety_id"] is not None and
                 not _canonical_id(value["safety_id"])) or
                (value["plan_id"] is not None and
                 not _canonical_id(value["plan_id"])) or
                (value["source_files"] is not None and
                 not isinstance(value["source_files"], dict)) or
                (value["error"] is not None and
                 (not isinstance(value["error"], str) or
                  re.fullmatch(r"[A-Z][A-Z0-9_]{2,63}", value["error"]) is None)) or
                raw != _json_bytes(value)):
            raise BackupError("INVALID_RESTORE_JOURNAL")
        return value

    def _write(self, value: dict, *, create: bool = False) -> None:
        path = self._path(value["request_id"])
        raw = _json_bytes(value)
        if len(raw) > MAX_RECORD:
            raise BackupError("INVALID_RESTORE_JOURNAL")
        if not create:
            self._read(value["request_id"])
        temporary = path if create else path.parent / (
            ".restore-request-" + value["request_id"] + "." +
            secrets.token_hex(12) + ".tmp")
        try:
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            with os.fdopen(fd, "wb") as output:
                output.write(raw)
                output.flush()
                os.fsync(output.fileno())
            if not create:
                os.replace(temporary, path)
            _fsync_dir(path.parent)
        finally:
            if not create:
                temporary.unlink(missing_ok=True)

    def _advance(self, record: dict, phase: str, **fields) -> None:
        changed = dict(record)
        changed.update(phase=phase,
                       updated_at=max(int(time.time()), record["created_at"]),
                       **fields)
        self._write(changed)
        record.update(changed)

    def _command(self, args: list[str], *, timeout: int) -> str:
        try:
            result = self.runner(args, capture_output=True, text=True,
                                 timeout=timeout, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise BackupError("DOCKER_UNAVAILABLE") from exc
        if result.returncode != 0 or len(result.stdout) > 65536:
            raise BackupError("DOCKER_UNAVAILABLE")
        return result.stdout.strip()

    def _container_state(self, identity: str) -> tuple[bool, bool]:
        raw = self._command(["docker", "inspect", "--format", "{{json .State}}", identity],
                            timeout=10)
        try:
            value = json.loads(raw, object_pairs_hook=_unique)
        except (ValueError, UnicodeError) as exc:
            raise BackupError("HUB_STATE_UNAVAILABLE") from exc
        if (not isinstance(value, dict) or
                any(type(value.get(key)) is not bool for key in
                    ("Running", "Paused", "Restarting"))):
            raise BackupError("HUB_STATE_UNAVAILABLE")
        health = value.get("Health")
        healthy = isinstance(health, dict) and health.get("Status") == "healthy"
        return (value["Running"] and not value["Paused"] and
                not value["Restarting"]), healthy

    def _managed_container(self, *, require_healthy: bool = True) -> str:
        raw = self._command([
            "docker", "container", "ls", "-a", "--no-trunc", "--quiet",
            "--filter", "label=com.docker.compose.project=sovagrid",
            "--filter", "label=com.docker.compose.service=hub",
        ], timeout=10)
        found = raw.splitlines()
        if len(found) != 1 or CONTAINER_ID.fullmatch(found[0]) is None:
            raise BackupError("HUB_CONTAINER_AMBIGUOUS")
        identity = found[0]
        mounts = self._command(["docker", "inspect", "--format", "{{json .Mounts}}",
                                identity], timeout=10)
        try:
            values = json.loads(mounts, object_pairs_hook=_unique)
        except (ValueError, UnicodeError) as exc:
            raise BackupError("HUB_CONTAINER_AMBIGUOUS") from exc
        if (not isinstance(values, list) or len(values) > 16 or
                sum(isinstance(item, dict) and item.get("Type") == "bind" and
                    item.get("Source") == str(self.manager.layout.data) and
                    item.get("Destination") == "/data" for item in values) != 1):
            raise BackupError("HUB_CONTAINER_AMBIGUOUS")
        running, healthy = self._container_state(identity)
        if require_healthy and (not running or not healthy):
            raise BackupError("HUB_NOT_HEALTHY")
        if require_healthy:
            self._bound_data(identity)
        return identity

    def _bound_data(self, identity: str) -> None:
        # A stopped container may retain a stale bind to the old directory
        # after renameat2. Docker health alone would then validate the wrong
        # database. Compare the mount inode from inside the exact container.
        script = "import os; s=os.stat('/data'); print(f'{s.st_dev}:{s.st_ino}')"
        raw = self._command(["docker", "exec", "--user", "10001:10001", identity,
                             "python3", "-c", script], timeout=10)
        info = self.manager.layout.data.stat()
        if raw != f"{info.st_dev}:{info.st_ino}":
            raise BackupError("HUB_MOUNT_CHANGED")

    def _stop(self, identity: str) -> None:
        running, _ = self._container_state(identity)
        if running:
            self._command(["docker", "container", "stop", "--time", "30", identity],
                          timeout=45)
        running, _ = self._container_state(identity)
        if running:
            raise BackupError("HUB_NOT_STOPPED")
        self.manager._require_offline()

    def _start(self, identity: str) -> None:
        running, _ = self._container_state(identity)
        if not running:
            self._command(["docker", "container", "start", identity], timeout=60)
        deadline = self.monotonic() + 150
        while True:
            running, healthy = self._container_state(identity)
            if running and healthy:
                self._bound_data(identity)
                return
            if self.monotonic() >= deadline:
                raise BackupError("HUB_RESTART_FAILED")
            self.sleep(2)

    def _running(self, record: dict) -> bool | None:
        try:
            return self._container_state(record["container_id"])[0]
        except BackupError:
            return None

    def _public(self, record: dict, *, inspect: bool) -> dict:
        phase = record["phase"]
        return {"ok": phase == "complete", "protocol": PROTOCOL,
                "request_id": record["request_id"], "target_id": record["target_id"],
                "phase": phase, "safety_id": record["safety_id"],
                "plan_id": record["plan_id"],
                "hub_running": self._running(record) if inspect else None,
                "error": record["error"] if record["error"] is not None else
                (None if phase == "complete" else "RESTORE_INCOMPLETE"),
                "created_at": record["created_at"]}

    def _records(self) -> list[dict]:
        self.manager._backups(create=False)
        files = []
        for item in self.manager.layout.backups.iterdir():
            if not item.name.startswith(".restore-request-"):
                continue
            match = JOURNAL_NAME.fullmatch(item.name)
            if match is None:
                info = item.lstat()
                if (TEMP_NAME.fullmatch(item.name) is None or
                        not stat.S_ISREG(info.st_mode) or
                        (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode),
                         info.st_nlink) != (self.manager.root_uid,
                                           self.manager.root_gid, 0o600, 1)):
                    raise BackupError("INVALID_RESTORE_JOURNAL")
                continue
            files.append(self._read(match.group(1)))
            if len(files) > MAX_JOURNALS:
                raise BackupError("TOO_MANY_RESTORE_JOURNALS")
        return sorted(files, key=lambda item: (item["created_at"], item["request_id"]),
                      reverse=True)

    def list(self) -> dict:
        records = self._records()
        unfinished = [item for item in records if item["phase"] not in TERMINAL]
        if len(unfinished) > LIST_LIMIT:
            raise BackupError("TOO_MANY_RESTORE_JOURNALS")
        # A crash from long ago must stay discoverable even after many later
        # completed restores. The final result is still newest-first.
        selected = unfinished + [item for item in records if item["phase"] in TERMINAL][
            :LIST_LIMIT - len(unfinished)]
        selected.sort(key=lambda item: (item["created_at"], item["request_id"]),
                      reverse=True)
        return {"ok": True, "protocol": PROTOCOL,
                "restores": [self._public(item, inspect=False)
                             for item in selected]}

    def status(self, request_id: str) -> dict:
        if not _canonical_id(request_id):
            raise BackupError("INVALID_ID")
        self.manager._backups(create=False)
        path = self._path(request_id)
        if not path.exists() and not path.is_symlink():
            raise BackupError("RESTORE_NOT_FOUND")
        return self._public(self._read(request_id), inspect=True)

    def _failure(self, record: dict, failure: BaseException) -> None:
        error = _code(failure)
        identity = record["container_id"]
        try:
            phase = record["phase"]
            plan = record["plan_id"]
            if phase == "finalizing" and plan is not None:
                plan_path = self.manager._plan_path(plan)
                stage = self.manager.layout.parent / (".restore-" + plan)
                if (not plan_path.exists() and not plan_path.is_symlink() and
                        not stage.exists() and not stage.is_symlink()):
                    self.manager.verify(record["safety_id"])
                    if self._container_state(identity) == (True, True):
                        self._bound_data(identity)
                        try:
                            self._advance(record, "complete", error=None)
                        except (BackupError, OSError):
                            pass  # Keep a healthy Hub up; recover can write the journal later.
                        return
            if phase in ("applying", "applied", "starting", "started", "finalizing"):
                self._stop(identity)
                if plan is None:
                    raise BackupError("RESTORE_RECOVERY_REQUIRED")
                # If an apply failed before its exchange, the original source
                # still matches the plan. Otherwise undo only exact untouched
                # restored data. Any other drift stays offline for review.
                saved = self.manager._read_plan(plan)
                if self.manager._source_fingerprint() != saved["source_files"]:
                    self.manager.undo_restore(plan)
            elif phase in ("pending", "stopping", "stopped", "planning", "planned"):
                self._stop(identity)
            self._start(identity)
            self._advance(record, "failed_recovered", error=error)
        except BaseException:
            try:
                self._stop(identity)
            except BaseException:
                pass
            self._advance(record, "recovery_required", error="RESTORE_RECOVERY_REQUIRED")

    def apply(self, target_id: str, request_id: str) -> dict:
        if not _canonical_id(target_id) or not _canonical_id(request_id) or target_id == request_id:
            raise BackupError("INVALID_ID")
        with self.manager._restore_lock():
            self.manager._backups(create=False)
            path = self._path(request_id)
            if path.exists() or path.is_symlink():
                record = self._read(request_id)
                if record["target_id"] != target_id:
                    raise BackupError("RESTORE_KEY_REUSED")
                return self._public(record, inspect=True)
            if any(item["phase"] not in TERMINAL for item in self._records()):
                raise BackupError("RESTORE_BUSY")
            self.manager.verify(target_id)
            identity = self._managed_container()
            now = int(time.time())
            record = {"format": PROTOCOL, "request_id": request_id,
                      "target_id": target_id, "container_id": identity,
                      "created_at": now, "updated_at": now, "phase": "pending",
                      "safety_id": None, "plan_id": None,
                      "source_files": None, "error": None}
            self._write(record, create=True)
            try:
                self._advance(record, "stopping")
                self._stop(identity)
                self._advance(record, "stopped")
                self._advance(record, "planning")
                plan = self.manager.plan_restore(target_id)
                self._advance(record, "planned", plan_id=plan["plan_id"],
                              safety_id=plan["safety_id"],
                              source_files=self.manager._read_plan(plan["plan_id"])["source_files"])
                self._advance(record, "applying")
                self.manager.apply_restore(plan["plan_id"])
                self._advance(record, "applied")
                self._advance(record, "starting")
                self._start(identity)
                self._advance(record, "started")
                self._advance(record, "finalizing")
                self.manager.finalize_restore(plan["plan_id"])
                self._advance(record, "complete", error=None)
            except BaseException as exc:
                self._failure(record, exc)
            return self._public(record, inspect=True)

    def recover(self, request_id: str) -> dict:
        """Reconcile a lost SSH process without repeating an uncertain swap.

        Prefer the untouched pre-restore data. If Hub already started and
        changed the restored data, make a fresh checked safety copy before
        continuing the restored version. Ambiguous files remain offline.
        """
        if not _canonical_id(request_id):
            raise BackupError("INVALID_ID")
        with self.manager._restore_lock():
            self.manager._backups(create=False)
            record = self._read(request_id)
            if record["phase"] in TERMINAL:
                return self._public(record, inspect=True)
            original_phase = record["phase"]
            identity = record["container_id"]
            if self._managed_container(require_healthy=False) != identity:
                raise BackupError("HUB_CONTAINER_CHANGED")
            self._advance(record, "recovery_required",
                          error="RESTORE_RECOVERY_REQUIRED")
            try:
                self._stop(identity)
                source_files = record["source_files"]
                if source_files is None or self.manager._source_fingerprint() == source_files:
                    # No exchange occurred, or an earlier exact undo finished
                    # before its last journal write.
                    self._advance(record, "starting")
                    self._start(identity)
                    self._advance(record, "failed_recovered",
                                  error="RESTORE_INTERRUPTED")
                    return self._public(record, inspect=True)
                plan_id = record["plan_id"]
                if plan_id is None:
                    raise BackupError("RESTORE_RECOVERY_REQUIRED")
                plan_path = self.manager._plan_path(plan_id)
                stage = self.manager.layout.parent / (".restore-" + plan_id)
                if not plan_path.exists() and not plan_path.is_symlink():
                    if (original_phase != "finalizing" or
                            stage.exists() or stage.is_symlink() or
                            record["safety_id"] is None):
                        raise BackupError("RESTORE_RECOVERY_REQUIRED")
                    # Finalization may have succeeded just before the SSH
                    # process died. The safety snapshot remains mandatory.
                    self.manager.verify(record["safety_id"])
                    self.manager._source_fingerprint()
                    self._advance(record, "starting")
                    self._start(identity)
                    self._advance(record, "complete", error=None)
                    return self._public(record, inspect=True)
                plan = self.manager._read_plan(plan_id)
                if (plan["target_id"] != record["target_id"] or
                        plan["safety_id"] != record["safety_id"] or
                        plan["source_files"] != source_files or
                        self.manager._fingerprint_directory(stage) != source_files):
                    raise BackupError("RESTORE_RECOVERY_CHANGED")
                current = self.manager._source_fingerprint()
                if plan["restored_files"] is None:
                    raise BackupError("RESTORE_RECOVERY_REQUIRED")
                if current == plan["restored_files"]:
                    self.manager.undo_restore(plan_id)
                    self._advance(record, "starting")
                    self._start(identity)
                    self._advance(record, "failed_recovered",
                                  error="RESTORE_INTERRUPTED")
                    return self._public(record, inspect=True)
                if original_phase not in ("starting", "started", "finalizing",
                                          "recovery_required"):
                    raise BackupError("RESTORE_DATA_DRIFT")
                # Hub may have written WAL or fresh rows after the exchange.
                # A checked snapshot proves SQLite/token coherence and keeps
                # that post-start state before its independent restart.
                self.manager.create()
                self._advance(record, "starting")
                self._start(identity)
                self._advance(record, "finalizing")
                self.manager.finalize_restore(plan_id)
                self._advance(record, "complete", error=None)
            except BaseException:
                try:
                    self._stop(identity)
                except BaseException:
                    pass
                self._advance(record, "recovery_required",
                              error="RESTORE_RECOVERY_REQUIRED")
            return self._public(record, inspect=True)


def main(argv: list[str] | None = None) -> int:
    os.umask(0o077)
    args = list(sys.argv[1:] if argv is None else argv)
    try:
        service = RestoreOrchestrator()
        if args == ["list"]:
            result = service.list()
        elif len(args) == 2 and args[0] == "status":
            result = service.status(args[1])
        elif len(args) == 3 and args[0] == "apply":
            result = service.apply(args[1], args[2])
        elif len(args) == 2 and args[0] == "recover":
            result = service.recover(args[1])
        else:
            raise BackupError("INVALID_ARGUMENTS")
    except (BackupError, OSError, ValueError, TypeError) as exc:
        result = {"ok": False, "protocol": PROTOCOL, "request_id": None,
                  "target_id": None, "phase": "absent", "safety_id": None,
                  "plan_id": None, "hub_running": None, "error": _code(exc),
                  "created_at": None}
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
