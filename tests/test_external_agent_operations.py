# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Durable external Agent handoff never starts the same request twice."""

import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest import mock

from sovagrid_hub.external_agent_operations import (ExternalOperationError,
                                                     ExternalOperationStore)


REQUEST_ID = "12345678-1234-4234-8234-1234567890ab"
ARCHIVE = "a" * 64
CURRENT = "b" * 64
EXTERNAL = "c" * 64
REVIEW = "d" * 64
SECOND_ID = "87654321-4321-4321-8321-ba0987654321"


class OperationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / "operations"
        self.root.mkdir(mode=0o700)
        self.unit = Path(temporary.name) / "sovagrid-external-agent-apply@.service"
        self.unit.write_text("[Unit]\nDescription=synthetic test unit\n")
        self.unit.chmod(0o644)
        self.marker = Path(temporary.name) / ".external-agent-apply-managed-by-run-sh"
        self.marker.write_text("SOVAGRID_EXTERNAL_AGENT_APPLY_UNIT_V1\n")
        self.marker.chmod(0o600)
        self.calls = []

        def run(argv, **kwargs):
            self.calls.append((argv, kwargs))
            return subprocess.CompletedProcess(argv, 0, b"", b"")

        self.run = run
        self.store = ExternalOperationStore(root=self.root, unit_file=self.unit,
                                            unit_marker=self.marker,
                                            uid=os.getuid(), gid=os.getgid(), run=self.run)

    def apply(self, *, request_id=REQUEST_ID, archive=ARCHIVE):
        return self.store.apply(request_id, archive, CURRENT, EXTERNAL, REVIEW)

    def test_one_start_exact_durable_files_and_conflicting_reuse(self):
        record = self.apply()
        self.assertEqual(record["phase"], "accepted")
        self.assertEqual(record["error"], None)
        self.assertEqual(self.calls[0][0], ["/usr/bin/systemctl", "start", "--no-block",
                                             "sovagrid-external-agent-apply@" + REQUEST_ID + ".service"])
        self.assertEqual(self.calls[0][1]["timeout"], 15)
        directory = self.root / REQUEST_ID
        for name in ("request.json", "status.json", "status.lock"):
            path = directory / name
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(path.stat().st_nlink, 1)
        self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
        request = (directory / "request.json").read_bytes()
        decoded = json.loads(request)
        self.assertEqual(request, (json.dumps(decoded, sort_keys=True,
                                               separators=(",", ":")) + "\n").encode())
        self.assertEqual(decoded["archive_sha256"], ARCHIVE)
        self.assertEqual(self.apply(), record)
        self.assertEqual(len(self.calls), 1)
        with self.assertRaisesRegex(ExternalOperationError, "EXTERNAL_REQUEST_CONFLICT"):
            self.apply(archive="f" * 64)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.store.list(), [record])
        self.assertNotIn(ARCHIVE, json.dumps(self.store.list()))

    def test_nonzero_start_is_uncertain_and_replay_never_restarts(self):
        self.store.run = lambda *_args, **_kwargs: subprocess.CompletedProcess([], 1, b"", b"")
        failed = self.apply()
        self.assertEqual((failed["phase"], failed["error"]),
                         ("uncertain", "START_UNCERTAIN"))
        self.store.run = self.run
        self.assertEqual(self.apply(), failed)
        self.assertEqual(self.calls, [])

    def test_different_request_waits_for_active_operation(self):
        self.apply()
        with self.assertRaisesRegex(ExternalOperationError, "EXTERNAL_BUSY"):
            self.apply(request_id=SECOND_ID)
        self.assertFalse((self.root / SECOND_ID).exists())
        self.assertEqual(len(self.calls), 1)
        self.store._change_status(self.root / REQUEST_ID, REQUEST_ID,
                                  phase="complete", error=None)
        self.assertEqual(self.apply(request_id=SECOND_ID)["phase"], "accepted")
        self.assertEqual(len(self.calls), 2)

    def test_ambiguous_start_timeout_is_retained_without_replay(self):
        self.store.run = mock.Mock(side_effect=subprocess.TimeoutExpired([], 15))
        uncertain = self.apply()
        self.assertEqual((uncertain["phase"], uncertain["error"]),
                         ("uncertain", "START_UNCERTAIN"))
        self.assertEqual(self.apply(), uncertain)
        self.assertEqual(self.store.run.call_count, 1)

    def test_missing_systemctl_binary_is_failed_before_enqueue(self):
        self.store.run = mock.Mock(side_effect=FileNotFoundError())
        failed = self.apply()
        self.assertEqual((failed["phase"], failed["error"]), ("failed", "START_FAILED"))
        self.assertEqual(self.apply(), failed)
        self.assertEqual(self.store.run.call_count, 1)

    def test_unit_completion_wins_race_with_start_failure(self):
        def complete(_argv, **_kwargs):
            directory = self.root / REQUEST_ID
            accepted = json.loads((directory / "status.json").read_bytes())
            completed = {**accepted, "phase": "complete"}
            (directory / "status.json").write_text(json.dumps(completed, sort_keys=True,
                                                             separators=(",", ":")) + "\n")
            (directory / "status.json").chmod(0o600)
            return subprocess.CompletedProcess([], 1, b"", b"")

        self.store.run = complete
        self.assertEqual(self.apply()["phase"], "complete")
        self.assertEqual(self.store.status(REQUEST_ID)["phase"], "complete")

    def test_rejects_unsafe_paths_and_malformed_records(self):
        with self.assertRaisesRegex(ExternalOperationError, "EXTERNAL_INVALID_REQUEST"):
            self.apply(request_id="../escape")
        self.unit.chmod(0o666)
        with self.assertRaisesRegex(ExternalOperationError, "EXTERNAL_UNAVAILABLE"):
            self.apply()
        self.unit.chmod(0o644)
        self.marker.write_text("wrong marker\n")
        with self.assertRaisesRegex(ExternalOperationError, "EXTERNAL_UNAVAILABLE"):
            self.apply()
        self.marker.write_text("SOVAGRID_EXTERNAL_AGENT_APPLY_UNIT_V1\n")
        self.apply()
        status = self.root / REQUEST_ID / "status.json"
        status.write_text('{"format":1,"token":"secret"}\n')
        status.chmod(0o600)
        with self.assertRaisesRegex(ExternalOperationError, "EXTERNAL_INVALID_STATE"):
            self.store.status(REQUEST_ID)

    def test_crash_before_unit_start_expires_without_restarting(self):
        self.store.run = mock.Mock(side_effect=SystemExit("broker crashed"))
        with self.assertRaises(SystemExit):
            self.apply()
        self.assertEqual(self.store.status(REQUEST_ID)["phase"], "accepted")
        self.store.run = self.run
        with mock.patch("sovagrid_hub.external_agent_operations.time.time", return_value=9999999999):
            expired = self.apply()
            self.assertEqual((expired["phase"], expired["error"]),
                             ("uncertain", "RECOVERY_REQUIRED"))
            self.assertEqual(self.store.list(), [expired])
        self.assertEqual(self.calls, [])

    def test_activating_unit_remains_live_and_inactive_unit_is_reconciled(self):
        accepted = self.apply()
        seen = []

        def state(argv, **_kwargs):
            seen.append(argv)
            return subprocess.CompletedProcess(argv, 0, b"activating\n", b"")

        self.store.run = state
        with mock.patch("sovagrid_hub.external_agent_operations.time.time",
                        return_value=accepted["created_at"] + 31):
            self.assertEqual(self.store.status(REQUEST_ID)["phase"], "accepted")
        self.assertEqual(seen, [["/usr/bin/systemctl", "show", "-P", "ActiveState",
                                 "sovagrid-external-agent-apply@" + REQUEST_ID + ".service"]])

        def inactive(argv, **_kwargs):
            return subprocess.CompletedProcess(argv, 0, b"inactive\n", b"")

        self.store.run = inactive
        with mock.patch("sovagrid_hub.external_agent_operations.time.time",
                        return_value=accepted["created_at"] + 32):
            result = self.store.status(REQUEST_ID)
        self.assertEqual((result["phase"], result["error"]),
                         ("uncertain", "RECOVERY_REQUIRED"))
        self.assertEqual(self.store.status(REQUEST_ID), result)
        self.assertEqual(len(self.calls), 1)


if __name__ == "__main__":
    unittest.main()
