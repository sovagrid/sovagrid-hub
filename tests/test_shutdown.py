# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Docker's SIGTERM reaches the Hub serve cleanup path."""

from __future__ import annotations

import os
from pathlib import Path
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request

from sovagrid_hub.store import Store


@unittest.skipUnless(os.name == "posix", "SIGTERM is required for this test")
class ShutdownTests(unittest.TestCase):
    def test_sigterm_gracefully_stops_live_hub(self):
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / "hub.sqlite"
            Store(db).initialize("admin", "a-long-shutdown-test-password")
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
                listener.bind(("127.0.0.1", 0))
                port = listener.getsockname()[1]

            process = subprocess.Popen(
                [sys.executable, "-m", "sovagrid_hub", "--db", str(db),
                 "serve", "--bind", "127.0.0.1", "--port", str(port),
                 "--no-telegram-poll"],
                cwd=Path(__file__).resolve().parents[1],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
            try:
                deadline = time.monotonic() + 8
                while True:
                    if process.poll() is not None:
                        stdout, stderr = process.communicate()
                        self.fail(f"Hub exited before health check: {process.returncode}\n{stdout!r}\n{stderr!r}")
                    try:
                        with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=0.5) as response:
                            self.assertEqual(response.status, 200)
                            self.assertEqual(response.read(), b'{"ok":true}')
                        break
                    except (urllib.error.URLError, TimeoutError):
                        if time.monotonic() >= deadline:
                            self.fail("Hub did not start within 8 seconds")
                        time.sleep(0.05)

                process.send_signal(signal.SIGTERM)
                stdout, stderr = process.communicate(timeout=8)
                self.assertEqual(process.returncode, 0, (stdout, stderr))
                with sqlite3.connect(db) as connection:
                    self.assertEqual(connection.execute("PRAGMA quick_check").fetchone()[0], "ok")
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate(timeout=3)
