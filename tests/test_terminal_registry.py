# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
import threading
import time
import unittest

from sovagrid_hub.terminal import TerminalError, TerminalRegistry


class TerminalRegistryTests(unittest.TestCase):
    def test_only_one_long_poll_per_peer_and_server(self):
        registry = TerminalRegistry()
        session, _ = registry.create("server", "owner", "key", 80, 24)
        sid = session["id"]
        started = threading.Event()
        results = []

        def browser_wait():
            started.set()
            results.append(registry.events("server", sid, "owner", 0, lambda _: True))

        thread = threading.Thread(target=browser_wait)
        thread.start()
        started.wait(1)
        deadline = time.monotonic() + 1
        while sid not in registry._browser_waiting and time.monotonic() < deadline:
            time.sleep(0.01)
        with self.assertRaises(TerminalError) as context:
            registry.events("server", sid, "owner", 0, lambda _: True)
        self.assertEqual(context.exception.status, 429)
        registry.close("server", sid, "owner")
        thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(results[0]["state"], "closed")

        next_started = threading.Event()

        def agent_wait():
            next_started.set()
            results.append(registry.next_agent("server"))

        thread = threading.Thread(target=agent_wait)
        thread.start()
        next_started.wait(1)
        deadline = time.monotonic() + 1
        while "server" not in registry._next_waiting and time.monotonic() < deadline:
            time.sleep(0.01)
        with self.assertRaises(TerminalError) as context:
            registry.next_agent("server")
        self.assertEqual(context.exception.status, 429)
        registry.create("server", "owner", "second-key", 80, 24)
        thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertIsNotNone(results[1])


if __name__ == "__main__":
    unittest.main()
