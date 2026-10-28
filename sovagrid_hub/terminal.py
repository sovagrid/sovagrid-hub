# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Bounded, in-memory relay for interactive terminal sessions.

PTY bytes never enter SQLite or the audit log. Both peers connect to Hub;
the Agent uses only outbound HTTPS requests and owns the PTY lifetime.
"""

from __future__ import annotations

import base64
import hashlib
import json
import threading
import time
import uuid
from dataclasses import dataclass, field


class TerminalError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


def decode_frame(value: object) -> bytes:
    if not isinstance(value, str) or not value or len(value) > 5462:
        raise TerminalError(400, "Invalid terminal frame")
    if any(char not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for char in value):
        raise TerminalError(400, "Invalid terminal frame")
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, base64.binascii.Error) as exc:
        raise TerminalError(400, "Invalid terminal frame") from exc
    if (not 1 <= len(raw) <= 4096
            or base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != value):
        raise TerminalError(400, "Invalid terminal frame")
    return raw


def dimension(value: object, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise TerminalError(400, "Invalid terminal size")
    return value


@dataclass
class TerminalSession:
    id: str
    server_id: str
    owner_hash: str
    key: str
    cols: int
    rows: int
    created_at: int
    started: float
    browser_seen: float
    state: str = "pending"
    starting_at: float | None = None
    closed_at: float | None = None
    reason: str | None = None
    exit_code: int | None = None
    controls: list[dict] = field(default_factory=list)
    outputs: list[dict] = field(default_factory=list)
    control_seq: int = 0
    output_seq: int = 0
    control_acked: int = 0
    output_acked: int = 0
    control_bytes: int = 0
    output_bytes: int = 0
    last_control_hash: str = ""
    last_output_hash: str = ""


class TerminalRegistry:
    MAX_SESSIONS = 4
    MAX_WAITERS = 32
    OUTPUT_LIMIT = 512 * 1024
    INPUT_LIMIT = 64 * 1024
    IDLE_SECONDS = 90
    LIFE_SECONDS = 30 * 60
    RETAIN_SECONDS = 30

    def __init__(self):
        self._condition = threading.Condition()
        self._sessions: dict[str, TerminalSession] = {}
        self._keys: dict[tuple[str, str], tuple[str, int, int, str]] = {}
        self._browser_waiting: set[str] = set()
        self._agent_waiting: set[str] = set()
        self._next_waiting: set[str] = set()

    def _waiter_count(self) -> int:
        return len(self._browser_waiting) + len(self._agent_waiting) + len(self._next_waiting)

    def _close(self, item: TerminalSession, reason: str, exit_code: int | None = None):
        if item.state == "closed":
            return
        item.state = "closed"
        item.reason = reason
        item.exit_code = exit_code
        item.closed_at = time.monotonic()
        self._condition.notify_all()

    def _sweep(self):
        now = time.monotonic()
        for item in list(self._sessions.values()):
            if item.state != "closed":
                if now - item.started >= self.LIFE_SECONDS:
                    self._close(item, "time_limit")
                elif now - item.browser_seen >= self.IDLE_SECONDS:
                    self._close(item, "browser_idle")
                elif item.state == "starting" and item.starting_at is not None and now - item.starting_at >= 30:
                    self._close(item, "agent_start_timeout")
            if item.closed_at is not None and now - item.closed_at >= self.RETAIN_SECONDS:
                self._sessions.pop(item.id, None)
                self._keys.pop((item.owner_hash, item.key), None)

    def _item(self, server_id: str, session_id: str, owner_hash: str | None = None) -> TerminalSession:
        self._sweep()
        item = self._sessions.get(session_id)
        if item is None or item.server_id != server_id:
            raise TerminalError(404, "Terminal session not found")
        if owner_hash is not None and item.owner_hash != owner_hash:
            raise TerminalError(403, "Terminal session belongs to another login")
        return item

    @staticmethod
    def _summary(item: TerminalSession) -> dict:
        return {"id": item.id, "server_id": item.server_id,
                "state": item.state, "created_at": item.created_at}

    def create(self, server_id: str, owner_hash: str, key: str,
               cols: int, rows: int) -> tuple[dict, bool]:
        with self._condition:
            self._sweep()
            previous = self._keys.get((owner_hash, key))
            if previous:
                old_server, old_cols, old_rows, session_id = previous
                if (old_server, old_cols, old_rows) != (server_id, cols, rows):
                    raise TerminalError(409, "Idempotency-Key was used for another terminal")
                item = self._sessions.get(session_id)
                if item is None:
                    raise TerminalError(409, "Terminal session expired")
                return self._summary(item), False
            active = [item for item in self._sessions.values() if item.state != "closed"]
            if len(active) >= self.MAX_SESSIONS or any(item.server_id == server_id for item in active):
                raise TerminalError(429, "Terminal session limit reached")
            now = time.monotonic()
            item = TerminalSession(str(uuid.uuid4()), server_id, owner_hash, key,
                                   cols, rows, int(time.time()), now, now)
            self._sessions[item.id] = item
            self._keys[(owner_hash, key)] = (server_id, cols, rows, item.id)
            self._condition.notify_all()
            return self._summary(item), True

    def next_agent(self, server_id: str) -> dict | None:
        deadline = time.monotonic() + 15
        with self._condition:
            if server_id in self._next_waiting or self._waiter_count() >= self.MAX_WAITERS:
                raise TerminalError(429, "Terminal waiter limit reached")
            self._next_waiting.add(server_id)
            try:
                while True:
                    self._sweep()
                    for item in self._sessions.values():
                        if item.server_id == server_id and item.state == "pending":
                            item.state = "starting"
                            item.starting_at = time.monotonic()
                            self._condition.notify_all()
                            return {"id": item.id, "cols": item.cols, "rows": item.rows}
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        return None
                    self._condition.wait(min(remaining, 2))
            finally:
                self._next_waiting.discard(server_id)

    def owner_hash(self, server_id: str, session_id: str) -> str:
        with self._condition:
            return self._item(server_id, session_id).owner_hash

    def ready(self, server_id: str, session_id: str):
        with self._condition:
            item = self._item(server_id, session_id)
            if item.state != "starting":
                raise TerminalError(409, "Terminal session cannot start")
            item.state = "active"
            self._condition.notify_all()
            return {"state": item.state}

    def close(self, server_id: str, session_id: str, owner_hash: str | None = None,
              reason: str = "closed") -> dict:
        with self._condition:
            item = self._item(server_id, session_id, owner_hash)
            self._close(item, reason)
            return {"closed": True}

    def close_owner(self, owner_hash: str):
        with self._condition:
            for item in self._sessions.values():
                if item.owner_hash == owner_hash:
                    self._close(item, "session_revoked")

    def close_all(self):
        with self._condition:
            for item in self._sessions.values():
                self._close(item, "session_revoked")

    def close_server(self, server_id: str, reason: str):
        with self._condition:
            for item in self._sessions.values():
                if item.server_id == server_id:
                    self._close(item, reason)

    def has_active(self, server_id: str) -> bool:
        """Report relays still known to this Hub process, for maintenance."""
        with self._condition:
            self._sweep()
            return any(item.server_id == server_id and item.state != "closed"
                       for item in self._sessions.values())

    def _enqueue_control(self, item: TerminalSession, payload: dict) -> tuple[dict, bool]:
        if item.state == "closed":
            raise TerminalError(409, "Terminal session is closed")
        seq = payload["seq"]
        if type(seq) is not int or seq < 1 or seq > 1_000_000_000:
            raise TerminalError(400, "Invalid terminal sequence")
        digest = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        if seq == item.control_seq:
            if digest != item.last_control_hash:
                raise TerminalError(409, "Terminal sequence conflicts")
            return {"accepted": True, "next_seq": seq}, False
        if seq != item.control_seq + 1:
            raise TerminalError(409, "Terminal sequence gap")
        if payload["type"] == "input":
            size = len(decode_frame(payload["data"]))
            if item.control_bytes + size > self.INPUT_LIMIT:
                self._close(item, "input_overflow")
                raise TerminalError(429, "Terminal input limit reached")
            item.control_bytes += size
        item.control_seq = seq
        item.last_control_hash = digest
        item.controls.append(payload)
        item.browser_seen = time.monotonic()
        self._condition.notify_all()
        return {"accepted": True, "next_seq": seq}, True

    def input(self, server_id: str, session_id: str, owner_hash: str, seq: int, data: str):
        with self._condition:
            item = self._item(server_id, session_id, owner_hash)
            return self._enqueue_control(item, {"seq": seq, "type": "input", "data": data})

    def resize(self, server_id: str, session_id: str, owner_hash: str,
               seq: int, cols: int, rows: int):
        with self._condition:
            item = self._item(server_id, session_id, owner_hash)
            return self._enqueue_control(item, {"seq": seq, "type": "resize", "cols": cols, "rows": rows})

    def controls(self, server_id: str, session_id: str, after: int,
                 still_allowed) -> dict:
        deadline = time.monotonic() + 15
        with self._condition:
            if session_id in self._agent_waiting or self._waiter_count() >= self.MAX_WAITERS:
                raise TerminalError(429, "Terminal waiter limit reached")
            self._agent_waiting.add(session_id)
            try:
                while True:
                    item = self._item(server_id, session_id)
                    if not still_allowed(item.owner_hash):
                        self._close(item, "permission_revoked")
                    if after < item.control_acked or after > item.control_seq:
                        self._close(item, "control_cursor_lost")
                        raise TerminalError(409, "Terminal control cursor expired")
                    if after > item.control_acked:
                        item.control_acked = after
                        item.controls = [frame for frame in item.controls if frame["seq"] > after]
                        item.control_bytes = sum(len(decode_frame(frame["data"]))
                                                 for frame in item.controls if frame["type"] == "input")
                    frames = [frame for frame in item.controls if frame["seq"] > after][:64]
                    if frames or item.state == "closed" or time.monotonic() >= deadline:
                        return {"events": frames, "next_after": frames[-1]["seq"] if frames else after,
                                "state": item.state, "reason": item.reason}
                    self._condition.wait(min(deadline - time.monotonic(), 2))
            finally:
                self._agent_waiting.discard(session_id)

    def output(self, server_id: str, session_id: str, seq: int, data: str) -> tuple[dict, bool]:
        raw = decode_frame(data)
        with self._condition:
            item = self._item(server_id, session_id)
            if item.state != "active":
                raise TerminalError(409, "Terminal session is closed")
            if type(seq) is not int or seq < 1 or seq > 1_000_000_000:
                raise TerminalError(400, "Invalid terminal sequence")
            digest = hashlib.sha256(raw).hexdigest()
            if seq == item.output_seq:
                if digest != item.last_output_hash:
                    raise TerminalError(409, "Terminal sequence conflicts")
                return {"accepted": True, "next_seq": seq}, False
            if seq != item.output_seq + 1:
                raise TerminalError(409, "Terminal sequence gap")
            if item.output_bytes + len(raw) > self.OUTPUT_LIMIT:
                self._close(item, "output_overflow")
                raise TerminalError(429, "Terminal output limit reached")
            item.output_seq = seq
            item.last_output_hash = digest
            item.outputs.append({"seq": seq, "type": "output", "data": data})
            item.output_bytes += len(raw)
            self._condition.notify_all()
            return {"accepted": True, "next_seq": seq}, True

    def events(self, server_id: str, session_id: str, owner_hash: str,
               after: int, still_allowed) -> dict:
        deadline = time.monotonic() + 15
        with self._condition:
            if session_id in self._browser_waiting or self._waiter_count() >= self.MAX_WAITERS:
                raise TerminalError(429, "Terminal waiter limit reached")
            self._browser_waiting.add(session_id)
            try:
                while True:
                    item = self._item(server_id, session_id, owner_hash)
                    if not still_allowed(item.owner_hash):
                        self._close(item, "permission_revoked")
                        raise TerminalError(403, "Terminal permission revoked")
                    item.browser_seen = time.monotonic()
                    if after < item.output_acked or after > item.output_seq:
                        self._close(item, "output_cursor_lost")
                        raise TerminalError(409, "Terminal output expired")
                    if after > item.output_acked:
                        item.output_acked = after
                        item.outputs = [frame for frame in item.outputs if frame["seq"] > after]
                        item.output_bytes = sum(len(decode_frame(frame["data"])) for frame in item.outputs)
                    frames = []
                    size = 0
                    for frame in item.outputs:
                        if frame["seq"] > after:
                            frame_size = len(frame["data"])
                            if size + frame_size > 64 * 1024:
                                break
                            frames.append(frame)
                            size += frame_size
                    if frames or item.state == "closed" or time.monotonic() >= deadline:
                        return {"events": frames, "next_after": frames[-1]["seq"] if frames else after,
                                "state": item.state, "exit_code": item.exit_code,
                                "reason": item.reason}
                    self._condition.wait(min(deadline - time.monotonic(), 2))
            finally:
                self._browser_waiting.discard(session_id)

    def exit(self, server_id: str, session_id: str, exit_code: int | None) -> dict:
        with self._condition:
            item = self._item(server_id, session_id)
            if exit_code is not None and (type(exit_code) is not int or not -255 <= exit_code <= 255):
                raise TerminalError(400, "Invalid terminal exit code")
            self._close(item, "process_exit", exit_code)
            return {"state": item.state}
