# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""One canonical, admin-only request for transient managed-container logs."""

from __future__ import annotations

import re


MARKER = "/usr/local/bin/sovagrid-container-log-read"
IDENTITY = re.compile(r"[0-9a-f]{64}\Z")
ENGINES = frozenset(("docker", "podman"))


def request_parameters(data: object) -> tuple[str, str, int]:
    if not isinstance(data, dict) or set(data) != {"engine", "id", "lines"}:
        raise ValueError("Expected only engine, id and lines")
    engine, ident, lines = data["engine"], data["id"], data["lines"]
    if (not isinstance(engine, str) or engine not in ENGINES or
            not isinstance(ident, str) or IDENTITY.fullmatch(ident) is None or
            type(lines) is not int or not 1 <= lines <= 100):
        raise ValueError("Container logs require an engine, full ID and 1–100 lines")
    return engine, ident, lines


def build_command(data: object) -> str:
    engine, ident, lines = request_parameters(data)
    return f"{MARKER} read {engine} {ident} {lines}"


def parse_command(command: str) -> tuple[str, str, int]:
    if not isinstance(command, str):
        raise ValueError("Invalid container log command")
    parts = command.split(" ")
    if (len(parts) != 5 or parts[:2] != [MARKER, "read"] or
            not parts[4].isascii() or not parts[4].isdecimal()):
        raise ValueError("Invalid container log command")
    data = {"engine": parts[2], "id": parts[3], "lines": int(parts[4])}
    if build_command(data) != command:
        raise ValueError("Invalid container log command")
    return data["engine"], data["id"], data["lines"]


def safe_output(output: object) -> bool:
    return (isinstance(output, str) and len(output.encode("utf-8")) <= 8192 and
            all(char.isprintable() or char in "\n\t" for char in output))
