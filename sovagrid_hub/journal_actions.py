# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Build one canonical, bounded read-only journal request for the Agent."""

from __future__ import annotations

import re


MARKER = "/usr/local/bin/sovagrid-journal-read"
UNIT_NAME = re.compile(r"[A-Za-z0-9_.@-]{1,96}[.]service\Z")


def build_journal_command(data: object) -> str:
    if not isinstance(data, dict) or set(data) != {"unit", "lines"}:
        raise ValueError("Expected only unit and lines")
    unit, lines = data["unit"], data["lines"]
    if not isinstance(unit, str) or not UNIT_NAME.fullmatch(unit):
        raise ValueError("Invalid systemd service name")
    if type(lines) is not int or not 1 <= lines <= 100:
        raise ValueError("lines must be an integer between 1 and 100")
    return f"{MARKER} read {unit} {lines}"
