# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Admin-only, transient process inventory job contract."""

from __future__ import annotations

import json
import hashlib
import time

MARKER = "/usr/local/bin/sovagrid-process-inventory"
MAX_PAGE = 32
MAX_PID = 2**31 - 1
MAX_RSS = 2**63 - 1


def request_parameters(value: object) -> dict:
    if not isinstance(value, dict) or set(value) - {"after_pid", "limit", "filter"}:
        raise ValueError("Expected process page options")
    after_pid = value.get("after_pid", 0)
    limit = value.get("limit", MAX_PAGE)
    name_filter = value.get("filter", "")
    if (type(after_pid) is not int or not 0 <= after_pid <= MAX_PID
            or type(limit) is not int or not 1 <= limit <= MAX_PAGE
            or not isinstance(name_filter, str) or len(name_filter) > 16
            or len(name_filter.encode("utf-8")) > 64 or
            (name_filter and (not name_filter.isprintable() or name_filter != name_filter.strip()))):
        raise ValueError("Invalid process page options")
    return {"after_pid": after_pid, "limit": limit, "filter": name_filter}


def build_process_command(value: object) -> str:
    params = request_parameters(value)
    encoded = params["filter"].encode("utf-8").hex() or "-"
    return f"{MARKER} list {params['after_pid']} {params['limit']} {encoded}"


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("Duplicate process inventory field")
        value[key] = item
    return value


def validate_snapshot(output: str, expected_after: int, expected_limit: int,
                      expected_filter_sha256: str,
                      now: int | None = None) -> str:
    """Reject malformed Agent data before placing it in the ephemeral cache."""
    if not isinstance(output, str) or len(output.encode("utf-8")) > 8192:
        raise ValueError("Invalid process inventory output")
    try:
        value = json.loads(output, object_pairs_hook=_unique_object)
    except (ValueError, TypeError) as exc:
        raise ValueError("Invalid process inventory output") from exc
    now = int(time.time()) if now is None else now
    if (not isinstance(value, dict) or set(value) !=
            {"observed_at", "after_pid", "filter", "next_after_pid", "has_more", "processes"}
            or type(value["observed_at"]) is not int
            or not 1 <= value["observed_at"] <= 253402300799
            or abs(value["observed_at"] - now) > 300
            or type(value["after_pid"]) is not int or value["after_pid"] != expected_after
            or not isinstance(value["filter"], str) or len(value["filter"]) > 16
            or len(value["filter"].encode("utf-8")) > 64
            or (value["filter"] and (not value["filter"].isprintable()
                                     or value["filter"] != value["filter"].strip()))
            or hashlib.sha256(value["filter"].encode()).hexdigest() != expected_filter_sha256
            or type(value["next_after_pid"]) is not int
            or not expected_after <= value["next_after_pid"] <= MAX_PID
            or type(value["has_more"]) is not bool
            or not isinstance(value["processes"], list)
            or len(value["processes"]) > expected_limit
            or (value["has_more"] and value["next_after_pid"] == expected_after)):
        raise ValueError("Invalid process inventory output")
    previous = expected_after
    for item in value["processes"]:
        if (not isinstance(item, dict) or set(item) != {"pid", "name", "rss_bytes"}
                or type(item["pid"]) is not int or not previous < item["pid"] <= value["next_after_pid"]
                or not isinstance(item["name"], str) or not 1 <= len(item["name"]) <= 16
                or len(item["name"].encode("utf-8")) > 64 or not item["name"].isprintable()
                or value["filter"].casefold() not in item["name"].casefold()
                or type(item["rss_bytes"]) is not int or not 0 <= item["rss_bytes"] <= MAX_RSS):
            raise ValueError("Invalid process inventory row")
        previous = item["pid"]
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
