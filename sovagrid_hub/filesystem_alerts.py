# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Opt-in alerts for individually measured local filesystem mountpoints."""

from __future__ import annotations

import hashlib
import json
import math
import posixpath


MAX_RULES = 32
DEFAULT_HOLD_SECONDS = 120
MAX_HOLD_SECONDS = 86400
FRESH_SECONDS = 120
METRICS = frozenset(("space", "inodes"))
RULE_FIELDS = frozenset(("mountpoint", "metric", "threshold_percent"))


class FilesystemAlertConflict(Exception):
    """A concurrent administrator changed this server's filesystem rules."""


class FilesystemAlertInventoryUnavailable(Exception):
    """The newly selected filesystem is absent from fresh, valid evidence."""


def mountpoint(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("Filesystem mountpoint must be a canonical absolute path")
    try:
        length = len(value.encode("utf-8"))
    except UnicodeError:
        raise ValueError("Filesystem mountpoint must be UTF-8") from None
    if (not value.startswith("/") or "//" in value or not 1 <= length <= 128 or
            not value.isprintable() or posixpath.normpath(value) != value):
        raise ValueError("Filesystem mountpoint must be a canonical absolute path")
    return value


def validate_settings(payload: object) -> tuple[int, int, list[dict]]:
    if not isinstance(payload, dict) or set(payload) != {"revision", "hold_seconds", "rules"}:
        raise ValueError("Expected revision, hold_seconds and rules")
    revision, hold, rules = payload["revision"], payload["hold_seconds"], payload["rules"]
    if type(revision) is not int or not 0 <= revision < 2**63 - 1:
        raise ValueError("Invalid filesystem alert revision")
    if type(hold) is not int or not 0 <= hold <= MAX_HOLD_SECONDS:
        raise ValueError("Filesystem alert hold must be 0–86400 seconds")
    if not isinstance(rules, list) or len(rules) > MAX_RULES:
        raise ValueError("At most 32 filesystem alert rules are supported")
    clean = []
    seen = set()
    for rule in rules:
        if not isinstance(rule, dict) or set(rule) != RULE_FIELDS:
            raise ValueError("Invalid filesystem alert rule")
        path = mountpoint(rule["mountpoint"])
        metric = rule["metric"]
        threshold = rule["threshold_percent"]
        if not isinstance(metric, str) or metric not in METRICS or type(threshold) is not int or not 1 <= threshold <= 100:
            raise ValueError("Filesystem threshold must be an integer from 1 to 100")
        key = (path, metric)
        if key in seen:
            raise ValueError("Duplicate filesystem alert rule")
        seen.add(key)
        clean.append({"mountpoint": path, "metric": metric, "threshold_percent": threshold})
    if len(json.dumps(clean, ensure_ascii=False, separators=(",", ":")).encode("utf-8")) > 8192:
        raise ValueError("Filesystem alert rules exceed 8 KiB")
    return revision, hold, clean


def kind(path: str, metric: str) -> str:
    mountpoint(path)
    if not isinstance(metric, str) or metric not in METRICS:
        raise ValueError("Invalid filesystem alert metric")
    digest = hashlib.sha256((metric + "\0" + path).encode("utf-8")).hexdigest()
    return f"filesystem:{metric}:{digest}"


def _percent(total: object, available: object, reported: object) -> float | None:
    if (type(total) is not int or type(available) is not int or
            not isinstance(reported, (int, float)) or isinstance(reported, bool) or
            total < 0 or not 0 <= available <= total):
        raise ValueError("Invalid filesystem counters")
    try:
        finite = math.isfinite(reported)
    except OverflowError:
        finite = False
    if not finite:
        raise ValueError("Invalid filesystem percentage")
    if total == 0:
        return None
    computed = round(100.0 * (1 - available / total), 2)
    if abs(float(reported) - computed) > 0.05:
        raise ValueError("Contradictory filesystem percentage")
    return computed


def evidence(details: dict | None, *, observed_at: int | None,
             received_at: int, now: int) -> dict:
    """Use Hub receipt freshness; Agent and Hub clocks may differ by minutes."""
    result = {"source_status": "unavailable", "observed_at": observed_at,
              "filesystems": [], "measurements": {}}
    if type(received_at) is not int or not 0 <= now - received_at <= FRESH_SECONDS:
        return {**result, "source_status": "stale" if received_at else "unavailable"}
    if not isinstance(details, dict) or not isinstance(details.get("filesystems"), list):
        return result
    rows = details["filesystems"]
    if len(rows) > 16:
        return {**result, "source_status": "partial"}
    if not rows:
        return {**result, "source_status": "partial" if details.get("filesystems_truncated") is True
                else "unavailable"}
    clean = []
    values = {}
    seen = set()
    try:
        for item in rows:
            if not isinstance(item, dict):
                raise ValueError("Invalid filesystem row")
            path = mountpoint(item.get("mountpoint"))
            if path in seen:
                raise ValueError("Duplicate filesystem mountpoint")
            seen.add(path)
            fstype = item.get("fstype")
            if not isinstance(fstype, str) or not 1 <= len(fstype) <= 32 or not fstype.isprintable():
                raise ValueError("Invalid filesystem type")
            space = _percent(item.get("total_bytes"), item.get("available_bytes"),
                             item.get("used_percent"))
            inodes = _percent(item.get("inodes_total"), item.get("inodes_available"),
                              item.get("inodes_used_percent"))
            clean.append({"mountpoint": path, "fstype": fstype,
                          "space_used_percent": space, "inodes_used_percent": inodes})
            values[path, "space"] = space
            values[path, "inodes"] = inodes
    except ValueError:
        return {**result, "source_status": "partial"}
    clipped = details.get("filesystems_truncated") is True or len(rows) == 16
    return {"source_status": "partial" if clipped else "ok", "observed_at": observed_at,
            "filesystems": [] if clipped else clean, "measurements": values}


def observation(rule: dict, source: dict) -> dict:
    # A clipped list still proves values of rows actually present. Absence
    # never proves recovery, even when an older Agent omitted the clip flag.
    value = source["measurements"].get((rule["mountpoint"], rule["metric"]))
    return {"mountpoint": rule["mountpoint"], "metric": rule["metric"],
            "status": ("unknown" if value is None else
                       "alert" if value >= rule["threshold_percent"] else "normal"),
            "used_percent": value}


def migrate(db) -> None:
    db.execute("""CREATE TABLE IF NOT EXISTS filesystem_alert_settings (
        server_id TEXT PRIMARY KEY REFERENCES servers(id) ON DELETE CASCADE,
        rules_json TEXT NOT NULL, hold_seconds INTEGER NOT NULL,
        revision INTEGER NOT NULL, last_observed_at INTEGER)""")
