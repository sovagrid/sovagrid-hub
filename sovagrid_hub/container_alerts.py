# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Opt-in Docker health rules and conservative, typed inventory evidence."""

from __future__ import annotations

import hashlib
import json
import re


MAX_RULES = 12
DEFAULT_HOLD_SECONDS = 120
MAX_HOLD_SECONDS = 86400
FRESH_SECONDS = 120
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,95}\Z")
RULE_FIELDS = frozenset(("name", "stopped", "unhealthy", "missing"))


class ContainerAlertConflict(Exception):
    """Another administrator changed this server's Docker alert rules."""


class ContainerAlertInventoryUnavailable(Exception):
    """A newly selected name is absent from a fresh, complete Docker list."""


def validate_settings(payload: object) -> tuple[int, int, list[dict]]:
    if not isinstance(payload, dict) or set(payload) != {"revision", "hold_seconds", "rules"}:
        raise ValueError("Expected revision, hold_seconds and rules")
    revision = payload["revision"]
    hold = payload["hold_seconds"]
    rules = payload["rules"]
    if type(revision) is not int or not 0 <= revision < 2**63 - 1:
        raise ValueError("Invalid container alert revision")
    if type(hold) is not int or not 0 <= hold <= MAX_HOLD_SECONDS:
        raise ValueError("Container alert hold must be 0–86400 seconds")
    if not isinstance(rules, list) or len(rules) > MAX_RULES:
        raise ValueError("At most 12 Docker alert rules are supported")
    clean = []
    names = set()
    for rule in rules:
        if (not isinstance(rule, dict) or set(rule) != RULE_FIELDS or
                not isinstance(rule["name"], str) or NAME.fullmatch(rule["name"]) is None or
                any(type(rule[field]) is not bool for field in ("stopped", "unhealthy", "missing")) or
                not any(rule[field] for field in ("stopped", "unhealthy", "missing"))):
            raise ValueError("Invalid Docker alert rule")
        name = rule["name"]
        if name in names:
            raise ValueError("Duplicate Docker alert name")
        names.add(name)
        clean.append({key: rule[key] for key in ("name", "stopped", "unhealthy", "missing")})
    if len(json.dumps(clean, separators=(",", ":")).encode("ascii")) > 4096:
        raise ValueError("Docker alert rules exceed 4 KiB")
    return revision, hold, clean


def kind(name: str) -> str:
    if not isinstance(name, str) or NAME.fullmatch(name) is None:
        raise ValueError("Invalid Docker container name")
    return "container:" + hashlib.sha256(name.encode("ascii")).hexdigest()


def evidence(snapshot: dict | None, *, metric_collected_at: int,
             received_at: int, now: int) -> dict:
    """Only a newest, recent, complete Docker list can prove a transition.

    An Engine `unknown` item state is unknown for that one rule. Names are
    case sensitive, matching Docker's own container identity convention.
    """
    unavailable = {"source_status": "unavailable", "observed_at": None, "states": {},
                   "names": frozenset()}
    if not isinstance(snapshot, dict):
        return unavailable
    observed = snapshot.get("collected_at")
    if type(observed) is not int:
        return unavailable
    result = {**unavailable, "observed_at": observed}
    # Hub receipt time and Agent collection time each compare against their
    # own clock. Comparing observed directly with Hub `now` would reject a
    # healthy remote Agent when the machines differ by two minutes.
    if (type(metric_collected_at) is not int or
            not 0 <= now - received_at <= FRESH_SECONDS or
            not 0 <= metric_collected_at - observed <= FRESH_SECONDS):
        return {**result, "source_status": "stale"}
    engines = snapshot.get("engines")
    if not isinstance(engines, list):
        return result
    docker = next((item for item in engines if isinstance(item, dict) and
                   item.get("engine") == "docker"), None)
    if docker is None or docker.get("source_status") != "ok":
        return result
    if docker.get("truncated") is not False or not isinstance(docker.get("containers"), list):
        return {**result, "source_status": "partial"}
    names = {}
    for item in docker["containers"]:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            return {**result, "source_status": "partial"}
        name = item["name"]
        if NAME.fullmatch(name) is None or name in names:
            return {**result, "source_status": "partial"}
        state = item.get("state")
        health = item.get("health")
        if state == "running":
            status = "unhealthy" if health == "unhealthy" else "running"
        elif state in ("created", "paused", "restarting", "removing", "exited", "dead"):
            status = "stopped"
        else:
            status = "unknown"
        names[name] = status
    return {"source_status": "ok", "observed_at": observed, "states": names,
            "names": frozenset(names)}


def observation(rule: dict, source: dict) -> dict:
    name = rule["name"]
    if source["source_status"] != "ok":
        status = "unknown"
    else:
        status = source["states"].get(name, "missing")
    return {"name": name, "status": status}


def migrate(db) -> None:
    """Run inside the caller's SQLite migration transaction."""
    db.execute("""CREATE TABLE IF NOT EXISTS container_alert_settings (
        server_id TEXT PRIMARY KEY REFERENCES servers(id) ON DELETE CASCADE,
        rules_json TEXT NOT NULL, hold_seconds INTEGER NOT NULL,
        revision INTEGER NOT NULL, last_observed_at INTEGER)""")
