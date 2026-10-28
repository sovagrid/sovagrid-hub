# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Exact Docker action commands and bounded public broker results."""

from __future__ import annotations

import json
import re


MARKER = "/usr/local/bin/sovagrid-container-action-ctl"
IDENT = re.compile(r"[0-9a-f]{64}\Z")
STATE = frozenset(("created", "running", "paused", "restarting", "removing", "exited", "dead"))
ACTIONS = frozenset(("status", "start", "stop", "restart"))
RESULTS = frozenset(("ok", "failed", "uncertain"))
FIELDS = frozenset(("action", "id", "result", "state"))


def parameters(data: object) -> tuple[str, str, str]:
    if not isinstance(data, dict) or set(data) != {"action", "engine", "id"}:
        raise ValueError("Expected action, engine and full container ID")
    action, engine, ident = data["action"], data["engine"], data["id"]
    if (not isinstance(action, str) or action not in ACTIONS or engine != "docker" or
            not isinstance(ident, str) or IDENT.fullmatch(ident) is None):
        raise ValueError("Only exact Docker container actions are supported")
    return action, engine, ident


def build_command(data: object) -> str:
    action, engine, ident = parameters(data)
    return f"{MARKER} {action} {engine} {ident}"


def parse_command(command: object) -> tuple[str, str, str]:
    if not isinstance(command, str):
        raise ValueError("Invalid container action command")
    parts = command.split(" ")
    if len(parts) != 4:
        raise ValueError("Invalid container action command")
    action, engine, ident = parameters({"action": parts[1], "engine": parts[2], "id": parts[3]})
    if build_command({"action": action, "engine": engine, "id": ident}) != command:
        raise ValueError("Invalid container action command")
    return action, engine, ident


def is_container_action_command(command: object) -> bool:
    try:
        parse_command(command)
        return True
    except ValueError:
        return False


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate container action result field")
        result[key] = value
    return result


def result(output: object, action: str, ident: str) -> dict:
    if not isinstance(output, str) or len(output.encode("utf-8")) > 512:
        raise ValueError("Invalid container action result")
    try:
        value = json.loads(output, object_pairs_hook=_unique)
    except (UnicodeError, ValueError) as exc:
        raise ValueError("Invalid container action result") from exc
    if (not isinstance(value, dict) or set(value) != FIELDS or
            value["action"] != action or value["id"] != ident or
            not isinstance(value["result"], str) or value["result"] not in RESULTS or
            (value["state"] is not None and
             (not isinstance(value["state"], str) or value["state"] not in STATE))):
        raise ValueError("Invalid container action result")
    if value["result"] == "ok" and value["state"] is None:
        raise ValueError("Incomplete container action result")
    if value["result"] == "ok" and ((action == "stop" and value["state"] != "exited") or
                                      (action in ("start", "restart") and value["state"] != "running")):
        raise ValueError("Container action result contradicts the requested action")
    return {key: value[key] for key in ("action", "id", "result", "state")}


def control_status(job: dict | None, now: int, ident: str) -> dict:
    """Only a fresh exact status job can prove a usable preflight."""
    if not isinstance(ident, str) or IDENT.fullmatch(ident) is None:
        raise ValueError("Invalid container ID")
    unavailable = {"source_status": "unavailable", "engine": "docker", "id": ident,
                   "observed_at": None, "state": None}
    if not job or job.get("state") != "succeeded" or job.get("exit_code") != 0:
        return unavailable
    observed = job.get("completed_at")
    if type(observed) is not int or not 0 <= now - observed <= 90:
        return unavailable
    try:
        public = result(job.get("output"), "status", ident)
    except ValueError:
        return unavailable
    if public["result"] != "ok":
        return unavailable
    return {"source_status": "ok", "engine": "docker", "id": ident,
            "observed_at": observed, "state": public["state"]}


def protected_inventory(name: str, image: str) -> bool:
    """Reject obvious host/control-plane workloads before reaching root policy."""
    if not isinstance(name, str) or not isinstance(image, str):
        return True
    def forbidden(part: str) -> bool:
        part = part.casefold().lstrip("/")
        return (part.startswith(("sovagrid", "amnezia", "docker", "containerd", "wireguard",
                                 "openvpn", "tailscale", "xray", "sing-box", "ssh")) or
                "tunnel" in part)
    parts = image.split("/")
    if len(parts) > 1 and ("." in parts[0] or ":" in parts[0] or parts[0] == "localhost"):
        parts = parts[1:]
    return forbidden(name) or any(forbidden(part.split(":", 1)[0].split("@", 1)[0])
                                  for part in parts)
