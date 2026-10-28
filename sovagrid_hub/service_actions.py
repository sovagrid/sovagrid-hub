# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Exact, target-bound jobs for the opt-in Agent systemd broker."""

from __future__ import annotations

import json
import re


HELPER = "/usr/local/bin/sovagrid-service-ctl"
ACTIONS = frozenset(("status", "start", "stop", "restart"))
UNIT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.@-]{0,87}[.]service\Z")
STATE = re.compile(r"[a-z][a-z0-9-]{0,31}\Z")
RESULT_FIELDS = frozenset(("action", "unit", "result", "load_state",
                           "active_state", "sub_state"))
_PROTECTED_BASES = frozenset((
    "ssh", "sshd", "dropbear", "dbus", "networking", "networkmanager",
    "network-manager", "docker", "containerd", "podman", "cri-o",
    "nftables", "ufw", "firewalld", "iptables", "netfilter-persistent",
    "caddy", "wg-quick", "awg-quick", "openvpn", "strongswan", "ipsec",
))


def protected_mutation_unit(unit: str) -> bool:
    if not isinstance(unit, str) or not UNIT.fullmatch(unit):
        return False
    stem = unit[:-len(".service")].casefold()
    base = stem.split("@", 1)[0]
    return (base in _PROTECTED_BASES or base.startswith(("sovagrid", "systemd-", "amnezia", "autossh"))
            or "tunnel" in base)


def _unit(value: object) -> str:
    if (not isinstance(value, str) or not UNIT.fullmatch(value) or
            value.endswith("@.service")):
        raise ValueError("Invalid service unit")
    return value


def build_service_command(data: object) -> str:
    if (not isinstance(data, dict) or set(data) != {"action", "unit"} or
            not isinstance(data["action"], str) or data["action"] not in ACTIONS):
        raise ValueError("Invalid service action")
    return f"{HELPER} {data['action']} {_unit(data['unit'])}"


def status_command(unit: str) -> str:
    return build_service_command({"action": "status", "unit": unit})


def is_service_command(command: str) -> bool:
    if not isinstance(command, str):
        return False
    parts = command.split(" ")
    if len(parts) != 3:
        return False
    try:
        return build_service_command({"action": parts[1], "unit": parts[2]}) == command
    except ValueError:
        return False


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate service result field")
        result[key] = value
    return result


def control_status(job: dict | None, now: int, unit: str) -> dict:
    """Project only a fresh, successful status for the exact requested unit."""
    unit = _unit(unit)
    unavailable = {"source_status": "unavailable", "unit": unit,
                   "observed_at": None, "load_state": None,
                   "active_state": None, "sub_state": None}
    if not job or job.get("state") != "succeeded" or job.get("exit_code") != 0:
        return unavailable
    observed = job.get("completed_at")
    if type(observed) is not int or not 0 <= now - observed <= 90:
        return unavailable
    try:
        value = json.loads(job["output"], object_pairs_hook=_unique_pairs)
    except (ValueError, TypeError, KeyError):
        return unavailable
    if (not isinstance(value, dict) or set(value) != RESULT_FIELDS or
            value["action"] != "status" or value["unit"] != unit or
            value["result"] != "ok" or
            any(not isinstance(value[field], str) or not STATE.fullmatch(value[field])
                for field in ("load_state", "active_state", "sub_state"))):
        return unavailable
    return {"source_status": "ok", "unit": unit, "observed_at": observed,
            "load_state": value["load_state"],
            "active_state": value["active_state"], "sub_state": value["sub_state"]}
