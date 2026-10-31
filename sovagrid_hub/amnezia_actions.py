# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Exact, opt-in Amnezia broker jobs exposed to the Web admin.

Only pinned AWG2 or WireGuard peers enrolled by a root administrator are
supported. The Hub never accepts Docker flags, paths or plaintext profiles.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import re
import shlex


HELPER = "/usr/local/bin/sovagrid-amnezia-ctl"
TARGETS = ("awg2", "wireguard")
CLIENT = re.compile(r"[a-z][a-z0-9_-]{0,31}\Z")
PUBLIC_KEY = re.compile(r"[A-Za-z0-9_-]{87}\Z")
DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
CONFIRMATION = re.compile(r"[A-Za-z0-9_-]{43}\Z")
AWG_NUMBERS = frozenset(("Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4"))
AWG_RANGES = frozenset(("H1", "H2", "H3", "H4"))
AWG_VALUE = re.compile(r"[0-9]{1,10}(?:-[0-9]{1,10})?\Z")
FIELDS = {
    "status": frozenset(("action", "target")),
    "settings-preview": frozenset(("action", "target")),
    "settings-plan": frozenset(("action", "target", "expected_config_sha256",
                                "expected_generation", "parameters")),
    "settings-intent": frozenset(("action", "target", "expected_config_sha256",
                                  "expected_generation", "expected_proposed_config_sha256",
                                  "parameters")),
    "settings-apply": frozenset(("action", "target", "expected_config_sha256",
                                 "expected_generation", "expected_proposed_config_sha256",
                                 "parameters", "confirmation_id")),
    "add-profile": frozenset(("action", "target", "client", "address",
                               "endpoint_host", "public_key", "route")),
    "sealed-export": frozenset(("action", "target", "client", "public_key")),
    "revoke": frozenset(("action", "target", "client")),
}


def status_command(target: str) -> str:
    if target not in TARGETS:
        raise ValueError("Unsupported Amnezia target")
    return f"{HELPER} status {target}"


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate Amnezia status field")
        result[key] = value
    return result


def _recipient(value: object) -> str:
    if not isinstance(value, str) or not PUBLIC_KEY.fullmatch(value):
        raise ValueError("Invalid profile recipient key")
    try:
        raw = base64.urlsafe_b64decode(value + "=")
    except (ValueError, base64.binascii.Error) as exc:
        raise ValueError("Invalid profile recipient key") from exc
    if (len(raw) != 65 or raw[0] != 4 or
            base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != value):
        raise ValueError("Invalid profile recipient key")
    return value


def _client(value: object) -> str:
    if not isinstance(value, str) or not CLIENT.fullmatch(value):
        raise ValueError("Invalid Amnezia client name")
    return value


def _address(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("Invalid client IPv4 address")
    if value == "auto":
        return value
    try:
        parsed = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as exc:
        raise ValueError("Invalid client IPv4 address") from exc
    if str(parsed) != value:
        raise ValueError("Invalid client IPv4 address")
    return value


def _endpoint(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 253:
        raise ValueError("Invalid endpoint host")
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError:
        value = value.lower()
        if ("." not in value or not all(DNS_LABEL.fullmatch(label)
                                         for label in value.split("."))):
            raise ValueError("Invalid endpoint host")
    else:
        if str(parsed) != value:
            raise ValueError("Invalid endpoint host")
    return value


def _awg_parameters(value: object) -> dict[str, str]:
    """Validate the small numeric AWG3 patch before it reaches a root broker."""
    if (not isinstance(value, dict) or not value or
            set(value) - (AWG_NUMBERS | AWG_RANGES)):
        raise ValueError("Invalid Amnezia settings proposal")
    for name, item in value.items():
        if not isinstance(item, str) or not AWG_VALUE.fullmatch(item):
            raise ValueError("Invalid Amnezia settings proposal")
        parts = [int(part) for part in item.split("-")]
        if (item != "-".join(str(part) for part in parts) or
                max(parts) > (65535 if name in AWG_NUMBERS else 4294967295) or
                (len(parts) == 2 and (name in AWG_NUMBERS or parts[0] > parts[1]))):
            raise ValueError("Invalid Amnezia settings proposal")
    if ("Jmin" in value and "Jmax" in value and
            int(value["Jmin"]) > int(value["Jmax"])):
        raise ValueError("Invalid Amnezia settings proposal")
    return value


def _confirmation(value: object) -> str:
    if not isinstance(value, str) or not CONFIRMATION.fullmatch(value):
        raise ValueError("Invalid Amnezia settings confirmation")
    try:
        raw = base64.urlsafe_b64decode(value + "=")
    except (ValueError, base64.binascii.Error) as exc:
        raise ValueError("Invalid Amnezia settings confirmation") from exc
    if len(raw) != 32 or base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != value:
        raise ValueError("Invalid Amnezia settings confirmation")
    return value


def build_amnezia_command(data: object) -> str:
    if not isinstance(data, dict):
        raise ValueError("Expected Amnezia action object")
    action = data.get("action")
    if not isinstance(action, str) or action not in FIELDS:
        raise ValueError("Unsupported Amnezia action")
    if set(data) != FIELDS[action] or data["target"] not in TARGETS:
        raise ValueError("Unexpected Amnezia action fields or target")
    argv = [HELPER, action, data["target"]]
    if action in ("add-profile", "sealed-export", "revoke"):
        argv.append(_client(data["client"]))
    if action == "add-profile":
        route = data["route"]
        if route not in ("split", "full"):
            raise ValueError("Invalid Amnezia route")
        argv.extend((_address(data["address"]), _endpoint(data["endpoint_host"]),
                     _recipient(data["public_key"]), "--route", route))
    elif action == "sealed-export":
        argv.append(_recipient(data["public_key"]))
    elif action in ("settings-plan", "settings-intent", "settings-apply"):
        digest = data["expected_config_sha256"]
        generation = data["expected_generation"]
        if (data["target"] != "awg2" or not isinstance(digest, str) or
                not SHA256.fullmatch(digest) or type(generation) is not int or
                not 0 <= generation <= 1_000_000_000):
            raise ValueError("Invalid Amnezia settings proposal")
        patch = _awg_parameters(data["parameters"])
        argv.extend((digest, str(generation)))
        if action != "settings-plan":
            proposed = data["expected_proposed_config_sha256"]
            if (not isinstance(proposed, str) or not SHA256.fullmatch(proposed) or
                    proposed == digest):
                raise ValueError("Invalid Amnezia settings proposal")
            argv.append(proposed)
        argv.append(json.dumps(patch, sort_keys=True, separators=(",", ":")))
        if action == "settings-apply":
            argv.append(_confirmation(data["confirmation_id"]))
    return shlex.join(argv)


def is_amnezia_command(command: str) -> bool:
    try:
        argv = shlex.split(command)
        if len(argv) < 3 or argv[0] != HELPER or argv[2] not in TARGETS:
            return False
        action = argv[1]
        if action in ("status", "settings-preview") and len(argv) == 3:
            data = {"action": action, "target": argv[2]}
        elif action in ("settings-plan", "settings-intent", "settings-apply") and len(argv) == (
                6 if action == "settings-plan" else 7 if action == "settings-intent" else 8):
            patch_index = 5 if action == "settings-plan" else 6
            try:
                patch = json.loads(argv[patch_index], object_pairs_hook=_unique_pairs)
                generation = int(argv[4])
            except (TypeError, ValueError):
                return False
            if str(generation) != argv[4] or argv[patch_index] != json.dumps(
                    patch, sort_keys=True, separators=(",", ":")):
                return False
            data = {"action": action, "target": argv[2],
                    "expected_config_sha256": argv[3],
                    "expected_generation": generation, "parameters": patch}
            if action != "settings-plan":
                data["expected_proposed_config_sha256"] = argv[5]
            if action == "settings-apply":
                data["confirmation_id"] = argv[7]
        elif action == "add-profile" and len(argv) == 9 and argv[7] == "--route":
            data = {"action": action, "target": argv[2], "client": argv[3],
                    "address": argv[4], "endpoint_host": argv[5],
                    "public_key": argv[6], "route": argv[8]}
        elif action == "sealed-export" and len(argv) == 5:
            data = {"action": action, "target": argv[2], "client": argv[3],
                    "public_key": argv[4]}
        elif action == "revoke" and len(argv) == 4:
            data = {"action": action, "target": argv[2], "client": argv[3]}
        else:
            return False
        return build_amnezia_command(data) == command
    except (TypeError, ValueError):
        return False


def control_status(job: dict | None, now: int, target: str = "awg2") -> dict:
    """Project a recent broker status result; never trust raw Agent output."""
    if target not in TARGETS:
        raise ValueError("Unsupported Amnezia target")
    unavailable = {"source_status": "unavailable", "target": target, "observed_at": None,
                   "enrolled": False, "recovery_required": False, "owned_clients": []}
    if not job or job.get("state") != "succeeded" or job.get("exit_code") != 0:
        return unavailable
    observed = job.get("completed_at")
    if type(observed) is not int or not 0 <= now - observed <= 90:
        return unavailable
    try:
        value = json.loads(job["output"], object_pairs_hook=_unique_pairs)
    except (ValueError, TypeError, KeyError):
        return unavailable
    if (not isinstance(value, dict) or
            set(value) != {"target", "enrolled", "recovery_required", "owned_clients"} or
            value["target"] != target or type(value["enrolled"]) is not bool or
            type(value["recovery_required"]) is not bool or
            not isinstance(value["owned_clients"], list) or
            len(value["owned_clients"]) > 128):
        return unavailable
    clients = value["owned_clients"]
    if any(not isinstance(client, str) or not CLIENT.fullmatch(client)
           for client in clients) or clients != sorted(set(clients)):
        return unavailable
    return {"source_status": "ok", "target": target, "observed_at": observed,
            "enrolled": value["enrolled"], "recovery_required": value["recovery_required"],
            "owned_clients": clients}
