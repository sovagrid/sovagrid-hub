# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Validate managed WireGuard requests and build a fixed broker invocation.

The Hub never accepts raw commands, executable paths, or arbitrary CLI flags.
Only this small schema can reach the local sovagrid-vpn-ctl broker client.
"""

from __future__ import annotations

import ipaddress
import base64
import re
import shlex


HELPER = "/usr/local/bin/sovagrid-vpn-ctl"
_NAME = re.compile(r"[a-z][a-z0-9-]{1,31}\Z")
_CLIENT = re.compile(r"[a-z][a-z0-9_-]{0,31}\Z")
_PUBLIC_KEY = re.compile(r"[A-Za-z0-9_-]{87}\Z")
_DNS_LABEL = re.compile(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\Z")
_PRIVATE = tuple(ipaddress.IPv4Network(cidr) for cidr in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
))
_FIELDS = {
    "create": frozenset(("action", "name", "port", "subnet", "endpoint")),
    "activate": frozenset(("action", "name")),
    "add-client": frozenset(("action", "name", "client")),
    "revoke-client": frozenset(("action", "name", "client")),
    "sealed-export": frozenset(("action", "name", "client", "public_key")),
    "remove": frozenset(("action", "name", "confirm_name")),
}


def build_vpn_command(data: object) -> str:
    """Serialize the fixed broker argv in the job queue's command field."""
    if not isinstance(data, dict):
        raise ValueError("Expected VPN action object")
    action = data.get("action")
    if not isinstance(action, str) or action not in _FIELDS:
        raise ValueError("Unsupported VPN action")
    fields = set(data)
    if fields != _FIELDS[action] and not (
            action == "sealed-export" and fields == _FIELDS[action] | {"route"}):
        raise ValueError("Unexpected or missing VPN action fields")
    name = data["name"]
    if not isinstance(name, str) or not _NAME.fullmatch(name):
        raise ValueError("Invalid VPN instance name")

    argv = [HELPER, action, name]
    if action == "create":
        port = data["port"]
        if isinstance(port, bool) or not isinstance(port, int) or not 1024 <= port <= 65535:
            raise ValueError("VPN port must be an integer between 1024 and 65535")
        subnet = data["subnet"]
        if not isinstance(subnet, str):
            raise ValueError("VPN subnet must be a canonical private IPv4 CIDR")
        try:
            network = ipaddress.IPv4Network(subnet, strict=True)
        except ValueError as exc:
            raise ValueError("VPN subnet must be a canonical private IPv4 CIDR") from exc
        if (str(network) != subnet or not 24 <= network.prefixlen <= 30
                or not any(network.subnet_of(parent) for parent in _PRIVATE)):
            raise ValueError("VPN subnet must be a canonical private IPv4 /24–/30")
        endpoint = data["endpoint"]
        if not isinstance(endpoint, str) or not endpoint or len(endpoint) > 253:
            raise ValueError("VPN endpoint must be an IPv4 address or DNS name")
        try:
            address = ipaddress.IPv4Address(endpoint)
            if str(address) != endpoint:
                raise ValueError("VPN endpoint must be a canonical IPv4 address")
            endpoint = str(address)
        except ipaddress.AddressValueError:
            if "." not in endpoint or not all(_DNS_LABEL.fullmatch(part) for part in endpoint.split(".")):
                raise ValueError("VPN endpoint must be an IPv4 address or DNS name")
            endpoint = endpoint.lower()
        argv.extend(("--port", str(port), "--subnet", subnet, "--endpoint", endpoint))
    elif action in ("add-client", "revoke-client", "sealed-export"):
        client = data["client"]
        if not isinstance(client, str) or not _CLIENT.fullmatch(client):
            raise ValueError("Invalid VPN client name")
        argv.append(client)
        if action == "sealed-export":
            public_key = data["public_key"]
            if not isinstance(public_key, str) or not _PUBLIC_KEY.fullmatch(public_key):
                raise ValueError("Invalid encryption public key")
            try:
                raw_key = base64.urlsafe_b64decode(public_key + "=")
            except (ValueError, base64.binascii.Error) as exc:
                raise ValueError("Invalid encryption public key") from exc
            if (len(raw_key) != 65 or raw_key[0] != 4
                    or base64.urlsafe_b64encode(raw_key).decode("ascii").rstrip("=") != public_key):
                raise ValueError("Invalid encryption public key")
            argv.append(public_key)
            route = data.get("route", "split")
            if route not in ("split", "full") or not isinstance(route, str):
                raise ValueError("Invalid VPN client route")
            if route == "full":
                argv.extend(("--route", "full"))
    elif action == "remove":
        if data["confirm_name"] != name:
            raise ValueError("VPN removal requires matching confirm_name")
        argv.extend(("--confirm-name", name))

    # The Agent recognizes this canonical form, parses it, and sends a fixed
    # JSON request from its MainPID. No shell or CLI child runs for this marker.
    return shlex.join(argv)


def is_vpn_command(command: str) -> bool:
    """Recognize only the canonical broker commands emitted above.

    The job store uses this to grant enough runtime to a managed VPN change.
    Arbitrary web and Telegram commands retain their shorter timeout.
    """
    try:
        argv = shlex.split(command)
        if len(argv) < 3 or argv[0] != HELPER:
            return False
        action, name = argv[1:3]
        if action == "create" and len(argv) == 9 and argv[3::2] == ["--port", "--subnet", "--endpoint"]:
            data = {"action": action, "name": name, "port": int(argv[4]),
                    "subnet": argv[6], "endpoint": argv[8]}
        elif action == "activate" and len(argv) == 3:
            data = {"action": action, "name": name}
        elif action in ("add-client", "revoke-client") and len(argv) == 4:
            data = {"action": action, "name": name, "client": argv[3]}
        elif action == "sealed-export" and len(argv) in (5, 7):
            data = {"action": action, "name": name, "client": argv[3], "public_key": argv[4]}
            if len(argv) == 7:
                if argv[5:] != ["--route", "full"]:
                    return False
                data["route"] = "full"
        elif action == "remove" and len(argv) == 5 and argv[3] == "--confirm-name":
            data = {"action": action, "name": name, "confirm_name": argv[4]}
        else:
            return False
        return build_vpn_command(data) == command
    except (TypeError, ValueError):
        return False
