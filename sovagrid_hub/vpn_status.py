# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Validate and project the host's two independent sanitized VPN sources."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import time
from pathlib import Path

from .amnezia_status import project_amnezia_details


SERVICE_LABELS = {
    "amnezia-awg": "AmneziaWG",
    "amnezia-awg2": "AmneziaWG (awg2)",
    "amnezia-wireguard": "WireGuard (Amnezia)",
    "amnezia-openvpn": "OpenVPN (Amnezia)",
    "amnezia-ipsec": "IPsec (Amnezia)",
    "amnezia-xray": "Xray (Amnezia)",
    "amnezia-dns": "DNS (Amnezia)",
    "amnezia-socks5proxy": "SOCKS5 (Amnezia)",
}
STATES = {"created", "restarting", "running", "removing", "paused", "exited", "dead",
          "absent", "unknown", "identity_mismatch"}
HEALTH = {"healthy", "unhealthy", "starting", "not_reported", "unknown"}
MANAGED_STATES = {"active", "stopped", "error"}
MANAGED_NAME = re.compile(r"[a-z][a-z0-9-]{1,31}\Z")
PRIVATE_NETWORKS = tuple(ipaddress.IPv4Network(value) for value in
                         ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))


def _freshness(timestamp: int, now: int) -> str:
    return "ok" if 0 <= now - timestamp <= 90 else "stale"


def _docker(snapshot: dict, timestamp: int, now: int) -> tuple[str, list[dict]]:
    try:
        if snapshot.get("source") != "docker_cli" or snapshot.get("source_status") not in {"ok", "error"}:
            raise ValueError("Invalid Docker source")
        if snapshot["source_status"] == "error":
            return "error", []
        items = snapshot.get("services")
        if not isinstance(items, list) or len(items) > len(SERVICE_LABELS):
            raise ValueError("Invalid service list")
        seen = set()
        services = []
        for item in items:
            if not isinstance(item, dict):
                raise ValueError("Invalid service")
            name = item.get("name")
            if name not in SERVICE_LABELS or name in seen or item.get("state") not in STATES or item.get("health") not in HEALTH:
                raise ValueError("Invalid service state")
            seen.add(name)
            raw_ports = item.get("published_ports")
            if not isinstance(raw_ports, list) or len(raw_ports) > 16:
                raise ValueError("Invalid ports")
            ports = []
            for port in raw_ports:
                if not isinstance(port, dict) or set(port) != {"port", "protocol"}:
                    raise ValueError("Invalid port")
                number = port["port"]
                if isinstance(number, bool) or not isinstance(number, int) or not 1 <= number <= 65535 or port["protocol"] not in {"tcp", "udp"}:
                    raise ValueError("Invalid port")
                ports.append({"port": number, "protocol": port["protocol"]})
            services.append({"name": name, "service": SERVICE_LABELS[name],
                             "state": item["state"], "health": item["health"],
                             "published_ports": ports})
        return _freshness(timestamp, now), services
    except (ValueError, TypeError, KeyError):
        return "error", []


def _managed(snapshot: dict, timestamp: int, now: int) -> dict:
    source = snapshot.get("managed")
    if source is None:
        return {"source_status": "unavailable", "instances": []}
    try:
        if not isinstance(source, dict) or source.get("source_status") not in {"ok", "error"}:
            raise ValueError("Invalid managed source")
        if source["source_status"] == "error":
            return {"source_status": "error", "instances": []}
        rows = source.get("instances")
        if not isinstance(rows, list) or len(rows) > 64:
            raise ValueError("Invalid managed instances")
        instances = []
        seen = set()
        for row in rows:
            if not isinstance(row, dict):
                raise ValueError("Invalid managed instance")
            name = row.get("name")
            if not isinstance(name, str) or not MANAGED_NAME.fullmatch(name) or name in seen:
                raise ValueError("Invalid managed name")
            seen.add(name)
            interface = "sg" + hashlib.sha256(name.encode("ascii")).hexdigest()[:11]
            if row.get("interface") != interface or row.get("state") not in MANAGED_STATES:
                raise ValueError("Invalid managed interface or state")
            port = row.get("port")
            subnet = row.get("subnet")
            client_count = row.get("client_count")
            if row["state"] == "error" and (port is None or subnet is None or client_count is None):
                if (port, subnet, client_count) != (None, None, None):
                    raise ValueError("Partial managed fields")
            else:
                if isinstance(port, bool) or not isinstance(port, int) or not 1024 <= port <= 65535:
                    raise ValueError("Invalid managed port")
                try:
                    network = ipaddress.IPv4Network(subnet, strict=True)
                except (ValueError, TypeError) as exc:
                    raise ValueError("Invalid managed subnet") from exc
                if (str(network) != subnet or not 24 <= network.prefixlen <= 30 or
                        not any(network.subnet_of(parent) for parent in PRIVATE_NETWORKS)):
                    raise ValueError("Invalid managed subnet")
                capacity = network.num_addresses - 3  # network, broadcast, server
                if (isinstance(client_count, bool) or not isinstance(client_count, int) or
                        not 0 <= client_count <= capacity):
                    raise ValueError("Invalid managed client count")
            instances.append({"name": name, "interface": interface,
                              "port": port, "subnet": subnet,
                              "client_count": client_count, "state": row["state"]})
        return {"source_status": _freshness(timestamp, now), "instances": instances}
    except (ValueError, TypeError, KeyError):
        return {"source_status": "error", "instances": []}


def read_vpn_status(path: str | Path, now: int | None = None) -> dict:
    """Return a fixed public schema; failure in one source leaves the other."""
    now = int(time.time()) if now is None else now
    empty = {"schema_version": 1, "collected_at": None, "source_status": "unavailable",
             "services": [], "managed": {"source_status": "unavailable", "instances": []},
             "amnezia_details": {"schema_version": 1, "source_status": "unavailable", "services": []}}
    try:
        with open(path, "rb") as stream:
            raw = stream.read(65537)
    except FileNotFoundError:
        return empty
    except OSError:
        return empty | {"source_status": "error", "managed": {"source_status": "error", "instances": []},
                        "amnezia_details": {"schema_version": 1, "source_status": "error", "services": []}}
    try:
        if len(raw) > 65536:
            raise ValueError("Oversized snapshot")
        snapshot = json.loads(raw)
        if not isinstance(snapshot, dict) or snapshot.get("schema_version") != 1:
            raise ValueError("Invalid snapshot header")
        timestamp = snapshot.get("collected_at")
        if isinstance(timestamp, bool) or not isinstance(timestamp, int):
            raise ValueError("Invalid timestamp")
        docker_status, services = _docker(snapshot, timestamp, now)
        return {"schema_version": 1, "collected_at": timestamp,
                "source_status": docker_status, "services": services,
                "managed": _managed(snapshot, timestamp, now),
                "amnezia_details": project_amnezia_details(snapshot, timestamp, now)}
    except (ValueError, TypeError, KeyError):
        return empty | {"source_status": "error", "managed": {"source_status": "error", "instances": []},
                        "amnezia_details": {"schema_version": 1, "source_status": "error", "services": []}}
