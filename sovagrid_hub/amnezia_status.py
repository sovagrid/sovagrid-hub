# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Project only non-secret Amnezia protocol health into the Hub API."""

from __future__ import annotations


NAMES = frozenset({"amnezia-awg2", "amnezia-wireguard", "amnezia-xray"})
STATUSES = frozenset({"ready", "container_down", "identity_mismatch", "interface_down",
                      "registry_drift", "runtime_drift", "process_down", "error"})
BASE = frozenset({"name", "status", "configured_clients", "runtime_clients"})
WG_FIELDS = frozenset({"awg3_fields", "active_last_3m", "latest_handshake_at",
                       "received_bytes", "sent_bytes"})
XRAY_FIELDS = frozenset({"api_enabled", "stats_enabled"})


def _count(value: object, maximum: int = 2048) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError("Invalid Amnezia count")
    return value


def project_amnezia_details(snapshot: dict, outer_timestamp: int, now: int) -> dict:
    """Reject malformed/expanded schemas; never forward config, IDs or keys."""
    unavailable = {"schema_version": 1, "source_status": "unavailable", "services": []}
    source = snapshot.get("amnezia_details")
    if source is None:
        return unavailable
    try:
        if (not isinstance(source, dict) or set(source) !=
                {"schema_version", "collected_at", "source_status", "services"}
                or type(source["schema_version"]) is not int or source["schema_version"] != 1
                or type(source["collected_at"]) is not int
                or source["collected_at"] != outer_timestamp
                or source["source_status"] not in {"ok", "error"}
                or not isinstance(source["services"], list)):
            raise ValueError("Invalid Amnezia details")
        if source["source_status"] == "error":
            if source["services"]:
                raise ValueError("Invalid failed Amnezia details")
            return {"schema_version": 1, "source_status": "error", "services": []}
        if len(source["services"]) != len(NAMES):
            raise ValueError("Incomplete Amnezia details")
        output = []
        seen = set()
        for row in source["services"]:
            if not isinstance(row, dict):
                raise ValueError("Invalid Amnezia row")
            name, status = row.get("name"), row.get("status")
            if name not in NAMES or name in seen or status not in STATUSES:
                raise ValueError("Invalid Amnezia service")
            seen.add(name)
            allowed = BASE | (XRAY_FIELDS if name == "amnezia-xray" else WG_FIELDS)
            if not BASE.issubset(row) or not set(row).issubset(allowed):
                raise ValueError("Unexpected Amnezia field")
            configured, runtime = row["configured_clients"], row["runtime_clients"]
            if status in {"container_down", "identity_mismatch", "error"}:
                if configured is not None or runtime is not None or set(row) != BASE:
                    raise ValueError("Invalid unavailable Amnezia row")
            else:
                configured = _count(configured)
                if name == "amnezia-xray":
                    if runtime is not None or set(row) != BASE | XRAY_FIELDS:
                        raise ValueError("Invalid Xray row")
                    if type(row["api_enabled"]) is not bool or type(row["stats_enabled"]) is not bool:
                        raise ValueError("Invalid Xray flags")
                else:
                    runtime = _count(runtime)
                    if type(row.get("awg3_fields")) is not bool:
                        raise ValueError("Invalid AWG flags")
                    if status == "interface_down":
                        if set(row) != BASE | {"awg3_fields"} or runtime != 0:
                            raise ValueError("Invalid down interface")
                    else:
                        if set(row) != BASE | WG_FIELDS:
                            raise ValueError("Incomplete WG statistics")
                        active = _count(row["active_last_3m"])
                        if active > runtime:
                            raise ValueError("Invalid active count")
                        handshake = row["latest_handshake_at"]
                        if handshake is not None and (type(handshake) is not int or
                                                      not 0 <= handshake <= outer_timestamp + 300):
                            raise ValueError("Invalid handshake")
                        for field in ("received_bytes", "sent_bytes"):
                            _count(row[field], 2**64 - 1)
            output.append({field: row[field] for field in sorted(row)})
        if seen != NAMES:
            raise ValueError("Missing Amnezia service")
        status = "ok" if 0 <= now - outer_timestamp <= 90 else "stale"
        return {"schema_version": 1, "source_status": status, "services": output}
    except (TypeError, ValueError, KeyError):
        return {"schema_version": 1, "source_status": "error", "services": []}
