# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Bounded metadata contract for the separate external Agent root updater."""

from __future__ import annotations

import re
import uuid


SHA = re.compile(r"[0-9a-f]{64}\Z")
SCRIPT = "/opt/sovagrid-src/sovagrid-blueprint/deploy/external_agent_update.py"
FIELDS = {
    "external_status": (),
    "external_preview": ("archive_sha256", "current_hub_manifest_sha256"),
    "external_preflight": ("archive_sha256", "current_hub_manifest_sha256"),
    "external_apply": ("request_id", "archive_sha256", "current_hub_manifest_sha256",
                       "external_agent_manifest_sha256", "review_sha256"),
    "external_operation_status": ("request_id",),
    "external_operation_list": (),
}
FUTURE_METADATA = ["/var/lib/sovagrid-agent-enrollment/state.json",
                   "/var/lib/sovagrid-promotion/baseline.json"]
METADATA = ["/opt/sovagrid-agent-installer/source-manifest.json", *FUTURE_METADATA]
LIVE_GATES = ["ORIGINAL_HUB_AGENT_UPDATE_LEASE", "AGENT_IDLE_ACK", "TRIAL_FD_WATCHDOG"]


def valid_sha(value: object) -> bool:
    return isinstance(value, str) and SHA.fullmatch(value) is not None


def valid_request(value: object) -> bool:
    if (not isinstance(value, dict) or not isinstance(value.get("action"), str) or
            value["action"] not in FIELDS):
        return False
    if set(value) != {"action", *FIELDS[value["action"]]}:
        return False
    for name in FIELDS[value["action"]]:
        if name == "request_id":
            try:
                if not isinstance(value[name], str) or str(uuid.UUID(value[name])) != value[name]:
                    return False
            except (ValueError, TypeError):
                return False
        elif not valid_sha(value[name]):
            return False
    return True


def _changes(value: object) -> bool:
    if not isinstance(value, list) or not 0 < len(value) <= 256:
        return False
    for item in value:
        if not isinstance(item, dict) or set(item) != {"path", "operation"}:
            return False
        path = item["path"]
        if (not isinstance(path, str) or len(path) > 240 or
                re.fullmatch(r"/[a-zA-Z0-9_./-]+", path) is None or
                "//" in path or "/../" in path or path.endswith("/..") or
                not (path.startswith("/opt/sovagrid-agent/") or path in (
                    "/opt/sovagrid-agent-installer/source-manifest.json",
                    "/etc/systemd/system/sovagrid-agent.service")) or
                item["operation"] not in ("create", "remove", "replace")):
            return False
    return True


def valid_result(action: str, value: object) -> bool:
    if (action not in ("external_status", "external_preview", "external_preflight",
                       "external_apply") or not isinstance(value, dict) or
            value.get("protocol") != 1 or type(value["protocol"]) is not int):
        return False
    if action == "external_status":
        return (set(value) == {"protocol", "hub_only", "current_hub_manifest_sha256",
                               "external_agent_manifest_sha256", "idle_endpoint_present",
                               "live_idle_ack_verified"} and
                type(value["hub_only"]) is bool and
                valid_sha(value["current_hub_manifest_sha256"]) and
                (valid_sha(value["external_agent_manifest_sha256"]) if value["hub_only"]
                 else value["external_agent_manifest_sha256"] is None) and
                type(value["idle_endpoint_present"]) is bool and
                (value["hub_only"] or value["idle_endpoint_present"] is False) and
                value["live_idle_ack_verified"] is False)
    if action == "external_apply":
        return (set(value) == {"protocol", "applied", "external_agent_manifest_sha256",
                               "review_sha256"} and value["applied"] is True and
                valid_sha(value["external_agent_manifest_sha256"]) and
                valid_sha(value["review_sha256"]))
    base = {"protocol", "current_hub_manifest_sha256", "candidate_manifest_sha256",
            "external_agent_manifest_sha256", "external_agent_preserved", "tunnel_active",
            "source_paths_to_change", "future_metadata_paths", "original_hub_compatibility",
            "apply_supported", "apply_blockers", "explicit_review_required"}
    preflight = {"candidate_agent_file_count", "archive_sha256", "baseline_sha256",
                 "enrollment_sha256", "review_sha256", "metadata_paths_to_change",
                 "live_gates_pending"}
    if set(value) != (base | preflight if action == "external_preflight" else base):
        return False
    if not (all(valid_sha(value[name]) for name in (
            "current_hub_manifest_sha256", "candidate_manifest_sha256",
            "external_agent_manifest_sha256")) and
            value["candidate_manifest_sha256"] == value["current_hub_manifest_sha256"] and
            value["external_agent_preserved"] is True and value["tunnel_active"] is True and
            _changes(value["source_paths_to_change"]) and
            value["future_metadata_paths"] == FUTURE_METADATA and
            value["original_hub_compatibility"] == "verified_same_bundle" and
            type(value["apply_supported"]) is bool and
            value["explicit_review_required"] is True):
        return False
    if action == "external_preview":
        return value["apply_blockers"] == (["EXTERNAL_AGENT_PREFLIGHT_REQUIRED"]
                if value["apply_supported"] else ["TRIAL_CAPABILITY_MISSING"])
    return (value["apply_supported"] is True and value["apply_blockers"] == [] and
            type(value["candidate_agent_file_count"]) is int and
            0 < value["candidate_agent_file_count"] <= 256 and
            all(valid_sha(value[name]) for name in (
                "archive_sha256", "baseline_sha256", "enrollment_sha256", "review_sha256")) and
            value["metadata_paths_to_change"] == METADATA and
            value["live_gates_pending"] == LIVE_GATES)
