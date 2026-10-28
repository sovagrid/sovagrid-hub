# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Local-only panel routing through the managed root broker and CAS journal."""

from __future__ import annotations

from pathlib import Path

from .public_settings import (PANEL_PATH, PublicSettingsClient,
                              PublicSettingsExecutor, PublicSettingsError,
                              valid_hash, valid_id)


SCRIPT = Path("/opt/sovagrid-src/sovagrid-blueprint/deploy/local_web.py")
REQUESTS = Path("/var/lib/sovagrid/.local-web-requests")
URL = "http://127.0.0.1:8766"
HELPER_ERRORS = frozenset(("INVALID_REQUEST", "UNMANAGED", "SOURCE_UNTRUSTED",
                           "STATE_UNTRUSTED", "STATE_CHANGED", "PUBLIC_ACTIVE",
                           "COMMAND_FAILED", "LOCAL_UNHEALTHY", "ROLLBACK_FAILED",
                           "BUSY", "ROOT_REQUIRED"))


def validate_config(value: object) -> dict:
    if (not isinstance(value, dict) or set(value) != {"panel_path", "root_behavior"} or
            not isinstance(value["panel_path"], str) or len(value["panel_path"]) > 96 or
            PANEL_PATH.fullmatch(value["panel_path"]) is None or
            value["panel_path"].split("/")[1] in {"api", "healthz"} or
            value["root_behavior"] not in ("untouched", "panel", "redirect", "not_found")):
        raise PublicSettingsError("INVALID_REQUEST")
    return dict(value)


def validate_request(action: str, value: object) -> dict:
    if action == "status":
        if value != {}:
            raise PublicSettingsError("INVALID_REQUEST")
        return {}
    if not isinstance(value, dict):
        raise PublicSettingsError("INVALID_REQUEST")
    if action == "preview":
        if set(value) != {"config"}:
            raise PublicSettingsError("INVALID_REQUEST")
        return {"config": validate_config(value["config"])}
    if action == "apply":
        if (set(value) != {"config", "expected_state_sha256",
                           "source_manifest_sha256", "request_id"} or
                not valid_hash(value["expected_state_sha256"], nullable=True) or
                not valid_hash(value["source_manifest_sha256"]) or
                not valid_id(value["request_id"])):
            raise PublicSettingsError("INVALID_REQUEST")
        return {**value, "config": validate_config(value["config"])}
    if action == "disable":
        if (set(value) != {"expected_state_sha256", "request_id"} or
                not valid_hash(value["expected_state_sha256"], nullable=True) or
                not valid_id(value["request_id"])):
            raise PublicSettingsError("INVALID_REQUEST")
        return dict(value)
    raise PublicSettingsError("INVALID_REQUEST")


def validate_reply(action: str, value: object, *, config: dict | None = None,
                   source_sha: str | None = None) -> dict:
    if (not isinstance(value, dict) or value.get("protocol") != 1 or
            type(value.get("protocol")) is not int):
        raise PublicSettingsError("UNAVAILABLE")
    if value.get("ok") is False:
        error = value.get("error")
        if (set(value) != {"protocol", "ok", "error"} or not isinstance(error, dict) or
                set(error) != {"code", "message"} or
                not isinstance(error.get("code"), str) or error["code"] not in HELPER_ERRORS or
                not isinstance(error.get("message"), str) or len(error["message"]) > 256):
            raise PublicSettingsError("UNAVAILABLE")
        raise PublicSettingsError(error["code"])
    if value.get("ok") is not True:
        raise PublicSettingsError("UNAVAILABLE")
    if action == "disable":
        if (set(value) != {"protocol", "ok", "enabled", "changed", "expected_state_sha256"} or
                value["enabled"] is not False or type(value["changed"]) is not bool or
                value["expected_state_sha256"] is not None):
            raise PublicSettingsError("UNAVAILABLE")
        return value
    if action == "status":
        if (set(value) != {"protocol", "ok", "enabled", "config", "expected_state_sha256"} or
                type(value["enabled"]) is not bool or
                not valid_hash(value["expected_state_sha256"], nullable=True)):
            raise PublicSettingsError("UNAVAILABLE")
        if value["enabled"]:
            if value["expected_state_sha256"] is None:
                raise PublicSettingsError("UNAVAILABLE")
            try:
                validate_config(value["config"])
            except PublicSettingsError as exc:
                raise PublicSettingsError("UNAVAILABLE") from exc
        elif value["config"] is not None or value["expected_state_sha256"] is not None:
            raise PublicSettingsError("UNAVAILABLE")
        return value
    fields = {"protocol", "ok", "config", "expected_state_sha256",
              "source_manifest_sha256", "changed", "url", "certificate_verified"}
    if action == "apply":
        fields.add("enabled")
    if (set(value) != fields or value["config"] != config or
            not valid_hash(value["expected_state_sha256"], nullable=True) or
            not valid_hash(value["source_manifest_sha256"]) or
            type(value["changed"]) is not bool or value["url"] != URL or
            value["certificate_verified"] is not False):
        raise PublicSettingsError("UNAVAILABLE")
    if action == "apply" and (value["enabled"] is not True or
                              value["expected_state_sha256"] is None or
                              value["source_manifest_sha256"] != source_sha):
        raise PublicSettingsError("UNAVAILABLE")
    return value


class LocalSettingsExecutor(PublicSettingsExecutor):
    expected_script = SCRIPT
    helper_errors = HELPER_ERRORS

    def __init__(self, *, requests: Path = REQUESTS, uid: int = 0):
        super().__init__(script=SCRIPT, requests=requests, uid=uid)

    _validate_request = staticmethod(validate_request)
    _validate_reply = staticmethod(validate_reply)


class LocalSettingsClient(PublicSettingsClient):
    action_prefix = "local_"
    error_prefix = "LOCAL_"
    label = "Local Web"
    helper_errors = HELPER_ERRORS
    _validate_request = staticmethod(validate_request)
    _validate_reply = staticmethod(validate_reply)

    def _error_status(self, code: str) -> tuple[int, str]:
        if code == "INVALID_REQUEST":
            return 400, "Invalid local panel path or root behavior"
        if code == "PUBLIC_ACTIVE":
            return 409, "Public HTTPS is active; change the panel path in Public Web settings"
        if code in {"STATE_CHANGED", "KEY_REUSED", "BUSY", "REQUEST_LIMIT"}:
            return 409, "Local panel settings changed or cannot be applied"
        if code in {"UNCERTAIN", "ROLLBACK_FAILED"}:
            return 503, "Local Web result uncertain; refresh status"
        if code in self.helper_errors | {"UNAVAILABLE"}:
            return 503, "Local Web unavailable; refresh status"
        return 503, "Invalid Local Web broker reply"

    def disable(self, expected_state_sha256: str | None, request_id: str) -> dict:
        return self._request("disable", {"expected_state_sha256": expected_state_sha256,
                                         "request_id": request_id})
