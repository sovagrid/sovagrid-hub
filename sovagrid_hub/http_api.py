# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Loopback-only JSON API for SovaGrid Hub."""

from __future__ import annotations

import json
import hashlib
import ipaddress
import logging
import os
import re
import secrets
import socket
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from .auth import AuthenticationError, AuthorizationError, UserConflict, ROLES
from .checks import CheckError
from .enrollment import EnrollmentError
from .store import (AmneziaControlUnavailable, IdempotencyConflict, InodeSettingsConflict, InvalidMetric,
                    JournalRateLimited,
                    MaintenanceConflict, MonitoringSettingsConflict, PressureSettingsConflict,
                    ServiceControlUnavailable, ContainerControlUnavailable, Store)
from .agent_maintenance import MaintenanceLeaseBusy, MaintenanceLeaseInvalid
from .terminal import TerminalError, TerminalRegistry, dimension
from .files import FileRelayError, FileRegistry, MAX_FILE_BODY, path_digest
from .vpn_actions import build_vpn_command
from .amnezia_actions import TARGETS as AMNEZIA_TARGETS, build_amnezia_command, control_status
from .service_actions import (build_service_command,
                              control_status as service_control_status,
                              protected_mutation_unit as protected_service_mutation_unit,
                              status_command as service_status_command)
from .journal_actions import build_journal_command
from .process_actions import build_process_command, request_parameters as process_request_parameters
from .container_log_actions import build_command as build_container_log_command
from .container_actions import (build_command as build_container_action_command,
                                control_status as container_control_status)
from .container_alerts import ContainerAlertConflict, ContainerAlertInventoryUnavailable
from .filesystem_alerts import FilesystemAlertConflict, FilesystemAlertInventoryUnavailable
from .vpn_status import read_vpn_status
from .telegram_runtime import TelegramActivationError, TelegramModeError, TelegramStorageError
from .server_acl import AccessConflict
from .backup_client import (BackupBrokerClient, BackupClientError, HostBackupBrokerClient,
                            ReleaseFeedBrokerClient, ExternalAgentUpdateBrokerClient,
                            HOST_ID, HOST_SHA, canonical_id as backup_id)
from .external_agent_operations import canonical_id as external_operation_id
from .public_settings import (PublicSettingsClient, PublicSettingsClientError,
                              PublicSettingsError, PANEL_PATH, valid_hash as public_hash,
                              valid_id as public_id, validate_config as public_config)
from .local_settings import (LocalSettingsClient, validate_config as local_config)

MAX_BODY = 16384
READ_TIMEOUT_SECONDS = 10
DEFAULT_PANEL_PATH = "/sovagrid/monitoring/"
BUNDLE_MANIFEST_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class HubApp:
    def __init__(self, store: Store, telegram=None, trusted_proxies: set[str] | None = None,
                 vpn_status_path: str = "/vpn/status.json", backups=None, host_backups=None,
                 public_web=None, local_web=None, release_feed=None,
                 external_agent_update=None):
        self.store = store
        # The image build pins this public digest. A missing or malformed pin
        # must never be reported as a compatible running Hub.
        manifest_digest = os.environ.get("SOVAGRID_BUNDLE_MANIFEST_SHA256", "")
        self.bundle_manifest_sha256 = (manifest_digest if BUNDLE_MANIFEST_SHA256.fullmatch(manifest_digest)
                                       else None)
        self.telegram = telegram
        self.trusted_proxies = {"127.0.0.1", "::1"} | (trusted_proxies or set())
        self.vpn_status_path = vpn_status_path
        self.terminals = TerminalRegistry()
        self.files = FileRegistry()
        # Serialize a lease grant with in-memory relay creation and disclosure.
        # SQLite separately serializes all command queue operations.
        self.agent_maintenance_lock = threading.Lock()
        self.agent_maintenance_epoch = secrets.token_hex(16)
        self.backups = BackupBrokerClient() if backups is None else backups
        self.host_backups = HostBackupBrokerClient() if host_backups is None else host_backups
        self.release_feed = ReleaseFeedBrokerClient() if release_feed is None else release_feed
        self.external_agent_update = (ExternalAgentUpdateBrokerClient() if external_agent_update is None
                                      else external_agent_update)
        self.public_web = PublicSettingsClient() if public_web is None else public_web
        self.local_web = LocalSettingsClient() if local_web is None else local_web
        self.backup_lock = threading.Lock()
        self.host_backup_lock = threading.Lock()
        self.release_feed_lock = threading.Lock()
        self.external_agent_update_lock = threading.Lock()
        self.public_web_lock = threading.Lock()
        self.local_web_lock = threading.Lock()
        self._panel_location_lock = threading.Lock()
        self._panel_location_path: str | None = None
        self._panel_location_refreshing = False
        self._panel_location_next_refresh = 0.0
        self._panel_location_generation = 0
        self.login_lock = threading.Lock()
        self.login_attempts: dict[str, tuple[int, float, float]] = {}
        self.ssh_grant_attempts: dict[str, tuple[int, float, float]] = {}
        self.password_attempts: dict[str, tuple[int, float, float]] = {}

    def _set_panel_location(self, path: str, *, generation: int | None = None) -> None:
        # Status and apply results already cross a strict broker schema. Check
        # the one public value again before publishing it without auth.
        if (not isinstance(path, str) or len(path) > 96 or
                PANEL_PATH.fullmatch(path) is None or
                path.split("/")[1] in {"api", "healthz"}):
            return
        with self._panel_location_lock:
            if generation is not None and generation != self._panel_location_generation:
                return
            if generation is None:
                self._panel_location_generation += 1
            self._panel_location_path = path
            self._panel_location_next_refresh = time.monotonic() + 5

    def _refresh_panel_location(self) -> None:
        delay = 5
        with self._panel_location_lock:
            generation = self._panel_location_generation
        try:
            public = self.public_web.status()
            local = self.local_web.status()
            if public["enabled"] and local["enabled"]:
                # Two managed overlays must never be active together. Do not
                # conceal a damaged host by choosing one arbitrary route.
                with self._panel_location_lock:
                    if generation == self._panel_location_generation:
                        self._panel_location_path = None
                delay = 5
            elif public["enabled"]:
                path = public_config(public["config"])["panel_path"]
                self._set_panel_location(path, generation=generation)
            else:
                path = (local_config(local["config"])["panel_path"] if local["enabled"]
                        else DEFAULT_PANEL_PATH)
                self._set_panel_location(path, generation=generation)
            if not (public["enabled"] and local["enabled"]):
                delay = 5
        except Exception:
            # Discovery reveals only a validated relative path. Any broker or
            # reply failure must invalidate an older advertised route.
            with self._panel_location_lock:
                if generation == self._panel_location_generation:
                    self._panel_location_path = None
        finally:
            with self._panel_location_lock:
                self._panel_location_refreshing = False
                if generation == self._panel_location_generation:
                    self._panel_location_next_refresh = time.monotonic() + delay
                elif self._panel_location_path is None:
                    self._panel_location_next_refresh = time.monotonic()

    def _start_panel_location_refresh(self, *, invalidate: bool = False) -> None:
        with self._panel_location_lock:
            if invalidate:
                self._panel_location_path = None
                self._panel_location_generation += 1
            if self._panel_location_refreshing:
                return
            self._panel_location_refreshing = True
        threading.Thread(target=self._refresh_panel_location, daemon=True).start()

    def _invalidate_panel_location(self) -> None:
        # Do not queue a status request ahead of the pending root apply.
        with self._panel_location_lock:
            self._panel_location_path = None
            self._panel_location_generation += 1
            self._panel_location_next_refresh = time.monotonic() + 660

    def panel_location(self) -> str | None:
        with self._panel_location_lock:
            path = self._panel_location_path
            refresh = (not self._panel_location_refreshing and
                       time.monotonic() >= self._panel_location_next_refresh)
        if refresh:
            self._start_panel_location_refresh(invalidate=True)
            return None
        return path

    def login(self, username: str, password: str, source_ip: str = "127.0.0.1"):
        with self.login_lock:
            now = time.monotonic()
            # Bound memory even if clients use many IP addresses.
            if len(self.login_attempts) > 4096:
                self.login_attempts = {ip: item for ip, item in self.login_attempts.items()
                                       if now - item[2] < 300}
                if len(self.login_attempts) > 4096:
                    oldest = min(self.login_attempts, key=lambda ip: self.login_attempts[ip][2])
                    self.login_attempts.pop(oldest, None)
            count, blocked_until, _ = self.login_attempts.get(source_ip, (0, 0.0, now))
            if now < blocked_until:
                return "rate_limited", None
            if now >= blocked_until and blocked_until:
                count = 0
            result = self.store.login(username, password)
            if result is None:
                count += 1
                self.login_attempts[source_ip] = (count, now + 30 if count >= 5 else 0.0, now)
                return "invalid", None
            self.login_attempts.pop(source_ip, None)
            return "ok", result

    def redeem_ssh_grant(self, grant: object, source_ip: str):
        with self.login_lock:
            now = time.monotonic()
            if len(self.ssh_grant_attempts) > 4096:
                self.ssh_grant_attempts = {ip: item for ip, item in self.ssh_grant_attempts.items()
                                           if now - item[2] < 300}
                while len(self.ssh_grant_attempts) > 4096:
                    oldest = min(self.ssh_grant_attempts, key=lambda ip: self.ssh_grant_attempts[ip][2])
                    self.ssh_grant_attempts.pop(oldest, None)
            count, blocked_until, _ = self.ssh_grant_attempts.get(source_ip, (0, 0.0, now))
            if now < blocked_until:
                return "rate_limited", None
            if now >= blocked_until and blocked_until:
                count = 0
            result = self.store.redeem_ssh_grant(grant)
            if result is None:
                count += 1
                self.ssh_grant_attempts[source_ip] = (count, now + 30 if count >= 5 else 0.0, now)
                return "invalid", None
            self.ssh_grant_attempts.pop(source_ip, None)
            return "ok", result

    def change_password(self, session_token: str, old_password: str, new_password: str,
                        source_ip: str) -> str:
        session_key = "session:" + hashlib.sha256(session_token.encode()).hexdigest()
        ip_key = "ip:" + source_ip
        with self.login_lock:
            now = time.monotonic()
            if len(self.password_attempts) > 8190:
                self.password_attempts = {key: item for key, item in self.password_attempts.items()
                                          if now - item[2] < 300}
                while len(self.password_attempts) > 8190:
                    oldest = min(self.password_attempts, key=lambda key: self.password_attempts[key][2])
                    self.password_attempts.pop(oldest, None)
            for key in (session_key, ip_key):
                count, blocked_until, _ = self.password_attempts.get(key, (0, 0.0, now))
                if now < blocked_until:
                    return "rate_limited"
            # Recheck inside the lock, since another password-change request may
            # have revoked this session after the handler authenticated it.
            if not self.store.session_valid(session_token):
                return "unauthorized"
            changed = self.store.change_session_password(session_token, old_password, new_password)
            if changed is not None:
                self.password_attempts.pop(session_key, None)
                self.password_attempts.pop(ip_key, None)
                self.close_revoked(changed)
                return "changed"
            for key in (session_key, ip_key):
                count, blocked_until, _ = self.password_attempts.get(key, (0, 0.0, now))
                if now >= blocked_until and blocked_until:
                    count = 0
                count += 1
                self.password_attempts[key] = (count, now + 30 if count >= 5 else 0.0, now)
            return "invalid"

    def close_revoked(self, result: dict) -> dict:
        # Private session hashes are never part of an HTTP response.
        for owner in result.pop("_revoked_hashes", []):
            self.terminals.close_owner(owner)
            self.files.close_owner(owner)
        return result

    def emit(self, events: list[dict]):
        if self.telegram and events:
            self.telegram.enqueue(events)

    def emit_job_result(self, job: dict):
        if self.telegram and job.get("just_completed") and job.get("source") == "telegram":
            self.telegram.enqueue_job_result(job)


class HubHandler(BaseHTTPRequestHandler):
    app: HubApp
    server_version = "SovaGridHub/0.1"
    sys_version = ""

    def setup(self):
        self.request.settimeout(READ_TIMEOUT_SECONDS)
        super().setup()

    def log_message(self, format, *args):
        logging.info("HTTP %s", format % args)

    def _send(self, status: int, payload: dict):
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _error(self, status: int, message: str):
        self._send(status, {"error": message})

    def _body(self, max_size: int = MAX_BODY, *, reject_duplicate_keys: bool = False):
        if self.headers.get_content_type() != "application/json":
            self._error(415, "Content-Type must be application/json")
            return None
        try:
            size = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            size = -1
        if size < 0 or size > max_size:
            self._error(413, "Invalid or oversized request body")
            return None
        try:
            deadline = time.monotonic() + READ_TIMEOUT_SECONDS
            body = bytearray()
            while len(body) < size:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise socket.timeout()
                self.connection.settimeout(remaining)
                chunk = self.rfile.read1(min(size - len(body), 4096))
                if not chunk:
                    self._error(400, "Incomplete request body")
                    self.close_connection = True
                    return None
                body.extend(chunk)
            self.connection.settimeout(READ_TIMEOUT_SECONDS)
            def unique_object(pairs):
                result = {}
                for key, value in pairs:
                    if key in result:
                        raise ValueError("Duplicate JSON field")
                    result[key] = value
                return result
            payload = json.loads(body, object_pairs_hook=unique_object if reject_duplicate_keys else None)
            # A client can send headers, wait while its bearer token is
            # revoked, then finish the body. Authorization at route entry is
            # not enough for POST endpoints with side effects.
            body_auth = getattr(self, "_body_auth", None)
            if body_auth is not None:
                kind, server_id = body_auth
                if kind == "agent":
                    if not self.app.store.agent_valid(server_id, self._token()):
                        self._error(401, "Unauthorized")
                        return None
                elif not self._authenticated(kind):
                    return None
            return payload
        except (socket.timeout, TimeoutError):
            self.close_connection = True
            self.connection.settimeout(READ_TIMEOUT_SECONDS)
            self._error(408, "Request body timeout")
            return None
        except (UnicodeDecodeError, ValueError):
            self._error(400, "Invalid JSON")
            return None

    def _source_ip(self) -> str:
        # Only the loopback reverse proxy may supply this header. The bundled
        # Caddy configuration overwrites any value sent by a remote client.
        peer = self.client_address[0]
        if peer in self.app.trusted_proxies:
            forwarded = self.headers.get("X-SovaGrid-Client-IP", "")
            try:
                return str(ipaddress.ip_address(forwarded))
            except ValueError:
                pass
        return peer

    def _token(self) -> str:
        value = self.headers.get("Authorization", "")
        return value[7:] if value.startswith("Bearer ") else ""

    def _authenticated(self, role: str = "admin") -> bool:
        info = self.app.store.session_info(self._token())
        if info is None:
            self._error(401, "Unauthorized")
            return False
        if ROLES[info["user"]["role"]] < ROLES[role]:
            self._error(403, "Insufficient role")
            return False
        path = urlsplit(self.path).path
        match = re.match(r"/api/v1/servers/([^/]+)(?:/|$)", path)
        if match and not self.app.store.server_access_allowed(self._token(), match.group(1), role):
            valid = self.app.store.session_valid(self._token())
            self._error(403 if valid else 401, "Server access denied" if valid else "Unauthorized")
            return False
        global_admin = (path.startswith(("/api/v1/users", "/api/v1/telegram", "/api/v1/backups",
                                         "/api/v1/host-backups",
                                         "/api/v1/release-feed",
                                         "/api/v1/external-agent-update",
                                         "/api/v1/public-web",
                                         "/api/v1/local-web",
                                         "/api/v1/agent-enrollments")) or
                        (path == "/api/v1/servers" and self.command == "POST") or
                        (path in ("/api/v1/monitoring/settings",
                                  "/api/v1/monitoring/pressure-settings",
                                  "/api/v1/monitoring/inode-settings") and self.command != "GET"))
        if global_admin and not self.app.store.unrestricted_admin(self._token()):
            valid = self.app.store.session_valid(self._token())
            self._error(403 if valid else 401,
                        "Unrestricted administrator required" if valid else "Unauthorized")
            return False
        if path == "/api/v1/vpn" and not self.app.store.session_unrestricted(self._token()):
            self._error(403, "Server access denied")
            return False
        self._identity = info["user"]
        self._body_auth = (role, None)
        return True

    def _admin(self) -> bool:
        return self._authenticated("admin")

    def _public_web_origin_ok(self) -> bool:
        """Bearer auth is primary; reject a browser request from another origin."""
        origin = self.headers.get("Origin")
        if origin is None:
            return True  # Native clients and CLI requests do not set Origin.
        host = self.headers.get("Host", "")
        proto = (self.headers.get("X-Forwarded-Proto", "http")
                 if self.client_address[0] in self.app.trusted_proxies else "http")
        if proto not in ("http", "https") or not host or origin != proto + "://" + host:
            self._error(403, "Cross-origin request denied")
            return False
        return True

    def _dispatch(self, name):
        try:
            getattr(self, "_" + name)()
        except AuthenticationError:
            self._error(401, "Unauthorized")
        except AuthorizationError:
            self._error(403, "Insufficient role")
        except UserConflict as exc:
            self._error(409, str(exc))
        except AccessConflict as exc:
            self._error(409, str(exc))
        except (CheckError, EnrollmentError) as exc:
            self._error(exc.status, str(exc))

    def do_GET(self):
        self._dispatch("get")

    def do_POST(self):
        self._dispatch("post")

    def do_PUT(self):
        self._dispatch("put")

    def do_DELETE(self):
        self._dispatch("delete")

    def do_PATCH(self):
        self._dispatch("patch")

    def _terminal_owner(self) -> str:
        return hashlib.sha256(self._token().encode()).hexdigest()

    @staticmethod
    def _terminal_after(url) -> int:
        args = parse_qs(url.query, keep_blank_values=True)
        value = args.get("after", ["0"])
        if set(args) - {"after"} or len(value) != 1 or not value[0].isascii() or not value[0].isdecimal():
            raise TerminalError(400, "Invalid terminal cursor")
        after = int(value[0])
        if after > 1_000_000_000:
            raise TerminalError(400, "Invalid terminal cursor")
        return after

    def _terminal_allowed(self, owner_hash: str, server_id: str) -> bool:
        return self.app.store.terminal_access_valid(owner_hash, server_id)

    def _enrollment_get(self, url):
        match = re.fullmatch(r"/api/v1/agent-enrollments/([^/]+)", url.path)
        if match is None:
            return False
        if not self._admin():
            return True
        try:
            if url.query:
                raise ValueError("Unexpected enrollment query parameters")
            result = self.app.store.agent_enrollment(match.group(1), session_token=self._token())
        except ValueError as exc:
            self._error(400, str(exc))
            return True
        self._send(200, {"protocol": 1, "enrollment": result})
        return True

    def _enrollment_post(self, path):
        match = re.fullmatch(r"/api/v1/agent-enrollments/([^/]+)(/cancel)?", path)
        if match is None:
            return False
        if not self._admin():
            return True
        if urlsplit(self.path).query:
            self._error(400, "Unexpected enrollment query parameters")
            return True
        payload = self._body(4096, reject_duplicate_keys=True)
        if payload is None:
            return True
        try:
            if match.group(2):
                result = self.app.store.cancel_agent_enrollment(match.group(1), payload, session_token=self._token())
                status = 200
            else:
                result, created = self.app.store.register_agent_enrollment(match.group(1), payload, session_token=self._token())
                status = 201 if created else 200
        except ValueError as exc:
            self._error(400, str(exc))
            return True
        self._send(status, {"protocol": 1, "enrollment": result})
        return True

    def _agent_management_get(self, url):
        match = re.fullmatch(r"/api/v1/servers/([^/]+)/agent-management", url.path)
        if match is None and url.path != "/api/v1/agent-management":
            return False
        if not self._admin():
            return True
        try:
            if url.query:
                raise ValueError("Unexpected Agent management query parameters")
            result = (self.app.store.agent_management(match.group(1), session_token=self._token()) if match
                      else self.app.store.agent_management_servers(session_token=self._token()))
        except ValueError as exc:
            self._error(400, str(exc))
            return True
        self._send(200, result)
        return True

    def _agent_management_post(self, path):
        match = re.fullmatch(r"/api/v1/servers/([^/]+)/agent-management", path)
        if match is None:
            return False
        if not self._admin():
            return True
        if urlsplit(self.path).query:
            self._error(400, "Unexpected Agent management query parameters")
            return True
        payload = self._body(4096, reject_duplicate_keys=True)
        if payload is None:
            return True
        try:
            result = self.app.store.save_agent_management(match.group(1), payload, session_token=self._token())
        except ValueError as exc:
            self._error(400, str(exc))
            return True
        if not result["enabled"]:
            self.app.terminals.close_server(result["server_id"], "permission_revoked")
            self.app.files.close_server(result["server_id"])
        self._send(200, result)
        return True

    def _checks_get(self, url):
        match = re.fullmatch(r"/api/v1/servers/([^/]+)/checks(?:/(config)|/([^/]+)/history)?", url.path)
        if match is None:
            return False
        server_id, config, check_id = match.groups()
        if not self._authenticated("admin" if config else "viewer"):
            return True
        try:
            if check_id is not None:
                query = parse_qs(url.query, keep_blank_values=True)
                values = query.get("limit", ["60"])
                if (set(query) - {"limit"} or len(values) != 1 or not values[0].isascii()
                        or not values[0].isdecimal() or len(values[0]) > 2):
                    raise ValueError("Check history limit must be between 1 and 60")
                result = self.app.store.check_history(server_id, check_id, int(values[0]), session_token=self._token())
            else:
                if url.query:
                    raise ValueError("Unexpected check query parameters")
                result = (self.app.store.check_config(server_id, session_token=self._token()) if config else
                          self.app.store.checks_summary(server_id, session_token=self._token()))
        except ValueError as exc:
            self._error(400, str(exc))
            return True
        self._send(200, result)
        return True

    def _checks_post(self, path):
        match = re.fullmatch(r"/api/v1/servers/([^/]+)/checks/(config|claim|([^/]+)/(run|result))", path)
        if match is None:
            return False
        server_id, route, check_id, action = match.groups()
        agent = route == "claim" or action == "result"
        if agent:
            if not self.app.store.agent_valid(server_id, self._token()):
                self._error(401, "Unauthorized")
                return True
            self._body_auth = ("agent", server_id)
        elif not self._admin():
            return True
        data = self._body(32768 if route == "config" else 4096)
        if data is None:
            return True
        try:
            if route == "config":
                result = self.app.store.save_check_config(server_id, data, session_token=self._token())
            elif route == "claim":
                result = self.app.store.claim_check(server_id, self._token(), data)
            elif action == "run":
                result = self.app.store.run_check(server_id, check_id, data, session_token=self._token())
            else:
                result = self.app.store.record_check_result(server_id, check_id, self._token(), data)
        except ValueError as exc:
            self._error(400, str(exc))
            return True
        self._send(200, result)
        return True

    def _get(self):
        url = urlsplit(self.path)
        if url.path == "/healthz":
            self._send(200, {"ok": True})
            return
        if url.path == "/api/v1/panel-location":
            if url.query:
                self._error(400, "Unexpected panel location query parameters")
                return
            path = self.app.panel_location()
            if path is None:
                self._error(503, "Panel location is not ready")
            else:
                self._send(200, {"panel_path": path})
            return
        if url.path == "/api/v1/release-feed":
            if not self._admin():
                return
            if url.query:
                self._error(400, "INVALID_REQUEST")
                return
            try:
                result = self.app.release_feed.status()
                if not self.app.store.unrestricted_admin(self._token()):
                    self._error(401, "Unauthorized")
                    return
                self._send(200, result)
            except BackupClientError as exc:
                self._error(exc.status, str(exc))
            return
        if url.path == "/api/v1/external-agent-update":
            if not self._admin():
                return
            if url.query:
                self._error(400, "INVALID_REQUEST")
                return
            try:
                result = self.app.external_agent_update.status()
                if not self.app.store.unrestricted_admin(self._token()):
                    self._error(401, "Unauthorized")
                    return
                self._send(200, result)
            except BackupClientError as exc:
                self._error(exc.status, str(exc))
            return
        if url.path == "/api/v1/external-agent-update/operations":
            if not self._admin():
                return
            if url.query:
                self._error(400, "INVALID_REQUEST")
                return
            try:
                result = self.app.external_agent_update.operations()
                if not self.app.store.unrestricted_admin(self._token()):
                    self._error(401, "Unauthorized")
                    return
                self._send(200, result)
            except BackupClientError as exc:
                self._error(exc.status, str(exc))
            return
        operation = re.fullmatch(r"/api/v1/external-agent-update/operations/([^/]+)", url.path)
        if operation:
            if not self._admin():
                return
            if url.query or not external_operation_id(operation.group(1)):
                self._error(400, "INVALID_REQUEST")
                return
            try:
                result = self.app.external_agent_update.operation_status(operation.group(1))
                if not self.app.store.unrestricted_admin(self._token()):
                    self._error(401, "Unauthorized")
                    return
                self._send(200, result)
            except BackupClientError as exc:
                self._error(exc.status, str(exc))
            return
        if url.path == "/api/v1/public-web":
            if not self._admin():
                return
            if url.query:
                self._error(400, "Unexpected public Web query parameters")
                return
            try:
                result = self.app.public_web.status()
                if not self.app.store.unrestricted_admin(self._token()):
                    self._error(401, "Unauthorized")
                    return
                self._send(200, result)
            except PublicSettingsClientError as exc:
                self._error(exc.status, str(exc))
            return
        if url.path == "/api/v1/local-web":
            if not self._admin():
                return
            if url.query:
                self._error(400, "Unexpected local Web query parameters")
                return
            try:
                result = self.app.local_web.status()
                if not self.app.store.unrestricted_admin(self._token()):
                    self._error(401, "Unauthorized")
                    return
                self._send(200, result)
            except PublicSettingsClientError as exc:
                self._error(exc.status, str(exc))
            return
        host_base = "/api/v1/host-backups"
        host_status = re.fullmatch(r"/api/v1/host-backups/operations/([0-9a-f]{32})", url.path)
        host_verify = re.fullmatch(r"/api/v1/host-backups/archives/([0-9a-f]{32})/verify", url.path)
        if url.path in (host_base + "/plan", host_base + "/archives",
                        host_base + "/operations") or host_status or host_verify:
            if not self._admin():
                return
            if url.query:
                self._error(400, "Unexpected host backup query parameters")
                return
            try:
                if url.path == host_base + "/plan":
                    result = self.app.host_backups.plan()
                elif url.path == host_base + "/archives":
                    result = self.app.host_backups.archives()
                elif url.path == host_base + "/operations":
                    result = self.app.host_backups.operations()
                elif host_verify:
                    result = self.app.host_backups.verify_archive(host_verify.group(1))
                else:
                    result = self.app.host_backups.operation_status(host_status.group(1))
                if not self.app.store.unrestricted_admin(self._token()):
                    self._error(401, "Unauthorized")
                    return
                self._send(200, result)
            except BackupClientError as exc:
                self._error(exc.status, str(exc))
            return
        restore_status = re.fullmatch(r"/api/v1/backups/restores/([^/]+)", url.path)
        if url.path == "/api/v1/backups/restores" or restore_status:
            if not self._admin():
                return
            if url.query:
                self._error(400, "Unexpected restore query parameters")
                return
            if restore_status and not backup_id(restore_status.group(1)):
                self._error(400, "Invalid restore request ID")
                return
            try:
                result = (self.app.backups.restore_status(restore_status.group(1))
                          if restore_status else self.app.backups.restore_list())
                if not self.app.store.unrestricted_admin(self._token()):
                    self._error(401, "Unauthorized")
                    return
                self._send(200, result)
            except BackupClientError as exc:
                self._error(exc.status, str(exc))
            return
        if url.path == "/api/v1/backups" or re.fullmatch(r"/api/v1/backups/[^/]+", url.path):
            if not self._admin():
                return
            if url.query:
                self._error(400, "Unexpected backup query parameters")
                return
            if not self.app.backup_lock.acquire(blocking=False):
                self._error(409, "Backup operation is busy")
                return
            try:
                if url.path == "/api/v1/backups":
                    result = self.app.backups.list()
                else:
                    identity = url.path.rsplit("/", 1)[1]
                    if not backup_id(identity):
                        self._error(400, "Invalid backup ID")
                        return
                    result = {"backup": self.app.backups.verify(identity)}
                if not self.app.store.unrestricted_admin(self._token()):
                    self._error(401, "Unauthorized")
                    return
                self._send(200, result)
            except BackupClientError as exc:
                self._error(exc.status, str(exc))
            finally:
                self.app.backup_lock.release()
            return
        user_access = re.fullmatch(r"/api/v1/users/([^/]+)/server-access", url.path)
        bot_access = re.fullmatch(r"/api/v1/telegram/bindings/([0-9]+)/([0-9]+)/server-access", url.path)
        if user_access or bot_access:
            if not self._admin():
                return
            if url.query:
                self._error(400, "Unexpected access query parameters")
                return
            kind = "user" if user_access else "bot"
            key = (user_access.group(1),) if user_access else (int(bot_access.group(1)), int(bot_access.group(2)))
            policy = self.app.store.server_access_policy(kind, key, session_token=self._token())
            if policy is None:
                self._error(404, "Principal not found")
            else:
                self._send(200, {"access": policy})
            return
        if self._enrollment_get(url):
            return
        if self._agent_management_get(url):
            return
        if self._checks_get(url):
            return
        match = re.fullmatch(r"/api/v1/servers/([^/]+)/terminal/next", url.path)
        if match:
            server_id = match.group(1)
            if not self.app.store.agent_valid(server_id, self._token()):
                self._error(401, "Unauthorized")
                return
            if not self.app.store.server_commands_enabled(server_id):
                self.app.terminals.close_server(server_id, "permission_revoked")
                self._error(403, "Remote commands are disabled")
                return
            try:
                session = self.app.terminals.next_agent(server_id)
            except TerminalError as exc:
                self._error(exc.status, str(exc))
                return
            # A token can be rotated while the long poll is waiting. Recheck
            # before disclosing a leased session to the old Agent.
            if not self.app.store.agent_valid(server_id, self._token()):
                self._error(401, "Unauthorized")
                return
            with self.app.agent_maintenance_lock:
                if session and self.app.store.agent_maintenance_active(server_id):
                    try:
                        self.app.terminals.close(server_id, session["id"],
                                                 reason="agent_maintenance")
                    except TerminalError:
                        pass  # A concurrent close already removed the relay.
                    session = None
            if session and not self._terminal_allowed(self.app.terminals.owner_hash(server_id, session["id"]), server_id):
                self.app.terminals.close(server_id, session["id"], reason="permission_revoked")
                session = None
            self._send(200, {"session": session})
            return
        match = re.fullmatch(r"/api/v1/servers/([^/]+)/files/next", url.path)
        if match:
            server_id = match.group(1)
            if not self.app.store.agent_valid(server_id, self._token()):
                self._error(401, "Unauthorized")
                return
            if not self.app.store.server_commands_enabled(server_id):
                self.app.files.close_server(server_id)
                self._error(403, "Remote commands are disabled")
                return
            try:
                operation = self.app.files.next_agent(
                    server_id, lambda owner: self.app.store.terminal_access_valid(owner, server_id))
            except FileRelayError as exc:
                self._error(exc.status, str(exc))
                return
            if not self.app.store.agent_valid(server_id, self._token()):
                self._error(401, "Unauthorized")
                return
            with self.app.agent_maintenance_lock:
                if operation and self.app.store.agent_maintenance_active(server_id):
                    self.app.files.close_operation(server_id, operation["id"])
                    operation = None
            if operation:
                try:
                    owner = self.app.files.owner_hash(server_id, operation["id"])
                except FileRelayError:
                    operation = None
                else:
                    if not self.app.store.terminal_access_valid(owner, server_id):
                        self.app.files.close_operation(server_id, operation["id"])
                        operation = None
            self._send(200, {"operation": operation})
            return
        match = re.fullmatch(r"/api/v1/servers/([^/]+)/terminal/sessions/([^/]+)/controls", url.path)
        if match:
            server_id, session_id = match.groups()
            if not self.app.store.agent_valid(server_id, self._token()):
                self._error(401, "Unauthorized")
                return
            try:
                after = self._terminal_after(url)
                result = self.app.terminals.controls(
                    server_id, session_id, after,
                    lambda owner: self._terminal_allowed(owner, server_id))
            except TerminalError as exc:
                self._error(exc.status, str(exc))
                return
            if not self.app.store.agent_valid(server_id, self._token()):
                self._error(401, "Unauthorized")
                return
            if not self._terminal_allowed(self.app.terminals.owner_hash(server_id, session_id), server_id):
                self.app.terminals.close(server_id, session_id, reason="permission_revoked")
                # Tell the Agent to stop without returning buffered input.
                result = {"events": [], "next_after": after, "state": "closed",
                          "reason": result["reason"] or "permission_revoked"}
            self._send(200, result)
            return
        match = re.fullmatch(r"/api/v1/servers/([^/]+)/jobs/next", url.path)
        if match:
            server_id = match.group(1)
            token = self._token()
            if not self.app.store.agent_valid(server_id, token):
                self._error(401, "Unauthorized")
                return
            job = self.app.store.lease_job(server_id, agent_token=token)
            if not self.app.store.agent_valid(server_id, token):
                if job is not None:
                    self.app.store.cancel_undisclosed_job(server_id, job["id"])
                self._error(401, "Unauthorized")
                return
            self._send(200, {"job": job})
            return
        match = re.fullmatch(r"/api/v1/servers/([^/]+)/agent-compatibility", url.path)
        if match:
            server_id = match.group(1)
            token = self._token()
            if not self.app.store.agent_valid(server_id, token):
                self._error(401, "Unauthorized")
                return
            if url.query:
                self._error(400, "Unexpected compatibility query parameters")
                return
            digest = self.app.bundle_manifest_sha256
            if digest is None:
                self._error(503, "Running Hub bundle manifest is unavailable")
                return
            # Token rotation can race a request; disclose the compatibility
            # proof only while this exact server credential is still current.
            if not self.app.store.agent_valid(server_id, token):
                self._error(401, "Unauthorized")
                return
            self._send(200, {"protocol": 1, "bundle_manifest_sha256": digest})
            return
        readable = url.path in ("/api/v1/session", "/api/v1/session/access",
                                "/api/v1/servers", "/api/v1/incidents",
                                "/api/v1/monitoring/settings",
                                "/api/v1/monitoring/pressure-settings",
                                "/api/v1/monitoring/inode-settings", "/api/v1/vpn") or re.fullmatch(
                                    r"/api/v1/servers/[^/]+/(metrics|vpn|maintenance|amnezia/control|services/control|containers/control|containers/alerts|filesystems/alerts)", url.path)
        if not self._authenticated("viewer" if readable else "admin"):
            return
        if url.path == "/api/v1/session":
            info = self.app.store.session_info(self._token())
            if info is None:
                self._error(401, "Unauthorized")
            else:
                self._send(200, info)
            return
        if url.path == "/api/v1/session/access":
            self._send(200, {"access": self.app.store.own_access_summary(self._token())})
            return
        if url.path == "/api/v1/users":
            self._send(200, {"users": self.app.store.users(session_token=self._token())})
            return
        match = re.fullmatch(r"/api/v1/servers/([^/]+)/files/operations/([^/]+)", url.path)
        if match:
            server_id, operation_id = match.groups()
            if not self.app.store.terminal_access_valid(self._terminal_owner(), server_id):
                self.app.files.close_owner(self._terminal_owner())
                self._error(403, "File permission revoked")
                return
            try:
                operation = self.app.files.get(server_id, operation_id, self._terminal_owner())
            except FileRelayError as exc:
                self._error(exc.status, str(exc))
                return
            if not self.app.store.session_valid(self._token()):
                self._error(401, "Unauthorized")
                return
            if not self.app.store.terminal_access_valid(self._terminal_owner(), server_id):
                self.app.files.close_owner(self._terminal_owner())
                self._error(403, "File permission revoked")
                return
            self._send(200, {"operation": operation})
            return
        match = re.fullmatch(r"/api/v1/servers/([^/]+)/terminal/sessions/([^/]+)/events", url.path)
        if match:
            server_id, session_id = match.groups()
            try:
                after = self._terminal_after(url)
                result = self.app.terminals.events(
                    server_id, session_id, self._terminal_owner(), after,
                    lambda owner: self._terminal_allowed(owner, server_id))
            except TerminalError as exc:
                self._error(exc.status, str(exc))
                return
            # Logout and password change can occur between the registry's
            # permission check and a long-poll response carrying PTY output.
            if not self.app.store.session_valid(self._token()):
                self._error(401, "Unauthorized")
                return
            if not self._terminal_allowed(self._terminal_owner(), server_id):
                self.app.terminals.close(server_id, session_id, self._terminal_owner(), "permission_revoked")
                self._error(403, "Terminal permission revoked")
                return
            self._send(200, result)
            return
        if url.path == "/api/v1/servers":
            self._send(200, {"servers": self.app.store.servers(session_token=self._token())})
            return
        match = re.fullmatch(r"/api/v1/servers/([^/]+)/maintenance", url.path)
        if match:
            windows = self.app.store.maintenance_windows(match.group(1), session_token=self._token())
            if windows is None:
                self._error(404, "Server not found")
            else:
                self._send(200, {"server_id": match.group(1), "windows": windows})
            return
        if url.path == "/api/v1/monitoring/settings":
            self._send(200, {"settings": self.app.store.monitoring_settings()})
            return
        if url.path == "/api/v1/monitoring/pressure-settings":
            if url.query:
                self._error(400, "Unexpected pressure settings query parameters")
                return
            self._send(200, {"settings": self.app.store.pressure_settings()})
            return
        if url.path == "/api/v1/monitoring/inode-settings":
            if url.query:
                self._error(400, "Unexpected inode settings query parameters")
                return
            self._send(200, {"settings": self.app.store.inode_settings()})
            return
        if url.path == "/api/v1/telegram":
            if self.app.telegram is None:
                self._error(503, "Telegram management is unavailable")
            else:
                self._send(200, {"telegram": self.app.telegram.status()})
            return
        if url.path == "/api/v1/vpn":
            self._send(200, {"vpn": read_vpn_status(self.app.vpn_status_path)})
            return
        match = re.fullmatch(r"/api/v1/servers/([^/]+)/vpn", url.path)
        if match:
            if url.query:
                self._error(400, "Unexpected VPN inventory query parameters")
            elif not self.app.store.server_exists(match.group(1)):
                self._error(404, "Server not found")
            else:
                try:
                    self._send(200, self.app.store.remote_vpn_inventory(
                        match.group(1), session_token=self._token()))
                except (AuthenticationError, AuthorizationError):
                    self._error(403 if self.app.store.session_valid(self._token()) else 401,
                                "Server access denied")
            return
        match = re.fullmatch(r"/api/v1/servers/([^/]+)/amnezia/control", url.path)
        if match:
            server_id = match.group(1)
            query = parse_qs(url.query, keep_blank_values=True)
            if (query and (set(query) != {"target"} or len(query["target"]) != 1 or
                           query["target"][0] not in AMNEZIA_TARGETS)):
                self._error(400, "Invalid Amnezia target query")
                return
            target = query["target"][0] if query else "awg2"
            if not self.app.store.server_exists(server_id):
                self._error(404, "Server not found")
                return
            status_job = self.app.store.latest_amnezia_control_job(
                server_id, target, session_token=self._token())
            self._send(200, {"control": control_status(status_job, int(time.time()), target)})
            return
        match = re.fullmatch(r"/api/v1/servers/([^/]+)/services/control", url.path)
        if match:
            query = parse_qs(url.query, keep_blank_values=True)
            if set(query) != {"unit"} or len(query["unit"]) != 1:
                self._error(400, "Expected one service unit query")
                return
            unit = query["unit"][0]
            try:
                service_status_command(unit)
            except ValueError as exc:
                self._error(400, str(exc))
                return
            server_id = match.group(1)
            if not self.app.store.server_exists(server_id):
                self._error(404, "Server not found")
                return
            status_job = self.app.store.latest_service_control_job(
                server_id, unit, session_token=self._token())
            self._send(200, {"control": service_control_status(
                status_job, int(time.time()), unit)})
            return
        match = re.fullmatch(r"/api/v1/servers/([^/]+)/containers/control", url.path)
        if match:
            query = parse_qs(url.query, keep_blank_values=True)
            if set(query) != {"engine", "id"} or any(len(values) != 1 for values in query.values()):
                self._error(400, "Expected one Docker engine and full container ID")
                return
            ident = query["id"][0]
            try:
                build_container_action_command({"action": "status", "engine": query["engine"][0],
                                                "id": ident})
            except ValueError as exc:
                self._error(400, str(exc))
                return
            server_id = match.group(1)
            if not self.app.store.server_exists(server_id):
                self._error(404, "Server not found")
                return
            status_job = self.app.store.latest_container_control_job(
                server_id, ident, session_token=self._token())
            self._send(200, {"control": container_control_status(
                status_job, int(time.time()), ident)})
            return
        match = re.fullmatch(r"/api/v1/servers/([^/]+)/containers/alerts", url.path)
        if match:
            if url.query:
                self._error(400, "Unexpected Docker alert query parameters")
                return
            server_id = match.group(1)
            if not self.app.store.server_exists(server_id):
                self._error(404, "Server not found")
                return
            self._send(200, self.app.store.container_alert_settings(
                server_id, session_token=self._token()))
            return
        match = re.fullmatch(r"/api/v1/servers/([^/]+)/filesystems/alerts", url.path)
        if match:
            if url.query:
                self._error(400, "Unexpected filesystem alert query parameters")
                return
            server_id = match.group(1)
            if not self.app.store.server_exists(server_id):
                self._error(404, "Server not found")
                return
            self._send(200, self.app.store.filesystem_alert_settings(
                server_id, session_token=self._token()))
            return
        match = re.fullmatch(r"/api/v1/servers/([^/]+)/metrics", url.path)
        if match:
            server_id = match.group(1)
            if not self.app.store.server_exists(server_id):
                self._error(404, "Server not found")
                return
            try:
                limit = int(parse_qs(url.query).get("limit", ["60"])[0])
            except ValueError:
                limit = 0
            if not 1 <= limit <= 1000:
                self._error(400, "limit must be between 1 and 1000")
                return
            self._send(200, {"server_id": server_id, "metrics": self.app.store.history(server_id, limit, session_token=self._token())})
            return
        if url.path == "/api/v1/incidents":
            state = parse_qs(url.query).get("state", [None])[0]
            if state not in (None, "firing", "resolved"):
                self._error(400, "Invalid state")
                return
            self._send(200, {"incidents": self.app.store.incidents(state=state, session_token=self._token())})
            return
        if url.path == "/api/v1/jobs":
            self._send(200, {"jobs": self.app.store.jobs(session_token=self._token())})
            return
        match = re.fullmatch(r"/api/v1/jobs/([^/]+)", url.path)
        if match:
            try:
                job = self.app.store.job(match.group(1), self._token())
            except PermissionError:
                self._error(403, "Transient result belongs to another session")
                return
            if job is None:
                self._error(404, "Job not found")
            else:
                self._send(200, {"job": job})
            return
        if url.path == "/api/v1/audit":
            self._send(200, {"events": self.app.store.audit_events(session_token=self._token())})
            return
        self._error(404, "Not found")

    def _post(self):
        self._body_auth = None
        path = urlsplit(self.path).path
        if path in ("/api/v1/external-agent-update/preview",
                    "/api/v1/external-agent-update/preflight",
                    "/api/v1/external-agent-update/apply"):
            if not self._admin() or not self._public_web_origin_ok():
                return
            if urlsplit(self.path).query:
                self._error(400, "INVALID_REQUEST")
                return
            action = path.rsplit("/", 1)[1]
            data = self._body(512, reject_duplicate_keys=True)
            if data is None:
                return
            fields = {"archive_sha256", "current_hub_manifest_sha256"}
            if action == "apply":
                fields |= {"request_id", "external_agent_manifest_sha256", "review_sha256",
                           "confirmed"}
            if (not isinstance(data, dict) or set(data) != fields or
                    (action == "apply" and data["confirmed"] is not True) or
                    (action == "apply" and not external_operation_id(data["request_id"])) or
                    any(not isinstance(data[name], str) or
                        BUNDLE_MANIFEST_SHA256.fullmatch(data[name]) is None
                        for name in fields - {"confirmed", "request_id"})):
                self._error(400, "INVALID_REQUEST")
                return
            if not self.app.external_agent_update_lock.acquire(blocking=False):
                self._error(409, "EXTERNAL_BUSY")
                return
            try:
                if action == "apply":
                    self.app.store.audit_external_agent_update_request(
                        data["request_id"], data["archive_sha256"],
                        data["current_hub_manifest_sha256"],
                        data["external_agent_manifest_sha256"], data["review_sha256"],
                        session_token=self._token())
                arguments = [data["archive_sha256"], data["current_hub_manifest_sha256"]]
                if action == "apply":
                    arguments.insert(0, data["request_id"])
                    arguments += [data["external_agent_manifest_sha256"], data["review_sha256"]]
                result = getattr(self.app.external_agent_update, action)(*arguments)
                if not self.app.store.unrestricted_admin(self._token()):
                    self._error(401, "Unauthorized")
                    return
                self._send(200, result)
            except BackupClientError as exc:
                self._error(exc.status, str(exc))
            finally:
                self.app.external_agent_update_lock.release()
            return
        if path in ("/api/v1/release-feed/enable", "/api/v1/release-feed/disable"):
            if not self._admin() or not self._public_web_origin_ok():
                return
            if urlsplit(self.path).query:
                self._error(400, "INVALID_REQUEST")
                return
            data = self._body(256, reject_duplicate_keys=True)
            if data is None:
                return
            if (not isinstance(data, dict) or set(data) != {"expected_state"} or
                    not isinstance(data["expected_state"], str) or
                    BUNDLE_MANIFEST_SHA256.fullmatch(data["expected_state"]) is None):
                self._error(400, "INVALID_REQUEST")
                return
            if not self.app.release_feed_lock.acquire(blocking=False):
                self._error(409, "STATE_CHANGED")
                return
            try:
                action = path.rsplit("/", 1)[1]
                self.app.store.audit_release_feed_request(
                    action, data["expected_state"], session_token=self._token())
                result = getattr(self.app.release_feed, action)(data["expected_state"])
                if not self.app.store.unrestricted_admin(self._token()):
                    self._error(401, "Unauthorized")
                    return
                self._send(200, result)
            except BackupClientError as exc:
                self._error(exc.status, str(exc))
            finally:
                self.app.release_feed_lock.release()
            return
        maintenance = re.fullmatch(
            r"/api/v1/servers/([^/]+)/agent-maintenance/lease(?:/(renew|release))?", path)
        if maintenance:
            server_id, action = maintenance.groups()
            token = self._token()
            if not self.app.store.agent_valid(server_id, token):
                self._error(401, "Unauthorized")
                return
            if urlsplit(self.path).query:
                self._error(400, "Unexpected maintenance query parameters")
                return
            self._body_auth = ("agent", server_id)
            data = self._body(256, reject_duplicate_keys=True)
            if data is None:
                return
            if not isinstance(data, dict):
                self._error(400, "Invalid maintenance lease request")
                return
            try:
                if action is None:
                    digest = self.app.bundle_manifest_sha256
                    if digest is None:
                        self._error(503, "Running Hub bundle manifest is unavailable")
                        return
                    if set(data) != {"bundle_manifest_sha256"} or data["bundle_manifest_sha256"] != digest:
                        self._error(409, "Running Hub bundle does not match")
                        return
                    with self.app.agent_maintenance_lock:
                        active = (self.app.terminals.has_active(server_id) or
                                  self.app.files.has_active(server_id))
                        result = self.app.store.acquire_agent_maintenance_lease(
                            server_id, token, digest,
                            hub_epoch=self.app.agent_maintenance_epoch,
                            relays_active=active)
                    status = 201
                else:
                    if set(data) != {"lease_token"}:
                        self._error(400, "Invalid maintenance lease request")
                        return
                    if action == "renew":
                        result = self.app.store.renew_agent_maintenance_lease(
                            server_id, token, data["lease_token"],
                            hub_epoch=self.app.agent_maintenance_epoch,
                            bundle_manifest_sha256=self.app.bundle_manifest_sha256 or "")
                        status = 200
                    else:
                        released = self.app.store.release_agent_maintenance_lease(
                            server_id, token, data["lease_token"])
                        result = {"released": released} if released is not None else None
                        status = 200
            except MaintenanceLeaseBusy as exc:
                self._error(409, str(exc))
                return
            except MaintenanceLeaseInvalid as exc:
                self._error(409, str(exc))
                return
            except ValueError as exc:
                self._error(400, str(exc))
                return
            if result is None or not self.app.store.agent_valid(server_id, token):
                self._error(401, "Unauthorized")
                return
            self._send(status, result)
            return
        if path in ("/api/v1/public-web/preview", "/api/v1/public-web/apply"):
            if not self._admin() or not self._public_web_origin_ok():
                return
            if urlsplit(self.path).query:
                self._error(400, "Unexpected public Web query parameters")
                return
            data = self._body(1024, reject_duplicate_keys=True)
            if data is None:
                return
            action = path.rsplit("/", 1)[1]
            if not isinstance(data, dict):
                self._error(400, "Invalid public Web request")
                return
            if action == "preview":
                if set(data) != {"config"}:
                    self._error(400, "Invalid public Web preview")
                    return
            elif (set(data) != {"config", "expected_state_sha256",
                                "source_manifest_sha256", "request_id"} or
                  not public_hash(data["expected_state_sha256"], nullable=True) or
                  not public_hash(data["source_manifest_sha256"]) or
                  not public_id(data["request_id"])):
                self._error(400, "Invalid public Web apply")
                return
            try:
                config = public_config(data["config"])
            except PublicSettingsError:
                self._error(400, "Invalid public address or panel path")
                return
            if not self.app.public_web_lock.acquire(blocking=False):
                self._error(409, "Public Web operation is busy")
                return
            try:
                config_sha = hashlib.sha256(json.dumps(config, sort_keys=True,
                                                       separators=(",", ":")).encode()).hexdigest()
                self.app.store.audit_public_web_request(
                    action, config_sha, request_id=data.get("request_id"),
                    session_token=self._token())
                if action == "apply":
                    self.app._invalidate_panel_location()
                result = (self.app.public_web.preview(config) if action == "preview" else
                          self.app.public_web.apply(config, data["expected_state_sha256"],
                                                    data["source_manifest_sha256"],
                                                    data["request_id"]))
                if action == "apply":
                    self.app._set_panel_location(config["panel_path"])
                # Root apply can take minutes and restart Hub. A revoked token
                # cannot receive the result after that gap.
                if not self.app.store.unrestricted_admin(self._token()):
                    self._error(401, "Unauthorized")
                    return
                self._send(200, result)
            except PublicSettingsClientError as exc:
                if action == "apply":
                    self.app._start_panel_location_refresh(invalidate=True)
                self._error(exc.status, str(exc))
            finally:
                self.app.public_web_lock.release()
            return
        if path in ("/api/v1/local-web/preview", "/api/v1/local-web/apply",
                    "/api/v1/local-web/disable"):
            if not self._admin() or not self._public_web_origin_ok():
                return
            if urlsplit(self.path).query:
                self._error(400, "Unexpected local Web query parameters")
                return
            data = self._body(1024, reject_duplicate_keys=True)
            if data is None:
                return
            action = path.rsplit("/", 1)[1]
            if not isinstance(data, dict):
                self._error(400, "Invalid local Web request")
                return
            if action == "preview":
                valid = set(data) == {"config"}
            elif action == "apply":
                valid = (set(data) == {"config", "expected_state_sha256",
                                       "source_manifest_sha256", "request_id"} and
                         public_hash(data["expected_state_sha256"], nullable=True) and
                         public_hash(data["source_manifest_sha256"]) and
                         public_id(data["request_id"]))
            else:
                valid = (set(data) == {"expected_state_sha256", "request_id"} and
                         public_hash(data["expected_state_sha256"], nullable=True) and
                         public_id(data["request_id"]))
            if not valid:
                self._error(400, "Invalid local Web " + action)
                return
            if action != "disable":
                try:
                    config = local_config(data["config"])
                except PublicSettingsError:
                    self._error(400, "Invalid local panel path or root behavior")
                    return
            else:
                config = None
            if not self.app.local_web_lock.acquire(blocking=False):
                self._error(409, "Local Web operation is busy")
                return
            try:
                config_sha = (hashlib.sha256(json.dumps(config, sort_keys=True,
                                                       separators=(",", ":")).encode()).hexdigest()
                              if config is not None else None)
                self.app.store.audit_local_web_request(
                    action, config_sha, request_id=data.get("request_id"),
                    session_token=self._token())
                if action != "preview":
                    self.app._invalidate_panel_location()
                if action == "preview":
                    result = self.app.local_web.preview(config)
                elif action == "apply":
                    result = self.app.local_web.apply(config, data["expected_state_sha256"],
                                                      data["source_manifest_sha256"],
                                                      data["request_id"])
                else:
                    result = self.app.local_web.disable(data["expected_state_sha256"],
                                                        data["request_id"])
                if action != "preview":
                    self.app._set_panel_location(config["panel_path"] if config is not None
                                                 else DEFAULT_PANEL_PATH)
                if not self.app.store.unrestricted_admin(self._token()):
                    self._error(401, "Unauthorized")
                    return
                self._send(200, result)
            except PublicSettingsClientError as exc:
                if action != "preview":
                    self.app._start_panel_location_refresh(invalidate=True)
                self._error(exc.status, str(exc))
            finally:
                self.app.local_web_lock.release()
            return
        host_base = "/api/v1/host-backups"
        host_recover = re.fullmatch(
            r"/api/v1/host-backups/operations/([0-9a-f]{32})/recover", path)
        if path == host_base + "/operations" or host_recover:
            if not self._admin():
                return
            if urlsplit(self.path).query:
                self._error(400, "Unexpected host backup query parameters")
                return
            data = self._body(256, reject_duplicate_keys=True)
            if data is None:
                return
            if host_recover:
                request_id = host_recover.group(1)
                if data != {}:
                    self._error(400, "Expected an empty object")
                    return
                digest = None
            else:
                if (not isinstance(data, dict) or set(data) != {
                        "request_id", "expected_manifest_sha256"} or
                        not isinstance(data["request_id"], str) or
                        HOST_ID.fullmatch(data["request_id"]) is None or
                        not isinstance(data["expected_manifest_sha256"], str) or
                        HOST_SHA.fullmatch(data["expected_manifest_sha256"]) is None):
                    self._error(400, "Expected request ID and manifest SHA-256")
                    return
                request_id = data["request_id"]
                digest = data["expected_manifest_sha256"]
            if not self.app.host_backup_lock.acquire(blocking=False):
                self._error(409, "Host backup operation is busy")
                return
            try:
                self.app.store.audit_host_backup_request(
                    request_id, recover=bool(host_recover), session_token=self._token())
                result = (self.app.host_backups.recover(request_id) if host_recover else
                          self.app.host_backups.start(request_id, digest))
                if not self.app.store.unrestricted_admin(self._token()):
                    self._error(401, "Unauthorized")
                    return
                self._send(200 if result["phase"] in ("complete", "recovered", "failed")
                           else 202, result)
            except BackupClientError as exc:
                self._error(exc.status, str(exc))
            finally:
                self.app.host_backup_lock.release()
            return
        if path == "/api/v1/session/ssh-grant":
            if urlsplit(self.path).query:
                self._error(400, "Unexpected query parameters")
                return
            data = self._body(max_size=128, reject_duplicate_keys=True)
            if data is None:
                return
            if not isinstance(data, dict) or set(data) != {"grant"}:
                self._error(400, "Expected one SSH grant")
                return
            state, result = self.app.redeem_ssh_grant(data["grant"], self._source_ip())
            if state == "rate_limited":
                self._error(429, "Too many SSH grant attempts")
            elif state == "invalid":
                self._error(401, "Invalid or expired SSH grant")
            else:
                info = self.app.store.session_info(result[0])
                if info is None:
                    self._error(401, "Unauthorized")
                else:
                    self._send(200, {"token": result[0], **info})
            return
        restore_recover = re.fullmatch(r"/api/v1/backups/restores/([^/]+)/recover", path)
        if path == "/api/v1/backups/restore" or restore_recover:
            if not self._admin():
                return
            if urlsplit(self.path).query:
                self._error(400, "Unexpected restore query parameters")
                return
            data = self._body(128, reject_duplicate_keys=True)
            if data is None:
                return
            if restore_recover:
                request_id = restore_recover.group(1)
                if data != {} or not backup_id(request_id):
                    self._error(400, "Expected an empty object and a restore request UUID")
                    return
                target_id = None
            else:
                if (not isinstance(data, dict) or set(data) != {"backup_id", "request_id"} or
                        not backup_id(data["backup_id"]) or
                        not backup_id(data["request_id"]) or
                        data["backup_id"] == data["request_id"]):
                    self._error(400, "Expected backup_id and request_id UUIDs")
                    return
                request_id, target_id = data["request_id"], data["backup_id"]
            if not self.app.backup_lock.acquire(blocking=False):
                self._error(409, "Backup operation is busy")
                return
            try:
                self.app.store.audit_restore_request(request_id, target_id=target_id,
                                                     recover=bool(restore_recover),
                                                     session_token=self._token())
                result = (self.app.backups.restore_recover(request_id) if restore_recover
                          else self.app.backups.restore_apply(target_id, request_id))
                self._send(200 if result["phase"] in ("complete", "failed_recovered")
                           else 202, result)
            except BackupClientError as exc:
                self._error(exc.status, str(exc))
            finally:
                self.app.backup_lock.release()
            return
        if path == "/api/v1/backups":
            if not self._admin():
                return
            if urlsplit(self.path).query:
                self._error(400, "Unexpected backup query parameters")
                return
            keys = self.headers.get_all("Idempotency-Key", [])
            if len(keys) != 1 or not backup_id(keys[0]):
                self._error(400, "Exactly one canonical UUID Idempotency-Key is required")
                return
            data = self._body(64, reject_duplicate_keys=True)
            if data is None:
                return
            if data != {}:
                self._error(400, "Expected an empty object")
                return
            if not self.app.backup_lock.acquire(blocking=False):
                self._error(409, "Backup operation is busy")
                return
            try:
                self.app.store.audit_backup_request(keys[0], session_token=self._token())
                backup, created = self.app.backups.create(keys[0])
                if not self.app.store.unrestricted_admin(self._token()):
                    self._error(401, "Unauthorized")
                    return
                self._send(201 if created else 200, {"backup": backup})
            except BackupClientError as exc:
                self._error(exc.status, str(exc))
            finally:
                self.app.backup_lock.release()
            return
        if self._enrollment_post(path):
            return
        if self._agent_management_post(path):
            return
        if self._checks_post(path):
            return
        if path == "/api/v1/session":
            data = self._body()
            if data is None:
                return
            if not isinstance(data, dict) or not isinstance(data.get("username"), str) or not isinstance(data.get("password"), str):
                self._error(400, "Expected username and password")
                return
            if len(data["password"]) > 1024 or len(data["username"]) > 80:
                self._error(400, "Invalid credentials")
                return
            try:
                data["password"].encode("utf-8")
                data["username"].encode("utf-8")
            except UnicodeError:
                self._error(400, "Invalid credentials")
                return
            state, result = self.app.login(data["username"], data["password"], self._source_ip())
            if state == "rate_limited":
                self._error(429, "Too many login attempts")
            elif state == "invalid":
                self._error(401, "Invalid credentials")
            else:
                info = self.app.store.session_info(result[0])
                if info is None:
                    self._error(401, "Unauthorized")
                else:
                    self._send(200, {"token": result[0], **info})
            return
        match = re.fullmatch(r"/api/v1/servers/([^/]+)/vpn", path)
        if match:
            server_id = match.group(1)
            if urlsplit(self.path).query:
                self._error(400, "Unexpected VPN inventory query parameters")
                return
            if not self.app.store.agent_valid(server_id, self._token()):
                self._error(401, "Unauthorized")
                return
            self._body_auth = ("agent", server_id)
            data = self._body(max_size=65536, reject_duplicate_keys=True)
            if data is None:
                return
            try:
                received_at = self.app.store.put_vpn_inventory(
                    server_id, data, agent_token=self._token())
            except ValueError as exc:
                self._error(422, str(exc))
                return
            except AuthenticationError:
                self._error(401, "Unauthorized")
                return
            self._send(202, {"accepted": True, "received_at": received_at})
            return
        match = re.fullmatch(r"/api/v1/servers/([^/]+)/metrics", path)
        if match:
            server_id = match.group(1)
            if not self.app.store.agent_valid(server_id, self._token()):
                self._error(401, "Unauthorized")
                return
            self._body_auth = ("agent", server_id)
            data = self._body()
            if data is None:
                return
            try:
                events = self.app.store.ingest(server_id, data, agent_token=self._token())
            except InvalidMetric as exc:
                self._error(422, str(exc))
                return
            self.app.emit(events)
            # The first report from a new Agent stays compatible with an old
            # Hub. Advertise optional detail categories after accepting it.
            self._send(202, {"accepted": True, "metric_details": ["pressure", "cpu_times"]})
            return
        match = re.fullmatch(r"/api/v1/servers/([^/]+)/jobs/([^/]+)/result", path)
        if match:
            server_id, job_id = match.groups()
            if not self.app.store.agent_valid(server_id, self._token()):
                self._error(401, "Unauthorized")
                return
            self._body_auth = ("agent", server_id)
            data = self._body()
            if data is None:
                return
            if not isinstance(data, dict):
                self._error(400, "Expected JSON object")
                return
            try:
                job = self.app.store.finish_job(server_id, job_id, data.get("state"), data.get("exit_code"), data.get("output"))
            except ValueError as exc:
                self._error(400, str(exc))
                return
            if job is None:
                self._error(404, "Job not found")
            else:
                self.app.emit_job_result(job)
                job.pop("just_completed", None)
                self._send(200, {"job": job})
            return
        match = re.fullmatch(r"/api/v1/servers/([^/]+)/terminal/sessions/([^/]+)/(ready|output|exit)", path)
        if match:
            server_id, session_id, action = match.groups()
            if not self.app.store.agent_valid(server_id, self._token()):
                self._error(401, "Unauthorized")
                return
            self._body_auth = ("agent", server_id)
            data = self._body()
            if data is None:
                return
            try:
                if not isinstance(data, dict):
                    raise TerminalError(400, "Expected terminal object")
                if action == "ready" and set(data) == set():
                    if not self._terminal_allowed(self.app.terminals.owner_hash(server_id, session_id), server_id):
                        self.app.terminals.close(server_id, session_id, reason="permission_revoked")
                        raise TerminalError(403, "Terminal permission revoked")
                    result = self.app.terminals.ready(server_id, session_id)
                    status = 200
                elif action == "output" and set(data) == {"seq", "data"}:
                    if not self._terminal_allowed(self.app.terminals.owner_hash(server_id, session_id), server_id):
                        self.app.terminals.close(server_id, session_id, reason="permission_revoked")
                        raise TerminalError(403, "Terminal permission revoked")
                    result, created = self.app.terminals.output(server_id, session_id,
                                                                data["seq"], data["data"])
                    status = 202 if created else 200
                elif action == "exit" and set(data) == {"exit_code"}:
                    result = self.app.terminals.exit(server_id, session_id, data["exit_code"])
                    self.app.store.audit_terminal("terminal_exited", server_id, session_id)
                    status = 200
                else:
                    raise TerminalError(400, "Invalid terminal action body")
            except TerminalError as exc:
                self._error(exc.status, str(exc))
                return
            self._send(status, result)
            return
        match = re.fullmatch(r"/api/v1/servers/([^/]+)/files/operations/([^/]+)/result", path)
        if match:
            server_id, operation_id = match.groups()
            if not self.app.store.agent_valid(server_id, self._token()):
                self._error(401, "Unauthorized")
                return
            self._body_auth = ("agent", server_id)
            if not self.app.store.server_commands_enabled(server_id):
                self.app.files.close_server(server_id)
                self._error(403, "Remote commands are disabled")
                return
            data = self._body(max_size=MAX_FILE_BODY)
            if data is None:
                return
            try:
                if not self.app.store.agent_valid(server_id, self._token()):
                    raise FileRelayError(401, "Unauthorized")
                owner = self.app.files.owner_hash(server_id, operation_id)
                if not self.app.store.terminal_access_valid(owner, server_id):
                    self.app.files.close_operation(server_id, operation_id)
                    raise FileRelayError(403, "File permission revoked")
                kind, digest = self.app.files.audit_meta(server_id, operation_id)
                result = self.app.files.result(server_id, operation_id, data)
            except FileRelayError as exc:
                self._error(exc.status, str(exc))
                return
            self.app.store.audit_file("file_completed", server_id, operation_id, kind, digest,
                                      data["state"] if data["state"] == "succeeded" else data["code"])
            self._send(200, {"operation": result})
            return
        role = ("viewer" if path in ("/api/v1/admin/password", "/api/v1/session/password") else
                "operator" if re.fullmatch(r"/api/v1/incidents/[^/]+/ack", path) else "admin")
        if not self._authenticated(role):
            return
        if path == "/api/v1/users":
            data = self._body()
            if data is None:
                return
            if not isinstance(data, dict) or set(data) != {"username", "password", "role"}:
                self._error(400, "Expected username, password and role")
                return
            try:
                user = self.app.store.create_user(data["username"], data["password"], data["role"],
                                                  session_token=self._token())
            except ValueError as exc:
                self._error(400, str(exc))
                return
            self._send(201, {"user": user})
            return
        match = re.fullmatch(r"/api/v1/users/([^/]+)/password", path)
        if match:
            data = self._body()
            if data is None:
                return
            if not isinstance(data, dict) or set(data) != {"revision", "password"}:
                self._error(400, "Expected revision and password")
                return
            try:
                result = self.app.store.reset_user_password(match.group(1), data["revision"], data["password"],
                                                             session_token=self._token())
            except ValueError as exc:
                self._error(400, str(exc))
                return
            if result is None:
                self._error(404, "User not found")
            else:
                self._send(200, self.app.close_revoked(result))
            return
        if path in ("/api/v1/admin/password", "/api/v1/session/password"):
            data = self._body()
            if data is None:
                return
            if (not isinstance(data, dict) or set(data) != {"current_password", "new_password"}
                    or not isinstance(data["current_password"], str)
                    or not isinstance(data["new_password"], str)):
                self._error(400, "Expected current_password and new_password")
                return
            old_password, new_password = data["current_password"], data["new_password"]
            if not old_password or len(old_password) > 1024:
                self._error(400, "Current password is required")
                return
            try:
                old_password.encode("utf-8")
                new_password.encode("utf-8")
            except UnicodeError:
                self._error(400, "Passwords must contain valid Unicode text")
                return
            if not 12 <= len(new_password) <= 1024 or not new_password.strip():
                self._error(400, "New password must contain 12–1024 characters and not be blank")
                return
            if old_password == new_password:
                self._error(400, "New password must differ from current password")
                return
            state = self.app.change_password(self._token(), old_password, new_password, self._source_ip())
            if state == "rate_limited":
                self._error(429, "Too many password attempts; retry after 30 seconds")
            elif state == "unauthorized":
                self._error(401, "Unauthorized")
            elif state == "invalid":
                self._error(403, "Current password is incorrect")
            else:
                self._send(200, {"changed": True, "sessions_revoked": True})
            return
        if path == "/api/v1/monitoring/settings":
            data = self._body()
            if data is None:
                return
            try:
                settings = self.app.store.save_monitoring_settings(data, session_token=self._token())
            except MonitoringSettingsConflict:
                self._error(409, "Monitoring settings changed in another session; reload before saving")
                return
            except ValueError as exc:
                self._error(400, str(exc))
                return
            self._send(200, {"settings": settings})
            return
        if path == "/api/v1/monitoring/pressure-settings":
            if urlsplit(self.path).query:
                self._error(400, "Unexpected pressure settings query parameters")
                return
            data = self._body(4096, reject_duplicate_keys=True)
            if data is None:
                return
            try:
                settings = self.app.store.save_pressure_settings(data, session_token=self._token())
            except PressureSettingsConflict:
                self._error(409, "Pressure settings changed in another session; reload before saving")
                return
            except ValueError as exc:
                self._error(400, str(exc))
                return
            self._send(200, {"settings": settings})
            return
        if path == "/api/v1/monitoring/inode-settings":
            if urlsplit(self.path).query:
                self._error(400, "Unexpected inode settings query parameters")
                return
            data = self._body(4096, reject_duplicate_keys=True)
            if data is None:
                return
            try:
                settings = self.app.store.save_inode_settings(data, session_token=self._token())
            except InodeSettingsConflict:
                self._error(409, "Inode settings changed in another session; reload before saving")
                return
            except ValueError as exc:
                self._error(400, str(exc))
                return
            self._send(200, {"settings": settings})
            return
        if path == "/api/v1/telegram/token":
            if self.app.telegram is None:
                self._error(503, "Telegram management is unavailable")
                return
            data = self._body()
            if data is None:
                return
            if not isinstance(data, dict) or set(data) != {"token"}:
                self._error(400, "Expected only token")
                return
            try:
                result = self.app.telegram.set_token(data["token"], self._token())
            except TelegramModeError as exc:
                self._error(409, str(exc))
                return
            except TelegramActivationError as exc:
                self._error(exc.status, str(exc))
                return
            except TelegramStorageError as exc:
                self._error(503, str(exc))
                return
            except ValueError as exc:
                self._error(400, str(exc))
                return
            except PermissionError:
                self._error(401, "Unauthorized")
                return
            self.app.store.audit_telegram_token("telegram_token_saved", identity=self._identity)
            self._send(200, {"telegram": result})
            return
        if path == "/api/v1/telegram/bindings":
            data = self._body()
            if data is None:
                return
            if not isinstance(data, dict) or set(data) != {"user_id", "chat_id", "role"}:
                self._error(400, "Expected user_id, chat_id and role")
                return
            try:
                self.app.store.add_bot_user(data["user_id"], data["chat_id"],
                                            data["role"], actor="hub-admin",
                                            session_token=self._token())
            except ValueError as exc:
                self._error(400, str(exc))
                return
            except PermissionError:
                self._error(401, "Unauthorized")
                return
            self._send(200, {"binding": {"user_id": data["user_id"],
                                         "chat_id": data["chat_id"], "role": data["role"]}})
            return
        match = re.fullmatch(r"/api/v1/telegram/requests/([0-9]+)/([0-9]+)/(approve|reject)", path)
        if match:
            if self.app.telegram is None:
                self._error(503, "Telegram management is unavailable")
                return
            data = self._body()
            if data is None:
                return
            user_id, chat_id, action = int(match.group(1)), int(match.group(2)), match.group(3)
            if action == "approve":
                if not isinstance(data, dict) or set(data) != {"role"}:
                    self._error(400, "Expected only role")
                    return
                try:
                    binding = self.app.store.approve_bot_pairing(
                        user_id, chat_id, data["role"], session_token=self._token())
                except ValueError as exc:
                    self._error(400, str(exc))
                    return
                except PermissionError:
                    self._error(401, "Unauthorized")
                    return
                if binding is None:
                    self._error(404, "Telegram request not found")
                    return
                self.app.telegram.notify_pairing_result(chat_id, binding["role"])
            else:
                if data != {}:
                    self._error(400, "Expected an empty object")
                    return
                try:
                    rejected = self.app.store.reject_bot_pairing(
                        user_id, chat_id, session_token=self._token())
                except ValueError as exc:
                    self._error(400, str(exc))
                    return
                except PermissionError:
                    self._error(401, "Unauthorized")
                    return
                if not rejected:
                    self._error(404, "Telegram request not found")
                    return
                self.app.telegram.notify_pairing_result(chat_id, None)
            self._send(200, {"telegram": self.app.telegram.status()})
            return
        match = re.fullmatch(r"/api/v1/servers/([^/]+)/files/operations", path)
        if match:
            server_id = match.group(1)
            if not self.app.store.terminal_access_valid(self._terminal_owner(), server_id):
                enabled = self.app.store.server_commands_enabled(server_id)
                self._error(404 if enabled is None else 403,
                            "Server not found" if enabled is None else "Remote commands are disabled")
                return
            keys = self.headers.get_all("Idempotency-Key", [])
            if len(keys) != 1:
                self._error(400, "Exactly one Idempotency-Key header is required")
                return
            data = self._body(max_size=MAX_FILE_BODY)
            if data is None:
                return
            try:
                with self.app.agent_maintenance_lock:
                    if self.app.store.agent_maintenance_active(server_id):
                        raise FileRelayError(409, "Agent maintenance is in progress")
                    operation, created = self.app.files.create(
                        server_id, self._terminal_owner(), keys[0], data)
            except FileRelayError as exc:
                self._error(exc.status, str(exc))
                return
            if not self.app.store.session_valid(self._token()):
                self.app.files.close_operation(server_id, operation["id"])
                self._error(401, "Unauthorized")
                return
            if not self.app.store.terminal_access_valid(self._terminal_owner(), server_id):
                self.app.files.close_operation(server_id, operation["id"])
                self._error(403, "Remote commands are disabled")
                return
            if created:
                self.app.store.audit_file("file_requested", server_id, operation["id"],
                                          data["action"], path_digest(data), session_token=self._token())
            self._send(201 if created else 200, {"operation": operation})
            return
        match = re.fullmatch(r"/api/v1/servers/([^/]+)/terminal/sessions", path)
        if match:
            server_id = match.group(1)
            keys = self.headers.get_all("Idempotency-Key", [])
            if len(keys) != 1:
                self._error(400, "Exactly one Idempotency-Key header is required")
                return
            try:
                if str(uuid.UUID(keys[0])) != keys[0]:
                    raise ValueError()
            except (ValueError, AttributeError):
                self._error(400, "Idempotency-Key must be a canonical UUID")
                return
            data = self._body()
            if data is None:
                return
            try:
                if not isinstance(data, dict) or set(data) != {"cols", "rows"}:
                    raise TerminalError(400, "Expected terminal size")
                cols = dimension(data["cols"], 20, 300)
                rows = dimension(data["rows"], 10, 120)
                enabled = self.app.store.server_commands_enabled(server_id)
                if enabled is None:
                    raise TerminalError(404, "Server not found")
                if not enabled:
                    raise TerminalError(403, "Remote commands are disabled")
                with self.app.agent_maintenance_lock:
                    if self.app.store.agent_maintenance_active(server_id):
                        raise TerminalError(409, "Agent maintenance is in progress")
                    session, created = self.app.terminals.create(
                        server_id, self._terminal_owner(), keys[0], cols, rows)
            except TerminalError as exc:
                self._error(exc.status, str(exc))
                return
            if created:
                self.app.store.audit_terminal("terminal_opened", server_id, session["id"], session_token=self._token())
            if not self.app.store.session_valid(self._token()):
                self.app.terminals.close(server_id, session["id"], reason="session_revoked")
                self._error(401, "Unauthorized")
                return
            if not self._terminal_allowed(self._terminal_owner(), server_id):
                self.app.terminals.close(server_id, session["id"], reason="permission_revoked")
                self._error(403, "Terminal permission revoked")
                return
            self._send(201 if created else 200, {"session": session})
            return
        match = re.fullmatch(r"/api/v1/servers/([^/]+)/terminal/sessions/([^/]+)/(input|resize)", path)
        if match:
            server_id, session_id, action = match.groups()
            data = self._body()
            if data is None:
                return
            try:
                if not isinstance(data, dict):
                    raise TerminalError(400, "Expected terminal object")
                if not self._terminal_allowed(self._terminal_owner(), server_id):
                    self.app.terminals.close(server_id, session_id, self._terminal_owner(), "permission_revoked")
                    raise TerminalError(403, "Terminal permission revoked")
                if action == "input" and set(data) == {"seq", "data"}:
                    result, created = self.app.terminals.input(
                        server_id, session_id, self._terminal_owner(), data["seq"], data["data"])
                elif action == "resize" and set(data) == {"seq", "cols", "rows"}:
                    result, created = self.app.terminals.resize(
                        server_id, session_id, self._terminal_owner(), data["seq"],
                        dimension(data["cols"], 20, 300), dimension(data["rows"], 10, 120))
                else:
                    raise TerminalError(400, "Invalid terminal action body")
            except TerminalError as exc:
                self._error(exc.status, str(exc))
                return
            self._send(202 if created else 200, result)
            return
        if path == "/api/v1/servers":
            data = self._body()
            if data is None:
                return
            try:
                server = self.app.store.create_server(data.get("name") if isinstance(data, dict) else None, session_token=self._token())
            except ValueError as exc:
                self._error(400, str(exc))
                return
            self._send(201, server)
            return
        match = re.fullmatch(r"/api/v1/servers/([^/]+)/maintenance", path)
        if match:
            data = self._body()
            if data is None:
                return
            try:
                window = self.app.store.create_maintenance(match.group(1), data, session_token=self._token())
            except KeyError:
                self._error(404, "Server not found")
                return
            except ValueError as exc:
                self._error(400, str(exc))
                return
            except MaintenanceConflict as exc:
                self._error(409, str(exc))
                return
            self._send(201, {"window": window})
            return
        match = re.fullmatch(r"/api/v1/servers/([^/]+)/rotate-token", path)
        if match:
            try:
                token = self.app.store.rotate_agent_token(match.group(1), session_token=self._token())
            except MaintenanceLeaseBusy as exc:
                self._error(409, str(exc))
                return
            if token is None:
                self._error(404, "Server not found")
            else:
                self.app.terminals.close_server(match.group(1), "agent_token_rotated")
                self.app.files.close_server(match.group(1))
                self._send(200, {"server_id": match.group(1), "agent_token": token})
            return
        match = re.fullmatch(r"/api/v1/servers/([^/]+)/commands", path)
        if match:
            data = self._body()
            if data is None:
                return
            if not isinstance(data, dict) or not isinstance(data.get("enabled"), bool):
                self._error(400, "Expected boolean enabled")
                return
            if not self.app.store.set_remote_commands(match.group(1), data["enabled"], session_token=self._token()):
                self._error(404, "Server not found")
            else:
                if not data["enabled"]:
                    self.app.terminals.close_server(match.group(1), "permission_revoked")
                    self.app.files.close_server(match.group(1))
                self._send(200, {"server_id": match.group(1), "remote_commands_enabled": data["enabled"]})
            return
        match = re.fullmatch(r"/api/v1/servers/([^/]+)/jobs", path)
        if match:
            data = self._body()
            if data is None:
                return
            if not isinstance(data, dict) or set(data) != {"command"}:
                self._error(400, "Expected only command")
                return
            try:
                job, created = self.app.store.queue_web_job(
                    match.group(1), self._token(), data["command"],
                    self.headers.get("Idempotency-Key"))
            except KeyError:
                self._error(404, "Server not found")
                return
            except PermissionError as exc:
                self._error(403, str(exc))
                return
            except ValueError as exc:
                self._error(400, str(exc))
                return
            except IdempotencyConflict as exc:
                self._error(409, str(exc))
                return
            self._send(201 if created else 200, {"job": job})
            return
        match = re.fullmatch(r"/api/v1/servers/([^/]+)/processes/snapshot", path)
        if match:
            if urlsplit(self.path).query:
                self._error(400, "Unexpected process query parameters")
                return
            keys = self.headers.get_all("Idempotency-Key", [])
            if len(keys) != 1:
                self._error(400, "Exactly one Idempotency-Key header is required")
                return
            data = self._body(max_size=512, reject_duplicate_keys=True)
            if data is None:
                return
            try:
                params = process_request_parameters(data)
                command = build_process_command(params)
                job, created = self.app.store.queue_web_job(
                    match.group(1), self._token(), command, keys[0],
                    audit_action="process_inventory_requested",
                    audit_details={"after_pid": params["after_pid"], "limit": params["limit"],
                                   "filter_sha256": hashlib.sha256(params["filter"].encode()).hexdigest()})
            except KeyError:
                self._error(404, "Server not found")
                return
            except PermissionError as exc:
                self._error(403, str(exc))
                return
            except ValueError as exc:
                self._error(400, str(exc))
                return
            except IdempotencyConflict as exc:
                self._error(409, str(exc))
                return
            self._send(201 if created else 200, {"job": job})
            return
        match = re.fullmatch(r"/api/v1/servers/([^/]+)/containers/logs", path)
        if match:
            keys = self.headers.get_all("Idempotency-Key", [])
            if len(keys) != 1:
                self._error(400, "Exactly one Idempotency-Key header is required")
                return
            data = self._body(max_size=512, reject_duplicate_keys=True)
            if data is None:
                return
            try:
                command = build_container_log_command(data)
                job, created = self.app.store.queue_web_job(
                    match.group(1), self._token(), command, keys[0],
                    audit_action="container_logs_requested")
            except KeyError:
                self._error(404, "Server not found")
                return
            except PermissionError as exc:
                self._error(403, str(exc))
                return
            except ValueError as exc:
                self._error(400, str(exc))
                return
            except IdempotencyConflict as exc:
                self._error(409, str(exc))
                return
            except JournalRateLimited as exc:
                self._error(429, str(exc))
                return
            self._send(201 if created else 200, {"job": job})
            return
        match = re.fullmatch(r"/api/v1/servers/([^/]+)/journal", path)
        if match:
            keys = self.headers.get_all("Idempotency-Key", [])
            if len(keys) != 1:
                self._error(400, "Exactly one Idempotency-Key header is required")
                return
            data = self._body()
            if data is None:
                return
            try:
                command = build_journal_command(data)
                units = self.app.store.journal_units(match.group(1))
                if units is None:
                    self._error(404, "Server not found")
                    return
                if data["unit"] not in units:
                    self._error(403, "Journal access is disabled or unit is not allowed")
                    return
                job, created = self.app.store.queue_web_job(
                    match.group(1), self._token(), command, keys[0],
                    audit_action="journal_requested",
                    audit_details={"unit": data["unit"], "lines": data["lines"]})
            except KeyError:
                self._error(404, "Server not found")
                return
            except PermissionError as exc:
                self._error(403, str(exc))
                return
            except ValueError as exc:
                self._error(400, str(exc))
                return
            except IdempotencyConflict as exc:
                self._error(409, str(exc))
                return
            except JournalRateLimited as exc:
                self._error(429, str(exc))
                return
            self._send(201 if created else 200, {"job": job})
            return
        match = re.fullmatch(r"/api/v1/servers/([^/]+)/vpn/actions", path)
        if match:
            keys = self.headers.get_all("Idempotency-Key", [])
            if len(keys) != 1:
                self._error(400, "Exactly one Idempotency-Key header is required")
                return
            data = self._body()
            if data is None:
                return
            try:
                command = build_vpn_command(data)
                job, created = self.app.store.queue_web_job(
                    match.group(1), self._token(), command, keys[0],
                    allow_vpn_marker=True)
            except KeyError:
                self._error(404, "Server not found")
                return
            except PermissionError as exc:
                self._error(403, str(exc))
                return
            except ValueError as exc:
                self._error(400, str(exc))
                return
            except IdempotencyConflict as exc:
                self._error(409, str(exc))
                return
            self._send(201 if created else 200, {"job": job})
            return
        match = re.fullmatch(r"/api/v1/servers/([^/]+)/amnezia/actions", path)
        if match:
            keys = self.headers.get_all("Idempotency-Key", [])
            if len(keys) != 1:
                self._error(400, "Exactly one Idempotency-Key header is required")
                return
            data = self._body(reject_duplicate_keys=True)
            if data is None:
                return
            try:
                command = build_amnezia_command(data)
                job, created = self.app.store.queue_web_job(
                    match.group(1), self._token(), command, keys[0],
                    require_amnezia_ready=data["target"] if data["action"] != "status" else None,
                    allow_amnezia_marker=True)
            except KeyError:
                self._error(404, "Server not found")
                return
            except AmneziaControlUnavailable as exc:
                self._error(503, str(exc))
                return
            except PermissionError as exc:
                self._error(403, str(exc))
                return
            except ValueError as exc:
                self._error(400, str(exc))
                return
            except IdempotencyConflict as exc:
                self._error(409, str(exc))
                return
            self._send(201 if created else 200, {"job": job})
            return
        match = re.fullmatch(r"/api/v1/servers/([^/]+)/services/actions", path)
        if match:
            keys = self.headers.get_all("Idempotency-Key", [])
            if len(keys) != 1:
                self._error(400, "Exactly one Idempotency-Key header is required")
                return
            data = self._body()
            if data is None:
                return
            try:
                command = build_service_command(data)
                if data["action"] != "status" and protected_service_mutation_unit(data["unit"]):
                    raise PermissionError("This service is reserved for host access or SovaGrid")
                job, created = self.app.store.queue_web_job(
                    match.group(1), self._token(), command, keys[0],
                    require_service_ready=data["unit"] if data["action"] != "status" else None,
                    audit_details={"service_action": data["action"], "unit": data["unit"]},
                    allow_service_marker=True)
            except KeyError:
                self._error(404, "Server not found")
                return
            except ServiceControlUnavailable as exc:
                self._error(503, str(exc))
                return
            except PermissionError as exc:
                self._error(403, str(exc))
                return
            except ValueError as exc:
                self._error(400, str(exc))
                return
            except IdempotencyConflict as exc:
                self._error(409, str(exc))
                return
            self._send(201 if created else 200, {"job": job})
            return
        match = re.fullmatch(r"/api/v1/servers/([^/]+)/containers/actions", path)
        if match:
            if urlsplit(self.path).query:
                self._error(400, "Unexpected container action query")
                return
            if not self._public_web_origin_ok():
                return
            keys = self.headers.get_all("Idempotency-Key", [])
            if len(keys) != 1:
                self._error(400, "Exactly one Idempotency-Key header is required")
                return
            data = self._body(max_size=512, reject_duplicate_keys=True)
            if data is None:
                return
            try:
                command = build_container_action_command(data)
                action, ident = data["action"], data["id"]
                job, created = self.app.store.queue_web_job(
                    match.group(1), self._token(), command, keys[0],
                    require_container_ready=ident if action != "status" else None,
                    allow_container_action_marker=True)
            except KeyError:
                self._error(404, "Server not found")
                return
            except ContainerControlUnavailable as exc:
                self._error(503, str(exc))
                return
            except PermissionError as exc:
                self._error(403, str(exc))
                return
            except ValueError as exc:
                self._error(400, str(exc))
                return
            except IdempotencyConflict as exc:
                self._error(409, str(exc))
                return
            self._send(201 if created else 200, {"job": job})
            return
        match = re.fullmatch(r"/api/v1/incidents/([^/]+)/ack", path)
        if match:
            incident = self.app.store.acknowledge(match.group(1), session_token=self._token())
            if incident is None:
                self._error(404, "Incident not found")
            else:
                self._send(200, {"incident": incident})
            return
        self._error(404, "Not found")

    def _put(self):
        self._body_auth = None
        url = urlsplit(self.path)
        filesystem_match = re.fullmatch(r"/api/v1/servers/([^/]+)/filesystems/alerts", url.path)
        if filesystem_match:
            if not self._authenticated("admin") or not self._public_web_origin_ok():
                return
            if url.query:
                self._error(400, "Unexpected filesystem alert query parameters")
                return
            data = self._body(8192, reject_duplicate_keys=True)
            if data is None:
                return
            try:
                result = self.app.store.save_filesystem_alert_settings(
                    filesystem_match.group(1), data, session_token=self._token())
            except FilesystemAlertConflict:
                self._error(409, "Filesystem alert settings changed; reload before saving")
                return
            except FilesystemAlertInventoryUnavailable:
                self._error(409, "Select new mountpoints from fresh filesystem inventory")
                return
            except KeyError:
                self._error(404, "Server not found")
                return
            except ValueError as exc:
                self._error(400, str(exc))
                return
            self._send(200, result)
            return
        match = re.fullmatch(r"/api/v1/servers/([^/]+)/containers/alerts", url.path)
        if match is None:
            self._error(404, "Not found")
            return
        if not self._authenticated("admin") or not self._public_web_origin_ok():
            return
        if url.query:
            self._error(400, "Unexpected Docker alert query parameters")
            return
        data = self._body(4096, reject_duplicate_keys=True)
        if data is None:
            return
        try:
            result = self.app.store.save_container_alert_settings(
                match.group(1), data, session_token=self._token())
        except ContainerAlertConflict:
            self._error(409, "Docker alert settings changed in another session; reload before saving")
            return
        except ContainerAlertInventoryUnavailable:
            self._error(409, "Select new names from a fresh complete Docker inventory")
            return
        except KeyError:
            self._error(404, "Server not found")
            return
        except ValueError as exc:
            self._error(400, str(exc))
            return
        self._send(200, result)

    def _delete(self):
        url = urlsplit(self.path)
        path = url.path
        if not self._authenticated("viewer" if path == "/api/v1/session" else "admin"):
            return
        match = re.fullmatch(r"/api/v1/users/([^/]+)", path)
        if match:
            args = parse_qs(url.query, keep_blank_values=True)
            revision = args.get("revision", [])
            if (set(args) != {"revision"} or len(revision) != 1 or len(revision[0]) > 19 or
                    not revision[0].isascii() or not revision[0].isdecimal()):
                self._error(400, "Exactly one revision query parameter is required")
                return
            try:
                result = self.app.store.delete_user(match.group(1), int(revision[0]), session_token=self._token())
            except ValueError as exc:
                self._error(400, str(exc))
                return
            if result is None:
                self._error(404, "User not found")
            else:
                self._send(200, self.app.close_revoked(result))
            return
        match = re.fullmatch(r"/api/v1/servers/([^/]+)/files/operations/([^/]+)", path)
        if match:
            server_id, operation_id = match.groups()
            if not self.app.store.terminal_access_valid(self._terminal_owner(), server_id):
                self.app.files.close_owner(self._terminal_owner())
                self._error(403, "File permission revoked")
                return
            try:
                self.app.files.get(server_id, operation_id, self._terminal_owner())
            except FileRelayError as exc:
                self._error(exc.status, str(exc))
                return
            self.app.files.close_operation(server_id, operation_id)
            self._send(200, {"closed": True})
            return
        match = re.fullmatch(r"/api/v1/servers/([^/]+)/maintenance/([^/]+)", path)
        if match:
            try:
                result = self.app.store.cancel_maintenance(*match.groups(), session_token=self._token())
            except MaintenanceConflict as exc:
                self._error(409, str(exc))
                return
            if result is None:
                self._error(404, "Maintenance window not found")
                return
            window, events = result
            self.app.emit(events)
            self._send(200, {"window": window})
            return
        if path == "/api/v1/telegram/token":
            if self.app.telegram is None:
                self._error(503, "Telegram management is unavailable")
                return
            try:
                result = self.app.telegram.remove_token(self._token())
            except TelegramModeError as exc:
                self._error(409, str(exc))
                return
            except TelegramStorageError as exc:
                self._error(503, str(exc))
                return
            except PermissionError:
                self._error(401, "Unauthorized")
                return
            self.app.store.audit_telegram_token("telegram_token_removed", identity=self._identity)
            self._send(200, {"telegram": result})
            return
        match = re.fullmatch(r"/api/v1/telegram/bindings/([0-9]+)/([0-9]+)", path)
        if match:
            try:
                removed = self.app.store.remove_bot_user(
                    int(match.group(1)), int(match.group(2)), actor="hub-admin",
                    session_token=self._token())
            except ValueError as exc:
                self._error(400, str(exc))
                return
            except PermissionError:
                self._error(401, "Unauthorized")
                return
            self._send(200, {"removed": removed})
            return
        match = re.fullmatch(r"/api/v1/servers/([^/]+)/terminal/sessions/([^/]+)", path)
        if match:
            server_id, session_id = match.groups()
            try:
                result = self.app.terminals.close(server_id, session_id, self._terminal_owner())
            except TerminalError as exc:
                self._error(exc.status, str(exc))
                return
            self.app.store.audit_terminal("terminal_closed", server_id, session_id, session_token=self._token())
            self._send(200, result)
            return
        if path == "/api/v1/session":
            self.app.terminals.close_owner(self._terminal_owner())
            self.app.files.close_owner(self._terminal_owner())
            self.app.store.logout(self._token())
            self._send(200, {"revoked": True})
            return
        self._error(404, "Not found")

    def _patch(self):
        path = urlsplit(self.path).path
        if not self._admin():
            return
        user_access = re.fullmatch(r"/api/v1/users/([^/]+)/server-access", path)
        bot_access = re.fullmatch(r"/api/v1/telegram/bindings/([0-9]+)/([0-9]+)/server-access", path)
        if user_access or bot_access:
            if urlsplit(self.path).query:
                self._error(400, "Unexpected access query parameters")
                return
            data = self._body(131072, reject_duplicate_keys=True)
            if data is None:
                return
            kind = "user" if user_access else "bot"
            key = (user_access.group(1),) if user_access else (int(bot_access.group(1)), int(bot_access.group(2)))
            try:
                result = self.app.store.save_server_access_policy(kind, key, data, session_token=self._token())
            except ValueError as exc:
                self._error(400, str(exc))
                return
            if result is None:
                self._error(404, "Principal not found")
            else:
                self._send(200, {"access": self.app.close_revoked(result)})
            return
        match = re.fullmatch(r"/api/v1/users/([^/]+)", path)
        if not match:
            self._error(404, "Not found")
            return
        data = self._body()
        if data is None:
            return
        try:
            result = self.app.store.update_user(match.group(1), data, session_token=self._token())
        except ValueError as exc:
            self._error(400, str(exc))
            return
        if result is None:
            self._error(404, "User not found")
        else:
            self._send(200, self.app.close_revoked(result))


class HubHTTPServer(ThreadingHTTPServer):
    daemon_threads = True


def make_server(app: HubApp, port: int = 8765, bind: str = "127.0.0.1") -> HubHTTPServer:
    handler = type("BoundHubHandler", (HubHandler,), {"app": app})
    return HubHTTPServer((bind, port), handler)
