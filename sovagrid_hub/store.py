# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""SQLite persistence and alert evaluation for SovaGrid Hub."""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import secrets
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

from .auth import (AccountStore, AuthorizationError, USER_SCHEMA, SESSION_SCHEMA, SSH_GRANT_SCHEMA, migrate_accounts)
from .checks import CheckStore, migrate_checks
from .enrollment import EnrollmentStore, migrate_enrollments
from .agent_management import AgentManagementStore, migrate_agent_management
from .agent_maintenance import AgentMaintenanceStore, migrate_agent_maintenance
from .server_acl import ServerACLStore, migrate_server_acl
from .vpn_status import empty_vpn_status, project_vpn_status
from .vpn_actions import HELPER as VPN_MARKER, is_vpn_command
from .amnezia_actions import (HELPER as AMNEZIA_MARKER, control_status,
                              is_amnezia_command, status_command)
from .service_actions import (HELPER as SERVICE_MARKER,
                              control_status as service_control_status,
                              build_service_command, is_service_command,
                              status_command as service_status_command)
from .journal_actions import MARKER as JOURNAL_MARKER, UNIT_NAME
from .process_actions import MARKER as PROCESS_MARKER, validate_snapshot as validate_process_snapshot
from .container_log_actions import (MARKER as CONTAINER_LOG_MARKER,
                                    parse_command as parse_container_log_command,
                                    safe_output as safe_container_log_output)
from .container_actions import (MARKER as CONTAINER_ACTION_MARKER,
                                build_command as build_container_action_command,
                                parse_command as parse_container_action_command,
                                is_container_action_command,
                                control_status as container_control_status,
                                protected_inventory as protected_container_inventory,
                                result as container_action_result)
from .container_alerts import (ContainerAlertConflict, ContainerAlertInventoryUnavailable,
                               DEFAULT_HOLD_SECONDS as CONTAINER_ALERT_DEFAULT_HOLD,
                               evidence as container_alert_evidence,
                               kind as container_alert_kind,
                               migrate as migrate_container_alerts,
                               observation as container_alert_observation,
                               validate_settings as validate_container_alert_settings)
from .filesystem_alerts import (FilesystemAlertConflict, FilesystemAlertInventoryUnavailable,
                                DEFAULT_HOLD_SECONDS as FILESYSTEM_ALERT_DEFAULT_HOLD,
                                evidence as filesystem_alert_evidence,
                                kind as filesystem_alert_kind,
                                migrate as migrate_filesystem_alerts,
                                observation as filesystem_alert_observation,
                                validate_settings as validate_filesystem_alert_settings)


METRIC_FIELDS = (
    "cpu_percent",
    "memory_percent",
    "disk_percent",
    "network_rx_bytes",
    "network_tx_bytes",
    "load1",
    "uptime_seconds",
)
OPTIONAL_FIELDS = ("memory_total_bytes", "memory_available_bytes", "disk_total_bytes", "disk_available_bytes")
PERCENT_FIELDS = {"cpu_percent", "memory_percent", "disk_percent"}
NONNEGATIVE_FIELDS = set(METRIC_FIELDS + OPTIONAL_FIELDS) - PERCENT_FIELDS
ALERT_FIELDS = {"high_cpu": "cpu_percent", "high_memory": "memory_percent", "high_disk": "disk_percent"}
DEFAULT_THRESHOLDS = {"high_cpu": 90.0, "high_memory": 90.0, "high_disk": 90.0}
PRESSURE_ALERT_FIELDS = {
    "high_psi_cpu_some": ("pressure", "cpu", "some", "avg10"),
    "high_psi_memory_some": ("pressure", "memory", "some", "avg10"),
    "high_psi_memory_full": ("pressure", "memory", "full", "avg10"),
    "high_psi_io_some": ("pressure", "io", "some", "avg10"),
    "high_psi_io_full": ("pressure", "io", "full", "avg10"),
    "high_cpu_iowait": ("cpu_times", "iowait_percent"),
    "high_cpu_steal": ("cpu_times", "steal_percent"),
}
PRESSURE_ALERT_DEFAULT_HOLD_SECONDS = 60
ROOT_INODE_ALERT_KIND = "high_root_inodes"
ROOT_INODE_ALERT_DEFAULT_HOLD_SECONDS = 60
DETAIL_KEYS = {"swap", "filesystems", "filesystems_truncated", "interfaces", "load5", "load15", "processes", "top_processes", "disk_io", "services", "journal_units", "clock", "containers", "pressure", "cpu_times"}
PRESSURE_MODES = {"cpu": ("some",), "memory": ("some", "full"), "io": ("some", "full")}
PRESSURE_AVERAGES = ("avg10", "avg60", "avg300")
SERVICE_NAME = re.compile(r"[A-Za-z0-9_.@-]{1,96}[.]service\Z")
PROCESS_NAME = re.compile(r"[A-Za-z0-9_.:+@-]{1,16}\Z")
TIME_ZONE = re.compile(r"[A-Za-z0-9_.+-]+(?:/[A-Za-z0-9_.+-]+){0,4}\Z")
CLOCK_FIELDS = {"system_utc_epoch", "timezone", "ntp_synchronized", "rtc_local_time", "rtc_utc_epoch", "rtc_offset_seconds"}
CLOCK_MAX_EPOCH = 253402300799
CLOCK_MAX_OFFSET = 2**31 - 1
CONTAINER_ID = re.compile(r"[0-9a-f]{64}\Z")
CONTAINER_STATES = ("created", "running", "paused", "restarting", "removing", "exited", "dead", "unknown")
CONTAINER_HEALTH = (None, "starting", "healthy", "unhealthy")
CONTAINER_REASONS = (None, "no_socket", "no_access", "error")
MAX_COMMAND_BYTES = 2048
BOT_PAIRING_LIMIT = 100
BOT_PAIRING_TTL_SECONDS = 7 * 86400
BOT_PAIRING_REJECT_SECONDS = 86400
BOT_UPDATE_CURSOR_IDLE_SECONDS = 48 * 3600
JOURNAL_OUTPUT_TTL_SECONDS = 300
JOURNAL_OUTPUT_LIMIT = 32
JOURNAL_MIN_INTERVAL_SECONDS = 20
MAINTENANCE_MIN_SECONDS = 60
MAINTENANCE_MAX_SECONDS = 7 * 86400
OUTBOX_LEASE_SECONDS = 60
OUTBOX_RETRY_MAX_SECONDS = 3600


class IdempotencyConflict(Exception):
    """The same request key was already used for a different command."""


class JournalRateLimited(Exception):
    """A session already requested a journal snapshot recently."""


class AmneziaControlUnavailable(Exception):
    """No recent successful status probe proves local opt-in."""


class ServiceControlUnavailable(Exception):
    """No recent successful unit status proves the local service policy."""


class ContainerControlUnavailable(Exception):
    """No complete current inventory or exact status proves safe control."""


class InvalidMetric(ValueError):
    pass


class MonitoringSettingsConflict(Exception):
    """Another administrator saved monitoring settings first."""


class PressureSettingsConflict(Exception):
    """Another administrator saved optional pressure thresholds first."""


class InodeSettingsConflict(Exception):
    """Another administrator saved the root inode alert rule first."""


class MaintenanceConflict(Exception):
    """A server already has an active window, or the window has ended."""


def validate_command(command: object, *, allow_journal_marker: bool = False,
                     allow_process_marker: bool = False,
                     allow_container_log_marker: bool = False,
                     allow_container_action_marker: bool = False,
                     allow_service_marker: bool = False,
                     allow_vpn_marker: bool = False,
                     allow_amnezia_marker: bool = False) -> str:
    """Keep every remote-command entry point within the agent's input bound."""
    if not isinstance(command, str):
        raise ValueError("Command must be a string")
    command = command.strip()
    if not command or "\x00" in command or len(command.encode("utf-8")) > MAX_COMMAND_BYTES:
        raise ValueError("Command must contain 1–2048 UTF-8 bytes and no NUL")
    if JOURNAL_MARKER in command and not allow_journal_marker:
        raise ValueError("Journal requests require the dedicated endpoint")
    if PROCESS_MARKER in command and not allow_process_marker:
        raise ValueError("Process inventory requires the dedicated endpoint")
    if CONTAINER_LOG_MARKER in command and not allow_container_log_marker:
        raise ValueError("Container logs require the dedicated endpoint")
    if CONTAINER_ACTION_MARKER.rsplit("/", 1)[-1] in command and not allow_container_action_marker:
        raise ValueError("Container actions require the dedicated endpoint")
    if SERVICE_MARKER.rsplit("/", 1)[-1] in command and not allow_service_marker:
        raise ValueError("Service control requires the dedicated endpoint")
    if VPN_MARKER.rsplit("/", 1)[-1] in command and not allow_vpn_marker:
        raise ValueError("VPN control requires the dedicated endpoint")
    if AMNEZIA_MARKER.rsplit("/", 1)[-1] in command and not allow_amnezia_marker:
        raise ValueError("Amnezia control requires the dedicated endpoint")
    return command


def _control_kind_matches(command: str, kind: str) -> bool:
    """Keep queued legacy generic jobs out of newly privileged Agent routes."""
    marked = {name for name, marker in (("vpn", VPN_MARKER), ("amnezia", AMNEZIA_MARKER),
                                       ("service", SERVICE_MARKER),
                                       ("container", CONTAINER_ACTION_MARKER))
              if marker.rsplit("/", 1)[-1] in command}
    if kind == "generic":
        return not marked
    if marked != {kind}:
        return False
    return (is_vpn_command(command) if kind == "vpn" else
            is_amnezia_command(command) if kind == "amnezia" else
            is_service_command(command) if kind == "service" else
            is_container_action_command(command) if kind == "container" else False)


def _job_list_output(output: str | None, control_kind: str) -> str | None:
    """Keep one-use AWG3 confirmations out of the general job history."""
    if not isinstance(output, str) or not output:
        return output
    # Also cover malformed/legacy results and ordinary command output that
    # contains this field. A false positive is safer than leaking a handle.
    if "confirmation_id" in output:
        return ""
    try:
        value = json.loads(output)
    except (ValueError, RecursionError):
        return output
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, dict):
            if "confirmation_id" in item:
                return ""
            if control_kind == "amnezia" and item.get("action") == "settings_intent":
                return ""
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)
    return output


_JOB_COLUMNS = ("id", "server_id", "actor_user_id", "chat_id", "source",
                "session_token_hash", "idempotency_key", "command_sha256",
                "control_kind", "command", "state", "created_at", "delivered_at",
                "completed_at", "exit_code", "output")


def _migrate_container_control_jobs(db: sqlite3.Connection) -> None:
    """Rebuild the old CHECK transactionally while preserving job rowids.

    SQLite cannot widen a column CHECK with ALTER TABLE. No table has a foreign
    key to jobs; only the two known indexes may be dropped/recreated here.
    Unknown schema extensions abort the migration without touching old rows.
    """
    row = db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='jobs'").fetchone()
    if row is None:
        raise RuntimeError("Jobs table is missing")
    if "'container'" not in row["sql"]:
        columns = {item["name"] for item in db.execute("PRAGMA table_info(jobs)")}
        if columns != set(_JOB_COLUMNS):
            raise RuntimeError("Unrecognized jobs table schema")
        indexes = {item["name"] for item in db.execute(
            "SELECT name FROM sqlite_master WHERE tbl_name='jobs' AND type IN ('index','trigger')"
        ) if not item["name"].startswith("sqlite_autoindex_")}
        if indexes - {"jobs_server_state", "web_job_request_key"}:
            raise RuntimeError("Unknown jobs index or trigger")
        db.execute("""CREATE TABLE jobs_container_new (
            id TEXT PRIMARY KEY, server_id TEXT NOT NULL REFERENCES servers(id),
            actor_user_id INTEGER NOT NULL, chat_id INTEGER NOT NULL,
            source TEXT NOT NULL DEFAULT 'telegram' CHECK(source IN ('telegram','web')),
            session_token_hash TEXT, idempotency_key TEXT, command_sha256 TEXT,
            control_kind TEXT NOT NULL DEFAULT 'generic'
                CHECK(control_kind IN ('generic','vpn','amnezia','service','container')),
            command TEXT NOT NULL, state TEXT NOT NULL, created_at INTEGER NOT NULL,
            delivered_at INTEGER, completed_at INTEGER, exit_code INTEGER, output TEXT
        )""")
        columns_sql = ",".join(_JOB_COLUMNS)
        db.execute(f"INSERT INTO jobs_container_new(rowid,{columns_sql}) "
                   f"SELECT rowid,{columns_sql} FROM jobs")
        before = db.execute("SELECT COUNT(*) FROM jobs").fetchone()[0]
        copied = db.execute("SELECT COUNT(*) FROM jobs_container_new").fetchone()[0]
        if copied != before:
            raise RuntimeError("Jobs migration row count changed")
        db.execute("DROP TABLE jobs")
        db.execute("ALTER TABLE jobs_container_new RENAME TO jobs")
        db.execute("CREATE INDEX jobs_server_state ON jobs(server_id, state, created_at)")
        db.execute("""CREATE UNIQUE INDEX web_job_request_key
                   ON jobs(session_token_hash, idempotency_key)
                   WHERE idempotency_key IS NOT NULL""")
    db.execute("""CREATE TABLE IF NOT EXISTS container_control_jobs (
        job_id TEXT PRIMARY KEY REFERENCES jobs(id) ON DELETE CASCADE,
        engine TEXT NOT NULL CHECK(engine='docker'),
        action TEXT NOT NULL CHECK(action IN ('status','start','stop','restart')),
        container_id TEXT NOT NULL CHECK(length(container_id)=64)
    )""")
    if db.execute("PRAGMA foreign_key_check").fetchone() is not None:
        raise RuntimeError("Jobs migration violates foreign keys")


def _detail_number(value, name: str, *, integer: bool = False, percent: bool = False):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise InvalidMetric(f"details.{name} must be a finite number")
    if value < 0 or (percent and value > 100):
        raise InvalidMetric(f"details.{name} is out of range")
    try:
        finite = math.isfinite(value)
    except OverflowError:
        finite = False
    if not finite:
        raise InvalidMetric(f"details.{name} must be a finite number")
    if integer and (value > 2**63 - 1 or int(value) != value):
        raise InvalidMetric(f"details.{name} must be a 64-bit integer")
    return int(value) if integer else float(value)


def _detail_name(value, name: str, max_length: int):
    if not isinstance(value, str) or not 1 <= len(value) <= max_length or not value.isprintable():
        raise InvalidMetric(f"details.{name} is invalid")
    return value


def _validate_clock(value: object) -> dict:
    if not isinstance(value, dict) or set(value) != CLOCK_FIELDS:
        raise InvalidMetric("details.clock has invalid fields")
    system = value["system_utc_epoch"]
    rtc = value["rtc_utc_epoch"]
    offset = value["rtc_offset_seconds"]
    zone = value["timezone"]
    if type(system) is not int or not 1 <= system <= CLOCK_MAX_EPOCH:
        raise InvalidMetric("details.clock.system_utc_epoch is invalid")
    if zone is not None and (not isinstance(zone, str) or not 1 <= len(zone) <= 64 or not TIME_ZONE.fullmatch(zone)):
        raise InvalidMetric("details.clock.timezone is invalid")
    for key in ("ntp_synchronized", "rtc_local_time"):
        if value[key] is not None and type(value[key]) is not bool:
            raise InvalidMetric(f"details.clock.{key} is invalid")
    if rtc is not None and (type(rtc) is not int or not 1 <= rtc <= CLOCK_MAX_EPOCH):
        raise InvalidMetric("details.clock.rtc_utc_epoch is invalid")
    if offset is not None and (type(offset) is not int or abs(offset) > CLOCK_MAX_OFFSET):
        raise InvalidMetric("details.clock.rtc_offset_seconds is invalid")
    if (rtc is None) != (offset is None) or (rtc is not None and
            (value["rtc_local_time"] is not False or rtc - system != offset)):
        raise InvalidMetric("details.clock RTC fields are inconsistent")
    return {key: value[key] for key in CLOCK_FIELDS}


def _validate_containers(value: object) -> dict:
    if (not isinstance(value, dict) or set(value) != {"version", "collected_at", "engines"} or
            type(value["version"]) is not int or value["version"] != 1):
        raise InvalidMetric("details.containers has invalid fields")
    stamp = value["collected_at"]
    if type(stamp) is not int or not 1 <= stamp <= CLOCK_MAX_EPOCH:
        raise InvalidMetric("details.containers.collected_at is invalid")
    engines = value["engines"]
    if not isinstance(engines, list) or len(engines) != 2:
        raise InvalidMetric("details.containers.engines is invalid")
    clean_engines = []
    for expected, engine in zip(("docker", "podman"), engines):
        if (not isinstance(engine, dict) or set(engine) != {"engine", "source_status", "reason", "truncated", "containers"} or
                engine["engine"] != expected or engine["source_status"] not in ("ok", "unavailable") or
                engine["reason"] not in CONTAINER_REASONS or type(engine["truncated"]) is not bool or
                not isinstance(engine["containers"], list) or len(engine["containers"]) > 12 or
                (engine["source_status"] == "ok") != (engine["reason"] is None) or
                (engine["source_status"] == "unavailable" and (engine["containers"] or engine["truncated"]))):
            raise InvalidMetric("details.containers engine is invalid")
        clean_items, seen = [], set()
        for item in engine["containers"]:
            if not isinstance(item, dict) or set(item) != {"id", "name", "image", "state", "health", "restarts", "cpu_percent", "memory_bytes"}:
                raise InvalidMetric("details.containers item has invalid fields")
            ident, name, image = item["id"], item["name"], item["image"]
            if (not isinstance(ident, str) or not CONTAINER_ID.fullmatch(ident) or ident in seen or
                    not isinstance(name, str) or not 1 <= len(name) <= 96 or not name.isprintable() or
                    not isinstance(image, str) or not 1 <= len(image) <= 160 or not image.isprintable() or
                    item["state"] not in CONTAINER_STATES or item["health"] not in CONTAINER_HEALTH):
                raise InvalidMetric("details.containers identity is invalid")
            seen.add(ident)
            restarts, cpu, memory = item["restarts"], item["cpu_percent"], item["memory_bytes"]
            if restarts is not None and (type(restarts) is not int or not 0 <= restarts <= 2**31 - 1):
                raise InvalidMetric("details.containers.restarts is invalid")
            if cpu is not None and (isinstance(cpu, bool) or not isinstance(cpu, (int, float)) or not math.isfinite(cpu) or not 0 <= cpu <= 10000):
                raise InvalidMetric("details.containers.cpu_percent is invalid")
            if memory is not None and (type(memory) is not int or not 0 <= memory <= 2**63 - 1):
                raise InvalidMetric("details.containers.memory_bytes is invalid")
            clean_items.append({key: item[key] for key in ("id", "name", "image", "state", "health", "restarts", "cpu_percent", "memory_bytes")})
        clean_engines.append({"engine": expected, "source_status": engine["source_status"], "reason": engine["reason"],
                              "truncated": engine["truncated"], "containers": clean_items})
    clean = {"version": 1, "collected_at": stamp, "engines": clean_engines}
    if len(json.dumps(clean, ensure_ascii=False, separators=(",", ":")).encode("utf-8")) > 10000:
        raise InvalidMetric("details.containers exceeds 10 KiB")
    return clean


def _validate_pressure(value: object) -> dict:
    if not isinstance(value, dict) or not value or set(value) - set(PRESSURE_MODES):
        raise InvalidMetric("details.pressure has invalid resources")
    clean = {}
    for resource, modes in PRESSURE_MODES.items():
        if resource not in value:
            continue
        source = value[resource]
        if not isinstance(source, dict) or set(source) != set(modes):
            raise InvalidMetric(f"details.pressure.{resource} has invalid modes")
        clean[resource] = {}
        for mode in modes:
            item = source[mode]
            if not isinstance(item, dict) or set(item) != {*PRESSURE_AVERAGES, "total_us"}:
                raise InvalidMetric(f"details.pressure.{resource}.{mode} has invalid fields")
            clean[resource][mode] = {
                key: _detail_number(item[key], f"pressure.{resource}.{mode}.{key}", percent=True)
                for key in PRESSURE_AVERAGES
            }
            total = item["total_us"]
            if type(total) is not int or not 0 <= total <= 2**63 - 1:
                raise InvalidMetric(f"details.pressure.{resource}.{mode}.total_us is invalid")
            clean[resource][mode]["total_us"] = total
    return clean


def validate_details(details: object) -> dict:
    if not isinstance(details, dict) or set(details) - DETAIL_KEYS:
        raise InvalidMetric("details must be an object with supported categories")
    clean = {}
    if "filesystems_truncated" in details:
        if type(details["filesystems_truncated"]) is not bool:
            raise InvalidMetric("details.filesystems_truncated must be a boolean")
        clean["filesystems_truncated"] = details["filesystems_truncated"]
    if "clock" in details:
        clean["clock"] = _validate_clock(details["clock"])
    if "containers" in details:
        clean["containers"] = _validate_containers(details["containers"])
    if "pressure" in details:
        clean["pressure"] = _validate_pressure(details["pressure"])
    if "cpu_times" in details:
        item = details["cpu_times"]
        if not isinstance(item, dict) or set(item) != {"iowait_percent", "steal_percent"}:
            raise InvalidMetric("details.cpu_times has invalid fields")
        clean["cpu_times"] = {
            key: _detail_number(item[key], f"cpu_times.{key}", percent=True)
            for key in ("iowait_percent", "steal_percent")
        }
    if "swap" in details:
        item = details["swap"]
        if not isinstance(item, dict) or set(item) != {"total_bytes", "free_bytes", "used_percent"}:
            raise InvalidMetric("details.swap has invalid fields")
        clean["swap"] = {
            "total_bytes": _detail_number(item["total_bytes"], "swap.total_bytes", integer=True),
            "free_bytes": _detail_number(item["free_bytes"], "swap.free_bytes", integer=True),
            "used_percent": _detail_number(item["used_percent"], "swap.used_percent", percent=True),
        }
        if clean["swap"]["free_bytes"] > clean["swap"]["total_bytes"]:
            raise InvalidMetric("details.swap free_bytes exceeds total_bytes")
    for key, name_key, max_name, numeric_fields in (
        ("filesystems", "mountpoint", 128, {"total_bytes": "int", "available_bytes": "int", "used_percent": "percent",
                                             "inodes_total": "int", "inodes_available": "int", "inodes_used_percent": "percent"}),
        ("interfaces", "name", 64, {"rx_bytes": "int", "tx_bytes": "int", "rx_errors": "int", "tx_errors": "int"}),
        ("disk_io", "device", 64, {"read_bytes": "int", "write_bytes": "int"}),
    ):
        if key not in details:
            continue
        items = details[key]
        if not isinstance(items, list) or len(items) > 16:
            raise InvalidMetric(f"details.{key} must contain at most 16 items")
        clean_items = []
        seen = set()
        for item in items:
            extra = {"fstype"} if key == "filesystems" else set()
            if not isinstance(item, dict) or set(item) != {name_key, *numeric_fields, *extra}:
                raise InvalidMetric(f"details.{key} item has invalid fields")
            name = _detail_name(item[name_key], f"{key}.{name_key}", max_name)
            if name in seen:
                raise InvalidMetric(f"details.{key} contains duplicate names")
            seen.add(name)
            clean_item = {name_key: name}
            if key == "filesystems":
                clean_item["fstype"] = _detail_name(item["fstype"], "filesystems.fstype", 32)
            for field, kind in numeric_fields.items():
                clean_item[field] = _detail_number(item[field], f"{key}.{field}", integer=kind == "int", percent=kind == "percent")
            if key == "filesystems":
                if clean_item["available_bytes"] > clean_item["total_bytes"] or clean_item["inodes_available"] > clean_item["inodes_total"]:
                    raise InvalidMetric("details.filesystems available exceeds total")
            clean_items.append(clean_item)
        clean[key] = clean_items
    for key in ("load5", "load15"):
        if key in details:
            clean[key] = _detail_number(details[key], key)
    if "processes" in details:
        item = details["processes"]
        if not isinstance(item, dict) or set(item) != {"running", "blocked"}:
            raise InvalidMetric("details.processes has invalid fields")
        clean["processes"] = {key: _detail_number(item[key], f"processes.{key}", integer=True) for key in ("running", "blocked")}
    if "top_processes" in details:
        items = details["top_processes"]
        if not isinstance(items, list) or len(items) > 10:
            raise InvalidMetric("details.top_processes must contain at most 10 items")
        clean_items = []
        seen = set()
        for item in items:
            if not isinstance(item, dict) or set(item) != {"pid", "name", "rss_bytes"}:
                raise InvalidMetric("details.top_processes item has invalid fields")
            pid = item["pid"]
            name = item["name"]
            rss = item["rss_bytes"]
            if (type(pid) is not int or not 1 <= pid <= 2**31 - 1 or pid in seen
                    or not isinstance(name, str) or not PROCESS_NAME.fullmatch(name)
                    or type(rss) is not int or not 0 < rss <= 2**63 - 1):
                raise InvalidMetric("details.top_processes item is invalid")
            seen.add(pid)
            clean_items.append({"pid": pid, "name": name, "rss_bytes": rss})
        clean["top_processes"] = clean_items
    if "services" in details:
        item = details["services"]
        if not isinstance(item, dict) or set(item) != {"failed_count", "units"}:
            raise InvalidMetric("details.services has invalid fields")
        failed_count = _detail_number(item["failed_count"], "services.failed_count", integer=True)
        units = item["units"]
        if not isinstance(units, list) or len(units) > 16:
            raise InvalidMetric("details.services.units must contain at most 16 items")
        clean_units = []
        seen = set()
        for unit in units:
            if not isinstance(unit, dict) or set(unit) != {"name", "active", "sub"}:
                raise InvalidMetric("details.services unit has invalid fields")
            name = unit["name"]
            active = unit["active"]
            sub = unit["sub"]
            if (not isinstance(name, str) or not SERVICE_NAME.fullmatch(name) or name in seen or
                    active not in ("active", "inactive", "failed", "activating", "deactivating") or
                    not isinstance(sub, str) or not re.fullmatch(r"[a-z-]{1,32}", sub)):
                raise InvalidMetric("details.services unit is invalid")
            seen.add(name)
            clean_units.append({"name": name, "active": active, "sub": sub})
        clean["services"] = {"failed_count": failed_count, "units": clean_units}
    if "journal_units" in details:
        units = details["journal_units"]
        if (not isinstance(units, list) or not 1 <= len(units) <= 16 or
                any(not isinstance(unit, str) or not UNIT_NAME.fullmatch(unit) for unit in units) or
                len(set(units)) != len(units)):
            raise InvalidMetric("details.journal_units must contain 1–16 unique .service names")
        clean["journal_units"] = list(units)
    if len(json.dumps(clean, ensure_ascii=False, separators=(",", ":")).encode("utf-8")) > 12000:
        raise InvalidMetric("details exceeds 12 KiB")
    return clean


def validate_metric(payload: object, now: float | None = None) -> dict:
    if not isinstance(payload, dict):
        raise InvalidMetric("Expected a JSON object")
    if now is None:
        now = time.time()
    allowed = set(METRIC_FIELDS + OPTIONAL_FIELDS + ("collected_at", "details"))
    if set(payload) - allowed:
        raise InvalidMetric("Unknown metric fields")
    if set(METRIC_FIELDS + ("collected_at",)) - set(payload):
        raise InvalidMetric("Missing required metric fields")
    clean = {}
    for field in METRIC_FIELDS + OPTIONAL_FIELDS + ("collected_at",):
        if field not in payload:
            continue
        value = payload[field]
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
            raise InvalidMetric(f"{field} must be a finite number")
        if field in PERCENT_FIELDS and not 0 <= value <= 100:
            raise InvalidMetric(f"{field} must be between 0 and 100")
        if field in NONNEGATIVE_FIELDS and value < 0:
            raise InvalidMetric(f"{field} must be nonnegative")
        if field not in PERCENT_FIELDS and field != "load1":
            if value > 2**63 - 1 or int(value) != value:
                raise InvalidMetric(f"{field} must be a 64-bit integer")
        clean[field] = float(value) if field in PERCENT_FIELDS or field == "load1" else int(value)
    if "details" in payload:
        clean["details"] = validate_details(payload["details"])
    skew = abs(clean["collected_at"] - now)
    clock = clean.get("details", {}).get("clock", {})
    unsynchronized = (clock.get("ntp_synchronized") is False and
                      abs(clock.get("system_utc_epoch", 0) - clean["collected_at"]) <= 10 and
                      skew <= 86400)
    if skew > 300 and not unsynchronized:
        raise InvalidMetric("collected_at differs from hub clock by more than five minutes")
    if skew > 30 and unsynchronized:
        # Graphs use Hub receipt time when the source clock is known to be
        # unreliable. Its own UTC epoch remains visible in diagnostics.
        clean["collected_at"] = int(now)
    return clean


def root_inode_percent(details: dict) -> float | None:
    """Trust only a root mount with supported, internally consistent counters."""
    filesystems = details.get("filesystems")
    if not isinstance(filesystems, list):
        return None
    root = next((item for item in filesystems if item["mountpoint"] == "/"), None)
    if root is None:
        return None
    total, available = root["inodes_total"], root["inodes_available"]
    if total <= 0 or not 0 <= available <= total:
        return None
    used = round(100.0 * (1 - available / total), 2)
    if abs(root["inodes_used_percent"] - used) > 0.05:
        return None
    return used


class Store(AgentMaintenanceStore, ServerACLStore, AccountStore, CheckStore,
            EnrollmentStore, AgentManagementStore):
    def __init__(self, path: str | Path, *, offline_seconds: int = 120, thresholds: dict | None = None):
        self.path = str(path)
        self.offline_seconds = offline_seconds
        self.thresholds = DEFAULT_THRESHOLDS | (thresholds or {})
        # Process names are transient diagnostics. Keep only the newest report
        # in memory; historical metrics never persist individual processes.
        self._processes_lock = threading.Lock()
        self._latest_processes: dict[str, tuple[int, int, list[dict] | None]] = {}
        # Container names and image tags are transient diagnostics. Persisting
        # them every 30 seconds would inflate SQLite and retain old inventory.
        self._latest_containers: dict[str, tuple[int, int, dict | None]] = {}
        # Journal text and process names stay transient. Keep at most 32 recent
        # bounded results in this Hub process; never persist them in SQLite.
        self._journal_lock = threading.RLock()
        self._journal_outputs: dict[str, tuple[float, str]] = {}

    def _prune_journal_outputs(self):
        now = time.monotonic()
        self._journal_outputs = {key: value for key, value in self._journal_outputs.items()
                                 if value[0] > now}
        while len(self._journal_outputs) > JOURNAL_OUTPUT_LIMIT:
            oldest = min(self._journal_outputs, key=lambda key: self._journal_outputs[key][0])
            self._journal_outputs.pop(oldest, None)

    def prune_journal_outputs(self):
        """Run from Hub's ten-second maintenance sweep, including when idle."""
        with self._journal_lock:
            self._prune_journal_outputs()

    def _monitoring_settings(self, db) -> dict:
        row = db.execute("SELECT * FROM monitoring_settings WHERE singleton=1").fetchone()
        if row is not None:
            return {key: row[key] for key in ("high_cpu", "high_memory", "high_disk", "offline_seconds", "trigger_minutes", "revision")}
        # A missing row preserves command-line defaults until the first UI save.
        return {**self.thresholds, "offline_seconds": self.offline_seconds, "trigger_minutes": 0, "revision": 0}

    def monitoring_settings(self) -> dict:
        with self.connection() as db:
            return self._monitoring_settings(db)

    def save_monitoring_settings(self, payload: object, *, session_token: str | None = None) -> dict:
        fields = {"high_cpu", "high_memory", "high_disk", "offline_seconds", "trigger_minutes", "revision"}
        if not isinstance(payload, dict) or set(payload) not in (fields, fields - {"trigger_minutes"}):
            raise ValueError("Expected high_cpu, high_memory, high_disk, offline_seconds, optional trigger_minutes and revision")
        values = {}
        for key in ("high_cpu", "high_memory", "high_disk"):
            value = payload[key]
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not 1 <= value <= 100 or not math.isfinite(value):
                raise ValueError(f"{key} must be a number between 1 and 100 percent")
            values[key] = float(value)
        offline = payload["offline_seconds"]
        if isinstance(offline, bool) or not isinstance(offline, int) or not 10 <= offline <= 86400:
            raise ValueError("offline_seconds must be an integer between 10 and 86400")
        trigger = payload.get("trigger_minutes")
        if "trigger_minutes" in payload and (type(trigger) is not int or not 0 <= trigger <= 1440):
            raise ValueError("trigger_minutes must be an integer between 0 and 1440")
        revision = payload["revision"]
        if isinstance(revision, bool) or not isinstance(revision, int) or revision < 0:
            raise ValueError("revision must be a nonnegative integer")
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            identity = self._require_unrestricted_admin(db, session_token)
            current = self._monitoring_settings(db)
            if current["revision"] != revision:
                raise MonitoringSettingsConflict()
            if trigger is None:
                trigger = current["trigger_minutes"]
            next_revision = revision + 1
            db.execute("""INSERT INTO monitoring_settings
                (singleton, high_cpu, high_memory, high_disk, offline_seconds, trigger_minutes, revision)
                VALUES (1, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(singleton) DO UPDATE SET high_cpu=excluded.high_cpu,
                    high_memory=excluded.high_memory, high_disk=excluded.high_disk,
                    offline_seconds=excluded.offline_seconds, trigger_minutes=excluded.trigger_minutes,
                    revision=excluded.revision""",
                       (values["high_cpu"], values["high_memory"], values["high_disk"], offline, trigger, next_revision))
            result = {**values, "offline_seconds": offline, "trigger_minutes": trigger, "revision": next_revision}
            self._audit_account(db, identity, "monitoring_settings_changed", details={
                "previous": current, "current": result})
            return result

    @staticmethod
    def _pressure_settings(db) -> dict:
        row = db.execute("SELECT * FROM pressure_alert_settings WHERE singleton=1").fetchone()
        if row is None:
            return {"thresholds": {kind: None for kind in PRESSURE_ALERT_FIELDS},
                    "hold_seconds": PRESSURE_ALERT_DEFAULT_HOLD_SECONDS, "revision": 0}
        thresholds = json.loads(row["thresholds_json"])
        return {"thresholds": thresholds, "hold_seconds": row["hold_seconds"],
                "revision": row["revision"]}

    def pressure_settings(self) -> dict:
        with self.connection() as db:
            return self._pressure_settings(db)

    @staticmethod
    def _container_alert_settings(db, server_id: str) -> dict:
        row = db.execute("""SELECT rules_json,hold_seconds,revision,last_observed_at
                            FROM container_alert_settings WHERE server_id=?""",
                         (server_id,)).fetchone()
        if row is None:
            return {"revision": 0, "hold_seconds": CONTAINER_ALERT_DEFAULT_HOLD,
                    "rules": [], "last_observed_at": None}
        return {"revision": row["revision"], "hold_seconds": row["hold_seconds"],
                "rules": json.loads(row["rules_json"]),
                "last_observed_at": row["last_observed_at"]}

    def _container_alert_evidence(self, db, server_id: str, now: int) -> dict:
        server = db.execute("SELECT last_seen FROM servers WHERE id=?", (server_id,)).fetchone()
        if server is None:
            raise KeyError("Server not found")
        row = db.execute("SELECT id,collected_at FROM metrics WHERE server_id=? ORDER BY id DESC LIMIT 1",
                         (server_id,)).fetchone()
        with self._processes_lock:
            cached = self._latest_containers.get(server_id)
        snapshot = (cached[2] if row is not None and cached is not None and
                    cached[1] == row["id"] else None)
        return container_alert_evidence(
            snapshot, metric_collected_at=row["collected_at"] if row else 0,
            received_at=server["last_seen"] or 0, now=now)

    def _container_alert_public(self, db, server_id: str, now: int) -> dict:
        settings = self._container_alert_settings(db, server_id)
        source = self._container_alert_evidence(db, server_id, now)
        return {"revision": settings["revision"], "hold_seconds": settings["hold_seconds"],
                "rules": settings["rules"], "source_status": source["source_status"],
                "observed_at": source["observed_at"],
                "observations": [container_alert_observation(rule, source)
                                 for rule in settings["rules"]]}

    def container_alert_settings(self, server_id: str, *, session_token: str | None = None,
                                 now: int | None = None) -> dict:
        now = int(time.time()) if now is None else now
        with self.connection() as db:
            self._require_server_session(db, session_token, server_id, "viewer")
            return self._container_alert_public(db, server_id, now)

    def _retire_container_alert(self, db, server_id: str, name: str, now: int) -> None:
        event = self._set_incident(db, server_id, container_alert_kind(name), False, now,
                                   subject=name)
        if event is None:
            return
        db.execute("DELETE FROM maintenance_deferred WHERE incident_id=?", (event["id"],))
        db.execute("""UPDATE incident_outbox SET dropped_at=?, lease_until=NULL
                      WHERE incident_id=? AND delivered_at IS NULL AND dropped_at IS NULL""",
                   (now, event["id"]))

    def save_container_alert_settings(self, server_id: str, payload: object, *,
                                      session_token: str | None = None,
                                      now: int | None = None) -> dict:
        revision, hold, rules = validate_container_alert_settings(payload)
        now = int(time.time()) if now is None else now
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            identity = self._require_server_session(db, session_token, server_id, "admin")
            if db.execute("SELECT 1 FROM servers WHERE id=?", (server_id,)).fetchone() is None:
                raise KeyError("Server not found")
            current = self._container_alert_settings(db, server_id)
            if current["revision"] != revision:
                raise ContainerAlertConflict()
            old_rules = {rule["name"]: rule for rule in current["rules"]}
            new_rules = {rule["name"]: rule for rule in rules}
            newly_selected = set(new_rules) - set(old_rules)
            if newly_selected:
                source = self._container_alert_evidence(db, server_id, now)
                if source["source_status"] != "ok" or not newly_selected <= source["names"]:
                    raise ContainerAlertInventoryUnavailable()
            changed = (rules != current["rules"] or hold != current["hold_seconds"])
            changed_names = {name for name, old in old_rules.items()
                             if name not in new_rules or old != new_rules[name] or
                             hold != current["hold_seconds"]}
            for name in changed_names:
                self._retire_container_alert(db, server_id, name, now)
            if changed:
                # A policy edit cannot reuse an old breach's hold interval.
                for name in set(old_rules) | set(new_rules):
                    db.execute("DELETE FROM incident_candidates WHERE server_id=? AND kind=?",
                               (server_id, container_alert_kind(name)))
            db.execute("""INSERT INTO container_alert_settings
                         (server_id,rules_json,hold_seconds,revision,last_observed_at)
                         VALUES (?,?,?,?,?) ON CONFLICT(server_id) DO UPDATE SET
                         rules_json=excluded.rules_json,hold_seconds=excluded.hold_seconds,
                         revision=excluded.revision,last_observed_at=excluded.last_observed_at""",
                       (server_id, json.dumps(rules, separators=(",", ":")), hold, revision + 1,
                        None if changed else current["last_observed_at"]))
            self._audit_account(db, identity, "container_alert_settings_changed", server_id,
                                details={"previous_revision": revision, "revision": revision + 1,
                                         "rule_count": len(rules),
                                         "names_sha256": hashlib.sha256(
                                             "\0".join(sorted(new_rules)).encode("ascii")).hexdigest()},
                                now=now)
            return self._container_alert_public(db, server_id, now)

    @staticmethod
    def _filesystem_alert_settings(db, server_id: str) -> dict:
        row = db.execute("""SELECT rules_json,hold_seconds,revision,last_observed_at
                            FROM filesystem_alert_settings WHERE server_id=?""",
                         (server_id,)).fetchone()
        if row is None:
            return {"revision": 0, "hold_seconds": FILESYSTEM_ALERT_DEFAULT_HOLD,
                    "rules": [], "last_observed_at": None}
        return {"revision": row["revision"], "hold_seconds": row["hold_seconds"],
                "rules": json.loads(row["rules_json"]),
                "last_observed_at": row["last_observed_at"]}

    @staticmethod
    def _filesystem_alert_evidence(db, server_id: str, now: int) -> dict:
        row = db.execute("""SELECT collected_at,received_at,details_json FROM metrics
                            WHERE server_id=? ORDER BY collected_at DESC,id DESC LIMIT 1""",
                         (server_id,)).fetchone()
        if row is None:
            return filesystem_alert_evidence(None, observed_at=None, received_at=0, now=now)
        return filesystem_alert_evidence(json.loads(row["details_json"]),
                                         observed_at=row["collected_at"],
                                         received_at=row["received_at"], now=now)

    def _filesystem_alert_public(self, db, server_id: str, now: int) -> dict:
        settings = self._filesystem_alert_settings(db, server_id)
        source = self._filesystem_alert_evidence(db, server_id, now)
        return {"server_id": server_id, "revision": settings["revision"], "hold_seconds": settings["hold_seconds"],
                "rules": settings["rules"], "source_status": source["source_status"],
                "observed_at": source["observed_at"],
                "filesystems": source["filesystems"],
                "observations": [filesystem_alert_observation(rule, source)
                                 for rule in settings["rules"]]}

    def filesystem_alert_settings(self, server_id: str, *, session_token: str | None = None,
                                  now: int | None = None) -> dict:
        now = int(time.time()) if now is None else now
        with self.connection() as db:
            self._require_server_session(db, session_token, server_id, "viewer")
            if db.execute("SELECT 1 FROM servers WHERE id=?", (server_id,)).fetchone() is None:
                raise KeyError("Server not found")
            return self._filesystem_alert_public(db, server_id, now)

    def _retire_filesystem_alert(self, db, server_id: str, path: str,
                                 metric: str, now: int) -> None:
        event = self._set_incident(db, server_id, filesystem_alert_kind(path, metric), False,
                                   now, subject=path)
        if event is None:
            return
        db.execute("DELETE FROM maintenance_deferred WHERE incident_id=?", (event["id"],))
        db.execute("""UPDATE incident_outbox SET dropped_at=?, lease_until=NULL
                      WHERE incident_id=? AND delivered_at IS NULL AND dropped_at IS NULL""",
                   (now, event["id"]))

    def save_filesystem_alert_settings(self, server_id: str, payload: object, *,
                                       session_token: str | None = None,
                                       now: int | None = None) -> dict:
        revision, hold, rules = validate_filesystem_alert_settings(payload)
        now = int(time.time()) if now is None else now
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            identity = self._require_server_session(db, session_token, server_id, "admin")
            if db.execute("SELECT 1 FROM servers WHERE id=?", (server_id,)).fetchone() is None:
                raise KeyError("Server not found")
            current = self._filesystem_alert_settings(db, server_id)
            if current["revision"] != revision:
                raise FilesystemAlertConflict()
            key = lambda rule: (rule["mountpoint"], rule["metric"])
            old_rules = {key(rule): rule for rule in current["rules"]}
            new_rules = {key(rule): rule for rule in rules}
            newly_selected = set(new_rules) - set(old_rules)
            if newly_selected:
                source = self._filesystem_alert_evidence(db, server_id, now)
                if source["source_status"] != "ok" or any(
                        source["measurements"].get(selected) is None for selected in newly_selected):
                    raise FilesystemAlertInventoryUnavailable()
            changed = rules != current["rules"] or hold != current["hold_seconds"]
            changed_keys = {selected for selected, old in old_rules.items()
                            if selected not in new_rules or old != new_rules[selected] or
                            hold != current["hold_seconds"]}
            for path, metric in changed_keys:
                self._retire_filesystem_alert(db, server_id, path, metric, now)
            if changed:
                for path, metric in set(old_rules) | set(new_rules):
                    db.execute("DELETE FROM incident_candidates WHERE server_id=? AND kind=?",
                               (server_id, filesystem_alert_kind(path, metric)))
            db.execute("""INSERT INTO filesystem_alert_settings
                         (server_id,rules_json,hold_seconds,revision,last_observed_at)
                         VALUES (?,?,?,?,?) ON CONFLICT(server_id) DO UPDATE SET
                         rules_json=excluded.rules_json,hold_seconds=excluded.hold_seconds,
                         revision=excluded.revision,last_observed_at=excluded.last_observed_at""",
                       (server_id, json.dumps(rules, ensure_ascii=False, separators=(",", ":")),
                        hold, revision + 1, None if changed else current["last_observed_at"]))
            identities = "\0".join(sorted(f"{path}\0{metric}" for path, metric in new_rules))
            self._audit_account(db, identity, "filesystem_alert_settings_changed", server_id,
                                details={"previous_revision": revision, "revision": revision + 1,
                                         "rule_count": len(rules),
                                         "rules_sha256": hashlib.sha256(identities.encode("utf-8")).hexdigest()},
                                now=now)
            return self._filesystem_alert_public(db, server_id, now)

    def save_pressure_settings(self, payload: object, *, session_token: str | None = None) -> dict:
        """CAS policy for optional pressure alerts, separate from legacy rules."""
        if not isinstance(payload, dict) or set(payload) != {"thresholds", "hold_seconds", "revision"}:
            raise ValueError("Expected thresholds, hold_seconds and revision")
        supplied = payload["thresholds"]
        if not isinstance(supplied, dict) or set(supplied) != set(PRESSURE_ALERT_FIELDS):
            raise ValueError("Expected all supported pressure thresholds")
        thresholds = {}
        for kind, value in supplied.items():
            if value is None:
                thresholds[kind] = None
                continue
            if (isinstance(value, bool) or not isinstance(value, (int, float)) or
                    not 0 < value <= 100):
                raise ValueError(f"{kind} must be null or a percentage above 0 and at most 100")
            try:
                finite = math.isfinite(value)
            except OverflowError:
                finite = False
            if not finite:
                raise ValueError(f"{kind} must be a finite percentage")
            thresholds[kind] = float(value)
        hold = payload["hold_seconds"]
        if type(hold) is not int or not 30 <= hold <= 86400:
            raise ValueError("hold_seconds must be an integer between 30 and 86400")
        revision = payload["revision"]
        if type(revision) is not int or not 0 <= revision < 2**63 - 1:
            raise ValueError("revision must be a nonnegative 64-bit integer")
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            identity = self._require_unrestricted_admin(db, session_token)
            current = self._pressure_settings(db)
            if current["revision"] != revision:
                raise PressureSettingsConflict()
            result = {"thresholds": thresholds, "hold_seconds": hold,
                      "revision": revision + 1}
            db.execute("""INSERT INTO pressure_alert_settings
                          (singleton, thresholds_json, hold_seconds, revision)
                          VALUES (1, ?, ?, ?)
                          ON CONFLICT(singleton) DO UPDATE SET
                          thresholds_json=excluded.thresholds_json,
                          hold_seconds=excluded.hold_seconds, revision=excluded.revision""",
                       (json.dumps(thresholds, sort_keys=True, separators=(",", ":")),
                        hold, result["revision"]))
            changed = ([kind for kind in PRESSURE_ALERT_FIELDS
                        if current["thresholds"][kind] != thresholds[kind]]
                       if current["hold_seconds"] == hold else list(PRESSURE_ALERT_FIELDS))
            if changed:
                db.execute("DELETE FROM incident_candidates WHERE kind IN (" +
                           ",".join("?" for _ in changed) + ")", changed)
            disabled = [kind for kind in PRESSURE_ALERT_FIELDS
                        if current["thresholds"][kind] is not None and thresholds[kind] is None]
            if disabled:
                now = int(time.time())
                recoveries = []
                for kind in disabled:
                    servers = db.execute("""SELECT server_id FROM incidents
                                            WHERE kind=? AND state='firing'""", (kind,)).fetchall()
                    for server in servers:
                        event = self._set_incident(db, server["server_id"], kind, False, now)
                        if event:
                            recoveries.append(event)
                # Reuse the normal maintenance and durable per-recipient outbox
                # decision inside this same transaction, even without another
                # Agent sample. Never send a recovery for an unalerted breach.
                if recoveries:
                    self._maintenance_notifications(db, recoveries, now)
            self._audit_account(db, identity, "pressure_alert_settings_changed", details={
                "previous": current, "current": result})
            return result

    @staticmethod
    def _inode_settings(db) -> dict:
        row = db.execute("SELECT * FROM root_inode_alert_settings WHERE singleton=1").fetchone()
        if row is None:
            return {"threshold_percent": None,
                    "hold_seconds": ROOT_INODE_ALERT_DEFAULT_HOLD_SECONDS, "revision": 0}
        return {"threshold_percent": row["threshold_percent"],
                "hold_seconds": row["hold_seconds"], "revision": row["revision"]}

    def inode_settings(self) -> dict:
        with self.connection() as db:
            return self._inode_settings(db)

    def save_inode_settings(self, payload: object, *, session_token: str | None = None) -> dict:
        """Opt-in, CAS-protected rule independent of old monitoring clients."""
        if not isinstance(payload, dict) or set(payload) != {
                "threshold_percent", "hold_seconds", "revision"}:
            raise ValueError("Expected threshold_percent, hold_seconds and revision")
        threshold = payload["threshold_percent"]
        if threshold is not None:
            if (isinstance(threshold, bool) or not isinstance(threshold, (int, float)) or
                    not 0 < threshold <= 100):
                raise ValueError("threshold_percent must be null or above 0 and at most 100")
            try:
                finite = math.isfinite(threshold)
            except OverflowError:
                finite = False
            if not finite:
                raise ValueError("threshold_percent must be finite")
            threshold = float(threshold)
        hold = payload["hold_seconds"]
        if type(hold) is not int or not 30 <= hold <= 86400:
            raise ValueError("hold_seconds must be an integer between 30 and 86400")
        revision = payload["revision"]
        if type(revision) is not int or not 0 <= revision < 2**63 - 1:
            raise ValueError("revision must be a nonnegative 64-bit integer")
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            identity = self._require_unrestricted_admin(db, session_token)
            current = self._inode_settings(db)
            if current["revision"] != revision:
                raise InodeSettingsConflict()
            result = {"threshold_percent": threshold, "hold_seconds": hold,
                      "revision": revision + 1}
            db.execute("""INSERT INTO root_inode_alert_settings
                          (singleton, threshold_percent, hold_seconds, revision)
                          VALUES (1, ?, ?, ?)
                          ON CONFLICT(singleton) DO UPDATE SET
                          threshold_percent=excluded.threshold_percent,
                          hold_seconds=excluded.hold_seconds, revision=excluded.revision""",
                       (threshold, hold, result["revision"]))
            changed = (current["threshold_percent"] != threshold or
                       current["hold_seconds"] != hold)
            if changed:
                db.execute("DELETE FROM incident_candidates WHERE kind=?",
                           (ROOT_INODE_ALERT_KIND,))
                # The old incident described an old policy. End it as an
                # administrative retirement: no fabricated recovery, and no
                # queued notification from that old policy may be sent later.
                now = int(time.time())
                servers = db.execute("""SELECT server_id FROM incidents
                                        WHERE kind=? AND state='firing'""",
                                     (ROOT_INODE_ALERT_KIND,)).fetchall()
                for server in servers:
                    self._retire_root_inode_alert(db, server["server_id"], now)
            self._audit_account(db, identity, "root_inode_alert_settings_changed",
                                details={"previous": current, "current": result})
            return result

    @contextmanager
    def connection(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA busy_timeout=10000")
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def initialize(self, username: str, password: str):
        if not 1 <= len(username) <= 80 or not username.isprintable():
            raise ValueError("Username must contain 1–80 printable characters")
        if not 12 <= len(password) <= 1024:
            raise ValueError("Password must contain 12–1024 characters")
        if Path(self.path).exists():
            raise FileExistsError("Database already exists; init will not overwrite it")
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        salt = secrets.token_bytes(16)
        digest = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1)
        with self.connection() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript(USER_SCHEMA + ";" + SESSION_SCHEMA + ";" + SSH_GRANT_SCHEMA + ";" + """
                CREATE TABLE servers (
                    id TEXT PRIMARY KEY, name TEXT NOT NULL, agent_token_hash TEXT NOT NULL,
                    created_at INTEGER NOT NULL, last_seen INTEGER,
                    remote_commands_enabled INTEGER NOT NULL DEFAULT 0,
                    management_revision INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
                    collected_at INTEGER NOT NULL, received_at INTEGER NOT NULL,
                    cpu_percent REAL NOT NULL, memory_percent REAL NOT NULL, disk_percent REAL NOT NULL,
                    network_rx_bytes INTEGER NOT NULL, network_tx_bytes INTEGER NOT NULL,
                    load1 REAL NOT NULL, uptime_seconds INTEGER NOT NULL,
                    memory_total_bytes INTEGER, memory_available_bytes INTEGER,
                    disk_total_bytes INTEGER, disk_available_bytes INTEGER,
                    details_json TEXT NOT NULL DEFAULT '{}'
                );
                CREATE INDEX metrics_server_time ON metrics(server_id, collected_at DESC, id DESC);
                CREATE TABLE incidents (
                    id TEXT PRIMARY KEY, server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
                    kind TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('firing','resolved')),
                    opened_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, resolved_at INTEGER,
                    acknowledged_at INTEGER, current_value REAL, threshold REAL,
                    alerted_at INTEGER, subject TEXT
                );
                CREATE INDEX incidents_state_time ON incidents(state, updated_at DESC);
                CREATE UNIQUE INDEX one_active_incident ON incidents(server_id, kind) WHERE state='firing';
                CREATE TABLE incident_outbox (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
                    chat_id INTEGER NOT NULL,
                    event_type TEXT NOT NULL CHECK(event_type IN ('firing','recovery','reminder')),
                    source_window_id TEXT NOT NULL DEFAULT '',
                    event_at INTEGER NOT NULL, value REAL,
                    attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at INTEGER NOT NULL,
                    lease_generation INTEGER NOT NULL DEFAULT 0, lease_until INTEGER,
                    delivered_at INTEGER, dropped_at INTEGER,
                    UNIQUE(incident_id, chat_id, event_type, source_window_id)
                );
                CREATE INDEX incident_outbox_due ON incident_outbox(next_attempt_at, id)
                    WHERE delivered_at IS NULL AND dropped_at IS NULL;
                CREATE INDEX incident_outbox_order ON incident_outbox(incident_id, chat_id, id)
                    WHERE delivered_at IS NULL AND dropped_at IS NULL;
                CREATE TABLE incident_candidates (
                    server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
                    kind TEXT NOT NULL, first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL,
                    current_value REAL, threshold REAL,
                    PRIMARY KEY(server_id, kind)
                );
                CREATE TABLE maintenance_windows (
                    id TEXT PRIMARY KEY, server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
                    starts_at INTEGER NOT NULL, ends_at INTEGER NOT NULL CHECK(ends_at > starts_at),
                    reason TEXT NOT NULL, cancelled_at INTEGER
                );
                CREATE INDEX maintenance_server_time ON maintenance_windows(server_id, starts_at DESC);
                CREATE TABLE maintenance_deferred (
                    incident_id TEXT PRIMARY KEY REFERENCES incidents(id) ON DELETE CASCADE,
                    server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
                    created_at INTEGER NOT NULL
                );
                CREATE TABLE monitoring_settings (
                    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                    high_cpu REAL NOT NULL, high_memory REAL NOT NULL, high_disk REAL NOT NULL,
                    offline_seconds INTEGER NOT NULL, trigger_minutes INTEGER NOT NULL DEFAULT 0,
                    revision INTEGER NOT NULL
                );
                CREATE TABLE pressure_alert_settings (
                    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                    thresholds_json TEXT NOT NULL,
                    hold_seconds INTEGER NOT NULL, revision INTEGER NOT NULL
                );
                CREATE TABLE root_inode_alert_settings (
                    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                    threshold_percent REAL,
                    hold_seconds INTEGER NOT NULL, revision INTEGER NOT NULL
                );
                CREATE TABLE bot_users (
                    user_id INTEGER NOT NULL, chat_id INTEGER NOT NULL,
                    role TEXT NOT NULL CHECK(role IN ('viewer','operator','admin')),
                    first_name TEXT NOT NULL DEFAULT '', last_name TEXT NOT NULL DEFAULT '',
                    username TEXT NOT NULL DEFAULT '',
                    PRIMARY KEY(user_id, chat_id)
                );
                CREATE TABLE bot_pairing_requests (
                    user_id INTEGER PRIMARY KEY, chat_id INTEGER NOT NULL CHECK(chat_id=user_id),
                    first_name TEXT NOT NULL, last_name TEXT NOT NULL, username TEXT NOT NULL,
                    requested_at INTEGER NOT NULL,
                    state TEXT NOT NULL CHECK(state IN ('pending','rejected')),
                    rejected_at INTEGER
                );
                CREATE TABLE telegram_bot_info (
                    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                    token_hash TEXT NOT NULL, username TEXT
                );
                CREATE TABLE telegram_update_cursors (
                    token_hash TEXT PRIMARY KEY, next_offset INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                );
                CREATE TABLE pending_commands (
                    code_hash TEXT PRIMARY KEY, server_id TEXT NOT NULL REFERENCES servers(id),
                    actor_user_id INTEGER NOT NULL, chat_id INTEGER NOT NULL,
                    command TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL
                );
                CREATE TABLE jobs (
                    id TEXT PRIMARY KEY, server_id TEXT NOT NULL REFERENCES servers(id),
                    actor_user_id INTEGER NOT NULL, chat_id INTEGER NOT NULL,
                    source TEXT NOT NULL DEFAULT 'telegram' CHECK(source IN ('telegram','web')),
                    session_token_hash TEXT,
                    idempotency_key TEXT,
                    command_sha256 TEXT,
                    control_kind TEXT NOT NULL DEFAULT 'generic'
                        CHECK(control_kind IN ('generic','vpn','amnezia','service','container')),
                    command TEXT NOT NULL, state TEXT NOT NULL,
                    created_at INTEGER NOT NULL, delivered_at INTEGER, completed_at INTEGER,
                    exit_code INTEGER, output TEXT
                );
                CREATE INDEX jobs_server_state ON jobs(server_id, state, created_at);
                CREATE UNIQUE INDEX web_job_request_key ON jobs(session_token_hash, idempotency_key)
                    WHERE idempotency_key IS NOT NULL;
                CREATE TABLE container_control_jobs (
                    job_id TEXT PRIMARY KEY REFERENCES jobs(id) ON DELETE CASCADE,
                    engine TEXT NOT NULL CHECK(engine='docker'),
                    action TEXT NOT NULL CHECK(action IN ('status','start','stop','restart')),
                    container_id TEXT NOT NULL CHECK(length(container_id)=64)
                );
                CREATE TABLE audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL,
                    actor TEXT NOT NULL, action TEXT NOT NULL, server_id TEXT,
                    subject_id TEXT, details TEXT NOT NULL DEFAULT '{}'
                );
                CREATE INDEX audit_events_time ON audit_events(at DESC);
            """)
            migrate_checks(db)
            migrate_enrollments(db)
            migrate_agent_management(db)
            migrate_agent_maintenance(db)
            migrate_server_acl(db)
            db.execute("""CREATE TABLE IF NOT EXISTS vpn_inventory (
                server_id TEXT PRIMARY KEY REFERENCES servers(id) ON DELETE CASCADE,
                received_at INTEGER NOT NULL,
                projection_json TEXT NOT NULL
            )""")
            migrate_container_alerts(db)
            migrate_filesystem_alerts(db)
            now = int(time.time())
            db.execute("INSERT INTO hub_users VALUES (?, ?, ?, ?, 'admin', 1, 1, ?, ?)",
                       (str(uuid.uuid4()), username, salt, digest, now, now))
        os.chmod(self.path, 0o600)

    def migrate(self):
        """Add columns introduced since the first MVP without resetting the database."""
        with self.connection() as db:
            # DDL must roll back with its backfill. Otherwise an interruption
            # can leave a new table that makes the next startup skip migration.
            db.execute("BEGIN IMMEDIATE")
            migrate_accounts(db)
            db.execute("""CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL,
                actor TEXT NOT NULL, action TEXT NOT NULL, server_id TEXT,
                subject_id TEXT, details TEXT NOT NULL DEFAULT '{}'
            )""")
            db.execute("CREATE INDEX IF NOT EXISTS audit_events_time ON audit_events(at DESC)")
            db.execute("""CREATE TABLE IF NOT EXISTS incidents (
                id TEXT PRIMARY KEY, server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
                kind TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('firing','resolved')),
                opened_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, resolved_at INTEGER,
                acknowledged_at INTEGER, current_value REAL, threshold REAL, alerted_at INTEGER,
                subject TEXT
            )""")
            db.execute("CREATE INDEX IF NOT EXISTS incidents_state_time ON incidents(state, updated_at DESC)")
            db.execute("CREATE UNIQUE INDEX IF NOT EXISTS one_active_incident ON incidents(server_id, kind) WHERE state='firing'")
            had_outbox = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='incident_outbox'").fetchone() is not None
            db.execute("""CREATE TABLE IF NOT EXISTS incident_outbox (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
                chat_id INTEGER NOT NULL,
                event_type TEXT NOT NULL CHECK(event_type IN ('firing','recovery','reminder')),
                source_window_id TEXT NOT NULL DEFAULT '',
                event_at INTEGER NOT NULL, value REAL,
                attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at INTEGER NOT NULL,
                lease_generation INTEGER NOT NULL DEFAULT 0, lease_until INTEGER,
                delivered_at INTEGER, dropped_at INTEGER,
                UNIQUE(incident_id, chat_id, event_type, source_window_id)
            )""")
            db.execute("""CREATE INDEX IF NOT EXISTS incident_outbox_due
                          ON incident_outbox(next_attempt_at, id)
                          WHERE delivered_at IS NULL AND dropped_at IS NULL""")
            db.execute("""CREATE INDEX IF NOT EXISTS incident_outbox_order
                          ON incident_outbox(incident_id, chat_id, id)
                          WHERE delivered_at IS NULL AND dropped_at IS NULL""")
            db.execute("""CREATE TABLE IF NOT EXISTS maintenance_windows (
                id TEXT PRIMARY KEY, server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
                starts_at INTEGER NOT NULL, ends_at INTEGER NOT NULL CHECK(ends_at > starts_at),
                reason TEXT NOT NULL, cancelled_at INTEGER
            )""")
            db.execute("CREATE INDEX IF NOT EXISTS maintenance_server_time ON maintenance_windows(server_id, starts_at DESC)")
            db.execute("""CREATE TABLE IF NOT EXISTS incident_candidates (
                server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
                kind TEXT NOT NULL, first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL,
                current_value REAL, threshold REAL,
                PRIMARY KEY(server_id, kind)
            )""")
            db.execute("""CREATE TABLE IF NOT EXISTS maintenance_deferred (
                incident_id TEXT PRIMARY KEY REFERENCES incidents(id) ON DELETE CASCADE,
                server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
                created_at INTEGER NOT NULL
            )""")
            db.execute("""CREATE TABLE IF NOT EXISTS monitoring_settings (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                high_cpu REAL NOT NULL, high_memory REAL NOT NULL, high_disk REAL NOT NULL,
                offline_seconds INTEGER NOT NULL, trigger_minutes INTEGER NOT NULL DEFAULT 0,
                revision INTEGER NOT NULL
            )""")
            db.execute("""CREATE TABLE IF NOT EXISTS pressure_alert_settings (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                thresholds_json TEXT NOT NULL,
                hold_seconds INTEGER NOT NULL, revision INTEGER NOT NULL
            )""")
            db.execute("""CREATE TABLE IF NOT EXISTS root_inode_alert_settings (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                threshold_percent REAL,
                hold_seconds INTEGER NOT NULL, revision INTEGER NOT NULL
            )""")
            settings_columns = {row["name"] for row in db.execute("PRAGMA table_info(monitoring_settings)")}
            if "trigger_minutes" not in settings_columns:
                db.execute("ALTER TABLE monitoring_settings ADD COLUMN trigger_minutes INTEGER NOT NULL DEFAULT 0")
            incident_columns = {row["name"] for row in db.execute("PRAGMA table_info(incidents)")}
            if "subject" not in incident_columns:
                db.execute("ALTER TABLE incidents ADD COLUMN subject TEXT")
            if "alerted_at" not in incident_columns:
                db.execute("ALTER TABLE incidents ADD COLUMN alerted_at INTEGER")
                # Legacy active incidents may already have emitted a firing alert.
                # Maintenance-deferred incidents were deliberately silent.
                db.execute("""UPDATE incidents SET alerted_at=opened_at WHERE state='firing'
                              AND id NOT IN (SELECT incident_id FROM maintenance_deferred)""")
            db.execute("""CREATE TABLE IF NOT EXISTS bot_users (
                user_id INTEGER NOT NULL, chat_id INTEGER NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('viewer','operator','admin')),
                first_name TEXT NOT NULL DEFAULT '', last_name TEXT NOT NULL DEFAULT '',
                username TEXT NOT NULL DEFAULT '', PRIMARY KEY(user_id, chat_id)
            )""")
            bot_columns = {row["name"] for row in db.execute("PRAGMA table_info(bot_users)")}
            for column in ("first_name", "last_name", "username"):
                if column not in bot_columns:
                    db.execute(f"ALTER TABLE bot_users ADD COLUMN {column} TEXT NOT NULL DEFAULT ''")
            if not had_outbox:
                # Existing active alerts had already been handed to the old
                # in-memory sender. These markers preserve recovery ordering
                # without replaying an uncertain historical firing alert.
                db.execute("""INSERT OR IGNORE INTO incident_outbox
                              (incident_id, chat_id, event_type, event_at, next_attempt_at, delivered_at)
                              SELECT i.id, b.chat_id, 'firing', i.alerted_at, i.alerted_at, i.alerted_at
                              FROM incidents AS i CROSS JOIN bot_users AS b
                              WHERE i.state='firing' AND i.alerted_at IS NOT NULL""")
            db.execute("""CREATE TABLE IF NOT EXISTS bot_pairing_requests (
                user_id INTEGER PRIMARY KEY, chat_id INTEGER NOT NULL CHECK(chat_id=user_id),
                first_name TEXT NOT NULL, last_name TEXT NOT NULL, username TEXT NOT NULL,
                requested_at INTEGER NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('pending','rejected')),
                rejected_at INTEGER
            )""")
            db.execute("""CREATE TABLE IF NOT EXISTS telegram_bot_info (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                token_hash TEXT NOT NULL, username TEXT
            )""")
            db.execute("""CREATE TABLE IF NOT EXISTS telegram_update_cursors (
                token_hash TEXT PRIMARY KEY, next_offset INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            )""")
            columns = {row["name"] for row in db.execute("PRAGMA table_info(metrics)")}
            if "details_json" not in columns:
                db.execute("ALTER TABLE metrics ADD COLUMN details_json TEXT NOT NULL DEFAULT '{}' ")
            job_columns = {row["name"] for row in db.execute("PRAGMA table_info(jobs)")}
            if job_columns:
                if "source" not in job_columns:
                    db.execute("ALTER TABLE jobs ADD COLUMN source TEXT NOT NULL DEFAULT 'telegram' CHECK(source IN ('telegram','web'))")
                if "session_token_hash" not in job_columns:
                    db.execute("ALTER TABLE jobs ADD COLUMN session_token_hash TEXT")
                if "idempotency_key" not in job_columns:
                    db.execute("ALTER TABLE jobs ADD COLUMN idempotency_key TEXT")
                if "command_sha256" not in job_columns:
                    db.execute("ALTER TABLE jobs ADD COLUMN command_sha256 TEXT")
                if "control_kind" not in job_columns:
                    db.execute("""ALTER TABLE jobs ADD COLUMN control_kind TEXT NOT NULL DEFAULT 'generic'
                               CHECK(control_kind IN ('generic','vpn','amnezia','service','container'))""")
                historical_web_jobs = list(db.execute(
                    "SELECT id, command FROM jobs WHERE source='web' AND command_sha256 IS NULL AND command<>''"))
                for job in historical_web_jobs:
                    db.execute("UPDATE jobs SET command_sha256=? WHERE id=?",
                               (hashlib.sha256(job["command"].encode()).hexdigest(), job["id"]))
                db.execute("""CREATE UNIQUE INDEX IF NOT EXISTS web_job_request_key
                           ON jobs(session_token_hash, idempotency_key)
                           WHERE idempotency_key IS NOT NULL""")
                # The agent already received these commands; only queue entries need plaintext.
                db.execute("UPDATE jobs SET command='' WHERE state<>'queued' AND command<>''")
                _migrate_container_control_jobs(db)
            migrate_checks(db)
            migrate_enrollments(db)
            migrate_agent_management(db)
            migrate_agent_maintenance(db)
            migrate_server_acl(db)
            db.execute("""CREATE TABLE IF NOT EXISTS vpn_inventory (
                server_id TEXT PRIMARY KEY REFERENCES servers(id) ON DELETE CASCADE,
                received_at INTEGER NOT NULL,
                projection_json TEXT NOT NULL
            )""")
            migrate_container_alerts(db)
            migrate_filesystem_alerts(db)

    @contextmanager
    def authorized_admin_session(self, token: str):
        """Serialize an external admin side effect with logout/password change."""
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            self._require_unrestricted_admin(db, token)
            yield

    def server_commands_enabled(self, server_id: str) -> bool | None:
        with self.connection() as db:
            row = db.execute("SELECT remote_commands_enabled FROM servers WHERE id=?",
                             (server_id,)).fetchone()
        return bool(row["remote_commands_enabled"]) if row else None

    def terminal_access_valid(self, token_hash: str, server_id: str,
                              now: int | None = None) -> bool:
        """Check the login and server opt-in in one SQLite read snapshot."""
        now = int(time.time()) if now is None else now
        with self.connection() as db:
            row = db.execute("""SELECT u.* FROM sessions AS s JOIN hub_users AS u ON u.id=s.user_id
                JOIN servers AS v ON v.id=? WHERE s.token_hash=? AND s.expires_at>?
                AND u.enabled=1 AND u.role='admin' AND v.remote_commands_enabled=1""",
                (server_id, token_hash, now)).fetchone()
            return row is not None and self._user_allowed(db, row, server_id, "admin")

    def audit_terminal(self, action: str, server_id: str, terminal_id: str, *, session_token=None):
        if action not in ("terminal_opened", "terminal_closed", "terminal_exited"):
            raise ValueError("Invalid terminal audit action")
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            if action == "terminal_exited":
                self._audit(db, f"agent:{server_id}", action, server_id, terminal_id)
            else:
                identity = self._require_server_session(db, session_token, server_id, "admin")
                self._audit_account(db, identity, action, server_id, terminal_id)

    def audit_file(self, action: str, server_id: str, operation_id: str,
                   kind: str, path_hash: str, outcome: str | None = None, *, session_token=None):
        if action not in ("file_requested", "file_completed"):
            raise ValueError("Invalid file audit action")
        details = {"operation_id": operation_id, "kind": kind, "path_hash": path_hash}
        if outcome is not None:
            details["outcome"] = outcome
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            if action == "file_completed":
                self._audit(db, f"agent:{server_id}", action, server_id, operation_id, details=details)
            else:
                identity = self._require_server_session(db, session_token, server_id, "admin")
                self._audit_account(db, identity, action, server_id, operation_id, details=details)

    def audit_backup_request(self, request_key: str, *, session_token: str) -> None:
        try:
            if not isinstance(request_key, str) or str(uuid.UUID(request_key)) != request_key:
                raise ValueError("Invalid backup request key")
        except (AttributeError, ValueError) as exc:
            raise ValueError("Invalid backup request key") from exc
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            identity = self._require_unrestricted_admin(db, session_token)
            self._audit_account(db, identity, "backup_create_requested",
                                subject_id=request_key)

    def audit_host_backup_request(self, request_id: str, *, recover: bool,
                                  session_token: str) -> None:
        if (not isinstance(request_id, str) or
                re.fullmatch(r"[0-9a-f]{32}", request_id) is None or
                type(recover) is not bool):
            raise ValueError("Invalid host backup request")
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            identity = self._require_unrestricted_admin(db, session_token)
            self._audit_account(db, identity,
                                "host_backup_recovery_requested" if recover
                                else "host_backup_create_requested",
                                subject_id=request_id)

    def audit_release_feed_request(self, action: str, expected_state: str, *,
                                   session_token: str) -> None:
        if (action not in ("enable", "disable") or
                not isinstance(expected_state, str) or
                re.fullmatch(r"[0-9a-f]{64}", expected_state) is None):
            raise ValueError("Invalid release feed request")
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            identity = self._require_unrestricted_admin(db, session_token)
            self._audit_account(db, identity, "release_feed_" + action + "_requested",
                                details={"expected_state": expected_state})

    def audit_public_web_request(self, action: str, config_sha256: str, *,
                                 request_id: str | None, session_token: str) -> None:
        try:
            canonical_id = isinstance(request_id, str) and str(uuid.UUID(request_id)) == request_id
        except (AttributeError, ValueError):
            canonical_id = False
        if (action not in ("preview", "apply") or
                not isinstance(config_sha256, str) or
                re.fullmatch(r"[0-9a-f]{64}", config_sha256) is None or
                (action == "preview" and request_id is not None) or
                (action == "apply" and not canonical_id)):
            raise ValueError("Invalid public Web audit request")
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            identity = self._require_unrestricted_admin(db, session_token)
            self._audit_account(db, identity, "public_web_" + action + "_requested",
                                subject_id=request_id,
                                details={"config_sha256": config_sha256})

    def audit_local_web_request(self, action: str, config_sha256: str | None, *,
                                request_id: str | None, session_token: str) -> None:
        try:
            canonical_id = isinstance(request_id, str) and str(uuid.UUID(request_id)) == request_id
        except (AttributeError, ValueError):
            canonical_id = False
        if (action not in ("preview", "apply", "disable") or
                ((action == "disable") != (config_sha256 is None)) or
                (config_sha256 is not None and
                 (not isinstance(config_sha256, str) or
                  re.fullmatch(r"[0-9a-f]{64}", config_sha256) is None)) or
                (action == "preview" and request_id is not None) or
                (action != "preview" and not canonical_id)):
            raise ValueError("Invalid local Web audit request")
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            identity = self._require_unrestricted_admin(db, session_token)
            details = {"config_sha256": config_sha256} if config_sha256 is not None else {}
            self._audit_account(db, identity, "local_web_" + action + "_requested",
                                subject_id=request_id, details=details)

    def audit_restore_request(self, request_id: str, *, target_id: str | None = None,
                              recover: bool = False, session_token: str) -> None:
        try:
            if (not isinstance(request_id, str) or
                    str(uuid.UUID(request_id)) != request_id or
                    (not recover and
                     (not isinstance(target_id, str) or
                      str(uuid.UUID(target_id)) != target_id)) or
                    (recover and target_id is not None)):
                raise ValueError("Invalid restore request")
        except (AttributeError, ValueError) as exc:
            raise ValueError("Invalid restore request") from exc
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            identity = self._require_unrestricted_admin(db, session_token)
            self._audit_account(db, identity,
                                "backup_restore_recovery_requested" if recover
                                else "backup_restore_requested",
                                subject_id=request_id,
                                details={} if recover else {"backup_id": target_id})

    def logout(self, token: str):
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        with self._journal_lock:
            with self.connection() as db:
                db.execute("BEGIN IMMEDIATE")
                identity = self._session_row(db, token)
                ids = [row[0] for row in db.execute("SELECT id FROM jobs WHERE session_token_hash=?",
                                                      (token_hash,)).fetchall()]
                db.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash,))
                cancelled = db.execute("UPDATE jobs SET state='cancelled', command='', completed_at=? WHERE source='web' AND session_token_hash=? AND state='queued'",
                                       (int(time.time()), token_hash)).rowcount
                if cancelled:
                    self._audit_account(db, identity, "queued_web_jobs_cancelled", details={"count": cancelled, "reason": "logout"})
                if identity is not None:
                    self._audit_account(db, identity, "session_logout")
            for job_id in ids:
                self._journal_outputs.pop(job_id, None)

    def create_server(self, name: str, now: int | None = None, *, session_token: str | None = None) -> dict:
        if not isinstance(name, str) or not 1 <= len(name.strip()) <= 80 or not name.isprintable():
            raise ValueError("Server name must contain 1–80 printable characters")
        now = int(time.time()) if now is None else now
        server_id = str(uuid.uuid4())
        token = secrets.token_urlsafe(32)
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            identity = self._require_unrestricted_admin(db, session_token)
            db.execute("INSERT INTO servers (id, name, agent_token_hash, created_at, last_seen) VALUES (?, ?, ?, ?, NULL)",
                       (server_id, name.strip(), hashlib.sha256(token.encode()).hexdigest(), now))
            self._audit_account(db, identity, "server_created", server_id, now=now)
        return {"id": server_id, "name": name.strip(), "created_at": now, "agent_token": token}

    def rotate_agent_token(self, server_id: str, *, session_token: str | None = None) -> str | None:
        token = secrets.token_urlsafe(32)
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            identity = self._require_server_session(db, session_token, server_id, "admin")
            self._reject_agent_maintenance(db, server_id, int(time.time()))
            cursor = db.execute("UPDATE servers SET agent_token_hash=? WHERE id=?",
                                (hashlib.sha256(token.encode()).hexdigest(), server_id))
            if cursor.rowcount:
                db.execute("""UPDATE server_checks SET lease_id=NULL,lease_revision=NULL,
                    lease_until=NULL,lease_token_hash=NULL WHERE server_id=?""", (server_id,))
                self._audit_account(db, identity, "agent_token_rotated", server_id)
            return token if cursor.rowcount else None

    def agent_valid(self, server_id: str, token: str) -> bool:
        if not token or len(token) > 256:
            return False
        with self.connection() as db:
            row = db.execute("SELECT agent_token_hash FROM servers WHERE id=?", (server_id,)).fetchone()
        return row is not None and hmac.compare_digest(row["agent_token_hash"], hashlib.sha256(token.encode()).hexdigest())

    def put_vpn_inventory(self, server_id: str, snapshot: object, *, agent_token: str,
                          now: int | None = None) -> int:
        """Persist only the public projector output, never Agent-supplied JSON."""
        if (type(snapshot) is not dict or type(snapshot.get("schema_version")) is not int or
                snapshot["schema_version"] != 1 or type(snapshot.get("collected_at")) is not int or
                snapshot["collected_at"] < 0 or snapshot.get("source") != "docker_cli" or
                snapshot.get("source_status") not in ("ok", "error") or
                type(snapshot.get("services")) is not list):
            raise ValueError("Invalid VPN inventory")
        try:
            payload_size = len(json.dumps(snapshot, ensure_ascii=False, allow_nan=False,
                                          separators=(",", ":")).encode("utf-8"))
        except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
            raise ValueError("Invalid VPN inventory") from exc
        if payload_size > 65536:
            raise ValueError("Oversized VPN inventory")
        # Agent freshness was checked on its own host. Hub must use receipt
        # time, because clocks in different countries can differ or drift.
        projection = project_vpn_status(snapshot, now=snapshot["collected_at"])
        serialized = json.dumps(projection, ensure_ascii=False, separators=(",", ":"))
        if len(serialized.encode("utf-8")) > 65536:
            raise ValueError("Oversized projected VPN inventory")
        received_at = int(time.time()) if now is None else now
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            self._check_agent(db, server_id, agent_token)
            db.execute("""INSERT INTO vpn_inventory(server_id,received_at,projection_json)
                          VALUES(?,?,?) ON CONFLICT(server_id) DO UPDATE SET
                          received_at=excluded.received_at,projection_json=excluded.projection_json""",
                       (server_id, received_at, serialized))
        return received_at

    def remote_vpn_inventory(self, server_id: str, *, session_token: str,
                             now: int | None = None) -> dict:
        now = int(time.time()) if now is None else now
        with self.connection() as db:
            self._require_server_session(db, session_token, server_id, "viewer")
            row = db.execute("SELECT received_at,projection_json FROM vpn_inventory WHERE server_id=?",
                             (server_id,)).fetchone()
        if row is None:
            return {"server_id": server_id, "received_at": None,
                    "freshness": "unavailable", "vpn": empty_vpn_status()}
        projection = json.loads(row["projection_json"])
        received_at = row["received_at"]
        fresh = 0 <= now - received_at <= 90
        if not fresh:
            for source in (projection, projection["managed"], projection["amnezia_details"]):
                if source["source_status"] == "ok":
                    source["source_status"] = "stale"
        return {"server_id": server_id, "received_at": received_at,
                "freshness": "ok" if fresh else "stale", "vpn": projection}

    @staticmethod
    def _metric_from_row(row):
        if row is None:
            return None
        result = {field: row[field] for field in ("collected_at",) + METRIC_FIELDS + OPTIONAL_FIELDS}
        result["details"] = json.loads(row["details_json"]) if "details_json" in row.keys() else {}
        return result

    def servers(self, now: int | None = None, *, session_token=None, bot=None) -> list[dict]:
        now = int(time.time()) if now is None else now
        with self.connection() as db:
            db.execute("BEGIN")
            identity = self._require_role_session(db, session_token, "viewer") if session_token is not None else None
            visible = self._visible_server_ids(db, identity=identity, bot=bot)
            offline_seconds = self._monitoring_settings(db)["offline_seconds"]
            maintenance = {row["server_id"]: dict(row) for row in db.execute(
                """SELECT id, server_id, starts_at, ends_at, reason FROM maintenance_windows
                   WHERE cancelled_at IS NULL AND starts_at<=? AND ends_at>?""", (now, now))}
            rows = db.execute("SELECT id, name, created_at, last_seen, remote_commands_enabled FROM servers ORDER BY name, id").fetchall()
            result = []
            for row in rows:
                if visible is not None and row["id"] not in visible:
                    continue
                access_role = (self._effective_bot_role(db, *bot, row["id"]) if bot is not None
                               else self._effective_user_role(db, identity, row["id"]))
                latest = db.execute("SELECT * FROM metrics WHERE server_id=? ORDER BY collected_at DESC, id DESC LIMIT 1", (row["id"],)).fetchone()
                online = row["last_seen"] is not None and now - row["last_seen"] <= offline_seconds
                sample = self._metric_from_row(latest)
                if sample is not None:
                    with self._processes_lock:
                        cached = self._latest_processes.get(row["id"])
                        container_cached = self._latest_containers.get(row["id"])
                    if online and cached is not None and (cached[0], cached[1]) == (latest["collected_at"], latest["id"]) and cached[2] is not None:
                        sample["details"]["top_processes"] = cached[2]
                    if container_cached is not None and (container_cached[0], container_cached[1]) == (latest["collected_at"], latest["id"]) and container_cached[2] is not None:
                        sample["details"]["containers"] = container_cached[2]
                result.append({"id": row["id"], "name": row["name"], "created_at": row["created_at"],
                               "last_seen": row["last_seen"], "online": online,
                               "access_role": access_role,
                               "maintenance": maintenance.get(row["id"]),
                               "remote_commands_enabled": bool(row["remote_commands_enabled"]),
                               "latest": sample})
            return result

    @staticmethod
    def _maintenance_status(row, now: int) -> dict:
        result = dict(row)
        result["status"] = ("cancelled" if row["cancelled_at"] is not None else
                            "active" if row["starts_at"] <= now < row["ends_at"] else "ended")
        return result

    def maintenance_windows(self, server_id: str, now: int | None = None, *, session_token=None) -> list[dict] | None:
        now = int(time.time()) if now is None else now
        with self.connection() as db:
            db.execute("BEGIN")
            self._require_server_session(db, session_token, server_id, "viewer")
            if db.execute("SELECT 1 FROM servers WHERE id=?", (server_id,)).fetchone() is None:
                return None
            rows = db.execute("""SELECT id, server_id, starts_at, ends_at, reason, cancelled_at
                                 FROM maintenance_windows WHERE server_id=?
                                 ORDER BY starts_at DESC, id DESC LIMIT 100""", (server_id,)).fetchall()
            return [self._maintenance_status(row, now) for row in rows]

    def create_maintenance(self, server_id: str, payload: object, now: int | None = None, *, session_token: str | None = None) -> dict:
        now = int(time.time()) if now is None else now
        if not isinstance(payload, dict) or set(payload) != {"ends_at", "reason"}:
            raise ValueError("Expected ends_at and reason")
        ends_at, reason = payload["ends_at"], payload["reason"]
        if type(ends_at) is not int or not now + MAINTENANCE_MIN_SECONDS <= ends_at <= now + MAINTENANCE_MAX_SECONDS:
            raise ValueError("ends_at must be 1 minute to 7 days in the future")
        if not isinstance(reason, str):
            raise ValueError("reason must be printable text")
        reason = reason.strip()
        if not 1 <= len(reason) <= 200 or not reason.isprintable() or len(reason.encode("utf-8")) > 512:
            raise ValueError("reason must contain 1–200 printable characters and at most 512 UTF-8 bytes")
        window_id = str(uuid.uuid4())
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            identity = self._require_server_session(db, session_token, server_id, "admin")
            if db.execute("SELECT 1 FROM servers WHERE id=?", (server_id,)).fetchone() is None:
                raise KeyError("Unknown server")
            active = db.execute("""SELECT 1 FROM maintenance_windows WHERE server_id=?
                                   AND cancelled_at IS NULL AND starts_at<=? AND ends_at>?""",
                                (server_id, now, now)).fetchone()
            if active is not None:
                raise MaintenanceConflict("An active maintenance window already exists")
            db.execute("""INSERT INTO maintenance_windows
                          (id, server_id, starts_at, ends_at, reason) VALUES (?, ?, ?, ?, ?)""",
                       (window_id, server_id, now, ends_at, reason))
            # Existing incidents receive a single reminder if they survive the window.
            db.execute("""INSERT OR IGNORE INTO maintenance_deferred (incident_id, server_id, created_at)
                          SELECT id, server_id, ? FROM incidents
                          WHERE server_id=? AND state='firing'""", (now, server_id))
            # A pre-window notification still waiting for Telegram must not
            # arrive during maintenance or after a newer reminder.
            db.execute("""UPDATE incident_outbox SET dropped_at=?, lease_until=NULL
                          WHERE incident_id IN (SELECT id FROM incidents WHERE server_id=?)
                            AND delivered_at IS NULL AND dropped_at IS NULL""", (now, server_id))
            self._audit_account(db, identity, "maintenance_started", server_id, window_id,
                        {"ends_at": ends_at, "reason": reason}, now=now)
            return {"id": window_id, "server_id": server_id, "starts_at": now,
                    "ends_at": ends_at, "reason": reason, "cancelled_at": None, "status": "active"}

    def cancel_maintenance(self, server_id: str, window_id: str, now: int | None = None, *, session_token: str | None = None) -> tuple[dict, list[dict]] | None:
        now = int(time.time()) if now is None else now
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            identity = self._require_server_session(db, session_token, server_id, "admin")
            row = db.execute("""SELECT id, server_id, starts_at, ends_at, reason, cancelled_at
                                FROM maintenance_windows WHERE id=? AND server_id=?""",
                             (window_id, server_id)).fetchone()
            if row is None:
                return None
            if row["cancelled_at"] is not None or not row["starts_at"] <= now < row["ends_at"]:
                raise MaintenanceConflict("Maintenance window is no longer active")
            db.execute("UPDATE maintenance_windows SET cancelled_at=? WHERE id=?", (now, window_id))
            self._audit_account(db, identity, "maintenance_cancelled", server_id, window_id, now=now)
            events = self._maintenance_notifications(db, [], now)
            return (self._maintenance_status({**dict(row), "cancelled_at": now}, now), events)

    def server_exists(self, server_id: str) -> bool:
        with self.connection() as db:
            return db.execute("SELECT 1 FROM servers WHERE id=?", (server_id,)).fetchone() is not None

    def journal_units(self, server_id: str, now: int | None = None) -> list[str] | None:
        """Advertised local allowlist from the latest authenticated, online Agent report."""
        now = int(time.time()) if now is None else now
        with self.connection() as db:
            server = db.execute("SELECT last_seen FROM servers WHERE id=?", (server_id,)).fetchone()
            if server is None:
                return None
            offline_seconds = self._monitoring_settings(db)["offline_seconds"]
            if server["last_seen"] is None or now - server["last_seen"] > offline_seconds:
                return []
            row = db.execute("SELECT details_json FROM metrics WHERE server_id=? ORDER BY collected_at DESC, id DESC LIMIT 1",
                             (server_id,)).fetchone()
            return json.loads(row["details_json"]).get("journal_units", []) if row else []

    def latest_amnezia_control_job(self, server_id: str, target: str = "awg2",
                                   *, session_token=None) -> dict | None:
        """Return the latest exact status probe, never a generic command result."""
        command_hash = hashlib.sha256(status_command(target).encode()).hexdigest()
        with self.connection() as db:
            self._require_server_session(db, session_token, server_id, "viewer")
            row = db.execute("""SELECT state, exit_code, output, completed_at FROM jobs
                                WHERE server_id=? AND source='web' AND command_sha256=?
                                ORDER BY jobs.rowid DESC LIMIT 1""",
                             (server_id, command_hash)).fetchone()
        return dict(row) if row else None

    def latest_service_control_job(self, server_id: str, unit: str,
                                   *, session_token=None) -> dict | None:
        """Return a status only if no later or uncertain mutation can stale it."""
        with self.connection() as db:
            self._require_server_session(db, session_token, server_id, "viewer")
            return self._ready_service_status(db, server_id, unit, int(time.time()))

    def latest_container_control_job(self, server_id: str, ident: str,
                                     *, session_token=None) -> dict | None:
        with self.connection() as db:
            self._require_server_session(db, session_token, server_id, "viewer")
            return self._ready_container_status(db, server_id, ident, int(time.time()))

    @staticmethod
    def _ready_container_status(db, server_id: str, ident: str, now: int) -> dict | None:
        status = db.execute("""SELECT j.rowid AS job_rowid,j.state,j.exit_code,j.output,j.completed_at
                FROM jobs j JOIN container_control_jobs c ON c.job_id=j.id
                WHERE j.server_id=? AND j.source='web' AND j.control_kind='container'
                  AND c.engine='docker' AND c.action='status' AND c.container_id=?
                ORDER BY j.rowid DESC LIMIT 1""", (server_id, ident)).fetchone()
        if status is None or container_control_status(dict(status), now, ident)["source_status"] != "ok":
            return None
        stale = db.execute("""SELECT 1 FROM jobs j
                JOIN container_control_jobs c ON c.job_id=j.id
                WHERE j.server_id=? AND j.source='web' AND j.control_kind='container'
                  AND c.engine='docker' AND c.container_id=? AND c.action<>'status'
                  AND (j.rowid>=? OR j.state IN ('queued','delivered')
                       OR j.completed_at IS NULL OR j.completed_at>=?) LIMIT 1""",
                (server_id, ident, status["job_rowid"], status["completed_at"])).fetchone()
        return None if stale else dict(status)

    def _fresh_container_inventory(self, db, server_id: str, ident: str, now: int) -> dict:
        server = db.execute("SELECT last_seen FROM servers WHERE id=?", (server_id,)).fetchone()
        if server is None:
            raise KeyError("Server not found")
        if server["last_seen"] is None or not 0 <= now - server["last_seen"] <= 120:
            raise ContainerControlUnavailable("Current Docker inventory is unavailable")
        last_metric = db.execute("SELECT id FROM metrics WHERE server_id=? ORDER BY id DESC LIMIT 1",
                                 (server_id,)).fetchone()
        with self._processes_lock:
            cached = self._latest_containers.get(server_id)
        if (last_metric is None or cached is None or cached[1] != last_metric["id"] or
                cached[2] is None):
            raise ContainerControlUnavailable("Current Docker inventory is unavailable")
        engines = [engine for engine in cached[2]["engines"]
                   if engine["engine"] == "docker" and engine["source_status"] == "ok"
                   and not engine["truncated"]]
        if len(engines) != 1:
            raise ContainerControlUnavailable("Complete Docker inventory is unavailable")
        items = [item for item in engines[0]["containers"] if item["id"] == ident]
        if len(items) != 1:
            raise ContainerControlUnavailable("Container is not in the complete Docker inventory")
        item = items[0]
        if protected_container_inventory(item["name"], item["image"]):
            raise PermissionError("Protected container cannot be controlled")
        return item

    @staticmethod
    def _ready_service_status(db, server_id: str, unit: str, now: int) -> dict | None:
        """A new status must finish after every earlier mutation of this unit."""
        status_hash = hashlib.sha256(service_status_command(unit).encode()).hexdigest()
        status = db.execute("""SELECT jobs.rowid AS job_rowid,state,exit_code,output,completed_at
                               FROM jobs WHERE server_id=? AND source='web' AND command_sha256=?
                               ORDER BY jobs.rowid DESC LIMIT 1""",
                            (server_id, status_hash)).fetchone()
        if status is None or service_control_status(dict(status), now, unit)["source_status"] != "ok":
            return None
        mutation_hashes = tuple(hashlib.sha256(build_service_command(
            {"action": action, "unit": unit}).encode()).hexdigest()
            for action in ("start", "stop", "restart"))
        stale = db.execute("""SELECT 1 FROM jobs WHERE server_id=? AND source='web'
                              AND command_sha256 IN (?,?,?)
                              AND (jobs.rowid>=? OR state IN ('queued','delivered')
                                   OR completed_at IS NULL OR completed_at>=?) LIMIT 1""",
                           (server_id, *mutation_hashes, status["job_rowid"],
                            status["completed_at"])).fetchone()
        return None if stale else dict(status)

    def history(self, server_id: str, limit: int = 60, *, session_token=None) -> list[dict]:
        with self.connection() as db:
            self._require_server_session(db, session_token, server_id, "viewer")
            rows = db.execute("SELECT * FROM metrics WHERE server_id=? ORDER BY collected_at DESC, id DESC LIMIT ?", (server_id, limit)).fetchall()
        return [self._metric_from_row(row) for row in reversed(rows)]

    def prune_metrics(self, retention_days: int = 30, now: int | None = None) -> int:
        now = int(time.time()) if now is None else now
        with self.connection() as db:
            return db.execute("DELETE FROM metrics WHERE received_at < ?", (now - retention_days * 86400,)).rowcount

    def _set_incident(self, db, server_id: str, kind: str, active: bool, now: int,
                      value: float | None = None, threshold: float | None = None,
                      trigger_seconds: int = 0, first_seen: int | None = None,
                      subject: str | None = None) -> dict | None:
        old = db.execute("SELECT * FROM incidents WHERE server_id=? AND kind=? AND state='firing'", (server_id, kind)).fetchone()
        if active and old is None:
            opened_at = now
            if trigger_seconds:
                candidate = db.execute("""SELECT first_seen, threshold FROM incident_candidates
                                          WHERE server_id=? AND kind=?""", (server_id, kind)).fetchone()
                # A changed threshold starts a fresh hold period. Previously
                # observed samples cannot prove a breach of the new rule.
                if candidate is None or candidate["threshold"] != threshold:
                    opened_at = now if candidate is not None else (first_seen if first_seen is not None else now)
                    db.execute("""INSERT INTO incident_candidates
                                  (server_id, kind, first_seen, last_seen, current_value, threshold)
                                  VALUES (?, ?, ?, ?, ?, ?)
                                  ON CONFLICT(server_id, kind) DO UPDATE SET
                                  first_seen=excluded.first_seen, last_seen=excluded.last_seen,
                                  current_value=excluded.current_value, threshold=excluded.threshold""",
                               (server_id, kind, opened_at, now, value, threshold))
                else:
                    opened_at = candidate["first_seen"]
                    db.execute("""UPDATE incident_candidates SET last_seen=?, current_value=?
                                  WHERE server_id=? AND kind=?""", (now, value, server_id, kind))
                if now - opened_at < trigger_seconds:
                    return None
            db.execute("DELETE FROM incident_candidates WHERE server_id=? AND kind=?", (server_id, kind))
            incident_id = str(uuid.uuid4())
            db.execute("""INSERT INTO incidents
                          (id, server_id, kind, state, opened_at, updated_at, current_value, threshold, subject)
                          VALUES (?, ?, ?, 'firing', ?, ?, ?, ?, ?)""",
                       (incident_id, server_id, kind, opened_at, now, value, threshold, subject))
            return {"id": incident_id, "server_id": server_id, "kind": kind, "state": "firing", "at": now,
                    "opened_at": opened_at,
                    "value": value, "threshold": threshold}
        if active and old is not None:
            db.execute("""UPDATE incidents SET updated_at=?, current_value=?, threshold=?,
                          subject=COALESCE(?,subject) WHERE id=?""",
                       (now, value, threshold, subject, old["id"]))
        if not active:
            db.execute("DELETE FROM incident_candidates WHERE server_id=? AND kind=?", (server_id, kind))
        if not active and old is not None:
            db.execute("""UPDATE incidents SET state='resolved', updated_at=?, resolved_at=?,
                          subject=COALESCE(?,subject) WHERE id=?""", (now, now, subject, old["id"]))
            return {"id": old["id"], "server_id": server_id, "kind": kind, "state": "resolved", "at": now,
                    "opened_at": old["opened_at"],
                    "value": value, "threshold": threshold}
        return None

    def _retire_root_inode_alert(self, db, server_id: str, now: int) -> None:
        """A disabled rule closes history without claiming the filesystem recovered."""
        event = self._set_incident(db, server_id, ROOT_INODE_ALERT_KIND, False, now)
        if event is None:
            return
        db.execute("DELETE FROM maintenance_deferred WHERE incident_id=?", (event["id"],))
        db.execute("""UPDATE incident_outbox SET dropped_at=?, lease_until=NULL
                      WHERE incident_id=? AND delivered_at IS NULL AND dropped_at IS NULL""",
                   (now, event["id"]))

    def _maintenance_notifications(self, db, events: list[dict], now: int) -> list[dict]:
        """Choose alerts in the same write transaction as incident/window changes.

        The pending row means a firing incident needs one reminder once no window
        covers its server. A recovery consumes that row without a false alert.
        """
        active_servers = {row["server_id"] for row in db.execute(
            """SELECT server_id FROM maintenance_windows
               WHERE cancelled_at IS NULL AND starts_at<=? AND ends_at>?""", (now, now))}
        notifications = []
        for event in events:
            incident_id = event["id"]
            if event["server_id"] in active_servers:
                if event["state"] == "firing":
                    db.execute("""INSERT OR IGNORE INTO maintenance_deferred
                                  (incident_id, server_id, created_at) VALUES (?, ?, ?)""",
                               (incident_id, event["server_id"], now))
                else:
                    db.execute("DELETE FROM maintenance_deferred WHERE incident_id=?", (incident_id,))
                continue
            db.execute("DELETE FROM maintenance_deferred WHERE incident_id=?", (incident_id,))
            if event["state"] == "firing":
                db.execute("UPDATE incidents SET alerted_at=? WHERE id=?", (now, incident_id))
                notifications.append(event)
            elif db.execute("SELECT alerted_at FROM incidents WHERE id=?", (incident_id,)).fetchone()["alerted_at"] is not None:
                # Recovery follows an alert that escaped maintenance, even if
                # a new window began and ended before this recovery sample.
                notifications.append(event)

        pending_rows = db.execute("""SELECT d.incident_id, d.server_id, i.kind, i.state,
                                           i.current_value, i.threshold, i.opened_at
                                    FROM maintenance_deferred AS d
                                    JOIN incidents AS i ON i.id=d.incident_id
                                    ORDER BY d.created_at, d.incident_id""").fetchall()
        for row in pending_rows:
            if row["server_id"] in active_servers:
                continue
            db.execute("DELETE FROM maintenance_deferred WHERE incident_id=?", (row["incident_id"],))
            if row["state"] == "firing":
                db.execute("UPDATE incidents SET alerted_at=? WHERE id=?", (now, row["incident_id"]))
                window = db.execute("""SELECT id FROM maintenance_windows WHERE server_id=?
                                       AND starts_at<=? ORDER BY starts_at DESC, rowid DESC LIMIT 1""",
                                    (row["server_id"], now)).fetchone()
                notifications.append({"id": row["incident_id"], "server_id": row["server_id"],
                                      "kind": row["kind"], "state": "firing", "at": now,
                                      "opened_at": row["opened_at"],
                                      "value": row["current_value"], "threshold": row["threshold"],
                                      "maintenance_reminder": True,
                                      "maintenance_window_id": window["id"] if window else None})
        self._queue_incident_notifications(db, notifications, now)
        return notifications

    @staticmethod
    def _queue_incident_notifications(db, events: list[dict], now: int) -> None:
        """Persist one event per currently bound private chat in the incident transaction."""
        for event in events:
            event_type = ("recovery" if event["state"] == "resolved" else
                          "reminder" if event.get("maintenance_reminder") else "firing")
            if event_type == "recovery":
                # Someone approved after the original alert must not receive
                # a recovery without the corresponding firing message.
                chats = db.execute("""SELECT DISTINCT b.chat_id FROM bot_users AS b
                    JOIN incident_outbox AS o ON o.chat_id=b.chat_id AND o.incident_id=?
                    WHERE o.event_type IN ('firing','reminder') AND o.dropped_at IS NULL
                    ORDER BY b.chat_id""",
                                   (event["id"],)).fetchall()
            else:
                chats = db.execute("SELECT DISTINCT chat_id FROM bot_users ORDER BY chat_id").fetchall()
            source_window_id = (event.get("maintenance_window_id") or "") if event_type == "reminder" else ""
            for chat in chats:
                db.execute("""INSERT OR IGNORE INTO incident_outbox
                    (incident_id, chat_id, event_type, source_window_id, event_at, value, next_attempt_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (event["id"], chat["chat_id"], event_type, source_window_id,
                     event["at"], event["value"], now))

    @staticmethod
    def _alert_delivery_allowed(db, event: dict, now: int) -> bool:
        at = event["at"]
        active = db.execute("""SELECT 1 FROM maintenance_windows WHERE server_id=?
                                   AND cancelled_at IS NULL AND starts_at<=? AND ends_at>?""",
                            (event["server_id"], now, now)).fetchone()
        if active is not None:
            return False
        # A queued pre-window alert must not arrive after a post-window
        # reminder. The reminder itself is exempt for its original window.
        exempt_window = event.get("maintenance_window_id") if event.get("maintenance_reminder") else None
        stale = db.execute("""SELECT 1 FROM maintenance_windows WHERE server_id=?
                                  AND starts_at<=? AND (? IS NULL OR id<>?) AND (
                                    starts_at>=? OR
                                    (?=0 AND ? < COALESCE(cancelled_at, ends_at)))
                                  LIMIT 1""", (event["server_id"], now,
                                           exempt_window, exempt_window, at,
                                           int(bool(event.get("maintenance_reminder"))), at)).fetchone()
        if stale is not None:
            return False
        if event.get("maintenance_reminder"):
            current = db.execute("SELECT state FROM incidents WHERE id=?", (event["id"],)).fetchone()
            return current is not None and current["state"] == "firing"
        return True

    def alert_delivery_allowed(self, event: dict, now: int | None = None) -> bool:
        """Drop alerts still queued when maintenance starts before Telegram sends them."""
        now = int(time.time()) if now is None else now
        with self.connection() as db:
            return self._alert_delivery_allowed(db, event, now)

    @staticmethod
    def _outbox_event(row) -> dict:
        reminder = row["event_type"] == "reminder"
        return {"id": row["incident_id"], "server_id": row["server_id"],
                "at": row["event_at"], "state": "resolved" if row["event_type"] == "recovery" else "firing",
                "maintenance_reminder": reminder,
                "maintenance_window_id": row["source_window_id"] if reminder else None}

    @staticmethod
    def _drop_outbox_chain(db, row, now: int) -> None:
        # A recovery without its predecessor is misleading. Cancel all later
        # pending transitions for this incident and private chat as well.
        db.execute("""UPDATE incident_outbox SET dropped_at=?, lease_until=NULL
                      WHERE incident_id=? AND chat_id=? AND id>=?
                        AND delivered_at IS NULL AND dropped_at IS NULL""",
                   (now, row["incident_id"], row["chat_id"], row["id"]))

    @staticmethod
    def _drop_disallowed_outbox_event(db, row, now: int) -> None:
        # A reminder becomes unnecessary when the incident recovers before it
        # is sent. A chat that already received an alert still needs recovery;
        # a chat with no delivered predecessor must remain silent.
        delivered_alert = row["event_type"] == "reminder" and db.execute("""
            SELECT 1 FROM incidents AS i
            WHERE i.id=? AND i.state='resolved' AND EXISTS (
                SELECT 1 FROM incident_outbox AS previous
                WHERE previous.incident_id=i.id AND previous.chat_id=?
                  AND previous.id<? AND previous.event_type IN ('firing','reminder')
                  AND previous.delivered_at IS NOT NULL AND previous.dropped_at IS NULL)
            """, (row["incident_id"], row["chat_id"], row["id"])).fetchone() is not None
        if delivered_alert:
            db.execute("""UPDATE incident_outbox SET dropped_at=?, lease_until=NULL
                          WHERE id=? AND delivered_at IS NULL AND dropped_at IS NULL""",
                       (now, row["id"]))
        else:
            Store._drop_outbox_chain(db, row, now)

    def claim_incident_outbox(self, now: int | None = None) -> dict | None:
        """Lease the oldest due transition whose predecessor has finished."""
        now = int(time.time()) if now is None else now
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            for _ in range(100):
                row = db.execute("""SELECT o.*, i.server_id, i.kind, i.opened_at,
                                           s.name AS server_name, b.role
                    FROM incident_outbox AS o
                    JOIN incidents AS i ON i.id=o.incident_id
                    JOIN servers AS s ON s.id=i.server_id
                    LEFT JOIN bot_users AS b ON b.chat_id=o.chat_id AND b.user_id=o.chat_id
                    WHERE o.delivered_at IS NULL AND o.dropped_at IS NULL
                      AND o.next_attempt_at<=? AND (o.lease_until IS NULL OR o.lease_until<=?)
                      AND NOT EXISTS (
                        SELECT 1 FROM incident_outbox AS prior
                        WHERE prior.incident_id=o.incident_id AND prior.chat_id=o.chat_id
                          AND prior.id<o.id AND prior.delivered_at IS NULL AND prior.dropped_at IS NULL)
                    ORDER BY o.id LIMIT 1""", (now, now)).fetchone()
                if row is None:
                    return None
                if row["role"] not in ("viewer", "operator", "admin") or not self._bot_allowed(db, row["chat_id"], row["chat_id"], row["server_id"]):
                    self._drop_outbox_chain(db, row, now)
                    continue
                if not self._alert_delivery_allowed(db, self._outbox_event(row), now):
                    self._drop_disallowed_outbox_event(db, row, now)
                    continue
                lease_generation = row["lease_generation"] + 1
                db.execute("UPDATE incident_outbox SET lease_generation=?, lease_until=? WHERE id=?",
                           (lease_generation, now + OUTBOX_LEASE_SECONDS, row["id"]))
                return {**dict(row), "lease_generation": lease_generation, "lease_until": now + OUTBOX_LEASE_SECONDS}
            return None

    def incident_outbox_send_allowed(self, row_id: int, lease_generation: int, now: int | None = None) -> bool:
        """Recheck binding and maintenance immediately before Telegram HTTP."""
        now = int(time.time()) if now is None else now
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("""SELECT o.*, i.server_id, b.role FROM incident_outbox AS o
                JOIN incidents AS i ON i.id=o.incident_id
                LEFT JOIN bot_users AS b ON b.chat_id=o.chat_id AND b.user_id=o.chat_id
                WHERE o.id=? AND o.lease_generation=? AND o.delivered_at IS NULL AND o.dropped_at IS NULL""",
                             (row_id, lease_generation)).fetchone()
            if row is None:
                return False
            if row["role"] not in ("viewer", "operator", "admin") or not self._bot_allowed(db, row["chat_id"], row["chat_id"], row["server_id"]):
                self._drop_outbox_chain(db, row, now)
                return False
            if not self._alert_delivery_allowed(db, self._outbox_event(row), now):
                self._drop_disallowed_outbox_event(db, row, now)
                return False
            return True

    def complete_incident_outbox(self, row_id: int, lease_generation: int, now: int | None = None) -> bool:
        now = int(time.time()) if now is None else now
        with self.connection() as db:
            cursor = db.execute("""UPDATE incident_outbox SET delivered_at=?, lease_until=NULL
                WHERE id=? AND lease_generation=? AND delivered_at IS NULL AND dropped_at IS NULL""",
                                (now, row_id, lease_generation))
            return cursor.rowcount == 1

    def retry_incident_outbox(self, row_id: int, lease_generation: int, *, permanent: bool = False,
                              now: int | None = None, retry_after: int | None = None) -> bool:
        now = int(time.time()) if now is None else now
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("""SELECT * FROM incident_outbox WHERE id=? AND lease_generation=?
                                AND delivered_at IS NULL AND dropped_at IS NULL""",
                             (row_id, lease_generation)).fetchone()
            if row is None:
                return False
            if permanent:
                self._drop_outbox_chain(db, row, now)
            else:
                attempts = min(row["attempts"] + 1, 1000000)
                delay = min(OUTBOX_RETRY_MAX_SECONDS, 5 * (2 ** min(attempts - 1, 10)))
                # The exponential backoff is capped; Telegram's explicit
                # flood-control floor must still be respected when longer.
                if type(retry_after) is int and 0 <= retry_after <= 2**31 - 1:
                    delay = max(delay, retry_after)
                db.execute("""UPDATE incident_outbox SET attempts=?, next_attempt_at=?,
                              lease_until=NULL WHERE id=?""",
                           (attempts, now + delay, row_id))
            return True

    def incident_outbox_pending_count(self) -> int:
        with self.connection() as db:
            return db.execute("""SELECT COUNT(*) FROM incident_outbox
                WHERE delivered_at IS NULL AND dropped_at IS NULL""").fetchone()[0]

    def prune_incident_outbox(self, now: int | None = None, retention_days: int = 30) -> int:
        now = int(time.time()) if now is None else now
        cutoff = now - retention_days * 86400
        with self.connection() as db:
            return db.execute("""DELETE FROM incident_outbox WHERE id IN (
                SELECT o.id FROM incident_outbox AS o JOIN incidents AS i ON i.id=o.incident_id
                WHERE i.state='resolved' AND (o.delivered_at<? OR o.dropped_at<?))""",
                              (cutoff, cutoff)).rowcount

    def ingest(self, server_id: str, payload: object, now: int | None = None,
               *, agent_token: str | None = None) -> list[dict]:
        now = int(time.time()) if now is None else now
        data = validate_metric(payload, now)
        details = data.pop("details", {})
        top = details.pop("top_processes", None)
        containers = details.pop("containers", None)
        events = []
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            # HTTP always supplies its bearer string. None remains reserved
            # for existing trusted local Store/CLI callers.
            if agent_token is not None:
                self._check_agent(db, server_id, agent_token)
            settings = self._monitoring_settings(db)
            pressure_settings = self._pressure_settings(db)
            inode_settings = self._inode_settings(db)
            server = db.execute("SELECT last_seen FROM servers WHERE id=?", (server_id,)).fetchone()
            if server is None:
                raise KeyError("Unknown server")
            previous_metric = db.execute(
                "SELECT collected_at FROM metrics WHERE server_id=? ORDER BY collected_at DESC,id DESC LIMIT 1",
                (server_id,)).fetchone()
            # Missing telemetry cannot confirm a sustained resource breach.
            if server["last_seen"] is not None and now - server["last_seen"] > settings["offline_seconds"]:
                db.execute("""DELETE FROM incident_candidates WHERE server_id=? AND kind<>'offline'""", (server_id,))
            fields = ("server_id", "received_at") + tuple(data.keys()) + ("details_json",)
            marks = ",".join("?" for _ in fields)
            metric_id = db.execute(f"INSERT INTO metrics ({','.join(fields)}) VALUES ({marks})",
                                   (server_id, now, *data.values(), json.dumps(details, ensure_ascii=False, separators=(",", ":")))).lastrowid
            db.execute("UPDATE servers SET last_seen=? WHERE id=?", (now, server_id))
            event = self._set_incident(db, server_id, "offline", False, now)
            if event:
                events.append(event)
            for kind, field in ALERT_FIELDS.items():
                threshold = float(settings[kind])
                event = self._set_incident(db, server_id, kind, data[field] >= threshold, now,
                                           data[field], threshold, settings["trigger_minutes"] * 60)
                if event:
                    events.append(event)
            # Missing systemd inventory is unknown, not a recovery signal.
            if "services" in details:
                failed = details["services"]["failed_count"]
                event = self._set_incident(db, server_id, "failed_services", failed > 0,
                                           now, float(failed), 1.0, settings["trigger_minutes"] * 60)
                if event:
                    events.append(event)
            else:
                db.execute("DELETE FROM incident_candidates WHERE server_id=? AND kind='failed_services'", (server_id,))
            for kind, path in PRESSURE_ALERT_FIELDS.items():
                threshold = pressure_settings["thresholds"][kind]
                value = details
                for part in path:
                    value = value.get(part) if isinstance(value, dict) else None
                if threshold is None:
                    # Disabling a rule is a known recovery on the next sample.
                    event = self._set_incident(db, server_id, kind, False, now)
                elif value is None:
                    # An older Agent or absent kernel PSI is unknown, not a
                    # recovery. It cannot extend an unconfirmed hold period.
                    db.execute("DELETE FROM incident_candidates WHERE server_id=? AND kind=?",
                               (server_id, kind))
                    event = None
                else:
                    event = self._set_incident(
                        db, server_id, kind, value >= threshold, now, value,
                        threshold, pressure_settings["hold_seconds"])
                if event:
                    events.append(event)
            inode_threshold = inode_settings["threshold_percent"]
            if inode_threshold is None:
                # This is an administrative close, not a measured recovery.
                self._retire_root_inode_alert(db, server_id, now)
                event = None
            else:
                inode_percent = root_inode_percent(details)
                if inode_percent is None:
                    # Missing root mount, unsupported inode counts, or a
                    # contradictory percentage is unknown. Never infer a
                    # recovery or extend a pending hold from it.
                    db.execute("""DELETE FROM incident_candidates
                                  WHERE server_id=? AND kind=?""",
                               (server_id, ROOT_INODE_ALERT_KIND))
                    event = None
                else:
                    event = self._set_incident(
                        db, server_id, ROOT_INODE_ALERT_KIND,
                        inode_percent >= inode_threshold, now, inode_percent,
                        inode_threshold, inode_settings["hold_seconds"])
            if event:
                events.append(event)
            filesystem_settings = self._filesystem_alert_settings(db, server_id)
            if filesystem_settings["rules"] and (previous_metric is None or
                    data["collected_at"] >= previous_metric["collected_at"]):
                source = filesystem_alert_evidence(
                    details, observed_at=data["collected_at"], received_at=now, now=now)
                if (filesystem_settings["last_observed_at"] is None or
                        data["collected_at"] > filesystem_settings["last_observed_at"]):
                    for rule in filesystem_settings["rules"]:
                        alert_kind = filesystem_alert_kind(rule["mountpoint"], rule["metric"])
                        observed = filesystem_alert_observation(rule, source)
                        value = observed["used_percent"]
                        if value is None:
                            # A clipped list, absent mount, unsupported count or
                            # contradictory row cannot prove recovery or hold.
                            db.execute("DELETE FROM incident_candidates WHERE server_id=? AND kind=?",
                                       (server_id, alert_kind))
                            continue
                        event = self._set_incident(
                            db, server_id, alert_kind, value >= rule["threshold_percent"],
                            now, value, rule["threshold_percent"],
                            filesystem_settings["hold_seconds"], subject=rule["mountpoint"])
                        if event:
                            events.append(event)
                    if source["measurements"]:
                        db.execute("""UPDATE filesystem_alert_settings SET last_observed_at=?
                                      WHERE server_id=?""", (data["collected_at"], server_id))
            container_settings = self._container_alert_settings(db, server_id)
            if container_settings["rules"] and (previous_metric is None or
                    data["collected_at"] >= previous_metric["collected_at"]):
                source = container_alert_evidence(
                    containers, metric_collected_at=data["collected_at"],
                    received_at=now, now=now)
                if source["source_status"] != "ok":
                    # A missing, stale or clipped Engine view cannot prove a
                    # recovery, and must not extend an unconfirmed hold.
                    for rule in container_settings["rules"]:
                        db.execute("DELETE FROM incident_candidates WHERE server_id=? AND kind=?",
                                   (server_id, container_alert_kind(rule["name"])))
                elif (container_settings["last_observed_at"] is None or
                      source["observed_at"] > container_settings["last_observed_at"]):
                    for rule in container_settings["rules"]:
                        observed = container_alert_observation(rule, source)["status"]
                        kind = container_alert_kind(rule["name"])
                        if observed == "unknown":
                            db.execute("DELETE FROM incident_candidates WHERE server_id=? AND kind=?",
                                       (server_id, kind))
                            continue
                        event = self._set_incident(
                            db, server_id, kind, bool(rule.get(observed, False)), now,
                            trigger_seconds=container_settings["hold_seconds"],
                            subject=rule["name"])
                        if event:
                            events.append(event)
                    db.execute("""UPDATE container_alert_settings SET last_observed_at=?
                                  WHERE server_id=?""", (source["observed_at"], server_id))
            events = self._maintenance_notifications(db, events, now)
        with self._processes_lock:
            previous = self._latest_processes.get(server_id)
            if previous is None or (data["collected_at"], metric_id) > previous[:2]:
                self._latest_processes[server_id] = (data["collected_at"], metric_id, top)
                self._latest_containers[server_id] = (data["collected_at"], metric_id, containers)
        return events

    def sweep_offline(self, now: int | None = None) -> list[dict]:
        now = int(time.time()) if now is None else now
        events = []
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            settings = self._monitoring_settings(db)
            offline_seconds = settings["offline_seconds"]
            rows = db.execute("SELECT id, last_seen FROM servers WHERE last_seen IS NOT NULL").fetchall()
            for row in rows:
                elapsed = now - row["last_seen"]
                event = self._set_incident(db, row["id"], "offline", elapsed > offline_seconds,
                                           now, elapsed, offline_seconds,
                                           settings["trigger_minutes"] * 60,
                                           row["last_seen"] + offline_seconds + 1)
                if event:
                    events.append(event)
            return self._maintenance_notifications(db, events, now)

    def incidents(self, limit: int = 100, state: str | None = None, *, session_token=None, bot=None) -> list[dict]:
        query = "SELECT i.*, s.name AS server_name FROM incidents i JOIN servers s ON s.id=i.server_id"
        args = []
        if state is not None:
            query += " WHERE i.state=?"
            args.append(state)
        with self.connection() as db:
            identity = self._require_role_session(db, session_token, "viewer") if session_token is not None else None
            visible = self._visible_server_ids(db, identity=identity, bot=bot)
            if visible is not None:
                if not visible:
                    return []
                query += " AND " if state is not None else " WHERE "
                query += "i.server_id IN (" + ",".join("?" for _ in visible) + ")"
                args.extend(sorted(visible))
            query += " ORDER BY i.updated_at DESC, i.id DESC LIMIT ?"
            args.append(limit)
            rows = db.execute(query, args).fetchall()
        return [dict(row) for row in rows]

    def acknowledge(self, incident_id: str, now: int | None = None, actor: str = "local-cli", *, session_token: str | None = None, bot=None) -> dict | None:
        now = int(time.time()) if now is None else now
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            identity = self._require_role_session(db, session_token, "operator")
            target = db.execute("SELECT server_id FROM incidents WHERE id=?", (incident_id,)).fetchone()
            if target is None:
                return None
            if (not self._user_allowed(db, identity, target["server_id"], "operator") or
                    (bot is not None and not self._bot_allowed(db, *bot, target["server_id"], "operator"))):
                raise AuthorizationError("Server access denied")
            db.execute("UPDATE incidents SET acknowledged_at=? WHERE id=? AND state='firing'", (now, incident_id))
            row = db.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
            if row is not None:
                if identity is not None:
                    self._audit_account(db, identity, "incident_acknowledged", row["server_id"], incident_id, now=now)
                else:
                    self._audit(db, actor, "incident_acknowledged", row["server_id"], incident_id, now=now)
            return dict(row) if row else None

    def add_bot_user(self, user_id: int, chat_id: int, role: str, *, actor: str | None = None,
                     session_token: str | None = None):
        if (type(user_id) is not int or type(chat_id) is not int or
                not 0 < user_id <= 2**63 - 1 or not 0 < chat_id <= 2**63 - 1 or
                user_id != chat_id):
            raise ValueError("Telegram user_id and private chat_id must be positive integers")
        if role not in ("viewer", "operator", "admin"):
            raise ValueError("Invalid bot role")
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            identity = self._require_unrestricted_admin(db, session_token)
            previous = db.execute("SELECT role FROM bot_users WHERE user_id=? AND chat_id=?",
                                  (user_id, chat_id)).fetchone()
            if previous and previous["role"] == "admin" and role != "admin":
                self._cancel_bot_commands(db, user_id, chat_id, identity)
            db.execute("INSERT INTO bot_users(user_id, chat_id, role) VALUES (?, ?, ?) ON CONFLICT(user_id, chat_id) DO UPDATE SET role=excluded.role",
                       (user_id, chat_id, role))
            db.execute("DELETE FROM bot_pairing_requests WHERE user_id=? AND chat_id=?", (user_id, chat_id))
            self._audit_account(db, identity, "bot_binding_upsert",
                        details={"user_id": user_id, "chat_id": chat_id, "role": role})

    def bot_bindings(self) -> list[dict]:
        with self.connection() as db:
            rows = db.execute("""SELECT user_id, chat_id, role, first_name, last_name, username
                              FROM bot_users ORDER BY user_id, chat_id""").fetchall()
        return [dict(row) for row in rows]

    @staticmethod
    def _bot_pairing_identity(first_name, last_name, username) -> tuple[str, str, str]:
        def clean(value):
            return "".join(char for char in value if char.isprintable())[:80] if isinstance(value, str) else ""

        user = username if isinstance(username, str) and re.fullmatch(r"[A-Za-z0-9_]{1,32}", username) else ""
        return clean(first_name), clean(last_name), user

    @staticmethod
    def _prune_bot_pairings(db, now: int):
        db.execute("""DELETE FROM bot_pairing_requests
                   WHERE (state='pending' AND requested_at < ?)
                      OR (state='rejected' AND rejected_at < ?)""",
                   (now - BOT_PAIRING_TTL_SECONDS, now - BOT_PAIRING_REJECT_SECONDS))

    def request_bot_pairing(self, user_id: int, chat_id: int, first_name="", last_name="",
                            username="", now: int | None = None) -> str:
        if (type(user_id) is not int or type(chat_id) is not int or
                not 0 < user_id <= 2**63 - 1 or user_id != chat_id):
            raise ValueError("Telegram pairing requires a private chat")
        now = int(time.time()) if now is None else now
        first_name, last_name, username = self._bot_pairing_identity(first_name, last_name, username)
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            self._prune_bot_pairings(db, now)
            if db.execute("SELECT 1 FROM bot_users WHERE user_id=? AND chat_id=?",
                          (user_id, chat_id)).fetchone():
                return "bound"
            existing = db.execute("SELECT state FROM bot_pairing_requests WHERE user_id=?",
                                  (user_id,)).fetchone()
            if existing:
                return existing["state"]
            count = db.execute("SELECT COUNT(*) FROM bot_pairing_requests WHERE state='pending'").fetchone()[0]
            if count >= BOT_PAIRING_LIMIT:
                return "full"
            db.execute("""INSERT INTO bot_pairing_requests
                       (user_id, chat_id, first_name, last_name, username, requested_at, state)
                       VALUES (?, ?, ?, ?, ?, ?, 'pending')""",
                       (user_id, chat_id, first_name, last_name, username, now))
            self._audit(db, f"telegram:{user_id}", "bot_pairing_requested",
                        details={"user_id": user_id, "chat_id": chat_id}, now=now)
            return "created"

    def pending_bot_pairings(self, now: int | None = None) -> list[dict]:
        now = int(time.time()) if now is None else now
        with self.connection() as db:
            self._prune_bot_pairings(db, now)
            rows = db.execute("""SELECT user_id, chat_id, first_name, last_name, username, requested_at
                              FROM bot_pairing_requests WHERE state='pending'
                              ORDER BY requested_at, user_id LIMIT ?""", (BOT_PAIRING_LIMIT,)).fetchall()
        return [dict(row) for row in rows]

    def approve_bot_pairing(self, user_id: int, chat_id: int, role: str,
                            now: int | None = None, *, session_token: str | None = None) -> dict | None:
        if (type(user_id) is not int or type(chat_id) is not int or
                not 0 < user_id <= 2**63 - 1 or user_id != chat_id):
            raise ValueError("Telegram pairing requires a private chat")
        if role not in ("viewer", "operator", "admin"):
            raise ValueError("Invalid bot role")
        now = int(time.time()) if now is None else now
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            identity = self._require_unrestricted_admin(db, session_token)
            self._prune_bot_pairings(db, now)
            row = db.execute("""SELECT first_name, last_name, username FROM bot_pairing_requests
                              WHERE user_id=? AND chat_id=? AND state='pending'""",
                             (user_id, chat_id)).fetchone()
            if row is None:
                return None
            db.execute("""INSERT INTO bot_users
                       (user_id, chat_id, role, first_name, last_name, username)
                       VALUES (?, ?, ?, ?, ?, ?)
                       ON CONFLICT(user_id, chat_id) DO UPDATE SET
                       role=excluded.role, first_name=excluded.first_name,
                       last_name=excluded.last_name, username=excluded.username""",
                       (user_id, chat_id, role, row["first_name"], row["last_name"], row["username"]))
            db.execute("DELETE FROM bot_pairing_requests WHERE user_id=?", (user_id,))
            self._audit_account(db, identity, "bot_pairing_approved",
                        details={"user_id": user_id, "chat_id": chat_id, "role": role}, now=now)
            return {"user_id": user_id, "chat_id": chat_id, "role": role,
                    "first_name": row["first_name"], "last_name": row["last_name"],
                    "username": row["username"]}

    def reject_bot_pairing(self, user_id: int, chat_id: int, now: int | None = None,
                           *, session_token: str | None = None) -> bool:
        if (type(user_id) is not int or type(chat_id) is not int or
                not 0 < user_id <= 2**63 - 1 or user_id != chat_id):
            raise ValueError("Telegram pairing requires a private chat")
        now = int(time.time()) if now is None else now
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            identity = self._require_unrestricted_admin(db, session_token)
            self._prune_bot_pairings(db, now)
            changed = db.execute("""UPDATE bot_pairing_requests
                                 SET state='rejected', rejected_at=?
                                 WHERE user_id=? AND chat_id=? AND state='pending'""",
                                 (now, user_id, chat_id)).rowcount > 0
            if changed:
                self._audit_account(db, identity, "bot_pairing_rejected",
                            details={"user_id": user_id, "chat_id": chat_id}, now=now)
            return changed

    def set_telegram_bot_info(self, token: str, username: str | None):
        username = (username if isinstance(username, str) and
                    re.fullmatch(r"[A-Za-z0-9_]{5,32}", username) else None)
        with self.connection() as db:
            db.execute("""INSERT INTO telegram_bot_info(singleton, token_hash, username)
                       VALUES (1, ?, ?) ON CONFLICT(singleton) DO UPDATE SET
                       token_hash=excluded.token_hash, username=excluded.username""",
                       (hashlib.sha256(token.encode("ascii")).hexdigest(), username))

    def telegram_bot_username(self, token: str) -> str | None:
        with self.connection() as db:
            row = db.execute("SELECT token_hash, username FROM telegram_bot_info WHERE singleton=1").fetchone()
        digest = hashlib.sha256(token.encode("ascii")).hexdigest()
        return row["username"] if row and hmac.compare_digest(digest, row["token_hash"]) else None

    def clear_telegram_bot_info(self):
        with self.connection() as db:
            db.execute("DELETE FROM telegram_bot_info WHERE singleton=1")

    def telegram_update_offset(self, token: str, now: int | None = None) -> int:
        now = int(time.time()) if now is None else now
        digest = hashlib.sha256(token.encode("ascii")).hexdigest()
        with self.connection() as db:
            row = db.execute("SELECT next_offset, updated_at FROM telegram_update_cursors WHERE token_hash=?",
                             (digest,)).fetchone()
        age = now - row["updated_at"] if row else -1
        return row["next_offset"] if 0 <= age <= BOT_UPDATE_CURSOR_IDLE_SECONDS else 0

    def claim_telegram_update(self, token: str, update_id: int, now: int | None = None) -> bool:
        if type(update_id) is not int or not 0 <= update_id < 2**63 - 1:
            return False
        now = int(time.time()) if now is None else now
        digest = hashlib.sha256(token.encode("ascii")).hexdigest()
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT next_offset, updated_at FROM telegram_update_cursors WHERE token_hash=?",
                             (digest,)).fetchone()
            age = now - row["updated_at"] if row else -1
            if 0 <= age <= BOT_UPDATE_CURSOR_IDLE_SECONDS and update_id < row["next_offset"]:
                return False
            db.execute("""INSERT INTO telegram_update_cursors(token_hash, next_offset, updated_at)
                       VALUES (?, ?, ?) ON CONFLICT(token_hash) DO UPDATE SET
                       next_offset=excluded.next_offset, updated_at=excluded.updated_at""",
                       (digest, update_id + 1, now))
            return True

    def bot_role(self, user_id: int, chat_id: int) -> str | None:
        with self.connection() as db:
            row = db.execute("SELECT role FROM bot_users WHERE user_id=? AND chat_id=?", (user_id, chat_id)).fetchone()
            return row["role"] if row else None

    def bot_chats(self) -> set[int]:
        with self.connection() as db:
            return {row["chat_id"] for row in db.execute("SELECT DISTINCT chat_id FROM bot_users")}

    def remove_bot_user(self, user_id: int, chat_id: int, *, actor: str | None = None,
                        session_token: str | None = None) -> bool:
        if (type(user_id) is not int or type(chat_id) is not int or
                not 0 < user_id <= 2**63 - 1 or not 0 < chat_id <= 2**63 - 1 or
                user_id != chat_id):
            raise ValueError("Telegram user_id and private chat_id must be positive integers")
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            identity = self._require_unrestricted_admin(db, session_token)
            self._cancel_bot_commands(db, user_id, chat_id, identity)
            removed = db.execute("DELETE FROM bot_users WHERE user_id=? AND chat_id=?",
                                 (user_id, chat_id)).rowcount != 0
            if removed:
                db.execute("""UPDATE incident_outbox SET dropped_at=?, lease_until=NULL
                              WHERE chat_id=? AND delivered_at IS NULL AND dropped_at IS NULL""",
                           (int(time.time()), chat_id))
                self._audit_account(db, identity, "bot_binding_removed",
                            details={"user_id": user_id, "chat_id": chat_id})
            return removed

    def audit_telegram_token(self, action: str, *, identity=None):
        if action not in ("telegram_token_saved", "telegram_token_removed"):
            raise ValueError("Invalid Telegram token audit action")
        with self.connection() as db:
            self._audit_account(db, identity, action, details={"mode": "managed"})

    def _cancel_bot_commands(self, db, user_id: int, chat_id: int, identity=None):
        pending = db.execute("DELETE FROM pending_commands WHERE actor_user_id=? AND chat_id=?",
                             (user_id, chat_id)).rowcount
        queued = db.execute("UPDATE jobs SET state='cancelled', command='', completed_at=? WHERE actor_user_id=? AND chat_id=? AND state='queued'",
                            (int(time.time()), user_id, chat_id)).rowcount
        if pending or queued:
            self._audit_account(db, identity, "bot_commands_cancelled",
                        details={"user_id": user_id, "chat_id": chat_id,
                                 "pending": pending, "queued": queued})

    @staticmethod
    def _audit(db, actor: str, action: str, server_id: str | None = None,
               subject_id: str | None = None, details: dict | None = None, now: int | None = None):
        db.execute("INSERT INTO audit_events (at, actor, action, server_id, subject_id, details) VALUES (?, ?, ?, ?, ?, ?)",
                   (int(time.time()) if now is None else now, actor, action, server_id, subject_id,
                    json.dumps(details or {}, separators=(",", ":"))))

    def audit_events(self, limit: int = 100, *, session_token=None) -> list[dict]:
        with self.connection() as db:
            identity = self._require_admin_session(db, session_token) if session_token is not None else None
            visible = self._visible_server_ids(db, identity=identity, role="admin")
            if visible is not None:
                if not visible:
                    return []
                rows = db.execute("SELECT * FROM audit_events WHERE server_id IN (" + ",".join("?" for _ in visible) + ") ORDER BY id DESC LIMIT ?", (*sorted(visible), limit)).fetchall()
            else:
                rows = db.execute("SELECT * FROM audit_events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(row) for row in rows]

    def set_remote_commands(self, server_id: str, enabled: bool, *, session_token: str | None = None) -> bool:
        if type(enabled) is not bool:
            raise ValueError("Expected boolean enabled")
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            identity = self._require_server_session(db, session_token, server_id, "admin")
            server = db.execute("SELECT id,remote_commands_enabled,management_revision FROM servers WHERE id=?", (server_id,)).fetchone()
            if server is None:
                return False
            self._write_command_gate(db, server, enabled, identity)
            return True

    def request_command(self, server_id: str, actor_user_id: int, chat_id: int, command: str,
                        now: int | None = None) -> str:
        now = int(time.time()) if now is None else now
        command = validate_command(command)
        code = secrets.token_urlsafe(12)
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            role = db.execute("SELECT role FROM bot_users WHERE user_id=? AND chat_id=?",
                              (actor_user_id, chat_id)).fetchone()
            if role is None or role["role"] != "admin":
                raise PermissionError("Telegram admin binding required")
            if not self._bot_allowed(db, actor_user_id, chat_id, server_id, "admin"):
                raise PermissionError("Telegram server access denied")
            row = db.execute("SELECT remote_commands_enabled FROM servers WHERE id=?", (server_id,)).fetchone()
            if row is None:
                raise KeyError("Server not found")
            if not row["remote_commands_enabled"]:
                raise PermissionError("Remote commands are disabled for this server")
            self._reject_agent_maintenance(db, server_id, now)
            db.execute("DELETE FROM pending_commands WHERE expires_at < ?", (now,))
            db.execute("INSERT INTO pending_commands VALUES (?, ?, ?, ?, ?, ?, ?)",
                       (hashlib.sha256(code.encode()).hexdigest(), server_id, actor_user_id, chat_id,
                        command, now, now + 60))
            self._audit(db, f"telegram:{actor_user_id}", "command_requested", server_id,
                        details={"command_sha256": hashlib.sha256(command.encode()).hexdigest()}, now=now)
        return code

    def queue_web_job(self, server_id: str, session_token: str, command: str,
                      idempotency_key: str | None = None, now: int | None = None,
                      require_amnezia_ready: str | None = None, *, audit_action: str = "command_queued",
                      audit_details: dict | None = None,
                      require_service_ready: str | None = None,
                      require_container_ready: str | None = None,
                      allow_service_marker: bool = False,
                      allow_vpn_marker: bool = False,
                      allow_amnezia_marker: bool = False,
                      allow_container_action_marker: bool = False) -> tuple[dict, bool]:
        """Queue once per admin session and optional client-generated request key."""
        if audit_action not in ("command_queued", "journal_requested", "process_inventory_requested",
                                "container_logs_requested"):
            raise ValueError("Invalid audit action")
        if sum((allow_service_marker, allow_vpn_marker, allow_amnezia_marker,
                allow_container_action_marker)) > 1:
            raise ValueError("A job can use only one control protocol")
        control_kind = ("service" if allow_service_marker else "vpn" if allow_vpn_marker else
                        "amnezia" if allow_amnezia_marker else
                        "container" if allow_container_action_marker else "generic")
        command = validate_command(command,
                                   allow_journal_marker=audit_action == "journal_requested",
                                   allow_process_marker=audit_action == "process_inventory_requested",
                                   allow_container_log_marker=audit_action == "container_logs_requested",
                                   allow_container_action_marker=allow_container_action_marker,
                                   allow_service_marker=allow_service_marker,
                                   allow_vpn_marker=allow_vpn_marker,
                                   allow_amnezia_marker=allow_amnezia_marker)
        if control_kind != "generic" and not _control_kind_matches(command, control_kind):
            raise ValueError("Control requires an exact structured command")
        if control_kind == "service":
            _, action, unit = command.split(" ")
            if action != "status" and require_service_ready != unit:
                raise ValueError("Service mutation needs matching status preflight")
        if control_kind == "amnezia":
            _, action, target = command.split(" ", 3)[:3]
            if action != "status" and require_amnezia_ready != target:
                raise ValueError("Amnezia operation needs matching status preflight")
        container_action = (parse_container_action_command(command)
                            if control_kind == "container" else None)
        if container_action is not None:
            action, _engine, ident = container_action
            if action != "status" and require_container_ready != ident:
                raise ValueError("Container mutation needs matching status preflight")
            audit_details = {"container_action": action,
                             "container_id_sha256": hashlib.sha256(ident.encode()).hexdigest(),
                             "engine": "docker"}
        container_target = (parse_container_log_command(command)
                            if audit_action == "container_logs_requested" else None)
        if idempotency_key is not None:
            if not isinstance(idempotency_key, str):
                raise ValueError("Idempotency-Key must be a UUID")
            try:
                parsed = uuid.UUID(idempotency_key)
            except (ValueError, AttributeError) as exc:
                raise ValueError("Idempotency-Key must be a UUID") from exc
            if str(parsed) != idempotency_key:
                raise ValueError("Idempotency-Key must be a canonical UUID")
        now = int(time.time()) if now is None else now
        token_hash = hashlib.sha256(session_token.encode()).hexdigest()
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            identity = self._require_server_session(db, session_token, server_id, "admin", now)
            self._reject_agent_maintenance(db, server_id, now)
            if idempotency_key is not None:
                previous = db.execute("""SELECT id, server_id, source, state, created_at,
                                             command_sha256, control_kind FROM jobs
                                        WHERE session_token_hash=? AND idempotency_key=?""",
                                      (token_hash, idempotency_key)).fetchone()
                if previous is not None:
                    if (previous["server_id"] != server_id or
                            previous["command_sha256"] != hashlib.sha256(command.encode()).hexdigest() or
                            previous["control_kind"] != control_kind):
                        raise IdempotencyConflict("Idempotency-Key was used for another command")
                    if container_action is not None:
                        sidecar = db.execute("""SELECT engine,action,container_id
                            FROM container_control_jobs WHERE job_id=?""",
                            (previous["id"],)).fetchone()
                        if (sidecar is None or tuple(sidecar) !=
                                (container_action[1], container_action[0], container_action[2])):
                            raise IdempotencyConflict("Container job provenance changed")
                    return ({key: previous[key] for key in ("id", "server_id", "source", "state", "created_at")}, False)
            server = db.execute("SELECT remote_commands_enabled, last_seen FROM servers WHERE id=?", (server_id,)).fetchone()
            if server is None:
                raise KeyError("Server not found")
            if not server["remote_commands_enabled"]:
                raise PermissionError("Remote commands are disabled for this server")
            if container_action is not None:
                self._fresh_container_inventory(db, server_id, container_action[2], now)
                if container_action[0] != "status" and self._ready_container_status(
                        db, server_id, container_action[2], now) is None:
                    raise ContainerControlUnavailable("Container control is unavailable; check status first")
            if container_target is not None:
                engine, ident, lines = container_target
                with self._processes_lock:
                    cached = self._latest_containers.get(server_id)
                if (server["last_seen"] is None or not 0 <= now - server["last_seen"] <= 120 or
                        cached is None or cached[2] is None):
                    raise PermissionError("Fresh container inventory is unavailable")
                sources = [source for source in cached[2]["engines"]
                           if source["engine"] == engine and source["source_status"] == "ok"
                           and not source["truncated"]]
                if len(sources) != 1 or not any(item["id"] == ident
                                                for item in sources[0]["containers"]):
                    raise PermissionError("Container is not in the complete inventory")
                # Audit identifiers, never log content or the raw command.
                audit_details = {"engine": engine,
                                 "container_id_sha256": hashlib.sha256(ident.encode()).hexdigest(),
                                 "lines": lines}
            if audit_action in ("journal_requested", "container_logs_requested"):
                recent = db.execute("""SELECT 1 FROM audit_events a
                    JOIN jobs j ON j.id=a.subject_id
                    WHERE a.at>? AND a.action=? AND a.server_id=?
                      AND j.server_id=? AND j.session_token_hash=? LIMIT 1""",
                                    (now - JOURNAL_MIN_INTERVAL_SECONDS, audit_action, server_id,
                                     server_id, token_hash)).fetchone()
                if recent is not None:
                    raise JournalRateLimited("Подождите 20 секунд перед следующим запросом диагностических данных")
            if require_amnezia_ready:
                status_hash = hashlib.sha256(status_command(require_amnezia_ready).encode()).hexdigest()
                status_row = db.execute("""SELECT state, exit_code, output, completed_at FROM jobs
                                          WHERE server_id=? AND source='web' AND command_sha256=?
                                          ORDER BY jobs.rowid DESC LIMIT 1""",
                                        (server_id, status_hash)).fetchone()
                control = control_status(dict(status_row) if status_row else None, now,
                                         require_amnezia_ready)
                if (control["source_status"] != "ok" or not control["enrolled"] or
                        control["recovery_required"]):
                    raise AmneziaControlUnavailable("Amnezia control is unavailable or requires recovery")
            if require_service_ready:
                if self._ready_service_status(db, server_id, require_service_ready, now) is None:
                    raise ServiceControlUnavailable("Service control is unavailable; check status first")
            job_id = str(uuid.uuid4())
            db.execute("""INSERT INTO jobs
                       (id, server_id, actor_user_id, chat_id, source, session_token_hash,
                        idempotency_key, command_sha256, control_kind, command, state, created_at)
                       VALUES (?, ?, 0, 0, 'web', ?, ?, ?, ?, ?, 'queued', ?)""",
                       (job_id, server_id, token_hash, idempotency_key,
                        hashlib.sha256(command.encode()).hexdigest(), control_kind,
                        command, now))
            if container_action is not None:
                db.execute("""INSERT INTO container_control_jobs
                    (job_id,engine,action,container_id) VALUES (?,?,?,?)""",
                    (job_id, container_action[1], container_action[0], container_action[2]))
            self._audit_account(db, identity, audit_action, server_id, job_id,
                        details={"source": "web", "command_sha256": hashlib.sha256(command.encode()).hexdigest(),
                                 **(audit_details or {})}, now=now)
        return ({"id": job_id, "server_id": server_id, "source": "web", "state": "queued", "created_at": now}, True)

    def confirm_command(self, code: str, actor_user_id: int, chat_id: int, now: int | None = None) -> dict | None:
        now = int(time.time()) if now is None else now
        if not code or len(code) > 100:
            return None
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            role = db.execute("SELECT role FROM bot_users WHERE user_id=? AND chat_id=?",
                              (actor_user_id, chat_id)).fetchone()
            if role is None or role["role"] != "admin":
                return None
            row = db.execute("SELECT p.*, s.remote_commands_enabled FROM pending_commands p JOIN servers s ON s.id=p.server_id WHERE code_hash=?",
                             (hashlib.sha256(code.encode()).hexdigest(),)).fetchone()
            if row is not None and self._agent_maintenance_active(db, row["server_id"], now):
                return None
            if row is None or row["expires_at"] < now or row["actor_user_id"] != actor_user_id or row["chat_id"] != chat_id or not row["remote_commands_enabled"] or not self._bot_allowed(db, actor_user_id, chat_id, row["server_id"], "admin"):
                return None
            db.execute("DELETE FROM pending_commands WHERE code_hash=?", (row["code_hash"],))
            try:
                validate_command(row["command"])
            except ValueError:
                self._audit(db, f"telegram:{actor_user_id}", "command_cancelled", row["server_id"],
                            details={"reason": "reserved_control_protocol"}, now=now)
                return None
            job_id = str(uuid.uuid4())
            db.execute("INSERT INTO jobs (id, server_id, actor_user_id, chat_id, command, state, created_at) VALUES (?, ?, ?, ?, ?, 'queued', ?)",
                       (job_id, row["server_id"], actor_user_id, chat_id, row["command"], now))
            self._audit(db, f"telegram:{actor_user_id}", "command_queued", row["server_id"], job_id, now=now)
            return {"id": job_id, "server_id": row["server_id"], "state": "queued"}

    def lease_job(self, server_id: str, now: int | None = None,
                  *, agent_token: str | None = None) -> dict | None:
        now = int(time.time()) if now is None else now
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            # The HTTP handler's initial bearer check may have completed before
            # token rotation. Authorize again under the same write lock that
            # claims and clears a queued command.
            if agent_token is not None:
                if not agent_token or len(agent_token) > 256:
                    return None
                server = db.execute("SELECT agent_token_hash FROM servers WHERE id=?", (server_id,)).fetchone()
                if (server is None or not hmac.compare_digest(
                        server["agent_token_hash"], hashlib.sha256(agent_token.encode()).hexdigest())):
                    return None
            if self._agent_maintenance_active(db, server_id, now):
                return None
            revoked = 0
            rejected_protocol = 0
            for queued in db.execute("""SELECT id,source,session_token_hash,actor_user_id,chat_id,
                                              command,control_kind
                    FROM jobs WHERE server_id=? AND state='queued'""", (server_id,)).fetchall():
                valid_protocol = _control_kind_matches(queued["command"], queued["control_kind"])
                if valid_protocol and queued["control_kind"] == "container":
                    sidecar = db.execute("""SELECT engine,action,container_id
                        FROM container_control_jobs WHERE job_id=?""", (queued["id"],)).fetchone()
                    action, engine, ident = parse_container_action_command(queued["command"])
                    valid_protocol = sidecar is not None and tuple(sidecar) == (engine, action, ident)
                if ((queued["control_kind"] != "generic" and queued["source"] != "web") or
                        not valid_protocol):
                    db.execute("UPDATE jobs SET state='cancelled',command='',completed_at=? WHERE id=?",
                               (now, queued["id"]))
                    rejected_protocol += 1
                    continue
                if queued["source"] == "web":
                    identity = db.execute("""SELECT u.* FROM sessions s JOIN hub_users u ON u.id=s.user_id
                        WHERE s.token_hash=? AND s.expires_at>? AND u.enabled=1""",
                        (queued["session_token_hash"], now)).fetchone()
                    allowed = identity is not None and self._user_allowed(db, identity, server_id, "admin")
                else:
                    allowed = self._bot_allowed(db, queued["actor_user_id"], queued["chat_id"], server_id, "admin")
                if not allowed:
                    db.execute("UPDATE jobs SET state='cancelled',command='',completed_at=? WHERE id=?",
                               (now, queued["id"]))
                    revoked += 1
            if revoked:
                self._audit(db, "system", "queued_jobs_cancelled", server_id,
                            details={"count": revoked, "reason": "access_revoked"}, now=now)
            if rejected_protocol:
                self._audit(db, "system", "queued_jobs_cancelled", server_id,
                            details={"count": rejected_protocol,
                                     "reason": "reserved_control_protocol"}, now=now)
            server = db.execute("SELECT remote_commands_enabled FROM servers WHERE id=?", (server_id,)).fetchone()
            if server is None or not server["remote_commands_enabled"]:
                return None
            job = db.execute("""SELECT j.* FROM jobs j WHERE j.server_id=? AND j.state='queued'
                                ORDER BY j.created_at, j.id LIMIT 1""", (server_id,)).fetchone()
            if job is None:
                return None
            db.execute("UPDATE jobs SET state='delivered', command='', delivered_at=? WHERE id=?", (now, job["id"]))
            self._audit(db, f"agent:{server_id}", "command_delivered", server_id, job["id"], now=now)
            return {"id": job["id"], "command": job["command"],
                    "timeout_seconds": (135 if is_amnezia_command(job["command"]) else
                                        105 if is_vpn_command(job["command"]) else
                                        60 if is_service_command(job["command"]) else
                                        40 if is_container_action_command(job["command"]) else 15),
                    "output_limit_bytes": 8192}

    def cancel_undisclosed_job(self, server_id: str, job_id: str, now: int | None = None) -> None:
        """Record a revoked lease that was withheld from the HTTP response."""
        now = int(time.time()) if now is None else now
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            cancelled = db.execute("""UPDATE jobs SET state='cancelled', completed_at=?
                WHERE id=? AND server_id=? AND state='delivered'""", (now, job_id, server_id)).rowcount
            if cancelled:
                self._audit(db, "system", "command_cancelled", server_id, job_id,
                            details={"reason": "agent_token_rotated_before_disclosure"}, now=now)

    def finish_job(self, server_id: str, job_id: str, state: str, exit_code: int | None,
                   output: str, now: int | None = None) -> dict | None:
        if state not in ("succeeded", "failed", "timed_out", "output_limited"):
            raise ValueError("Invalid job state")
        if not isinstance(output, str) or len(output.encode("utf-8")) > 8192:
            raise ValueError("Output exceeds 8192 bytes")
        if exit_code is not None and (isinstance(exit_code, bool) or not isinstance(exit_code, int)):
            raise ValueError("Invalid exit code")
        now = int(time.time()) if now is None else now
        with self._journal_lock:
            with self.connection() as db:
                db.execute("BEGIN IMMEDIATE")
                row = db.execute("SELECT * FROM jobs WHERE id=? AND server_id=?", (job_id, server_id)).fetchone()
                if row is None:
                    return None
                special = db.execute("""SELECT action,details FROM audit_events
                    WHERE action IN ('journal_requested','process_inventory_requested',
                                     'container_logs_requested')
                      AND server_id=? AND subject_id=? LIMIT 1""",
                                     (server_id, job_id)).fetchone()
                transient = special is not None
                process_job = special is not None and special["action"] == "process_inventory_requested"
                container_log_job = special is not None and special["action"] == "container_logs_requested"
                just_completed = row["state"] == "delivered"
                if just_completed:
                    if process_job:
                        # A compromised or older Agent must not place arbitrary
                        # text in the transient process view. Fail closed.
                        try:
                            request = json.loads(special["details"])
                            if state != "succeeded" or exit_code != 0:
                                output = "Process inventory unavailable"
                            else:
                                output = validate_process_snapshot(output,
                                    request["after_pid"], request["limit"],
                                    request["filter_sha256"], now)
                        except (KeyError, TypeError, ValueError):
                            state, exit_code, output = "failed", None, "Process inventory response was invalid"
                    if container_log_job and (not safe_container_log_output(output) or
                                              (state == "succeeded" and exit_code != 0)):
                        state, exit_code, output = "failed", None, "Container log response was invalid"
                    if row["control_kind"] == "container":
                        target = db.execute("""SELECT engine,action,container_id
                            FROM container_control_jobs WHERE job_id=?""", (job_id,)).fetchone()
                        action = target["action"] if target is not None else None
                        try:
                            if target is None or target["engine"] != "docker":
                                raise ValueError("Missing container job provenance")
                            public = container_action_result(output, action, target["container_id"])
                            expected = ("succeeded", 0) if public["result"] == "ok" else (
                                ("timed_out", None) if public["result"] == "uncertain" else
                                ("failed", None))
                            if (state, exit_code) != expected:
                                raise ValueError("Container job result state mismatch")
                            output = json.dumps(public, separators=(",", ":"))
                        except ValueError:
                            # The POST may have happened even if the reply was
                            # lost or malformed. Never describe a mutation as
                            # a known failure that a user could blindly retry.
                            state = "failed" if action == "status" else "timed_out"
                            exit_code = None
                            output = ("Container status unavailable" if action == "status" else
                                      "Container action outcome uncertain")
                    db.execute("UPDATE jobs SET state=?, completed_at=?, exit_code=?, output=? WHERE id=?",
                               (state, now, exit_code, "" if transient else output, job_id))
                    self._audit(db, f"agent:{server_id}", "command_completed", server_id, job_id,
                                {"state": state, "exit_code": exit_code}, now=now)
                updated = db.execute("SELECT id, server_id, actor_user_id, chat_id, source, state, created_at, delivered_at, completed_at, exit_code, output FROM jobs WHERE id=?", (job_id,)).fetchone()
                result = dict(updated) | {"just_completed": just_completed}
            if just_completed and transient:
                self._prune_journal_outputs()
                self._journal_outputs[job_id] = (time.monotonic() + JOURNAL_OUTPUT_TTL_SECONDS, output)
                self._prune_journal_outputs()
            return result

    def jobs(self, limit: int = 100, *, session_token=None) -> list[dict]:
        with self.connection() as db:
            identity = self._require_admin_session(db, session_token) if session_token is not None else None
            visible = self._visible_server_ids(db, identity=identity, role="admin")
            if visible is not None and not visible:
                return []
            query = "SELECT j.id, j.server_id, s.name AS server_name, j.actor_user_id, j.chat_id, j.source, j.state, j.created_at, j.delivered_at, j.completed_at, j.exit_code, j.output, j.control_kind FROM jobs j JOIN servers s ON s.id=j.server_id"
            args = []
            if visible is not None:
                query += " WHERE j.server_id IN (" + ",".join("?" for _ in visible) + ")"
                args.extend(sorted(visible))
            rows = db.execute(query + " ORDER BY j.created_at DESC, j.id DESC LIMIT ?", (*args, limit)).fetchall()
        summaries = []
        for row in rows:
            summary = dict(row)
            summary["output"] = _job_list_output(summary["output"], summary.pop("control_kind"))
            summaries.append(summary)
        return summaries

    def job(self, job_id: str, session_token: str | None = None) -> dict | None:
        with self._journal_lock:
            with self.connection() as db:
                row = db.execute("SELECT j.id, j.server_id, s.name AS server_name, j.actor_user_id, j.chat_id, j.source, j.session_token_hash, j.state, j.created_at, j.delivered_at, j.completed_at, j.exit_code, j.output FROM jobs j JOIN servers s ON s.id=j.server_id WHERE j.id=?", (job_id,)).fetchone()
                if row is None:
                    return None
                if session_token is not None:
                    self._require_server_session(db, session_token, row["server_id"], "admin")
                transient = db.execute("""SELECT 1 FROM audit_events
                    WHERE action IN ('journal_requested','process_inventory_requested',
                                     'container_logs_requested')
                      AND subject_id=? LIMIT 1""", (job_id,)).fetchone() is not None
            result = dict(row)
            if transient:
                if (not session_token or hashlib.sha256(session_token.encode()).hexdigest() !=
                        result["session_token_hash"]):
                    raise PermissionError("Transient result belongs to another session")
                self._prune_journal_outputs()
                cached = self._journal_outputs.get(job_id)
                result["transient_output"] = True
                result["output_expired"] = cached is None and result["state"] in (
                    "succeeded", "failed", "timed_out", "output_limited")
                result["output"] = cached[1] if cached is not None else ""
            result.pop("session_token_hash", None)
            return result

    def job_for_bot(self, job_id: str, actor_user_id: int, chat_id: int) -> dict | None:
        with self.connection() as db:
            row = db.execute("SELECT id, server_id, state, created_at, completed_at, exit_code, output FROM jobs WHERE id=? AND actor_user_id=? AND chat_id=?",
                             (job_id, actor_user_id, chat_id)).fetchone()
            if row is not None and not self._bot_allowed(db, actor_user_id, chat_id, row["server_id"], "admin"):
                return None
        return dict(row) if row else None
