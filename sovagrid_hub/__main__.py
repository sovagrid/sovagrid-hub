# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""SovaGrid Hub command line."""

from __future__ import annotations

import argparse
import getpass
import ipaddress
import json
import logging
import os
import signal
import threading
import time
from pathlib import Path

from .http_api import HubApp, make_server
from .store import Store
from .telegram_runtime import TelegramRuntime


def main(argv=None):
    parser = argparse.ArgumentParser(description="SovaGrid Hub")
    parser.add_argument("--db", default="/var/lib/sovagrid-hub/hub.sqlite", help="SQLite database path")
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init", help="Create database and admin account")
    init.add_argument("--username", default="admin")
    serve = sub.add_parser("serve", help="Serve HTTP behind a TLS reverse proxy")
    serve.add_argument("--bind", default="127.0.0.1", help="IPv4 listen address (default: 127.0.0.1)")
    serve.add_argument("--trusted-proxy", action="append", default=[], help="IPv4 proxy address allowed to set the client-IP header")
    serve.add_argument("--port", type=int, default=8765)
    serve.add_argument("--telegram-token-file", help="Managed data token path, or legacy external read-only token file")
    serve.add_argument("--no-telegram-poll", action="store_true")
    serve.add_argument("--cpu-threshold", type=float, default=90)
    serve.add_argument("--memory-threshold", type=float, default=90)
    serve.add_argument("--disk-threshold", type=float, default=90)
    serve.add_argument("--offline-seconds", type=int, default=120)
    serve.add_argument("--retention-days", type=int, default=30)
    bot = sub.add_parser("bot-user", help="Manage private Telegram bot bindings")
    bot.add_argument("action", choices=("add", "remove"))
    bot.add_argument("--user-id", type=int, required=True)
    bot.add_argument("--chat-id", type=int, required=True)
    bot.add_argument("--role", choices=("viewer", "operator", "admin"))
    passwd = sub.add_parser("passwd", help="Change admin password and revoke sessions")
    passwd.add_argument("--username", default="admin")
    sub.add_parser("ssh-grant", help="Issue a short, one-use Hub login grant from a host-authorized one-shot container")
    args = parser.parse_args(argv)
    os.umask(0o077)
    if args.command == "ssh-grant" and (os.getpid() != 1 or os.getuid() != 10001 or os.geteuid() != 10001):
        parser.error("ssh-grant requires a host-authorized one-shot Hub container running as UID 10001")
    if args.command == "serve":
        if any(not 0 < x <= 100 for x in (args.cpu_threshold, args.memory_threshold, args.disk_threshold)):
            parser.error("Thresholds must be >0 and <=100")
        if args.offline_seconds < 10 or not 1 <= args.retention_days <= 3650:
            parser.error("Invalid offline or retention interval")
        if not 1 <= args.port <= 65535:
            parser.error("Port must be between 1 and 65535")
        try:
            ipaddress.IPv4Address(args.bind)
            for proxy in args.trusted_proxy:
                ipaddress.IPv4Address(proxy)
        except ValueError:
            parser.error("--bind and --trusted-proxy must be IPv4 addresses")
    store = Store(args.db)
    if args.command == "init":
        password = getpass.getpass("Admin password (at least 12 characters): ")
        again = getpass.getpass("Repeat admin password: ")
        if password != again:
            parser.error("Passwords do not match")
        store.initialize(args.username, password)
        print("SovaGrid Hub database initialized.")
        return
    if not Path(args.db).exists():
        parser.error("Database does not exist; run init first")
    store.migrate()
    if args.command == "ssh-grant":
        print(json.dumps(store.issue_ssh_grant(), separators=(",", ":")))
        return
    if args.command == "bot-user":
        if args.action == "add":
            if args.role is None:
                parser.error("--role is required for add")
            store.add_bot_user(args.user_id, args.chat_id, args.role)
            print("Telegram binding saved.")
        else:
            store.remove_bot_user(args.user_id, args.chat_id)
            print("Telegram binding removed.")
        return
    if args.command == "passwd":
        old = getpass.getpass("Current admin password: ")
        new = getpass.getpass("New admin password (at least 12 characters): ")
        again = getpass.getpass("Repeat new admin password: ")
        if new != again:
            parser.error("Passwords do not match")
        if not store.change_password(args.username, old, new):
            parser.error("Current credentials are invalid")
        print("Password changed; existing sessions revoked.")
        return
    store = Store(args.db, offline_seconds=args.offline_seconds,
                  thresholds={"high_cpu": args.cpu_threshold, "high_memory": args.memory_threshold,
                              "high_disk": args.disk_threshold})
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    telegram = TelegramRuntime(store, args.db, args.telegram_token_file,
                               poll=not args.no_telegram_poll)
    app = HubApp(store, telegram, set(args.trusted_proxy))
    server = make_server(app, args.port, bind=args.bind)
    stop = threading.Event()

    def sweep():
        last_prune = 0.0
        while not stop.wait(10):
            try:
                app.emit(store.sweep_offline())
                store.prune_journal_outputs()
                if time.monotonic() - last_prune > 86400:
                    store.prune_metrics(args.retention_days)
                    store.prune_incident_outbox()
                    last_prune = time.monotonic()
            except Exception:
                logging.exception("Offline alert sweep failed")

    sweeper = threading.Thread(target=sweep, daemon=True, name="sovagrid-offline-sweep")
    previous_sigterm = None

    def terminate(_signum, _frame):
        # Docker stops the Hub with SIGTERM. Unwind serve_forever on the main
        # thread so its existing cleanup runs before the container exits.
        raise SystemExit(0)

    try:
        if threading.current_thread() is threading.main_thread():
            previous_sigterm = signal.signal(signal.SIGTERM, terminate)
        sweeper.start()
        telegram.start()
        logging.info("Hub listening on %s:%d", args.bind, server.server_port)
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        if previous_sigterm is not None:
            signal.signal(signal.SIGTERM, previous_sigterm)
        stop.set()
        server.server_close()
        telegram.close()


if __name__ == "__main__":
    main()
