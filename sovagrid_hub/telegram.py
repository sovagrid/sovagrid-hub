# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Optional Telegram alerts and role-gated commands."""

from __future__ import annotations

import json
import logging
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

from .vpn_status import read_vpn_status

TELEGRAM_ERROR_BODY_LIMIT = 4096


class _RejectRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow a redirect carrying a BotFather token in the URL."""

    def redirect_request(self, request, fp, code, message, headers, new_url):
        return None


class TelegramBot:
    def __init__(self, token: str, store, opener=None, vpn_status_path: str = "/vpn/status.json"):
        self.token = token.strip()
        self.store = store
        self.opener = opener or urllib.request.build_opener(_RejectRedirect()).open
        self.vpn_status_path = vpn_status_path
        self.stop = threading.Event()
        self._incident_wake = threading.Event()
        self.offset = store.telegram_update_offset(self.token)
        self.threads: list[threading.Thread] = []
        self.polling_started = False
        self.last_success_at: float | None = None
        self.last_error: str | None = None
        self._pairing_notice_at: dict[int, float] = {}

    def _call(self, method: str, payload: dict, timeout: int = 10) -> dict:
        request = urllib.request.Request(
            f"https://api.telegram.org/bot{self.token}/{method}",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with self.opener(request, timeout=timeout) as response:
            result = json.load(response)
        if not isinstance(result, dict) or result.get("ok") is not True:
            raise RuntimeError("Telegram API rejected request")
        return result

    def send_message(self, chat_id: int, message: str):
        self._call("sendMessage", {"chat_id": chat_id, "text": message[:4000]})

    def enqueue(self, events: list[dict]):
        # Store already committed incident outbox rows with their transitions.
        # This hint only reduces latency; a restarted bot polls SQLite anyway.
        if events:
            self._incident_wake.set()

    @staticmethod
    def _incident_kind(row: dict) -> str:
        if row["kind"].startswith("check:"):
            # Labels are administrator-controlled and may themselves contain a
            # private URL or token. Telegram only receives the stable check ID.
            return f"Недоступность проверки #{row['kind'][6:14]}"
        if row["kind"].startswith("tls:"):
            return f"Истекает TLS-сертификат проверки #{row['kind'][4:12]}"
        if row["kind"].startswith("container:"):
            # An opt-in Docker name can reveal a customer or workload. The
            # private chat receives only a short stable identifier.
            return f"Проблема с Docker-контейнером #{row['kind'][10:18]}"
        if row["kind"].startswith("filesystem:space:"):
            return f"Мало места на файловой системе #{row['kind'][17:25]}"
        if row["kind"].startswith("filesystem:inodes:"):
            return f"Заканчиваются inode файловой системы #{row['kind'][18:26]}"
        kinds = {"high_cpu": "Высокая нагрузка CPU", "high_memory": "Мало свободной памяти",
                 "high_disk": "Заканчивается место на диске",
                 "high_root_inodes": "Заканчиваются inode корневой файловой системы",
                 "failed_services": "Сбой системных служб",
                 "offline": "Нет связи с сервером",
                 "high_psi_cpu_some": "CPU перегружен (PSI, 10 с)",
                 "high_psi_memory_some": "Ожидание памяти (PSI, 10 с)",
                 "high_psi_memory_full": "Полная блокировка памяти (PSI, 10 с)",
                 "high_psi_io_some": "Ожидание диска (PSI, 10 с)",
                 "high_psi_io_full": "Полная блокировка I/O (PSI, 10 с)",
                 "high_cpu_iowait": "Время CPU в ожидании I/O",
                 "high_cpu_steal": "Время CPU, занятое гипервизором"}
        return kinds.get(row["kind"], row["kind"])

    @staticmethod
    def _incident_message(row: dict) -> str:
        state = "Восстановлено" if row["event_type"] == "recovery" else "Тревога"
        kind = TelegramBot._incident_kind(row)
        when = datetime.fromtimestamp(row["event_at"], timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        text = f"SovaGrid: {state}\nСервер: {row['server_name']}\nСобытие: {kind}\nВремя: {when}"
        if row["event_type"] == "reminder":
            text += "\nПовторное уведомление после окна обслуживания"
        if row["event_type"] == "recovery":
            elapsed = max(0, int(row["event_at"]) - int(row["opened_at"]))
            duration = f"{elapsed // 3600} ч {elapsed % 3600 // 60} мин" if elapsed >= 3600 else (
                f"{elapsed // 60} мин" if elapsed >= 60 else f"{elapsed} сек")
            text += f"\nДлительность: {duration}"
        if row["value"] is not None and row["kind"] == "failed_services":
            text += f"\nСлужб с ошибкой: {int(row['value'])}"
        elif row["value"] is not None and row["kind"].startswith("tls:"):
            label = "Новый сертификат действует ещё" if row["event_type"] == "recovery" else "До истечения"
            text += f"\n{label}: {row['value']:.1f} дн."
        elif row["value"] is not None and row["kind"] != "offline" and not row["kind"].startswith("check:"):
            text += f"\nЗначение: {row['value']:.1f}%"
        return text

    def enqueue_job_result(self, job: dict):
        # finish_job committed the outbox row with the job result. This hint
        # only wakes the sender; a restarted bot reads SQLite on its own.
        self._incident_wake.set()

    def enqueue_pairing_result(self, chat_id: int, role: str | None):
        # Approval/rejection and its notice were committed together.
        self._incident_wake.set()

    @staticmethod
    def _notice_message(row: dict) -> str:
        if row["kind"] == "job_result":
            return (f"SovaGrid: задание {row['source_id']} завершено: {row['job_state']} "
                    f"(exit={row['exit_code']}).\nВывод: /result {row['source_id']}")
        if row["kind"] == "pairing_approved":
            return f"SovaGrid: доступ подтверждён, роль {row['role']}. Отправьте /help."
        return "SovaGrid: запрос на подключение отклонён."

    def deliver_notice_once(self, now: int | None = None) -> bool:
        """Send one durable job/pairing notice with current ACL rechecked."""
        if self.stop.is_set():
            return False
        row = self.store.claim_telegram_notice(now=now)
        if row is None:
            return False
        if self.stop.is_set():
            self.store.retry_telegram_notice(row["id"], row["lease_generation"], now=now)
            return True
        if not self.store.telegram_notice_send_allowed(row["id"], row["lease_generation"], now=now):
            return True
        try:
            self.send_message(row["chat_id"], self._notice_message(row))
        except urllib.error.HTTPError as exc:
            permanent = exc.code in (400, 403, 410)
            retry_after = self._retry_after(exc) if exc.code == 429 else None
            try:
                exc.close()
            except Exception:
                pass
            self.store.retry_telegram_notice(row["id"], row["lease_generation"],
                                             permanent=permanent, now=now,
                                             retry_after=retry_after)
            logging.error("Telegram notice delivery failed; %s",
                          "dropped" if permanent else "retrying")
        except Exception:
            self.store.retry_telegram_notice(row["id"], row["lease_generation"], now=now)
            logging.error("Telegram notice delivery failed; retrying")
        else:
            self.store.complete_telegram_notice(row["id"], row["lease_generation"], now=now)
        return True

    @staticmethod
    def _retry_after(error: urllib.error.HTTPError) -> int | None:
        # Telegram returns flood-control delays in JSON ResponseParameters.
        # Read a bounded body and never log its description or request URL.
        try:
            body = error.read(TELEGRAM_ERROR_BODY_LIMIT + 1)
            if len(body) <= TELEGRAM_ERROR_BODY_LIMIT:
                result = json.loads(body)
                parameters = result.get("parameters") if isinstance(result, dict) else None
                delay = parameters.get("retry_after") if isinstance(parameters, dict) else None
                if type(delay) is int and 0 <= delay <= 2**31 - 1:
                    return delay
        except Exception:
            pass
        raw = error.headers.get("Retry-After") if error.headers is not None else None
        if isinstance(raw, str) and len(raw) <= 6 and raw.isascii() and raw.isdecimal():
            return int(raw)
        return None

    def deliver_incident_once(self, now: int | None = None) -> bool:
        """Send one durable transition, or return false when none is due."""
        if self.stop.is_set():
            return False
        row = self.store.claim_incident_outbox(now=now)
        if row is None:
            return False
        if self.stop.is_set():
            self.store.retry_incident_outbox(row["id"], row["lease_generation"], now=now)
            return True
        if not self.store.incident_outbox_send_allowed(row["id"], row["lease_generation"], now=now):
            return True
        try:
            self.send_message(row["chat_id"], self._incident_message(row))
        except urllib.error.HTTPError as exc:
            # HTTPError URLs contain BotFather tokens. Keep diagnostics fixed.
            # 401/404 can mean a BotFather token was revoked and may be
            # repaired in the panel; a blocked or invalid chat cannot.
            permanent = exc.code in (400, 403, 410)
            retry_after = self._retry_after(exc) if exc.code == 429 else None
            try:
                exc.close()
            except Exception:
                pass
            self.store.retry_incident_outbox(row["id"], row["lease_generation"], permanent=permanent,
                                             now=now, retry_after=retry_after)
            logging.error("Telegram incident delivery failed; %s", "dropped" if permanent else "retrying")
        except Exception:
            self.store.retry_incident_outbox(row["id"], row["lease_generation"], now=now)
            logging.error("Telegram incident delivery failed; retrying")
        else:
            self.store.complete_incident_outbox(row["id"], row["lease_generation"], now=now)
        return True

    def _send_loop(self):
        while not self.stop.is_set():
            try:
                incident = self.deliver_incident_once()
                notice = self.deliver_notice_once()
            except Exception:
                logging.error("Telegram outbox unavailable; retrying")
                self._incident_wake.wait(5)
                self._incident_wake.clear()
                continue
            if not incident and not notice:
                self._incident_wake.wait(1)
                self._incident_wake.clear()

    def _status(self, user_id=None, chat_id=None) -> str:
        servers = self.store.servers(bot=(user_id, chat_id) if user_id is not None else None)
        if not servers:
            return "SovaGrid: серверы пока не добавлены."
        lines = ["SovaGrid: состояние серверов"]
        for server in servers[:50]:
            state = "онлайн" if server["online"] else "офлайн"
            latest = server["latest"]
            if latest:
                lines.append(f"{server['name']}: {state}; CPU {latest['cpu_percent']:.1f}%, RAM {latest['memory_percent']:.1f}%, диск {latest['disk_percent']:.1f}%")
            else:
                lines.append(f"{server['name']}: нет метрик")
        if len(servers) > 50:
            lines.append(f"Ещё серверов: {len(servers) - 50}")
        return "\n".join(lines)[:4000]

    def _checks(self, user_id=None, chat_id=None) -> str:
        """Show fixed check states, never administrator targets or DNS answers."""
        labels = {"disabled": "выключена", "waiting": "ожидаем Agent",
                  "up": "доступна", "down": "недоступна", "stale": "данные устарели"}
        kinds = {"http": "HTTP", "tcp": "TCP", "dns": "DNS"}
        try:
            servers = self.store.servers(bot=(user_id, chat_id) if user_id is not None else None)
            lines = ["SovaGrid: сетевые проверки"]
            shown = 0
            length = len(lines[0])
            truncated = False
            for server in servers[:50]:
                summary = self.store.checks_summary(server["id"], bot=(user_id, chat_id) if user_id is not None else None)
                name = "".join(char for char in str(server["name"]) if char.isprintable())[:64]
                for row in summary["checks"]:
                    if shown >= 40:
                        truncated = True
                        break
                    line = (f"{name} · #{row['id'][:8]} · {kinds[row['kind']]}: "
                            f"{labels[row['state']]}")
                    if length + len(line) + 1 > 3800:
                        truncated = True
                        break
                    lines.append(line)
                    length += len(line) + 1
                    shown += 1
                if truncated:
                    break
        except Exception:
            return "SovaGrid: состояние сетевых проверок сейчас недоступно."
        if shown == 0:
            return ("SovaGrid: на первых 50 серверах нет сетевых проверок; полный список доступен в панели."
                    if len(servers) > 50 else "SovaGrid: сетевые проверки пока не настроены.")
        if len(servers) > 50 or truncated:
            lines.append("Показаны первые проверки; полный список доступен в панели.")
        return "\n".join(lines)

    def _vpn_status(self) -> str:
        try:
            snapshot = read_vpn_status(self.vpn_status_path)
        except Exception:
            # A failed inventory read must not interrupt Telegram polling or reveal paths.
            return "SovaGrid VPN: ошибка мониторинга; текущее состояние неизвестно."
        lines = ["SovaGrid VPN: состояние сервисов",
                 "Состояние службы и число настроенных клиентов не подтверждают работу VPN-подключения."]
        source_status = snapshot.get("source_status")
        if source_status == "ok":
            lines.append("Amnezia/Docker:")
            services = snapshot.get("services", [])
            if services:
                for service in services:
                    lines.append(f"{service['service']}: {service['state']}; Docker health: {service['health']}")
            else:
                lines.append("Известных VPN-контейнеров не обнаружено.")
        else:
            lines.append("Amnezia/Docker: " + self._vpn_source_message(source_status))

        managed = snapshot.get("managed")
        if not isinstance(managed, dict):
            lines.append("Управляемый WireGuard: данные недоступны.")
        elif managed.get("source_status") != "ok":
            lines.append("Управляемый WireGuard: " + self._vpn_source_message(managed.get("source_status")))
        else:
            lines.append("Управляемый WireGuard:")
            instances = managed.get("instances") or []
            if instances:
                for instance in instances:
                    count = instance["client_count"]
                    clients = (f"настроено клиентов: {count}" if count is not None
                               else "число клиентов неизвестно")
                    lines.append(f"{instance['name']}: {instance['state']}; {clients}")
            else:
                lines.append("Инстансов не обнаружено.")
        return "\n".join(lines)

    @staticmethod
    def _vpn_source_message(status) -> str:
        if status == "unavailable":
            return "данные недоступны; текущее состояние неизвестно."
        if status == "stale":
            return "данные устарели; текущее состояние неизвестно."
        return "ошибка мониторинга; текущее состояние неизвестно."

    def process_update(self, update: dict):
        if self.stop.is_set():
            return
        message = update.get("message")
        if not isinstance(message, dict):
            return
        chat = message.get("chat", {})
        sender = message.get("from", {})
        chat_id = chat.get("id")
        # A private chat ID identifies the user; group commands remain disabled.
        if chat.get("type") != "private" or sender.get("id") != chat_id:
            return
        text = message.get("text") or ""
        if not text.startswith("/"):
            return
        parts = text.split(maxsplit=2)
        command = parts[0].split("@", 1)[0]
        if command in ("/start", "/connect"):
            state = self.store.request_bot_pairing(sender["id"], chat_id,
                                                   sender.get("first_name"),
                                                   sender.get("last_name"),
                                                   sender.get("username"))
            now = time.monotonic()
            previous = self._pairing_notice_at.get(chat_id, 0.0)
            if state == "created" or now - previous >= 60:
                if len(self._pairing_notice_at) >= 512:
                    self._pairing_notice_at.pop(next(iter(self._pairing_notice_at)))
                self._pairing_notice_at[chat_id] = now
                response = {
                    "created": "SovaGrid: запрос отправлен администратору. После подтверждения отправьте /help.",
                    "pending": "SovaGrid: запрос уже ожидает подтверждения.",
                    "rejected": "SovaGrid: запрос пока отклонён. Повторите /start через 24 часа.",
                    "full": "SovaGrid: очередь запросов заполнена. Попробуйте позже.",
                    "bound": "SovaGrid: вы уже подключены. Отправьте /help.",
                }
                self.send_message(chat_id, response[state])
            return
        if command == "/whoami":
            self.send_message(chat_id, f"Telegram user_id: {sender['id']}\nprivate chat_id: {chat_id}")
            return
        role = self.store.bot_role(sender["id"], chat_id)
        if role is None:
            return
        if command == "/status":
            self.send_message(chat_id, self._status(sender["id"], chat_id))
        elif command == "/checks":
            self.send_message(chat_id, self._checks(sender["id"], chat_id))
        elif command == "/vpn":
            self.send_message(chat_id, self._vpn_status() if self.store.bot_unrestricted(sender["id"], chat_id)
                              else "Доступ к общему состоянию VPN ограничен.")
        elif command == "/alerts":
            incidents = self.store.incidents(limit=20, state="firing", bot=(sender["id"], chat_id))
            lines = ["Активные тревоги:"] + [
                f"{i['id']} {i['server_name']}: {self._incident_kind(i)}" for i in incidents]
            self.send_message(chat_id, "\n".join(lines) if incidents else "Активных тревог нет.")
        elif command == "/ack" and role in ("operator", "admin"):
            if len(parts) < 2:
                self.send_message(chat_id, "Формат: /ack <incident_id>")
            else:
                try:
                    incident = self.store.acknowledge(parts[1], actor=f"telegram:{sender['id']}",
                                                       bot=(sender["id"], chat_id))
                except PermissionError:
                    incident = None
                self.send_message(chat_id, "Тревога подтверждена." if incident else "Тревога не найдена.")
        elif command == "/exec" and role == "admin":
            if len(parts) < 3:
                self.send_message(chat_id, "Формат: /exec <server_id> <команда>")
                return
            try:
                code = self.store.request_command(parts[1], sender["id"], chat_id, parts[2])
            except (ValueError, KeyError, PermissionError):
                self.send_message(chat_id, "Команда отклонена: проверьте ID сервера и разрешение команд.")
                return
            self.send_message(chat_id, f"Подтвердите в течение 60 секунд: /confirm {code}")
        elif command == "/confirm" and role == "admin":
            if len(parts) < 2:
                self.send_message(chat_id, "Формат: /confirm <код>")
                return
            job = self.store.confirm_command(parts[1], sender["id"], chat_id)
            self.send_message(chat_id, f"Задание создано: {job['id']}" if job else "Код недействителен или срок истёк.")
        elif command == "/result" and role == "admin":
            if len(parts) < 2:
                self.send_message(chat_id, "Формат: /result <job_id>")
                return
            job = self.store.job_for_bot(parts[1], sender["id"], chat_id)
            if job is None:
                self.send_message(chat_id, "Задание не найдено.")
            else:
                self.send_message(chat_id, f"{job['id']}: {job['state']} (exit={job['exit_code']})\n{job['output'] or ''}"[:4000])
        elif command == "/help":
            options = ["/status — состояние серверов", "/checks — сетевые проверки",
                       "/vpn — состояние VPN-сервисов",
                       "/alerts — активные тревоги"]
            if role in ("operator", "admin"):
                options.append("/ack <incident_id> — подтвердить тревогу")
            if role == "admin":
                options.extend(["/exec <server_id> <команда>", "/confirm <код>", "/result <job_id>"])
            self.send_message(chat_id, "\n".join(options))

    def _poll_loop(self):
        while not self.stop.is_set():
            try:
                # Telegram may choose a new update-id range after a long idle
                # period. Reset only after the old delivery window has passed.
                self.offset = self.store.telegram_update_offset(self.token)
                result = self._call("getUpdates", {"offset": self.offset, "timeout": 20, "allowed_updates": ["message"]}, timeout=25)
                if self.stop.is_set():
                    return
                self.last_success_at = time.time()
                self.last_error = None
                for update in result.get("result", []):
                    if self.stop.is_set():
                        return
                    update_id = update.get("update_id")
                    if type(update_id) is not int or update_id < 0:
                        continue
                    # Claim before any command side effects. A crash can drop
                    # this update, but cannot execute it twice after restart.
                    claimed = self.store.claim_telegram_update(self.token, update_id)
                    self.offset = max(self.offset, update_id + 1)
                    if not claimed:
                        continue
                    try:
                        self.process_update(update)
                    except Exception:
                        logging.error("Telegram update processing failed")
            except Exception:
                self.last_error = "Telegram polling failed; retrying"
                logging.error("Telegram polling failed; retrying")
                self.stop.wait(5)

    def start(self, poll: bool = True):
        sender = threading.Thread(target=self._send_loop, daemon=True, name="sovagrid-telegram-send")
        sender.start()
        self.threads.append(sender)
        if poll:
            receiver = threading.Thread(target=self._poll_loop, daemon=True, name="sovagrid-telegram-poll")
            receiver.start()
            self.threads.append(receiver)
            self.polling_started = True

    def close(self):
        self.stop.set()
        self._incident_wake.set()
        for thread in self.threads:
            thread.join(timeout=2)
