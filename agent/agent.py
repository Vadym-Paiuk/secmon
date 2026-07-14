"""
SecMon Agent - фоновий процес на клієнтському Windows-ноутбуці.

Збирає події з:
  - Windows Firewall (Event Log)
  - Snort (alert_fast лог-файл)
шле на сервер по HTTP REST батчами, + періодичний heartbeat.

Запуск: python agent.py
Зупинка: Ctrl+C
"""
import time
import socket
import platform
import threading
import yaml
import requests

from firewall_reader import read_new_firewall_events
from snort_reader import SnortLogTailer, read_new_snort_events


def load_config(path: str = "config.yaml") -> dict:
    with open(path, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)

    if not cfg.get("node_id"):
        cfg["node_id"] = socket.gethostname()

    return cfg


def get_local_ip() -> str:
    """Визначає локальну IP-адресу машини в мережі (не 127.0.0.1)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip


class SecMonAgent:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.server_url = cfg["server_url"].rstrip("/")
        self.node_id = cfg["node_id"]
        self.event_buffer = []
        self.buffer_lock = threading.Lock()
        self.running = True

        self.snort_tailer = SnortLogTailer(cfg["snort_log_path"])
        self.last_fw_record_id = None

    # ---------- Збір подій ----------

    def collect_loop(self):
        """Окремий потік: постійно опитує джерела подій."""
        while self.running:
            try:
                self._collect_firewall()
                self._collect_snort()
            except Exception as ex:
                print(f"[agent] помилка збору подій: {ex}")
            time.sleep(3)

    def _collect_firewall(self):
        events, new_record_id = read_new_firewall_events(
            self.last_fw_record_id, self.cfg["firewall_event_ids"]
        )
        if new_record_id is not None:
            self.last_fw_record_id = new_record_id

        # Фільтруємо за min_severity і noise_ports з серверного конфігу
        min_sev = self.cfg.get("min_severity", 1)
        noise_ports = set(self.cfg.get("noise_ports", []))
        events = [
            e for e in events
            if (e.get("severity") or 0) >= min_sev
            and not (e.get("action") == "allowed" and e.get("port") in noise_ports)
        ]

        if events:
            self._add_to_buffer(events)
            print(f"[agent] firewall: +{len(events)} подій")

    def _collect_snort(self):
        if not self.cfg.get("snort_enabled", True):
            return  # Snort вимкнено з сервера

        events = read_new_snort_events(self.snort_tailer)
        if events:
            self._add_to_buffer(events)
            print(f"[agent] snort: +{len(events)} подій")

    def _add_to_buffer(self, events: list[dict]):
        for e in events:
            e["node_id"] = self.node_id
        with self.buffer_lock:
            self.event_buffer.extend(events)

    # ---------- Відправка на сервер ----------

    def flush_loop(self):
        """Окремий потік: періодично відправляє накопичені події на сервер."""
        while self.running:
            time.sleep(self.cfg["flush_interval"])
            self._flush()

    def _flush(self):
        with self.buffer_lock:
            if not self.event_buffer:
                return
            batch = self.event_buffer
            self.event_buffer = []

        try:
            resp = requests.post(
                f"{self.server_url}/api/events",
                json={"events": batch},
                timeout=10,
            )
            resp.raise_for_status()
            print(f"[agent] відправлено {len(batch)} подій -> сервер OK")
        except requests.RequestException as ex:
            print(f"[agent] не вдалось відправити події: {ex}, повертаю в буфер")
            with self.buffer_lock:
                self.event_buffer = batch + self.event_buffer

    def heartbeat_loop(self):
        """Окремий потік: каже серверу 'я живий' і перевіряє оновлення конфігу."""
        self._current_config_version = -1  # відстежуємо версію щоб не застосовувати двічі

        while self.running:
            try:
                requests.post(
                    f"{self.server_url}/api/heartbeat",
                    json={
                        "node_id": self.node_id,
                        "hostname": socket.gethostname(),
                        "ip_address": get_local_ip(),
                        "os_info": platform.platform(),
                    },
                    timeout=5,
                )
                print(f"[agent] heartbeat OK ({self.node_id})")

                # Перевіряємо чи є новий конфіг від сервера
                self._poll_config()

            except requests.RequestException as ex:
                print(f"[agent] heartbeat не вдався: {ex}")
            time.sleep(self.cfg["heartbeat_interval"])

    def _poll_config(self):
        """Запитує сервер на новий конфіг. Якщо версія нова — застосовує."""
        try:
            resp = requests.get(
                f"{self.server_url}/api/configs/{self.node_id}",
                timeout=5,
            )
            resp.raise_for_status()
            data = resp.json()
            server_version = data.get("version", 0)

            if server_version > self._current_config_version:
                self._apply_config(data["config"], server_version)
        except requests.RequestException as ex:
            print(f"[agent] не вдалось отримати конфіг: {ex}")

    def _apply_config(self, config: dict, version: int):
        """Застосовує новий конфіг отриманий від сервера."""
        old_version = self._current_config_version
        self._current_config_version = version

        # Оновлюємо інтервали якщо змінились
        if "flush_interval" in config:
            self.cfg["flush_interval"] = config["flush_interval"]
        if "heartbeat_interval" in config:
            self.cfg["heartbeat_interval"] = config["heartbeat_interval"]
        if "firewall_event_ids" in config:
            self.cfg["firewall_event_ids"] = config["firewall_event_ids"]
        if "snort_enabled" in config:
            self.cfg["snort_enabled"] = config["snort_enabled"]
        if "min_severity" in config:
            self.cfg["min_severity"] = config["min_severity"]
        if "noise_ports" in config:
            self.cfg["noise_ports"] = config["noise_ports"]

        print(f"[agent] конфіг оновлено: версія {old_version} → {version}, "
              f"flush={self.cfg['flush_interval']}с, "
              f"min_severity={self.cfg.get('min_severity', 1)}, "
              f"snort={'увімк' if self.cfg.get('snort_enabled', True) else 'вимк'}")


    def run(self):
        print(f"[agent] старт, node_id={self.node_id}, сервер={self.server_url}")
        threads = [
            threading.Thread(target=self.collect_loop, daemon=True),
            threading.Thread(target=self.flush_loop, daemon=True),
            threading.Thread(target=self.heartbeat_loop, daemon=True),
        ]
        for t in threads:
            t.start()

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[agent] зупинка...")
            self.running = False
            self._flush()  # відправити те, що лишилось у буфері


if __name__ == "__main__":
    config = load_config()
    agent = SecMonAgent(config)
    agent.run()
