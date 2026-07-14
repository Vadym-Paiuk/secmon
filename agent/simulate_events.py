"""
Генератор фейкових подій для тестування конвеєра агент -> сервер -> БД
без реального Snort чи Windows Firewall трафіку.

Запуск: python simulate_events.py
"""
import random
import time
import requests
import yaml

with open("config.yaml", "r", encoding="utf-8") as f:
    cfg = yaml.safe_load(f)

SERVER_URL = cfg["server_url"].rstrip("/")
NODE_ID = cfg.get("node_id") or "test-node-1"

SOURCES = ["firewall", "snort", "av"]
ACTIONS = ["blocked", "allowed", "alert"]


def random_ip():
    return f"192.168.0.{random.randint(2, 254)}"


def make_event():
    source = random.choice(SOURCES)
    action = "blocked" if source == "firewall" and random.random() < 0.3 else random.choice(ACTIONS)
    severity = random.randint(4, 5) if action == "blocked" else random.randint(1, 3)

    return {
        "node_id": NODE_ID,
        "source": source,
        "severity": severity,
        "src_ip": random_ip(),
        "dst_ip": random_ip(),
        "port": random.choice([22, 80, 443, 3389, 8080]),
        "action": action,
        "raw": {"simulated": True, "note": f"тестова подія {source}"},
    }


def send_heartbeat():
    requests.post(f"{SERVER_URL}/api/heartbeat", json={
        "node_id": NODE_ID,
        "hostname": "test-laptop",
        "ip_address": "192.168.0.99",
        "os_info": "Windows 11 (simulated)",
    })


def main():
    print(f"Шлю тестові події на {SERVER_URL}, node_id={NODE_ID}")
    send_heartbeat()

    for i in range(20):
        batch = [make_event() for _ in range(random.randint(1, 4))]
        resp = requests.post(f"{SERVER_URL}/api/events", json={"events": batch})
        print(f"[{i+1}/20] відправлено {len(batch)} подій -> {resp.status_code}")
        time.sleep(1)

    print("Готово. Перевір: GET /api/events, /api/nodes, /api/stats/summary, /api/alerts")


if __name__ == "__main__":
    main()
