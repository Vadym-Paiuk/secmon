"""
Читання Snort alert-логу у форматі alert_fast.

Формат рядка alert_fast приблизно такий:
    06/21-14:32:10.123456  [**] [1:1000001:1] ICMP test detected [**] \
    [Classification: Misc activity] [Priority: 3] {ICMP} 192.168.0.5 -> 192.168.0.10

Налаштування в snort.conf:
    output alert_fast: alert.ids
"""
import re
import os
from datetime import datetime, timezone

# Регулярка під стандартний alert_fast формат Snort
LINE_RE = re.compile(
    r"^(?P<ts>\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+"
    r"\[\*\*\]\s+\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+"
    r"(?P<msg>.+?)\s+\[\*\*\]\s+"
    r"(?:\[Classification:\s*(?P<classification>[^\]]*)\]\s+)?"
    r"(?:\[Priority:\s*(?P<priority>\d+)\]\s+)?"
    r"(?:\{(?P<proto>\w+)\}\s+)?"
    r"(?P<src_ip>[\d.]+)(?::\d+)?\s+->\s+(?P<dst_ip>[\d.]+)(?::(?P<dst_port>\d+))?"
)

# Snort priority (1=critical) -> наша 1-5 шкала severity (5=critical)
PRIORITY_TO_SEVERITY = {1: 5, 2: 4, 3: 3, 4: 2}


class SnortLogTailer:
    """
    "Tail -f"-подібний читач файлу: пам'ятає позицію, де зупинився,
    і при наступному виклику читає тільки нові рядки.
    Це найпростіший і найнадійніший спосіб для текстового логу, що постійно дописується.
    """

    def __init__(self, log_path: str):
        self.log_path = log_path
        self._position = 0
        # При першому запуску - одразу стаємо в кінець файлу,
        # щоб не заливати сервер всією історією
        if os.path.exists(log_path):
            self._position = os.path.getsize(log_path)

    def read_new_lines(self) -> list[str]:
        if not os.path.exists(self.log_path):
            return []

        lines = []
        with open(self.log_path, "r", encoding="utf-8", errors="ignore") as f:
            f.seek(self._position)
            for line in f:
                line = line.strip()
                if line:
                    lines.append(line)
            self._position = f.tell()

        return lines


def parse_snort_line(line: str) -> dict | None:
    """Парсить один рядок alert_fast у нормалізовану подію. Повертає None, якщо не матчиться."""
    m = LINE_RE.match(line)
    if not m:
        return None

    d = m.groupdict()
    priority = int(d["priority"]) if d.get("priority") else 3
    severity = PRIORITY_TO_SEVERITY.get(priority, 3)

    return {
        "source": "snort",
        "action": "alert",
        "severity": severity,
        "src_ip": d.get("src_ip"),
        "dst_ip": d.get("dst_ip"),
        "port": int(d["dst_port"]) if d.get("dst_port") else None,
        "raw": {
            "msg": d.get("msg"),
            "sid": d.get("sid"),
            "classification": d.get("classification"),
            "priority": priority,
            "proto": d.get("proto"),
            "snort_ts": d.get("ts"),
        },
        "ts": datetime.now(timezone.utc).isoformat(),
    }


def read_new_snort_events(tailer: SnortLogTailer) -> list[dict]:
    """Читає нові рядки з логу і повертає список нормалізованих подій."""
    events = []
    for line in tailer.read_new_lines():
        parsed = parse_snort_line(line)
        if parsed:
            events.append(parsed)
    return events
