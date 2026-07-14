"""
Читання подій Windows Firewall з Event Log.
"""

import win32evtlog
import xml.etree.ElementTree as ET
from datetime import datetime, timezone


FIREWALL_CHANNEL = "Security"

ACTION_MAP = {
    5152: "blocked",
    5157: "blocked",
    5154: "allowed",
    5156: "allowed",
}


def _parse_event_xml(xml_str: str) -> dict:
    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    root = ET.fromstring(xml_str)

    data = {}
    for el in root.findall(".//e:EventData/e:Data", ns):
        name = el.get("Name")
        data[name] = el.text

    event_id_el = root.find(".//e:System/e:EventID", ns)
    event_id = int(event_id_el.text) if event_id_el is not None else None

    return {"event_id": event_id, "fields": data}


def read_new_firewall_events(last_record_id: int | None, event_ids_filter: list[int]):
    events_out = []
    newest_record_id = last_record_id

    try:
        handle = win32evtlog.EvtQuery(
            FIREWALL_CHANNEL,
            win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection,
        )
    except Exception as ex:
        print(f"[firewall_reader] cannot open channel: {ex}")
        return [], last_record_id

    count_read = 0
    max_first_run = 200

    while True:
        events = win32evtlog.EvtNext(handle, 10)
        if not events:
            break

        for ev in events:
            xml_str = win32evtlog.EvtRender(ev, win32evtlog.EvtRenderEventXml)
            root = ET.fromstring(xml_str)

            parsed = _parse_event_xml(xml_str)
            event_id = parsed["event_id"]

            record_id_el = root.find(
                ".//{http://schemas.microsoft.com/win/2004/08/events/event}System/"
                "{http://schemas.microsoft.com/win/2004/08/events/event}EventRecordID"
            )
            record_id = int(record_id_el.text) if record_id_el is not None else None

            if last_record_id is not None and record_id is not None and record_id <= last_record_id:
                return events_out, newest_record_id

            if event_id not in event_ids_filter:
                count_read += 1
                if last_record_id is None and count_read >= max_first_run:
                    return events_out, newest_record_id
                continue

            fields = parsed["fields"]

            normalized = {
                "source": "firewall",
                "action": ACTION_MAP.get(event_id, "unknown"),
                "severity": 4 if ACTION_MAP.get(event_id) == "blocked" else 1,
                "src_ip": fields.get("SourceAddress"),
                "dst_ip": fields.get("DestAddress"),
                "port": int(fields.get("DestPort")) if fields.get("DestPort") and fields.get("DestPort").isdigit() else None,
                "raw": fields,
                "ts": datetime.now(timezone.utc).isoformat(),
            }

            # 🔥 ФІЛЬТР: прибираємо звичайний allowed-трафік
            NOISE_PORTS = {80, 443, 53, 123, 67, 68, 5353}  # HTTP, HTTPS, DNS, NTP, DHCP, mDNS
            if (normalized["action"] == "allowed" 
                and normalized["severity"] == 1 
                and normalized.get("port") in NOISE_PORTS):
                continue
            #if normalized["action"] == "allowed" and normalized["severity"] == 1:
                #continue  # пропускаємо звичайний дозволений трафік
            events_out.append(normalized)

            if newest_record_id is None or (record_id and record_id > newest_record_id):
                newest_record_id = record_id

            count_read += 1
            if last_record_id is None and count_read >= max_first_run:
                return events_out, newest_record_id

    return events_out, newest_record_id