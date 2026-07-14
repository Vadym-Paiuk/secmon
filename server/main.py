"""
SecMon Server v0.2 - з ієрархічним зберіганням та крос-кореляцією firewall↔Snort.
"""
import os
import logging
from datetime import datetime, timezone, timedelta

from fastapi import FastAPI, Depends, Body
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import func, desc, and_

from database import engine, get_db, Base
from models import Node, Event, EventArchive, Alert, Config
from schemas import EventBatchIn, NodeHeartbeat, EventOut, NodeOut

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("secmon-server")

Base.metadata.create_all(bind=engine)

app = FastAPI(title="SecMon Server", version="0.2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Часове вікно кореляції firewall↔Snort (хвилини)
CORRELATION_WINDOW_MIN = 10
# Горизонт оперативного шару (години) — після цього події без effectiveness архівуються
OPERATIONAL_HORIZON_H = 72


def _classify_threat(src_ip: str | None, dst_ip: str | None, port: int | None) -> str:
    """Визначає клас загрози за портом і напрямком."""
    if port in (22, 3389, 5900):
        return "lateral_movement"
    if port in (80, 443, 8080, 8443):
        return "reconnaissance"
    if port in (21, 25, 587, 993, 995):
        return "exfiltration"
    return "noise"


def _get_direction(src_ip: str | None, dst_ip: str | None) -> str:
    """Визначає напрямок трафіку відносно мережі 192.168.0.0/24."""
    def is_internal(ip):
        return ip and ip.startswith("192.168.0.")

    if is_internal(src_ip) and is_internal(dst_ip):
        return "internal"
    if is_internal(dst_ip):
        return "inbound"
    return "outbound"


@app.get("/")
def root():
    return {"status": "ok", "service": "secmon-server", "version": "0.2.0"}


@app.post("/api/heartbeat")
def heartbeat(payload: NodeHeartbeat, db: Session = Depends(get_db)):
    node = db.query(Node).filter(Node.node_id == payload.node_id).first()
    now = datetime.now(timezone.utc)
    if node is None:
        node = Node(
            node_id=payload.node_id, hostname=payload.hostname,
            ip_address=payload.ip_address, os_info=payload.os_info,
            last_seen=now, status="online",
        )
        db.add(node)
        log.info(f"Новий вузол: {payload.node_id} ({payload.hostname})")
    else:
        node.last_seen = now
        node.status = "online"
        node.hostname = payload.hostname
        node.ip_address = payload.ip_address
    db.commit()
    return {"status": "registered", "node_id": payload.node_id}


@app.post("/api/events")
def ingest_events(batch: EventBatchIn, db: Session = Depends(get_db)):
    if not batch.events:
        return {"inserted": 0}

    rows = []
    for e in batch.events:
        rows.append(Event(
            ts=e.ts or datetime.now(timezone.utc),
            node_id=e.node_id,
            source=e.source,
            severity=e.severity,
            src_ip=e.src_ip,
            dst_ip=e.dst_ip,
            port=e.port,
            action=e.action,
            raw=e.raw,
            effectiveness=0.0,
            layer="operational",
            direction=_get_direction(e.src_ip, e.dst_ip),
            threat_class=_classify_threat(e.src_ip, e.dst_ip, e.port),
        ))

    db.add_all(rows)
    db.commit()

    _run_correlation(db, batch.events)
    return {"inserted": len(rows)}


def _run_correlation(db: Session, events: list):
    """
    Кореляція двох рівнів:

    1. Проста: blocked + severity>=4 → alert (як раніше)
    2. Крос-джерельна firewall↔Snort: якщо src_ip з нової події вже
       фігурував в іншому джерелі протягом CORRELATION_WINDOW_MIN хвилин →
       підтверджений інцидент, підвищуємо effectiveness у всіх пов'язаних
       подіях і створюємо alert з вищою confidence.
    """
    window_start = datetime.now(timezone.utc) - timedelta(minutes=CORRELATION_WINDOW_MIN)

    for e in events:
        # --- Рівень 1: проста кореляція ---
        if e.action == "blocked" and (e.severity or 0) >= 4:
            alert = Alert(
                node_id=e.node_id,
                rule_triggered="high_severity_block",
                description=f"Заблоковано high-severity з {e.src_ip}",
                confidence=0.6,
                correlated_ips=[e.src_ip] if e.src_ip else [],
                incident_type=_classify_threat(e.src_ip, e.dst_ip, e.port),
            )
            db.add(alert)

        # --- Рівень 2: крос-кореляція firewall↔Snort по src_ip ---
        if not e.src_ip:
            continue

        OTHER_SOURCES = {"firewall", "snort", "av"} - {e.source}
        correlated = db.query(Event).filter(
            and_(
                Event.src_ip == e.src_ip,
                Event.source.in_(OTHER_SOURCES),
                Event.ts >= window_start,
            )
        ).all()

        if correlated:
            sources_found = {c.source for c in correlated}
            log.info(
                f"Крос-кореляція: {e.src_ip} фігурує в {e.source} і {sources_found} "
                f"протягом {CORRELATION_WINDOW_MIN}хв"
            )

            # Підвищуємо effectiveness у всіх пов'язаних подіях
            for c in correlated:
                c.effectiveness = min(1.0, (c.effectiveness or 0.0) + 0.4)
                c.layer = "analytical"

            # Оновлюємо effectiveness поточної події (ще не збережена — шукаємо тільки що додану)
            just_saved = db.query(Event).filter(
                and_(Event.src_ip == e.src_ip, Event.source == e.source, Event.ts >= window_start)
            ).all()
            for js in just_saved:
                js.effectiveness = min(1.0, (js.effectiveness or 0.0) + 0.4)
                js.layer = "analytical"

            # Створюємо підтверджений інцидент з високою confidence
            incident = Alert(
                node_id=e.node_id,
                rule_triggered="cross_source_correlation",
                description=(
                    f"IP {e.src_ip} виявлено одночасно у {e.source} та "
                    f"{', '.join(sources_found)} протягом {CORRELATION_WINDOW_MIN} хв"
                ),
                confidence=0.9,
                correlated_ips=[e.src_ip],
                incident_type=_classify_threat(e.src_ip, e.dst_ip, e.port),
            )
            db.add(incident)

    db.commit()


@app.get("/api/events", response_model=list[EventOut])
def list_events(
    node_id: str | None = None,
    source: str | None = None,
    layer: str | None = None,
    limit: int = 100,
    db: Session = Depends(get_db),
):
    query = db.query(Event).order_by(desc(Event.ts))
    if node_id:
        query = query.filter(Event.node_id == node_id)
    if source:
        query = query.filter(Event.source == source)
    if layer:
        query = query.filter(Event.layer == layer)
    return query.limit(limit).all()


@app.get("/api/nodes", response_model=list[NodeOut])
def list_nodes(db: Session = Depends(get_db)):
    nodes = db.query(Node).all()
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=30)
    for n in nodes:
        last_seen = n.last_seen
        if last_seen and last_seen.tzinfo is None:
            last_seen = last_seen.replace(tzinfo=timezone.utc)
        if last_seen and last_seen < cutoff:
            n.status = "offline"
    db.commit()
    return nodes


@app.get("/api/stats/summary")
def stats_summary(db: Session = Depends(get_db)):
    total_events      = db.query(func.count(Event.id)).scalar()
    total_nodes       = db.query(func.count(Node.node_id)).scalar()
    unresolved_alerts = db.query(func.count(Alert.id)).filter(Alert.resolved == False).scalar()
    analytical_events = db.query(func.count(Event.id)).filter(Event.layer == "analytical").scalar()
    archived_events   = db.query(func.count(EventArchive.id)).scalar()

    by_source = db.query(Event.source, func.count(Event.id)).group_by(Event.source).all()
    by_threat = db.query(Event.threat_class, func.count(Event.id)).group_by(Event.threat_class).all()

    return {
        "total_events":      total_events,
        "total_nodes":       total_nodes,
        "unresolved_alerts": unresolved_alerts,
        "analytical_events": analytical_events,
        "archived_events":   archived_events,
        "events_by_source":  {src: cnt for src, cnt in by_source},
        "events_by_threat":  {t: cnt for t, cnt in by_threat},
    }


@app.get("/api/alerts")
def list_alerts(resolved: bool | None = None, db: Session = Depends(get_db)):
    query = db.query(Alert).order_by(desc(Alert.ts))
    if resolved is not None:
        query = query.filter(Alert.resolved == resolved)
    return query.limit(100).all()


@app.get("/api/stats/layers")
def layer_stats(db: Session = Depends(get_db)):
    """Статистика по шарах зберігання — для розуміння розподілу даних."""
    operational = db.query(func.count(Event.id)).filter(Event.layer == "operational").scalar()
    analytical  = db.query(func.count(Event.id)).filter(Event.layer == "analytical").scalar()
    archived    = db.query(func.count(EventArchive.id)).scalar()
    avg_eff     = db.query(func.avg(Event.effectiveness)).scalar() or 0.0

    return {
        "operational": operational,
        "analytical":  analytical,
        "archived":    archived,
        "avg_effectiveness": round(float(avg_eff), 3),
    }



# ─── Дефолтний конфіг що видається агентам якщо специфічного нема ───────────
DEFAULT_AGENT_CONFIG = {
    "flush_interval": 30,
    "heartbeat_interval": 30,
    "min_severity": 2,           # не відправляти події з severity < 2
    "noise_ports": [80, 443, 53, 123, 67, 68, 5353],  # дозволений трафік на цих портах ігнорувати
    "snort_enabled": True,
    "firewall_event_ids": [5152, 5154, 5156, 5157],
}


@app.get("/api/configs/{node_id}")
def get_config(node_id: str, db: Session = Depends(get_db)):
    """
    Агент викликає цей ендпоінт під час heartbeat.
    Повертає актуальний конфіг для цього вузла.
    Якщо специфічного конфігу нема — повертає дефолтний.
    """
    cfg = (
        db.query(Config)
        .filter(Config.node_id == node_id, Config.config_type == "agent_policy")
        .order_by(desc(Config.version))
        .first()
    )
    if cfg:
        return {"node_id": node_id, "version": cfg.version, "config": cfg.payload}
    return {"node_id": node_id, "version": 0, "config": DEFAULT_AGENT_CONFIG}


@app.post("/api/configs/{node_id}")
def set_config(node_id: str, payload: dict = Body(...), db: Session = Depends(get_db)):
    """
    Адміністратор через дашборд або API встановлює конфіг для вузла.
    Автоматично інкрементує версію — агент побачить нову версію і застосує.
    """
    existing = (
        db.query(Config)
        .filter(Config.node_id == node_id, Config.config_type == "agent_policy")
        .order_by(desc(Config.version))
        .first()
    )
    new_version = (existing.version + 1) if existing else 1
    cfg = Config(
        node_id=node_id,
        config_type="agent_policy",
        payload=payload,
        version=new_version,
    )
    db.add(cfg)
    db.commit()
    log.info(f"Конфіг оновлено для {node_id}, версія {new_version}")
    return {"node_id": node_id, "version": new_version, "status": "saved"}


@app.get("/api/configs")
def list_configs(db: Session = Depends(get_db)):
    """Список поточних конфігів для всіх вузлів — для відображення в дашборді."""
    nodes = db.query(Node).all()
    result = []
    for n in nodes:
        cfg = (
            db.query(Config)
            .filter(Config.node_id == n.node_id, Config.config_type == "agent_policy")
            .order_by(desc(Config.version))
            .first()
        )
        result.append({
            "node_id": n.node_id,
            "hostname": n.hostname,
            "version": cfg.version if cfg else 0,
            "config": cfg.payload if cfg else DEFAULT_AGENT_CONFIG,
        })
    return result


if __name__ == "__main__":
    import uvicorn
    host = os.getenv("SERVER_HOST", "0.0.0.0")
    port = int(os.getenv("SERVER_PORT", "8000"))
    uvicorn.run("main:app", host=host, port=port, reload=True)

