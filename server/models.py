"""
SQLAlchemy ORM моделі - відповідають таблицям у PostgreSQL.
"""
from sqlalchemy import (
    Column, Integer, BigInteger, String, SmallInteger,
    Boolean, DateTime, ForeignKey, JSON, Float, Text
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.sql import func
from database import Base

# JSONB - тільки в PostgreSQL. Для SQLite (зручно для тесту на одному ноутбуці)
# автоматично використовується звичайний JSON - так таблиці створюються на обох БД.
JsonType = JSON().with_variant(JSONB(), "postgresql")


class Node(Base):
    """Зареєстровані клієнтські вузли (ноутбуки) в мережі."""
    __tablename__ = "nodes"

    node_id    = Column(String, primary_key=True)
    hostname   = Column(String)
    ip_address = Column(String)
    os_info    = Column(String)
    last_seen  = Column(DateTime(timezone=True))
    status     = Column(String, default="offline")  # online | offline


class Event(Base):
    """
    Оперативний шар — останні 72 години активних подій.
    Поле effectiveness: 0.0 = просто шум, 1.0 = підтверджена атака.
    Поле layer: 'operational' | 'analytical' (підтверджений інцидент).
    """
    __tablename__ = "events"

    id = Column(
        BigInteger().with_variant(Integer(), "sqlite"),
        primary_key=True, autoincrement=True
    )
    ts            = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    node_id       = Column(String, nullable=False)
    source        = Column(String, nullable=False)   # firewall | snort | av
    severity      = Column(SmallInteger)             # 1-5
    src_ip        = Column(String)
    dst_ip        = Column(String)
    port          = Column(Integer)
    action        = Column(String)                   # blocked | allowed | alert
    raw           = Column(JsonType)

    # --- нові поля відповідно до методу ---
    effectiveness = Column(Float, default=0.0)       # 0.0–1.0, підвищується при кореляції
    layer         = Column(String, default="operational")  # operational | analytical
    correlated_alert_id = Column(Integer, ForeignKey("alerts.id"), nullable=True)  # прив'язка до інциденту
    protocol      = Column(String)                   # TCP | UDP | ICMP
    direction     = Column(String)                   # inbound | outbound | internal
    threat_class  = Column(String)                   # reconnaissance | lateral_movement | exfiltration | noise


class EventArchive(Base):
    """
    Архівний шар — сирі події старші горизонту що не підтвердились як атаки.
    Зберігаються стиснуто (тільки ключові поля, без raw).
    """
    __tablename__ = "events_archive"

    id        = Column(BigInteger().with_variant(Integer(), "sqlite"), primary_key=True, autoincrement=True)
    orig_id   = Column(BigInteger().with_variant(Integer(), "sqlite"))  # оригінальний id з events
    ts        = Column(DateTime(timezone=True))
    node_id   = Column(String)
    source    = Column(String)
    severity  = Column(SmallInteger)
    src_ip    = Column(String)
    dst_ip    = Column(String)
    port      = Column(Integer)
    action    = Column(String)
    archived_at = Column(DateTime(timezone=True), server_default=func.now())


class Config(Base):
    """Конфігурації, що сервер розповсюджує на клієнтів."""
    __tablename__ = "configs"

    id          = Column(Integer, primary_key=True, autoincrement=True)
    node_id     = Column(String, ForeignKey("nodes.node_id"))
    config_type = Column(String)
    payload     = Column(JsonType)
    version     = Column(Integer, default=1)
    updated_at  = Column(DateTime(timezone=True), server_default=func.now())


class Alert(Base):
    """Алерти — підтверджені інциденти з кореляції."""
    __tablename__ = "alerts"

    id              = Column(Integer, primary_key=True, autoincrement=True)
    ts              = Column(DateTime(timezone=True), server_default=func.now())
    node_id         = Column(String)
    rule_triggered  = Column(String)
    description     = Column(String)
    resolved        = Column(Boolean, default=False)
    # --- нові поля ---
    correlated_ips  = Column(JsonType)    # список IP що були задіяні
    confidence      = Column(Float, default=0.5)  # 0.0–1.0, впевненість що це атака
    incident_type   = Column(String)      # reconnaissance | lateral_movement | exfiltration
