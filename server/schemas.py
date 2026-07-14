from datetime import datetime
from typing import Optional, Any
from pydantic import BaseModel


class EventIn(BaseModel):
    node_id: str
    source: str
    severity: Optional[int] = 1
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    port: Optional[int] = None
    action: Optional[str] = None
    raw: Optional[dict[str, Any]] = None
    ts: Optional[datetime] = None


class EventBatchIn(BaseModel):
    events: list[EventIn]


class NodeHeartbeat(BaseModel):
    node_id: str
    hostname: str
    ip_address: Optional[str] = None
    os_info: Optional[str] = None


class EventOut(BaseModel):
    id: int
    ts: datetime
    node_id: str
    source: str
    severity: Optional[int]
    src_ip: Optional[str]
    dst_ip: Optional[str]
    port: Optional[int]
    action: Optional[str]
    effectiveness: Optional[float]
    layer: Optional[str]
    direction: Optional[str]
    threat_class: Optional[str]

    class Config:
        from_attributes = True


class NodeOut(BaseModel):
    node_id: str
    hostname: Optional[str]
    ip_address: Optional[str]
    status: str
    last_seen: Optional[datetime]

    class Config:
        from_attributes = True
