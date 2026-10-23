"""Process investigation queries."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import Select, exists, func, select
from sqlalchemy.orm import Session

from app.db.models import Alert, Event, Process
from app.detection.processes import guid_key
from app.schemas.detection import AlertSummary, NetworkSummary, ProcessDetail, ProcessSummary

MAX_CHILDREN = 200
MAX_NETWORK_ROWS = 50


@dataclass(frozen=True)
class ProcessFilters:
    host_id: str | None = None
    image: str | None = None
    process_guid: str | None = None
    process_id: int | None = None
    since: datetime | None = None
    until: datetime | None = None


def _filters(statement: Select, f: ProcessFilters) -> Select:  # type: ignore[type-arg]
    if f.host_id:
        statement = statement.where(Process.host_id == f.host_id)
    if f.image:
        statement = statement.where(func.lower(Process.image).contains(f.image.lower(), autoescape=True))
    if f.process_guid:
        statement = statement.where(func.lower(Process.process_guid) == f.process_guid.lower())
    if f.process_id is not None:
        statement = statement.where(Process.process_id == f.process_id)
    if f.since:
        statement = statement.where(Process.last_seen >= f.since)
    if f.until:
        statement = statement.where(Process.first_seen < f.until)
    return statement


def list_processes(db: Session, f: ProcessFilters, page: int, page_size: int) -> tuple[list[Process], int]:
    total = db.scalar(_filters(select(func.count()).select_from(Process), f)) or 0
    statement = (
        _filters(select(Process), f)
        .order_by(Process.last_seen.desc(), Process.id)
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    return list(db.scalars(statement)), total


def _event_scope(process: Process) -> list:  # type: ignore[type-arg]
    """SQL conditions selecting the events that belong to this process."""
    if process.process_guid:
        return [Event.host_id == process.host_id, Event.process_guid == process.process_guid]
    # PID-keyed (Security 4688) process: bound by lifetime to avoid PID reuse.
    conditions = [Event.host_id == process.host_id, Event.process_id == process.process_id]
    if process.start_time is not None:
        conditions.append(Event.timestamp >= process.start_time)
    if process.end_time is not None:
        conditions.append(Event.timestamp <= process.end_time)
    return conditions


def process_detail(db: Session, process: Process) -> ProcessDetail:
    parent = (
        db.scalar(select(Process).where(Process.key == guid_key(process.host_id, process.parent_process_guid)))
        if process.parent_process_guid
        else None
    )
    children = (
        list(
            db.scalars(
                select(Process)
                .where(Process.host_id == process.host_id, Process.parent_process_guid == process.process_guid)
                .order_by(Process.first_seen)
                .limit(MAX_CHILDREN)
            )
        )
        if process.process_guid
        else []
    )
    scope = _event_scope(process)
    counts = dict(db.execute(select(Event.category, func.count()).where(*scope).group_by(Event.category)).all())

    ip = func.json_extract(Event.data, "$.DestinationIp")
    port = func.json_extract(Event.data, "$.DestinationPort")
    hostname = func.json_extract(Event.data, "$.DestinationHostname")
    protocol = func.json_extract(Event.data, "$.Protocol")
    network_rows = db.execute(
        select(ip, port, hostname, protocol, func.count(), func.min(Event.timestamp), func.max(Event.timestamp))
        .where(*scope, Event.category == "network_connection")
        .group_by(ip, port, hostname, protocol)
        .order_by(func.count().desc())
        .limit(MAX_NETWORK_ROWS)
    ).all()
    network = [
        NetworkSummary(
            destination_ip=r[0], destination_port=r[1], destination_hostname=r[2] if r[2] != "-" else None,
            protocol=r[3], connections=r[4],
            # min/max over a UTCDateTime column come back as raw strings from SQLite.
            first_seen=_as_utc(r[5]), last_seen=_as_utc(r[6]),
        )
        for r in network_rows
    ]

    signature = None
    if process.image:
        load = db.scalar(
            select(Event)
            .where(
                Event.host_id == process.host_id,
                Event.category == "image_load",
                func.lower(func.json_extract(Event.data, "$.ImageLoaded")) == process.image.lower(),
            )
            .order_by(Event.timestamp.desc())
            .limit(1)
        )
        if load is not None:
            signature = {"signed": load.signed, "signature": load.signature, "status": load.signature_status,
                         "observed_at": load.timestamp, "event_id": load.id}

    alerts = list(
        db.scalars(
            select(Alert)
            .where(Alert.host_id == process.host_id, alert_has_entity(f"process:{process.key}"))
            .order_by(Alert.last_seen.desc())
            .limit(100)
        )
    )
    return ProcessDetail(
        **ProcessSummary.model_validate(process).model_dump(),
        command_line=process.command_line,
        integrity_level=process.integrity_level,
        parent_process_guid=process.parent_process_guid,
        parent_process_id=process.parent_process_id,
        parent_image=process.parent_image,
        sha256=process.sha256, sha1=process.sha1, md5=process.md5, imphash=process.imphash,
        sources=process.sources,
        conflicts=process.conflicts,
        signature=signature,
        parent=ProcessSummary.model_validate(parent) if parent else None,
        children=[ProcessSummary.model_validate(c) for c in children],
        event_counts=counts,
        network=network,
        alerts=[AlertSummary.model_validate(a) for a in alerts],
    )


def alert_has_entity(entity: str):  # type: ignore[no-untyped-def]
    """EXISTS over SQLite json_each: exact match of one element of Alert.entities."""
    elements = func.json_each(Alert.entities).table_valued("value")
    return exists(select(1).select_from(elements).where(elements.c.value == entity))


def _as_utc(value: object) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    return datetime.fromisoformat(str(value)).replace(tzinfo=timezone.utc)
