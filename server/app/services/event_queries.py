"""Read-side queries for events. All filters are bound parameters."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session

from app.db.models import Event
from app.schemas.events import EventCategory, EventSource

EventSort = Literal[
    "timestamp", "-timestamp", "ingested_at", "-ingested_at", "source_event_id", "-source_event_id"
]

_SORT_COLUMNS = {
    "timestamp": Event.timestamp,
    "ingested_at": Event.ingested_at,
    "source_event_id": Event.source_event_id,
}


@dataclass(frozen=True)
class EventFilters:
    categories: list[EventCategory] | None = None
    source: EventSource | None = None
    channel: str | None = None
    source_event_id: int | None = None
    process_guid: str | None = None
    process_id: int | None = None
    image: str | None = None
    host_id: str | None = None
    since: datetime | None = None
    until: datetime | None = None


def _apply_filters(statement: Select, f: EventFilters) -> Select:  # type: ignore[type-arg]
    if f.categories:
        statement = statement.where(Event.category.in_([c.value for c in f.categories]))
    if f.source:
        statement = statement.where(Event.source == f.source.value)
    if f.channel:
        statement = statement.where(Event.channel == f.channel)
    if f.source_event_id is not None:
        statement = statement.where(Event.source_event_id == f.source_event_id)
    if f.process_guid:
        statement = statement.where(Event.process_guid == f.process_guid)
    if f.process_id is not None:
        statement = statement.where(Event.process_id == f.process_id)
    if f.image:
        statement = statement.where(func.lower(Event.image).contains(f.image.lower(), autoescape=True))
    if f.host_id:
        statement = statement.where(Event.host_id == f.host_id)
    if f.since:
        statement = statement.where(Event.timestamp >= f.since)
    if f.until:
        statement = statement.where(Event.timestamp < f.until)
    return statement


def list_events(
    session: Session, filters: EventFilters, sort: EventSort, page: int, page_size: int
) -> tuple[list[Event], int]:
    total = session.scalar(_apply_filters(select(func.count()).select_from(Event), filters)) or 0

    column = _SORT_COLUMNS[sort.lstrip("-")]
    order = column.desc() if sort.startswith("-") else column.asc()
    # Event.id as tiebreaker keeps pagination stable for equal timestamps.
    statement = (
        _apply_filters(select(Event), filters)
        .order_by(order, Event.id)
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    return list(session.scalars(statement)), total
