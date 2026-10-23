"""Event Explorer endpoints."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from pydantic import AwareDatetime
from sqlalchemy.orm import Session

from app.db.models import Event
from app.db.session import get_db
from app.schemas.common import ErrorResponse, Page
from app.schemas.events import EventCategory, EventDetail, EventSource, EventSummary
from app.services.event_queries import EventFilters, EventSort, list_events

router = APIRouter(prefix="/events", tags=["events"])

MAX_PAGE_SIZE = 500


def event_filters(
    category: Annotated[list[EventCategory] | None, Query(description="Repeat to match any of several")] = None,
    source: EventSource | None = None,
    channel: Annotated[str | None, Query(max_length=128)] = None,
    source_event_id: Annotated[int | None, Query(ge=0, le=65535)] = None,
    process_guid: Annotated[str | None, Query(max_length=64)] = None,
    process_id: Annotated[int | None, Query(ge=0, le=2**32 - 1)] = None,
    image: Annotated[str | None, Query(min_length=1, max_length=260, description="Case-insensitive substring")] = None,
    host_id: Annotated[str | None, Query(max_length=64)] = None,
    since: Annotated[AwareDatetime | None, Query(description="Inclusive, ISO 8601 with timezone")] = None,
    until: Annotated[AwareDatetime | None, Query(description="Exclusive, ISO 8601 with timezone")] = None,
) -> EventFilters:
    if since and until and since >= until:
        raise HTTPException(status_code=400, detail="'since' must be earlier than 'until'")
    return EventFilters(
        categories=category,
        source=source,
        channel=channel,
        source_event_id=source_event_id,
        process_guid=process_guid,
        process_id=process_id,
        image=image,
        host_id=host_id,
        since=since,
        until=until,
    )


@router.get("", response_model=Page[EventSummary], responses={400: {"model": ErrorResponse}})
def get_events(
    filters: Annotated[EventFilters, Depends(event_filters)],
    db: Annotated[Session, Depends(get_db)],
    page: Annotated[int, Query(ge=1, le=100_000)] = 1,
    page_size: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = 50,
    sort: EventSort = "-timestamp",
) -> Page[EventSummary]:
    items, total = list_events(db, filters, sort, page, page_size)
    return Page[EventSummary](
        items=[EventSummary.model_validate(item) for item in items],
        page=page,
        page_size=page_size,
        total=total,
    )


@router.get("/{event_id}", response_model=EventDetail, responses={404: {"model": ErrorResponse}})
def get_event(
    event_id: Annotated[str, Path(pattern=r"^[0-9a-f]{32}$")],
    db: Annotated[Session, Depends(get_db)],
    include_raw: Annotated[bool, Query(description="Include the original event XML")] = False,
) -> EventDetail:
    event = db.get(Event, event_id)
    if event is None:
        raise HTTPException(status_code=404, detail="Event not found")
    detail = EventDetail.model_validate(event)
    if not include_raw:
        detail.raw_xml = None
    return detail
