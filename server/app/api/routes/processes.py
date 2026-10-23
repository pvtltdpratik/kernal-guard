"""Process investigation endpoints."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from pydantic import AwareDatetime
from sqlalchemy.orm import Session

from app.api.deps import ID_PATTERN, validate_time_range
from app.db.models import Process
from app.db.session import get_db
from app.schemas.common import ErrorResponse, Page
from app.schemas.detection import ProcessDetail, ProcessSummary
from app.services.process_queries import ProcessFilters, list_processes, process_detail

router = APIRouter(prefix="/processes", tags=["processes"])


def process_filters(
    host_id: Annotated[str | None, Query(max_length=64)] = None,
    image: Annotated[str | None, Query(min_length=1, max_length=260, description="Case-insensitive substring")] = None,
    process_guid: Annotated[str | None, Query(max_length=64)] = None,
    process_id: Annotated[int | None, Query(ge=0, le=2**32 - 1)] = None,
    since: Annotated[AwareDatetime | None, Query(description="Active at or after (last_seen >= since)")] = None,
    until: Annotated[AwareDatetime | None, Query(description="Active before (first_seen < until)")] = None,
) -> ProcessFilters:
    validate_time_range(since, until)
    return ProcessFilters(host_id, image, process_guid, process_id, since, until)


@router.get("", response_model=Page[ProcessSummary], responses={400: {"model": ErrorResponse}})
def get_processes(
    filters: Annotated[ProcessFilters, Depends(process_filters)],
    db: Annotated[Session, Depends(get_db)],
    page: Annotated[int, Query(ge=1, le=100_000)] = 1,
    page_size: Annotated[int, Query(ge=1, le=200)] = 50,
) -> Page[ProcessSummary]:
    items, total = list_processes(db, filters, page, page_size)
    return Page[ProcessSummary](
        items=[ProcessSummary.model_validate(p) for p in items], page=page, page_size=page_size, total=total
    )


@router.get("/{process_id}", response_model=ProcessDetail, responses={404: {"model": ErrorResponse}})
def get_process(
    process_id: Annotated[str, Path(pattern=ID_PATTERN, description="KernelGuard process record id")],
    db: Annotated[Session, Depends(get_db)],
) -> ProcessDetail:
    process = db.get(Process, process_id)
    if process is None:
        raise HTTPException(status_code=404, detail="Process not found")
    return process_detail(db, process)
