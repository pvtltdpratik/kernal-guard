"""Incident endpoints."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from pydantic import AwareDatetime
from sqlalchemy.orm import Session

from app.api.deps import ID_PATTERN, get_detection_config, validate_time_range
from app.db.models import Incident
from app.db.session import get_db
from app.detection.config import DetectionConfig
from app.detection.types import Severity
from app.schemas.common import ErrorResponse, Page
from app.schemas.detection import IncidentDetail, IncidentPatch, IncidentStatus, IncidentSummary
from app.services.investigation import IncidentFilters, IncidentSort, incident_detail, list_incidents, update_incident

router = APIRouter(prefix="/incidents", tags=["incidents"])


def incident_filters(
    status: Annotated[list[IncidentStatus] | None, Query(description="Repeatable")] = None,
    severity: Annotated[list[Severity] | None, Query(description="Repeatable")] = None,
    host_id: Annotated[str | None, Query(max_length=64)] = None,
    q: Annotated[str | None, Query(min_length=1, max_length=200)] = None,
    min_score: Annotated[int | None, Query(ge=0, le=100)] = None,
    since: AwareDatetime | None = None,
    until: AwareDatetime | None = None,
) -> IncidentFilters:
    validate_time_range(since, until)
    return IncidentFilters(status, severity, host_id, q, min_score, since, until)


@router.get("", response_model=Page[IncidentSummary], responses={400: {"model": ErrorResponse}})
def get_incidents(
    filters: Annotated[IncidentFilters, Depends(incident_filters)],
    db: Annotated[Session, Depends(get_db)],
    page: Annotated[int, Query(ge=1, le=100_000)] = 1,
    page_size: Annotated[int, Query(ge=1, le=200)] = 25,
    sort: IncidentSort = "-last_seen",
) -> Page[IncidentSummary]:
    items, total = list_incidents(db, filters, sort, page, page_size)
    return Page[IncidentSummary](items=items, page=page, page_size=page_size, total=total)


def _get_incident(db: Session, incident_id: str) -> Incident:
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@router.get("/{incident_id}", response_model=IncidentDetail, responses={404: {"model": ErrorResponse}})
def get_incident(
    incident_id: Annotated[str, Path(pattern=ID_PATTERN)],
    db: Annotated[Session, Depends(get_db)],
    config: Annotated[DetectionConfig, Depends(get_detection_config)],
) -> IncidentDetail:
    return incident_detail(db, _get_incident(db, incident_id), config)


@router.patch("/{incident_id}", response_model=IncidentDetail, responses={404: {"model": ErrorResponse}})
def patch_incident(
    incident_id: Annotated[str, Path(pattern=ID_PATTERN)],
    body: IncidentPatch,
    db: Annotated[Session, Depends(get_db)],
    config: Annotated[DetectionConfig, Depends(get_detection_config)],
) -> IncidentDetail:
    incident = _get_incident(db, incident_id)
    update_incident(db, incident, body.status, body.note)
    db.commit()
    return incident_detail(db, incident, config)
