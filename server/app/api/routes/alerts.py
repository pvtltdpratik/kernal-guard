"""Alert endpoints."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from pydantic import AwareDatetime
from sqlalchemy.orm import Session

from app.api.deps import ID_PATTERN, get_detection_config, validate_time_range
from app.db.models import Alert
from app.db.session import get_db
from app.detection.config import DetectionConfig
from app.detection.types import Severity
from app.schemas.common import ErrorResponse, Page
from app.schemas.detection import AlertDetail, AlertPatch, AlertStatus, AlertSummary
from app.services.investigation import AlertFilters, AlertSort, alert_detail, list_alerts, update_alert

router = APIRouter(prefix="/alerts", tags=["alerts"])


def alert_filters(
    status: Annotated[list[AlertStatus] | None, Query(description="Repeatable")] = None,
    severity: Annotated[list[Severity] | None, Query(description="Repeatable")] = None,
    rule_id: Annotated[str | None, Query(max_length=32)] = None,
    host_id: Annotated[str | None, Query(max_length=64)] = None,
    process_guid: Annotated[str | None, Query(max_length=64)] = None,
    incident_id: Annotated[str | None, Query(pattern=ID_PATTERN)] = None,
    q: Annotated[str | None, Query(min_length=1, max_length=200, description="Search title and image")] = None,
    min_score: Annotated[int | None, Query(ge=0, le=100)] = None,
    since: Annotated[AwareDatetime | None, Query(description="last_seen >= since")] = None,
    until: Annotated[AwareDatetime | None, Query(description="last_seen < until")] = None,
) -> AlertFilters:
    validate_time_range(since, until)
    return AlertFilters(status, severity, rule_id, host_id, process_guid, incident_id, q, min_score, since, until)


@router.get("", response_model=Page[AlertSummary], responses={400: {"model": ErrorResponse}})
def get_alerts(
    filters: Annotated[AlertFilters, Depends(alert_filters)],
    db: Annotated[Session, Depends(get_db)],
    page: Annotated[int, Query(ge=1, le=100_000)] = 1,
    page_size: Annotated[int, Query(ge=1, le=200)] = 25,
    sort: AlertSort = "-last_seen",
) -> Page[AlertSummary]:
    items, total = list_alerts(db, filters, sort, page, page_size)
    return Page[AlertSummary](
        items=[AlertSummary.model_validate(a) for a in items], page=page, page_size=page_size, total=total
    )


def _get_alert(db: Session, alert_id: str) -> Alert:
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.get("/{alert_id}", response_model=AlertDetail, responses={404: {"model": ErrorResponse}})
def get_alert(
    alert_id: Annotated[str, Path(pattern=ID_PATTERN)],
    db: Annotated[Session, Depends(get_db)],
    config: Annotated[DetectionConfig, Depends(get_detection_config)],
) -> AlertDetail:
    return alert_detail(db, _get_alert(db, alert_id), config)


@router.patch(
    "/{alert_id}",
    response_model=AlertDetail,
    responses={404: {"model": ErrorResponse}, 422: {"model": ErrorResponse}},
)
def patch_alert(
    alert_id: Annotated[str, Path(pattern=ID_PATTERN)],
    body: AlertPatch,
    db: Annotated[Session, Depends(get_db)],
    config: Annotated[DetectionConfig, Depends(get_detection_config)],
) -> AlertDetail:
    alert = _get_alert(db, alert_id)
    update_alert(db, alert, body.status, body.note, config)
    db.commit()
    return alert_detail(db, alert, config)
