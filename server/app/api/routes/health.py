"""Liveness/readiness endpoint.

Reports backend, database and schema health only. Collector/sensor health
is a separate concern served by ``/api/v1/sensors/status``.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from alembic.runtime.migration import MigrationContext
from fastapi import APIRouter, Depends, Response, status
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app import __version__
from app.core.config import Settings, get_settings
from app.db.migrate import head_revision
from app.db.session import check_database, get_db
from app.schemas.health import ComponentHealth, HealthResponse

logger = logging.getLogger(__name__)

router = APIRouter(tags=["health"])


@router.get(
    "/health",
    response_model=HealthResponse,
    responses={503: {"model": HealthResponse, "description": "A required component is unhealthy"}},
)
def health(
    response: Response,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> HealthResponse:
    components: dict[str, ComponentHealth] = {}

    try:
        check_database(db)
        components["database"] = ComponentHealth(status="ok")
    except SQLAlchemyError:
        logger.exception("Database health check failed")
        components["database"] = ComponentHealth(status="error", detail="database unreachable")

    if components["database"].status == "ok":
        try:
            current = MigrationContext.configure(db.connection()).get_current_revision()
            head = head_revision()
            if current == head:
                components["schema"] = ComponentHealth(status="ok", detail=current)
            else:
                components["schema"] = ComponentHealth(
                    status="error",
                    detail=f"schema at {current or 'empty'}, expected {head}; run python -m app.db.migrate",
                )
        except SQLAlchemyError:
            logger.exception("Schema version check failed")
            components["schema"] = ComponentHealth(status="error", detail="schema version unreadable")

    healthy = all(c.status == "ok" for c in components.values())
    if not healthy:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return HealthResponse(
        status="ok" if healthy else "degraded",
        version=__version__,
        environment=settings.environment,
        timestamp=datetime.now(timezone.utc),
        components=components,
    )
