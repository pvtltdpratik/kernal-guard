"""Sensor status endpoint."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.db.session import get_db
from app.schemas.sensors import SensorStatusResponse
from app.services.sensors import build_sensor_status

router = APIRouter(prefix="/sensors", tags=["sensors"])


@router.get("/status", response_model=SensorStatusResponse)
def sensor_status(
    db: Annotated[Session, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> SensorStatusResponse:
    return build_sensor_status(db, settings)
