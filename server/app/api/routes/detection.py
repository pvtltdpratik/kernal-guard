"""Detection catalog: rules and the capability matrix."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_detection_config
from app.core.config import Settings, get_settings
from app.db.session import get_db
from app.detection.capabilities import CAPABILITIES, effective_visibility
from app.detection.config import DetectionConfig
from app.schemas.detection import CapabilityOut, RuleOut
from app.services.investigation import all_rules
from app.services.sensors import build_sensor_status, unhealthy_reasons

router = APIRouter(prefix="/detection", tags=["detection"])


@router.get("/rules", response_model=list[RuleOut])
def get_rules(config: Annotated[DetectionConfig, Depends(get_detection_config)]) -> list[RuleOut]:
    return all_rules(config)


@router.get("/capabilities", response_model=list[CapabilityOut])
def get_capabilities(
    db: Annotated[Session, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> list[CapabilityOut]:
    unhealthy = unhealthy_reasons(build_sensor_status(db, settings))
    result = []
    for cap in CAPABILITIES:
        visibility, note = effective_visibility(cap, unhealthy)
        result.append(
            CapabilityOut(
                technique_id=cap.technique_id,
                technique=cap.technique,
                design_visibility=cap.design_visibility,
                effective_visibility=visibility,
                effective_note=note,
                sensors=list(cap.sensors),
                evidence=cap.evidence,
                gaps=cap.gaps,
                rules=list(cap.rules),
            )
        )
    return result
