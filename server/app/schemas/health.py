"""Health check response schema."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel


class ComponentHealth(BaseModel):
    status: Literal["ok", "error"]
    detail: str | None = None


class HealthResponse(BaseModel):
    status: Literal["ok", "degraded"]
    version: str
    environment: str
    timestamp: datetime
    components: dict[str, ComponentHealth]
