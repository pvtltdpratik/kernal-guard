"""Top-level API routers.

``root_router`` holds unversioned operational endpoints (``/health``).
``api_v1_router`` is mounted at ``/api/v1``.
"""

from __future__ import annotations

from fastapi import APIRouter

from app.api.routes import alerts, detection, events, health, incidents, metrics, processes, sensors

root_router = APIRouter()
root_router.include_router(health.router)

api_v1_router = APIRouter(prefix="/api/v1")
for module in (events, alerts, incidents, processes, sensors, metrics, detection):
    api_v1_router.include_router(module.router)
