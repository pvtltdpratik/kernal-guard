"""Shared API dependencies."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Annotated

from fastapi import Depends, HTTPException

from app.core.config import Settings, get_settings
from app.detection.config import DetectionConfig, load_detection_config


@lru_cache(maxsize=4)
def _load(path: Path | None, mtime: float) -> DetectionConfig:
    return load_detection_config(path)


def get_detection_config(settings: Annotated[Settings, Depends(get_settings)]) -> DetectionConfig:
    path = settings.detection_config
    mtime = path.stat().st_mtime if path is not None and path.exists() else 0.0
    return _load(path, mtime)  # reloads automatically when the file changes


def validate_time_range(since: object, until: object) -> None:
    if since is not None and until is not None and since >= until:  # type: ignore[operator]
        raise HTTPException(status_code=400, detail="'since' must be earlier than 'until'")


ID_PATTERN = r"^[0-9a-f]{32}$"
