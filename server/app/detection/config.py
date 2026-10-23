"""Detection configuration: per-rule enablement, threshold overrides, allowlists.

Loaded from a JSON file (``KG_DETECTION_CONFIG``), validated with Pydantic.
Missing file = rule defaults. Example: ``config/detection/detection.example.json``.
"""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, Field, field_validator


class RuleOverride(BaseModel):
    enabled: bool = True
    thresholds: dict[str, float | int] = Field(default_factory=dict)


class Allowlist(BaseModel):
    """Suppress findings whose subject process image or hash is listed.

    Allowlisting is explicit and visible in the API; it is never inferred.
    """

    images: list[str] = Field(default_factory=list, description="Full paths, case-insensitive")
    sha256: list[str] = Field(default_factory=list)

    @field_validator("images")
    @classmethod
    def _lower_images(cls, value: list[str]) -> list[str]:
        return [v.strip().lower() for v in value if v.strip()]

    @field_validator("sha256")
    @classmethod
    def _lower_hashes(cls, value: list[str]) -> list[str]:
        return [v.strip().lower() for v in value if v.strip()]


class DetectionConfig(BaseModel):
    rules: dict[str, RuleOverride] = Field(default_factory=dict)
    allowlist: Allowlist = Field(default_factory=Allowlist)
    # Alerts sharing an entity within this window join the same incident.
    incident_window_minutes: int = Field(default=60, ge=1, le=7 * 24 * 60)
    # Evidence events linked per alert; further occurrences only bump the counter.
    max_evidence_per_alert: int = Field(default=25, ge=1, le=500)

    def is_enabled(self, rule_id: str) -> bool:
        override = self.rules.get(rule_id)
        return override.enabled if override else True

    def threshold(self, rule_id: str, name: str, default: float | int) -> float | int:
        override = self.rules.get(rule_id)
        if override and name in override.thresholds:
            return override.thresholds[name]
        return default


def load_detection_config(path: Path | None) -> DetectionConfig:
    if path is None or not path.exists():
        return DetectionConfig()
    return DetectionConfig.model_validate(json.loads(path.read_text(encoding="utf-8")))
