"""expression indexes for per-event correlation lookups

Detection rules look up related events by a JSON field (KG-SPY-001 by
ImageLoaded, KG-FILE-002 by TargetFilename). Without these indexes every
lookup scanned all events of the category in the time window, which made
detection cost quadratic in event volume.

Hand-written: Alembic autogenerate does not handle expression indexes.
Queries must use the identical expression (see app.detection.context.data_key).

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-23 21:30:00
"""
from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_INDEXES = {
    "ix_events_data_imageloaded": "ImageLoaded",
    "ix_events_data_targetfilename": "TargetFilename",
}


def upgrade() -> None:
    for name, field in _INDEXES.items():
        op.execute(
            f"CREATE INDEX IF NOT EXISTS {name} ON events "
            f"(category, lower(json_extract(data, '$.{field}')), timestamp)"
        )


def downgrade() -> None:
    for name in _INDEXES:
        op.execute(f"DROP INDEX IF EXISTS {name}")
