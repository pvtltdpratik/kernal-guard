"""Bounded event storage: purge by age, then by row cap.

Retention uses ``ingested_at`` rather than the event's own timestamp so a
source with a skewed clock cannot keep events forever or purge them early.
Deletes run in chunks to keep write locks short.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.db.models import Event

logger = logging.getLogger(__name__)

_CHUNK = 5000


@dataclass
class RetentionResult:
    expired: int = 0
    over_cap: int = 0


def _delete_ids(session: Session, ids: list[str]) -> int:
    if not ids:
        return 0
    session.execute(delete(Event).where(Event.id.in_(ids)))
    session.commit()
    return len(ids)


def apply_retention(
    session: Session, retention_days: int, max_rows: int, now: datetime | None = None
) -> RetentionResult:
    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(days=retention_days)
    result = RetentionResult()

    while True:
        ids = list(session.scalars(select(Event.id).where(Event.ingested_at < cutoff).limit(_CHUNK)))
        removed = _delete_ids(session, ids)
        result.expired += removed
        if removed < _CHUNK:
            break

    excess = (session.scalar(select(func.count()).select_from(Event)) or 0) - max_rows
    while excess > 0:
        batch = min(excess, _CHUNK)
        ids = list(
            session.scalars(select(Event.id).order_by(Event.ingested_at, Event.id).limit(batch))
        )
        removed = _delete_ids(session, ids)
        result.over_cap += removed
        excess -= removed
        if removed == 0:
            break

    if result.expired or result.over_cap:
        logger.info("retention applied", extra={"expired": result.expired, "over_cap": result.over_cap})
    return result
