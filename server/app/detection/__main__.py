"""Detection maintenance commands.

    python -m app.detection rescan [--since 2026-10-01T00:00:00Z]

Re-evaluates stored events with the current rules (e.g. after adding rules,
changing thresholds, or after detection failures). Idempotent: evidence
already linked to an alert is not counted again.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime

from sqlalchemy import select

from app.core.config import get_settings
from app.core.logging import configure_logging
from app.db.migrate import schema_status
from app.db.models import Event
from app.db.session import get_engine, get_sessionmaker
from app.detection.config import load_detection_config
from app.detection.engine import DetectionEngine

CHUNK = 500


def rescan(since: datetime | None) -> dict[str, int]:
    settings = get_settings()
    engine = DetectionEngine(load_detection_config(settings.detection_config))
    factory = get_sessionmaker()
    totals = {"events": 0, "alerts_created": 0, "alerts_updated": 0, "suppressed": 0, "rule_errors": 0, "incidents": 0}
    incidents: set[str] = set()

    with factory() as session, session.begin():
        engine.sync_rule_catalog(session)

    # Keyset pagination over (timestamp, id) so the scan is stable while processing.
    cursor: tuple[datetime, str] | None = None
    while True:
        with factory() as session, session.begin():
            statement = select(Event).order_by(Event.timestamp, Event.id).limit(CHUNK)
            if since is not None:
                statement = statement.where(Event.timestamp >= since)
            if cursor is not None:
                statement = statement.where(
                    (Event.timestamp > cursor[0]) | ((Event.timestamp == cursor[0]) & (Event.id > cursor[1]))
                )
            events = list(session.scalars(statement))
            if not events:
                break
            result = engine.process(session, events)
            cursor = (events[-1].timestamp, events[-1].id)
        totals["events"] += result.events
        totals["alerts_created"] += result.alerts_created
        totals["alerts_updated"] += result.alerts_updated
        totals["suppressed"] += result.suppressed
        totals["rule_errors"] += result.rule_errors
        incidents |= result.incidents_touched
    totals["incidents"] = len(incidents)
    return totals


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.detection")
    sub = parser.add_subparsers(dest="command", required=True)
    rescan_parser = sub.add_parser("rescan", help="re-evaluate stored events with current rules")
    rescan_parser.add_argument("--since", type=datetime.fromisoformat, help="ISO 8601 with timezone")
    args = parser.parse_args(argv)

    settings = get_settings()
    configure_logging(settings.log_level, settings.log_json)
    if not schema_status(get_engine()).up_to_date:
        print("Database schema is not at head. Run: python -m app.db.migrate", file=sys.stderr)
        return 2
    if args.since is not None and args.since.tzinfo is None:
        parser.error("--since must include a timezone, e.g. 2026-10-01T00:00:00+00:00")

    print(json.dumps(rescan(args.since), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
