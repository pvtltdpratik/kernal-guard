"""Collector process entry point.

    python -m app.collectors            # poll continuously
    python -m app.collectors --once     # one cycle, print a summary, exit

Runs separately from the API so that only this process needs elevated
read access to protected channels. It is read-only: it never modifies
event logs, processes or files.
"""

from __future__ import annotations

import argparse
import json
import signal
import sys
import threading

from app.collectors.eventlog_api import WindowsEventLogReader
from app.collectors.host import resolve_host_id
from app.collectors.registry import SENSORS
from app.collectors.runner import CollectorRunner
from app.core.config import get_settings
from app.core.logging import configure_logging
from app.db.migrate import schema_status
from app.detection.config import load_detection_config
from app.detection.engine import DetectionEngine
from app.db.session import get_engine, get_sessionmaker


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.collectors")
    parser.add_argument("--once", action="store_true", help="run a single collection cycle and exit")
    parser.add_argument("--sensors", help="comma-separated subset of: " + ", ".join(SENSORS))
    args = parser.parse_args(argv)

    settings = get_settings()
    configure_logging(settings.log_level, settings.log_json)

    names = [n.strip() for n in args.sensors.split(",")] if args.sensors else settings.collector_sensors
    unknown = [n for n in names if n not in SENSORS]
    if unknown:
        parser.error(f"unknown sensor(s): {', '.join(unknown)}")

    status = schema_status(get_engine())
    if not status.up_to_date:
        print(
            f"Database schema is at {status.current or 'empty'}, expected {status.head}. "
            "Run: .\\.venv\\Scripts\\python.exe -m app.db.migrate",
            file=sys.stderr,
        )
        return 2

    runner = CollectorRunner(
        sensors=[SENSORS[n] for n in names],
        reader=WindowsEventLogReader(),
        session_factory=get_sessionmaker(),
        host_id=resolve_host_id(settings.host_id),
        settings=settings,
        engine=DetectionEngine(load_detection_config(settings.detection_config)) if settings.detection_enabled else None,
    )

    if args.once:
        results = runner.run_once()
        summary = [
            {k: v for k, v in vars(r).items() if k != "errors" or v} for r in results
        ]
        print(json.dumps(summary, indent=2))
        return 0 if all(r.state in ("ok", "unavailable", "access_denied") for r in results) else 1

    stop = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    runner.run_forever(stop)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
