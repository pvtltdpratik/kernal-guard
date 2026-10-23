"""The Alembic migrations must produce exactly the schema the models declare."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext
from sqlalchemy import Engine, inspect, select
from sqlalchemy.dialects import sqlite

from app.db.base import Base
from app.db.models import Event
from app.detection.context import data_key
from app.db.migrate import alembic_config, schema_status
from app.db.session import build_engine


def test_migrated_schema_matches_models(engine: Engine) -> None:
    with engine.connect() as connection:
        diff = compare_metadata(MigrationContext.configure(connection), Base.metadata)
    assert diff == []
    assert schema_status(engine).up_to_date


def test_expected_indexes_exist(engine: Engine) -> None:
    indexes = {ix["name"] for ix in inspect(engine).get_indexes("events")}
    assert {
        "ix_events_timestamp",
        "ix_events_category_timestamp",
        "ix_events_process_guid",
        "ix_events_process_id",
        "ix_events_source_event_id",
        "ix_events_ingested_at",
    } <= indexes


@pytest.mark.parametrize(("field", "index"), [("ImageLoaded", "ix_events_data_imageloaded"),
                                              ("TargetFilename", "ix_events_data_targetfilename")])
def test_correlation_lookups_use_expression_index(engine: Engine, field: str, index: str) -> None:
    """Guards against rule queries drifting from the index expression (which
    silently reverts detection to a quadratic scan)."""
    now = datetime.now(timezone.utc)
    statement = select(Event.id).where(
        Event.category == "image_load", data_key(field) == "x", Event.timestamp >= now,
        Event.timestamp <= now, Event.host_id == "h",
    )
    compiled = statement.compile(dialect=sqlite.dialect())
    with engine.connect() as connection:
        plan = " ".join(r[-1] for r in connection.exec_driver_sql(
            "EXPLAIN QUERY PLAN " + str(compiled), tuple(compiled.params.values())))
    assert f"USING INDEX {index}" in plan


def test_downgrade_to_base_and_back(tmp_path: Path) -> None:
    engine = build_engine(f"sqlite:///{(tmp_path / 'm.db').as_posix()}")
    config = alembic_config()
    with engine.begin() as connection:
        config.attributes["connection"] = connection
        command.upgrade(config, "head")
        command.downgrade(config, "base")
        assert set(inspect(connection).get_table_names()) <= {"alembic_version"}
        command.upgrade(config, "head")
    assert schema_status(engine).up_to_date
    engine.dispose()


def test_unmigrated_database_reported(tmp_path: Path) -> None:
    engine = build_engine(f"sqlite:///{(tmp_path / 'empty.db').as_posix()}")
    status = schema_status(engine)
    assert status.current is None and not status.up_to_date
    engine.dispose()
