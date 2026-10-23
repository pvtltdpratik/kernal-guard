"""Database engine and session management."""

from __future__ import annotations

from collections.abc import Iterator
from functools import lru_cache

from sqlalchemy import Engine, create_engine, event, text
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings


def build_engine(database_url: str) -> Engine:
    is_sqlite = database_url.startswith("sqlite")
    engine = create_engine(
        database_url,
        # FastAPI runs sync dependencies in a threadpool, so the SQLite
        # connection may be used from a thread other than its creator.
        connect_args={"check_same_thread": False} if is_sqlite else {},
        pool_pre_ping=True,
    )
    if is_sqlite:
        event.listen(engine, "connect", _configure_sqlite)
        # pysqlite's own transaction handling breaks SAVEPOINT; let SQLAlchemy
        # emit BEGIN itself (documented SQLAlchemy recipe for pysqlite).
        event.listen(engine, "begin", lambda conn: conn.exec_driver_sql("BEGIN"))
    return engine


def _configure_sqlite(dbapi_connection, _connection_record) -> None:  # type: ignore[no-untyped-def]
    dbapi_connection.isolation_level = None
    cursor = dbapi_connection.cursor()
    # WAL lets the API read while the collector writes; foreign keys are
    # off by default in SQLite.
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.execute("PRAGMA busy_timeout=5000")
    cursor.close()


@lru_cache
def get_engine() -> Engine:
    settings = get_settings()
    if settings.sqlite_path is not None:
        settings.sqlite_path.parent.mkdir(parents=True, exist_ok=True)
    return build_engine(settings.database_url)


@lru_cache
def get_sessionmaker() -> sessionmaker[Session]:
    return sessionmaker(bind=get_engine(), autoflush=False, expire_on_commit=False)


def get_db() -> Iterator[Session]:
    """FastAPI dependency yielding a session that is always closed."""
    session = get_sessionmaker()()
    try:
        yield session
    finally:
        session.close()


def check_database(session: Session) -> bool:
    session.execute(text("SELECT 1"))
    return True
