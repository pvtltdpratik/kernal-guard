"""Schema version checks and programmatic upgrades.

Usage: ``python -m app.db.migrate`` upgrades the configured database to head.
"""

from __future__ import annotations

from dataclasses import dataclass

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import Engine

from app.core.config import SERVER_ROOT


@dataclass(frozen=True)
class SchemaStatus:
    current: str | None
    head: str | None

    @property
    def up_to_date(self) -> bool:
        return self.current is not None and self.current == self.head


def alembic_config() -> Config:
    config = Config(str(SERVER_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(SERVER_ROOT / "migrations"))
    config.attributes["skip_logging_config"] = True
    return config


def head_revision() -> str | None:
    return ScriptDirectory.from_config(alembic_config()).get_current_head()


def schema_status(engine: Engine) -> SchemaStatus:
    with engine.connect() as connection:
        current = MigrationContext.configure(connection).get_current_revision()
    return SchemaStatus(current=current, head=head_revision())


def upgrade_to_head(engine: Engine | None = None) -> None:
    config = alembic_config()
    if engine is None:
        command.upgrade(config, "head")
        return
    with engine.begin() as connection:
        config.attributes["connection"] = connection
        command.upgrade(config, "head")


if __name__ == "__main__":
    upgrade_to_head()
    print("Database schema is at head.")
