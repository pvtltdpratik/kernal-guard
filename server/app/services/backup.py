"""Consistent online backup of the SQLite database.

Uses SQLite's backup API, which is safe while the collector and API are
writing (a plain file copy of a WAL database can be inconsistent).

Usage: ``python -m app.services.backup [destination-dir]``
"""

from __future__ import annotations

import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

from app.core.config import SERVER_ROOT, get_settings


def backup_sqlite(source: Path, destination_dir: Path, keep: int = 7) -> Path:
    destination_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    target = destination_dir / f"{source.stem}-{stamp}.db"

    with sqlite3.connect(f"file:{source.as_posix()}?mode=ro", uri=True) as src, sqlite3.connect(target) as dst:
        src.backup(dst)

    backups = sorted(destination_dir.glob(f"{source.stem}-*.db"))
    for old in backups[:-keep]:
        old.unlink()
    return target


def main() -> int:
    settings = get_settings()
    if settings.sqlite_path is None:
        print("Backup supports file-based SQLite databases only.", file=sys.stderr)
        return 1
    if not settings.sqlite_path.exists():
        print(f"Database not found: {settings.sqlite_path}", file=sys.stderr)
        return 1
    destination = Path(sys.argv[1]) if len(sys.argv) > 1 else SERVER_ROOT / "data" / "backups"
    print(backup_sqlite(settings.sqlite_path, destination))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
