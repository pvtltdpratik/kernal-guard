"""Run the API with host/port taken from validated settings.

Usage: ``python -m app``. Prefer this over invoking uvicorn directly so
the loopback-only binding check in ``Settings`` always applies.
"""

from __future__ import annotations

import uvicorn

from app.core.config import get_settings


def main() -> None:
    settings = get_settings()
    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.environment == "development",
        log_config=None,  # app.core.logging owns log configuration
    )


if __name__ == "__main__":
    main()
