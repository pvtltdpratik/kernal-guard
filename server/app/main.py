"""FastAPI application factory."""

from __future__ import annotations

import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.api.router import api_v1_router, root_router
from app.core.config import Settings, get_settings
from app.core.errors import register_exception_handlers
from app.core.logging import configure_logging
from app.core.middleware import RequestContextMiddleware

logger = logging.getLogger(__name__)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level, settings.log_json)

    app = FastAPI(
        title="KernelGuard API",
        version=__version__,
        description="Windows endpoint telemetry, detection and investigation API.",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=False,
        allow_methods=["GET", "PATCH"],
        allow_headers=["Content-Type", "X-Request-ID"],  # PATCH with JSON body needs Content-Type
        expose_headers=["X-Request-ID"],
    )
    app.add_middleware(RequestContextMiddleware)

    register_exception_handlers(app)
    app.include_router(root_router)
    app.include_router(api_v1_router)

    logger.info(
        "KernelGuard API initialised",
        extra={"version": __version__, "environment": settings.environment},
    )
    return app


app = create_app()
