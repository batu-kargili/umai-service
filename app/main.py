"""Application entrypoint for the Umai service.

This module assembles the FastAPI application, including startup hooks,
middleware, routers, and service-level error handling.
"""

from contextlib import asynccontextmanager
import logging
import uuid

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.admin import router as admin_router
from app.api.extension import ext_admin_router, ext_router
from app.api.ops import router as ops_router
from app.api.public import router as public_router
from app.core.errors import ServiceError
from app.core.license import bootstrap_license
from app.core.logging import configure_logging, reset_request_id, set_request_id
from app.core.runtime_validation import validate_service_runtime
from app.core.settings import settings

logger = logging.getLogger("umai.service")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    """Run startup checks before the service begins accepting requests."""
    validate_service_runtime()
    await bootstrap_license()
    yield


def create_app() -> FastAPI:
    """Build and configure the FastAPI application instance."""
    # Configure structured logging before any request handling begins so startup
    # and runtime logs follow the same format.
    configure_logging()
    app = FastAPI(title=settings.service_name, lifespan=lifespan)

    # Allow configured frontends to call the API across origins.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_allow_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # The operations router exposes health and service diagnostics endpoints.
    app.include_router(ops_router)
    # The admin router serves privileged endpoints for internal management tasks.
    app.include_router(admin_router)
    # The public router provides the main customer-facing API surface.
    app.include_router(public_router)
    # The extension router handles browser extension requests used by clients.
    app.include_router(ext_router)
    # The extension admin router adds privileged controls for extension workflows.
    app.include_router(ext_admin_router)

    @app.middleware("http")
    async def request_id_middleware(request: Request, call_next):
        """Attach a stable request id to the request context and response."""
        # Reuse a caller-provided request id when available so logs can be
        # correlated across upstream services; otherwise generate one locally.
        request_id = request.headers.get("X-Request-Id") or str(uuid.uuid4())
        token = set_request_id(request_id)
        request.state.request_id = request_id
        try:
            response = await call_next(request)
        finally:
            reset_request_id(token)
        response.headers["X-Request-Id"] = request_id
        return response

    @app.exception_handler(ServiceError)
    async def handle_service_error(_request, exc: ServiceError):
        """Convert domain-specific service errors into a consistent JSON payload."""
        logger.warning(
            "service.error type=%s status=%s message=%s",
            exc.error_type,
            exc.status_code,
            exc.message,
        )
        return JSONResponse(status_code=exc.status_code, content={"error": exc.to_dict()})

    return app


app = create_app()
