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

logger = logging.getLogger("duvarai.service")


def create_app() -> FastAPI:
    configure_logging()
    app = FastAPI(title=settings.service_name)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_allow_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(ops_router)
    app.include_router(admin_router)
    app.include_router(public_router)
    app.include_router(ext_router)
    app.include_router(ext_admin_router)

    @app.on_event("startup")
    async def load_license():
        validate_service_runtime()
        await bootstrap_license()

    @app.middleware("http")
    async def request_id_middleware(request: Request, call_next):
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
        logger.warning(
            "service.error type=%s status=%s message=%s",
            exc.error_type,
            exc.status_code,
            exc.message,
        )
        return JSONResponse(status_code=exc.status_code, content={"error": exc.to_dict()})

    return app


app = create_app()
