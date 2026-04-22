from __future__ import annotations

import logging
import os

from sqlalchemy.engine import make_url

from app.core.settings import settings

logger = logging.getLogger("duvarai.service.runtime")

_ENGINE_ALIASES = {
    "postgres": "postgresql",
    "postgresql": "postgresql",
    "oracle": "oracle",
    "mssql": "mssql",
    "sqlserver": "mssql",
    "sql_server": "mssql",
    "mysql": "mysql",
}

_SUPPORTED_DRIVERS = {
    "postgresql": {"postgresql+asyncpg"},
    "oracle": {"oracle+oracledb_async"},
    "mssql": {"mssql+aioodbc"},
}


def _runtime_environment() -> str:
    for key in ("DUVARAI_ENVIRONMENT", "APP_ENV", "ENVIRONMENT", "NODE_ENV"):
        raw = os.getenv(key)
        if raw and raw.strip():
            return raw.strip().lower()
    return "development"


def _is_production() -> bool:
    return _runtime_environment() in {"prod", "production"}


def _normalize_database_engine(value: str) -> str:
    normalized = _ENGINE_ALIASES.get(value.strip().lower())
    if not normalized:
        raise RuntimeError(f"Unsupported DUVARAI_DATABASE_ENGINE value: {value}")
    return normalized


def _database_engine_from_driver(drivername: str) -> str:
    driver = drivername.lower()
    if driver.startswith("postgresql"):
        return "postgresql"
    if driver.startswith("oracle"):
        return "oracle"
    if driver.startswith("mssql"):
        return "mssql"
    if driver.startswith("mysql"):
        return "mysql"
    return driver.split("+", 1)[0]


def validate_database_configuration() -> tuple[str, str]:
    """Validate the configured database engine/driver combination."""
    if not settings.database_url:
        raise RuntimeError("DUVARAI_DATABASE_URL is not set")

    drivername = make_url(settings.database_url).drivername.lower()
    inferred_engine = _database_engine_from_driver(drivername)

    if inferred_engine == "mysql":
        raise RuntimeError("MySQL support is planned for the next package release")

    configured_engine = (
        _normalize_database_engine(settings.database_engine)
        if settings.database_engine
        else inferred_engine
    )
    if configured_engine != inferred_engine:
        raise RuntimeError(
            f"DUVARAI_DATABASE_ENGINE={configured_engine} does not match driver {drivername}"
        )

    supported_drivers = _SUPPORTED_DRIVERS.get(configured_engine)
    if supported_drivers and drivername not in supported_drivers:
        supported_list = ", ".join(sorted(supported_drivers))
        raise RuntimeError(
            f"Driver {drivername} is not supported for {configured_engine}; "
            f"use one of: {supported_list}"
        )

    return configured_engine, drivername


def validate_service_runtime() -> None:
    """Check critical configuration at startup and emit warnings for missing settings.

    This is intentionally non-fatal: the service starts even without a database
    URL so that health/readiness probes can respond while the operator fixes
    configuration. Errors that would prevent *all* requests are surfaced through
    the ``/readyz`` endpoint instead.
    """
    warnings: list[str] = []
    production = _is_production()

    if not settings.database_url:
        warnings.append(
            "DUVARAI_DATABASE_URL is not set - all database-backed endpoints will fail"
        )
    else:
        try:
            database_engine, drivername = validate_database_configuration()
            logger.info(
                "runtime.validation.db engine=%s driver=%s",
                database_engine,
                drivername,
            )
        except RuntimeError as exc:
            warnings.append(str(exc))

    if not settings.ai_engine_base_url:
        warnings.append(
            "DUVARAI_AI_ENGINE_BASE_URL (or ENGINE_URL) is not set - "
            "guardrail evaluation will be unavailable"
        )

    admin_auth_mode = (settings.admin_auth_mode or "").strip().lower()
    if admin_auth_mode and admin_auth_mode not in {"development", "network-trust", "jwt"}:
        raise RuntimeError(
            "DUVARAI_ADMIN_AUTH_MODE must be one of development, network-trust, or jwt"
        )

    if production and not settings.redis_url:
        raise RuntimeError(
            "Production runtime requires DUVARAI_REDIS_URL for published guardrail snapshots"
        )

    snapshot_signing_key = settings.snapshot_signing_key or settings.ledger_signing_key
    if production and not snapshot_signing_key:
        raise RuntimeError(
            "Production runtime requires DUVARAI_SNAPSHOT_SIGNING_KEY "
            "(or DUVARAI_LEDGER_SIGNING_KEY) so snapshots are signed"
        )

    if production and not admin_auth_mode:
        raise RuntimeError(
            "Production runtime requires DUVARAI_ADMIN_AUTH_MODE to be explicitly set "
            "to development, network-trust, or jwt"
        )

    jwt_required = settings.enforce_admin_jwt or admin_auth_mode == "jwt"
    if production and admin_auth_mode == "jwt" and not settings.admin_jwt_hs256_secret:
        raise RuntimeError(
            "Production runtime requires DUVARAI_ADMIN_JWT_HS256_SECRET when "
            "DUVARAI_ADMIN_AUTH_MODE=jwt"
        )
    if jwt_required and not settings.admin_jwt_hs256_secret:
        warnings.append(
            "Admin JWT mode is enabled but DUVARAI_ADMIN_JWT_HS256_SECRET is not set - "
            "all admin requests will fail with AUTH_MISCONFIGURED"
        )

    if settings.require_redis and not settings.redis_url:
        warnings.append(
            "require_redis=true but DUVARAI_REDIS_URL is not set - "
            "snapshot publishing will fail"
        )
    if settings.redis_url and not snapshot_signing_key:
        warnings.append(
            "DUVARAI_SNAPSHOT_SIGNING_KEY is not set - "
            "published guardrail snapshots will be unsigned"
        )

    license_token = os.getenv("DUVARAI_LICENSE_TOKEN", "").strip()
    license_public_key = os.getenv("DUVARAI_LICENSE_PUBLIC_KEY", "").strip()
    license_public_keys = os.getenv("DUVARAI_LICENSE_PUBLIC_KEYS", "").strip()
    if license_token and not (license_public_key or license_public_keys):
        warnings.append(
            "DUVARAI_LICENSE_TOKEN is set but no DUVARAI_LICENSE_PUBLIC_KEY "
            "(or DUVARAI_LICENSE_PUBLIC_KEYS) is configured - "
            "license verification will fail"
        )

    for warning in warnings:
        logger.warning("runtime.validation msg=%r", warning)

    logger.info(
        "runtime.validation.ok service=%s db=%s engine=%s",
        settings.service_name,
        "configured" if settings.database_url else "MISSING",
        "configured" if settings.ai_engine_base_url else "MISSING",
    )
