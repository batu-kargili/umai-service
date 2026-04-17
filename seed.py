import asyncio
import datetime as dt
import json
import os
import uuid

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from app.core.settings import settings
from app.models.db import License, Tenant


FALLBACK_TENANT_ID = uuid.UUID("9f6ec99e-a12e-4ba0-9b68-3fae4825df19")
FALLBACK_TENANT_NAME = "DuvarAI Enterprise"
DEFAULT_LICENSE_DAYS = 3650


def _read_env(name: str, default: str) -> str:
    value = os.getenv(name, "").strip()
    return value or default


def _read_bool_env(name: str, default: bool) -> bool:
    value = os.getenv(name, "").strip().lower()
    if not value:
        return default
    return value in {"1", "true", "yes", "y", "on"}


def _read_uuid_env(name: str, default: uuid.UUID) -> uuid.UUID:
    value = os.getenv(name, "").strip()
    if not value:
        return default
    return uuid.UUID(value)


async def seed():
    tenant_id = _read_uuid_env("DUVARAI_SEED_TENANT_ID", FALLBACK_TENANT_ID)
    tenant_name = _read_env("DUVARAI_SEED_TENANT_NAME", FALLBACK_TENANT_NAME)
    license_days = int(_read_env("DUVARAI_SEED_LICENSE_DAYS", str(DEFAULT_LICENSE_DAYS)))
    plan_tier = _read_env("DUVARAI_SEED_LICENSE_PLAN", "enterprise")
    allow_llm_calls = _read_bool_env("DUVARAI_SEED_ALLOW_LLM_CALLS", True)

    engine = create_async_engine(settings.database_url)
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with async_session() as session:
        async with session.begin():
            tenant = await session.get(Tenant, tenant_id)
            if tenant is None:
                tenant = Tenant(tenant_id=tenant_id, name=tenant_name)
                session.add(tenant)
            else:
                tenant.name = tenant_name

            license_row = await session.get(License, tenant_id)
            expires_at = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=license_days)
            features_json = json.dumps(
                {
                    "tenant_id": str(tenant_id),
                    "status": "active",
                    "expires_at": expires_at.isoformat(),
                    "features": {
                        "tier": plan_tier,
                        "allow_llm_calls": allow_llm_calls,
                    },
                },
                separators=(",", ":"),
                ensure_ascii=True,
            )
            if license_row is None:
                session.add(
                    License(
                        tenant_id=tenant_id,
                        status="active",
                        expires_at=expires_at,
                        features_json=features_json,
                    )
                )
            else:
                license_row.status = "active"
                license_row.expires_at = expires_at
                license_row.features_json = features_json

    print("Seed data ensured for configured tenant/license.")


if __name__ == "__main__":
    asyncio.run(seed())
