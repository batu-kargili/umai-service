import asyncio
import datetime as dt
import json
import os
import uuid

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from app.core.library import get_guardrail_template
from app.core.redis import get_redis
from app.core.settings import settings
from app.core.snapshot_signing import pack_snapshot_record, sign_snapshot
from app.core.snapshots import build_snapshot_key, publish_snapshot
from app.models.db import Environment, Guardrail, GuardrailVersion, License, Policy, Project, Tenant


FALLBACK_TENANT_ID = uuid.UUID("9f6ec99e-a12e-4ba0-9b68-3fae4825df19")
FALLBACK_TENANT_NAME = "UMAI Enterprise"
DEFAULT_LICENSE_DAYS = 3650
DEFAULT_ENVIRONMENT_ID = "prod"
DEFAULT_ENVIRONMENT_NAME = "Production"
DEFAULT_PROJECT_ID = "poc"
DEFAULT_PROJECT_NAME = "PoC"


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


def _json(data: object) -> str:
    return json.dumps(data, separators=(",", ":"), ensure_ascii=True)


async def _ensure_guardrail_template(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    environment_id: str,
    environment_name: str,
    project_id: str,
    project_name: str,
    template_id: str,
    guardrail_id_override: str | None,
    guardrail_name_override: str | None,
    publish: bool,
) -> str | None:
    template = get_guardrail_template(template_id)
    if template is None:
        raise RuntimeError(f"Guardrail template not found: {template_id}")

    guardrail_id = guardrail_id_override or template["default_guardrail_id"]
    guardrail_name = guardrail_name_override or template["name"]
    version = int(template["version"])

    env = await session.get(Environment, (tenant_id, environment_id))
    if env is None:
        session.add(
            Environment(
                tenant_id=tenant_id,
                environment_id=environment_id,
                name=environment_name,
            )
        )
    else:
        env.name = environment_name

    project = await session.get(Project, (tenant_id, environment_id, project_id))
    if project is None:
        session.add(
            Project(
                tenant_id=tenant_id,
                environment_id=environment_id,
                project_id=project_id,
                name=project_name,
            )
        )
    else:
        project.name = project_name

    policy_snapshots: list[dict] = []
    for policy_template in template["policies"]:
        policy_id = policy_template["default_policy_id"]
        policy = await session.get(
            Policy,
            (tenant_id, environment_id, project_id, policy_id),
        )
        if policy is None:
            policy = Policy(
                tenant_id=tenant_id,
                environment_id=environment_id,
                project_id=project_id,
                policy_id=policy_id,
            )
            session.add(policy)
        policy.name = policy_template["name"]
        policy.type = policy_template["type"]
        policy.enabled = bool(policy_template["enabled"])
        policy.scope = "PROJECT"
        policy.phases_json = _json(policy_template["phases"])
        policy.config_json = _json(policy_template["config"])
        policy_snapshots.append(
            {
                "id": policy_id,
                "type": policy.type,
                "name": policy.name,
                "enabled": policy.enabled,
                "phases": policy_template["phases"],
                "config": policy_template["config"],
            }
        )

    guardrail = await session.get(
        Guardrail,
        (tenant_id, environment_id, project_id, guardrail_id),
    )
    if guardrail is None:
        guardrail = Guardrail(
            tenant_id=tenant_id,
            environment_id=environment_id,
            project_id=project_id,
            guardrail_id=guardrail_id,
        )
        session.add(guardrail)
    guardrail.name = guardrail_name
    guardrail.mode = template["mode"]
    guardrail.current_version = version

    snapshot_payload = {
        "guardrail_id": guardrail_id,
        "version": version,
        "mode": template["mode"],
        "phases": template["phases"],
        "preflight": template["preflight"],
        "policies": policy_snapshots,
        "llm_config": template["llm_config"],
    }
    if template.get("agt") is not None:
        snapshot_payload["agt"] = template["agt"]

    signature, key_id = sign_snapshot(snapshot_payload)
    snapshot_json = _json(snapshot_payload)
    version_row = await session.get(
        GuardrailVersion,
        (tenant_id, environment_id, project_id, guardrail_id, version),
    )
    if version_row is None:
        version_row = GuardrailVersion(
            tenant_id=tenant_id,
            environment_id=environment_id,
            project_id=project_id,
            guardrail_id=guardrail_id,
            version=version,
            created_by="seed",
        )
        session.add(version_row)
    version_row.snapshot_json = snapshot_json
    version_row.signature = signature
    version_row.key_id = key_id
    version_row.approved_by = "seed"
    version_row.approved_at = dt.datetime.now(dt.timezone.utc)

    if not publish:
        return None

    redis_key = build_snapshot_key(
        str(tenant_id),
        environment_id,
        project_id,
        guardrail_id,
        version,
    )
    redis = get_redis()
    await publish_snapshot(
        redis,
        redis_key,
        pack_snapshot_record(snapshot_payload, signature, key_id),
    )
    return redis_key


async def seed():
    tenant_id = _read_uuid_env("UMAI_SEED_TENANT_ID", FALLBACK_TENANT_ID)
    tenant_name = _read_env("UMAI_SEED_TENANT_NAME", FALLBACK_TENANT_NAME)
    license_days = int(_read_env("UMAI_SEED_LICENSE_DAYS", str(DEFAULT_LICENSE_DAYS)))
    plan_tier = _read_env("UMAI_SEED_LICENSE_PLAN", "enterprise")
    allow_llm_calls = _read_bool_env("UMAI_SEED_ALLOW_LLM_CALLS", True)
    guardrail_template_id = os.getenv("UMAI_SEED_GUARDRAIL_TEMPLATE_ID", "").strip()
    environment_id = _read_env("UMAI_SEED_ENVIRONMENT_ID", DEFAULT_ENVIRONMENT_ID)
    environment_name = _read_env("UMAI_SEED_ENVIRONMENT_NAME", DEFAULT_ENVIRONMENT_NAME)
    project_id = _read_env("UMAI_SEED_PROJECT_ID", DEFAULT_PROJECT_ID)
    project_name = _read_env("UMAI_SEED_PROJECT_NAME", DEFAULT_PROJECT_NAME)
    guardrail_id_override = os.getenv("UMAI_SEED_GUARDRAIL_ID", "").strip() or None
    guardrail_name_override = os.getenv("UMAI_SEED_GUARDRAIL_NAME", "").strip() or None
    publish_guardrail = _read_bool_env("UMAI_SEED_PUBLISH_GUARDRAIL", True)

    engine = create_async_engine(settings.database_url)
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    published_key: str | None = None

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

            if guardrail_template_id:
                published_key = await _ensure_guardrail_template(
                    session,
                    tenant_id=tenant_id,
                    environment_id=environment_id,
                    environment_name=environment_name,
                    project_id=project_id,
                    project_name=project_name,
                    template_id=guardrail_template_id,
                    guardrail_id_override=guardrail_id_override,
                    guardrail_name_override=guardrail_name_override,
                    publish=publish_guardrail,
                )

    await engine.dispose()
    print("Seed data ensured for configured tenant/license.")
    if guardrail_template_id:
        if published_key:
            print(f"Seed guardrail ensured and published: {published_key}")
        else:
            print("Seed guardrail ensured without publishing.")


if __name__ == "__main__":
    asyncio.run(seed())
