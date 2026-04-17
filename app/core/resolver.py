from __future__ import annotations

import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import ServiceError
from app.models.db import Environment, Guardrail, Project


async def resolve_environment(
    session: AsyncSession, tenant_id: uuid.UUID, environment_id: str
) -> Environment:
    env = await session.get(Environment, (tenant_id, environment_id))
    if env is None:
        raise ServiceError("ENV_NOT_FOUND", "Environment not found", 404)
    return env


async def resolve_project(
    session: AsyncSession, tenant_id: uuid.UUID, environment_id: str, project_id: str
) -> Project:
    project = await session.get(Project, (tenant_id, environment_id, project_id))
    if project is None:
        raise ServiceError("PROJECT_NOT_FOUND", "Project not found", 404)
    return project


async def resolve_guardrail(
    session: AsyncSession,
    tenant_id: uuid.UUID,
    environment_id: str,
    project_id: str,
    guardrail_id: str,
) -> Guardrail:
    guardrail = await session.get(
        Guardrail, (tenant_id, environment_id, project_id, guardrail_id)
    )
    if guardrail is None:
        raise ServiceError("GUARDRAIL_NOT_FOUND", "Guardrail not found", 404)
    return guardrail
