from __future__ import annotations

import asyncio
import datetime as dt
import json
import logging
import uuid

from fastapi import APIRouter, Depends, Header, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.async_jobs import schedule_guardrail_job
from app.core.auth import authenticate_api_key
from app.core.db import get_session, tenant_scope
from app.core.engine_client import evaluate_engine
from app.core.errors import ServiceError
from app.core.events import record_audit_event
from app.core.license import license_allows_llm_calls, require_active_license
from app.core.resolver import resolve_environment, resolve_guardrail, resolve_project
from app.core.settings import settings
from app.models.db import GuardrailJob, License, Tenant
from app.models.engine import EngineFlags, EngineRequest, EngineResponse
from app.models.license import LicensePayload
from app.models.public import (
    Decision,
    FreeSubscriptionRequest,
    FreeSubscriptionResponse,
    GuardrailJobStatusResponse,
    GuardrailJobWaitRequest,
    PublicGuardAsyncRequest,
    PublicGuardAsyncResponse,
    PublicGuardRequest,
    PublicGuardResponse,
    TriggeringPolicy,
)

router = APIRouter(prefix="/api/v1", tags=["public"])
logger = logging.getLogger("duvarai.service.public")

TERMINAL_JOB_STATUSES = {"COMPLETED", "FAILED", "TIMEOUT", "CANCELED"}


def _extract_api_key(x_duvarai_api_key: str | None, authorization: str | None) -> str | None:
    if x_duvarai_api_key:
        return x_duvarai_api_key
    if authorization and authorization.lower().startswith("bearer "):
        return authorization.split(" ", 1)[1].strip()
    return None


def _summarize_payload(payload: PublicGuardRequest) -> str:
    messages = payload.input.messages or []
    return (
        f"messages={len(messages)} phase_focus={payload.input.phase_focus} "
        f"content_type={payload.input.content_type} language={payload.input.language} "
        f"artifacts={len(payload.input.artifacts)} phase={payload.phase}"
    )


def _to_public_response(engine_response: EngineResponse) -> PublicGuardResponse:
    triggering_policy = None
    if engine_response.triggering_policy:
        triggering_policy = TriggeringPolicy(
            policy_id=engine_response.triggering_policy.policy_id,
            type=engine_response.triggering_policy.type,
            status=engine_response.triggering_policy.status,
        )
    return PublicGuardResponse(
        request_id=engine_response.request_id,
        decision=Decision(
            action=engine_response.decision.action,
            allowed=engine_response.decision.allowed,
            severity=engine_response.decision.severity,
            reason=engine_response.decision.reason,
        ),
        category=None,
        triggering_policy=triggering_policy,
        output_modifications=engine_response.output_modifications,
        latency_ms=int(engine_response.latency_ms.total),
        errors=[err.model_dump() for err in engine_response.errors],
    )


async def _authenticate_request_api_key(
    session: AsyncSession,
    x_duvarai_api_key: str | None,
    authorization: str | None,
):
    raw_key = _extract_api_key(x_duvarai_api_key, authorization)
    async with session.begin():
        api_key = await authenticate_api_key(session, raw_key)
    if not api_key.project_id:
        raise ServiceError("PROJECT_NOT_FOUND", "API key is not scoped to a project", 404)
    return api_key


async def _resolve_guard_context(
    session: AsyncSession,
    api_key,
    guardrail_id: str,
):
    tenant_id = api_key.tenant_id
    environment_id = api_key.environment_id
    project_id = api_key.project_id
    async with session.begin():
        async with tenant_scope(session, str(tenant_id)):
            license_row = await require_active_license(session, tenant_id)
            allow_llm_calls = license_allows_llm_calls(license_row)
            await resolve_environment(session, tenant_id, environment_id)
            await resolve_project(session, tenant_id, environment_id, project_id)
            guardrail = await resolve_guardrail(
                session, tenant_id, environment_id, project_id, guardrail_id
            )
    return tenant_id, environment_id, project_id, guardrail, allow_llm_calls


@router.post("/guardrails/{guardrail_id}/guard", response_model=PublicGuardResponse)
async def guard(
    guardrail_id: str,
    payload: PublicGuardRequest,
    request: Request,
    x_duvarai_api_key: str | None = Header(default=None, alias="X-DuvarAI-Api-Key"),
    authorization: str | None = Header(default=None, alias="Authorization"),
    session: AsyncSession = Depends(get_session),
) -> PublicGuardResponse:
    request_id = getattr(request.state, "request_id", None) or str(uuid.uuid4())
    logger.info(
        "guard.start request_id=%s guardrail_id=%s phase=%s",
        request_id,
        guardrail_id,
        payload.phase,
    )
    if settings.log_request_payloads:
        logger.info(
            "guard.payload request_id=%s body=%s",
            request_id,
            json.dumps(payload.model_dump(), separators=(",", ":"), ensure_ascii=True),
        )
    else:
        logger.info("guard.payload.summary request_id=%s %s", request_id, _summarize_payload(payload))

    api_key = await _authenticate_request_api_key(session, x_duvarai_api_key, authorization)
    tenant_id, environment_id, project_id, guardrail, allow_llm_calls = await _resolve_guard_context(
        session, api_key, guardrail_id
    )

    timestamp = dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")
    engine_request = EngineRequest(
        request_id=request_id,
        timestamp=timestamp,
        tenant_id=str(tenant_id),
        environment_id=environment_id,
        project_id=project_id,
        guardrail_id=guardrail_id,
        guardrail_version=guardrail.current_version,
        phase=payload.phase,
        input=payload.input,
        timeout_ms=payload.timeout_ms,
        flags=EngineFlags(allow_llm_calls=allow_llm_calls),
    )
    engine_response = await evaluate_engine(engine_request)

    async with session.begin():
        async with tenant_scope(session, str(tenant_id)):
            await record_audit_event(
                session,
                tenant_id=tenant_id,
                environment_id=environment_id,
                project_id=project_id,
                guardrail_id=guardrail_id,
                guardrail_version=guardrail.current_version,
                engine_response=engine_response,
                request_payload=payload,
            )
    return _to_public_response(engine_response)


@router.post("/guardrails/{guardrail_id}/guard/async", response_model=PublicGuardAsyncResponse)
async def guard_async(
    guardrail_id: str,
    payload: PublicGuardAsyncRequest,
    request: Request,
    x_duvarai_api_key: str | None = Header(default=None, alias="X-DuvarAI-Api-Key"),
    authorization: str | None = Header(default=None, alias="Authorization"),
    session: AsyncSession = Depends(get_session),
) -> PublicGuardAsyncResponse:
    request_id = getattr(request.state, "request_id", None) or str(uuid.uuid4())
    api_key = await _authenticate_request_api_key(session, x_duvarai_api_key, authorization)
    tenant_id, environment_id, project_id, guardrail, _ = await _resolve_guard_context(
        session, api_key, guardrail_id
    )
    job = GuardrailJob(
        tenant_id=tenant_id,
        environment_id=environment_id,
        project_id=project_id,
        guardrail_id=guardrail_id,
        guardrail_version=guardrail.current_version,
        request_id=request_id,
        phase=payload.phase,
        status="QUEUED",
        conversation_id=payload.conversation_id,
        request_payload_json=json.dumps(payload.model_dump(), separators=(",", ":"), ensure_ascii=True),
        webhook_url=payload.webhook_url,
        webhook_secret=payload.webhook_secret,
        created_at=dt.datetime.now(dt.timezone.utc),
    )
    async with session.begin():
        async with tenant_scope(session, str(tenant_id)):
            session.add(job)
        await session.flush()
    schedule_guardrail_job(job.id)
    return PublicGuardAsyncResponse(job_id=job.id, status=job.status, created_at=job.created_at)


async def _load_scoped_job(
    session: AsyncSession,
    job_id: uuid.UUID,
    x_duvarai_api_key: str | None,
    authorization: str | None,
) -> GuardrailJob:
    api_key = await _authenticate_request_api_key(session, x_duvarai_api_key, authorization)
    async with session.begin():
        async with tenant_scope(session, str(api_key.tenant_id)):
            job = await session.get(GuardrailJob, job_id)
            if job is None:
                raise ServiceError("JOB_NOT_FOUND", "Guardrail job not found", 404)
            if (
                job.tenant_id != api_key.tenant_id
                or job.environment_id != api_key.environment_id
                or job.project_id != api_key.project_id
            ):
                raise ServiceError("FORBIDDEN", "Job does not belong to this API key scope", 403)
    return job


def _job_to_response(job: GuardrailJob) -> GuardrailJobStatusResponse:
    result = None
    if job.response_payload_json:
        result = PublicGuardResponse.model_validate(json.loads(job.response_payload_json))
    return GuardrailJobStatusResponse(
        job_id=job.id,
        status=job.status,
        request_id=job.request_id,
        created_at=job.created_at,
        updated_at=job.updated_at,
        completed_at=job.completed_at,
        error=job.error_message,
        result=result,
    )


@router.get("/guardrails/jobs/{job_id}", response_model=GuardrailJobStatusResponse)
async def get_guard_job(
    job_id: uuid.UUID,
    x_duvarai_api_key: str | None = Header(default=None, alias="X-DuvarAI-Api-Key"),
    authorization: str | None = Header(default=None, alias="Authorization"),
    session: AsyncSession = Depends(get_session),
) -> GuardrailJobStatusResponse:
    job = await _load_scoped_job(session, job_id, x_duvarai_api_key, authorization)
    return _job_to_response(job)


@router.post("/guardrails/jobs/{job_id}/wait", response_model=GuardrailJobStatusResponse)
async def wait_guard_job(
    job_id: uuid.UUID,
    payload: GuardrailJobWaitRequest,
    x_duvarai_api_key: str | None = Header(default=None, alias="X-DuvarAI-Api-Key"),
    authorization: str | None = Header(default=None, alias="Authorization"),
    session: AsyncSession = Depends(get_session),
) -> GuardrailJobStatusResponse:
    waited = 0
    while waited < payload.timeout_ms:
        job = await _load_scoped_job(session, job_id, x_duvarai_api_key, authorization)
        if job.status in TERMINAL_JOB_STATUSES:
            return _job_to_response(job)
        await asyncio.sleep(payload.poll_interval_ms / 1000.0)
        waited += payload.poll_interval_ms
    job = await _load_scoped_job(session, job_id, x_duvarai_api_key, authorization)
    return _job_to_response(job)


@router.post("/guardrails/jobs/{job_id}/cancel", response_model=GuardrailJobStatusResponse)
async def cancel_guard_job(
    job_id: uuid.UUID,
    x_duvarai_api_key: str | None = Header(default=None, alias="X-DuvarAI-Api-Key"),
    authorization: str | None = Header(default=None, alias="Authorization"),
    session: AsyncSession = Depends(get_session),
) -> GuardrailJobStatusResponse:
    job = await _load_scoped_job(session, job_id, x_duvarai_api_key, authorization)
    if job.status in TERMINAL_JOB_STATUSES:
        return _job_to_response(job)
    async with session.begin():
        async with tenant_scope(session, str(job.tenant_id)):
            row = await session.get(GuardrailJob, job_id)
            if row is None:
                raise ServiceError("JOB_NOT_FOUND", "Guardrail job not found", 404)
            row.status = "CANCELED"
            row.completed_at = dt.datetime.now(dt.timezone.utc)
            row.updated_at = row.completed_at
            row.error_message = "Canceled by caller"
            job = row
    return _job_to_response(job)


@router.post("/subscriptions/free", response_model=FreeSubscriptionResponse)
async def subscribe_free_tier(
    payload: FreeSubscriptionRequest,
    session: AsyncSession = Depends(get_session),
) -> FreeSubscriptionResponse:
    tenant_id = uuid.uuid4()
    now = dt.datetime.now(dt.timezone.utc)
    expires_at = now + dt.timedelta(days=settings.free_license_days)

    license_payload = LicensePayload(
        license_id=f"free-{tenant_id}",
        tenant_id=tenant_id,
        issued_at=now,
        expires_at=expires_at,
        status="active",
        tenant_name=payload.tenant_name,
        issuer="DuvarAI",
        features={
            "tier": settings.free_plan_tier,
            "max_projects": settings.free_max_projects,
            "allow_llm_calls": settings.free_allow_llm_calls,
        },
    )
    features_json = json.dumps(
        license_payload.model_dump(mode="json", exclude_none=True),
        separators=(",", ":"),
        ensure_ascii=True,
    )

    async with session.begin():
        async with tenant_scope(session, str(tenant_id)):
            tenant = Tenant(tenant_id=tenant_id, name=payload.tenant_name, status="active")
            license_row = License(
                tenant_id=tenant_id,
                status="active",
                expires_at=expires_at,
                features_json=features_json,
            )
            session.add(tenant)
            session.add(license_row)

    logger.info(
        "subscription.free.created tenant_id=%s expires_at=%s",
        tenant_id,
        expires_at.isoformat(),
    )

    return FreeSubscriptionResponse(
        tenant_id=tenant_id,
        plan=settings.free_plan_tier,
        license_expires_at=expires_at,
    )
