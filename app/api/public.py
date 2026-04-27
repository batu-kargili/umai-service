from __future__ import annotations

import asyncio
import datetime as dt
import json
import logging
import uuid

from fastapi import APIRouter, Depends, Header, Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.agent_mesh import (
    build_agent_did,
    hash_secret,
    object_hash,
    public_key_fingerprint,
    trust_tier_for_score,
    verify_agent_context,
)
from app.core.async_jobs import schedule_guardrail_job
from app.core.auth import authenticate_api_key
from app.core.db import get_session, tenant_scope
from app.core.engine_client import evaluate_engine
from app.core.errors import ServiceError
from app.core.events import record_audit_event
from app.core.license import license_allows_llm_calls, require_active_license
from app.core.resolver import resolve_environment, resolve_guardrail, resolve_project
from app.core.settings import settings
from app.models.db import (
    AgentIdentityBootstrapToken,
    AgentIdentityCredential,
    AgentRegistryEntry,
    AgentRunSession,
    AgentRunStep,
    GuardrailJob,
    License,
    Tenant,
)
from app.models.engine import EngineFlags, EngineRequest, EngineResponse
from app.models.license import LicensePayload
from app.models.public import (
    AgentIdentityRegisterRequest,
    AgentIdentityRegisterResponse,
    AgentRunPatchRequest,
    AgentRunSessionResponse,
    AgentRunStartRequest,
    AgentRunStepCreateRequest,
    AgentRunStepResponse,
    AgentSignedContext,
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
logger = logging.getLogger("umai.service.public")

TERMINAL_JOB_STATUSES = {"COMPLETED", "FAILED", "TIMEOUT", "CANCELED"}


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _as_utc(value: dt.datetime) -> dt.datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=dt.timezone.utc)
    return value.astimezone(dt.timezone.utc)


def _json_or_none(value: object) -> str | None:
    if value is None:
        return None
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True)


def _load_json(value: str | None) -> dict | list | None:
    if not value:
        return None
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return None


def _extract_api_key(x_umai_api_key: str | None, authorization: str | None) -> str | None:
    if x_umai_api_key:
        return x_umai_api_key
    if authorization and authorization.lower().startswith("bearer "):
        return authorization.split(" ", 1)[1].strip()
    return None


def _agent_context_body_hash(payload: PublicGuardRequest) -> str:
    return object_hash(payload.model_dump(mode="json", exclude={"agent_context"}))


def _inject_agent_metadata(payload: PublicGuardRequest, verified_agent) -> PublicGuardRequest:
    enriched = payload.model_copy(deep=True)
    if not enriched.input.artifacts:
        return enriched
    for artifact in enriched.input.artifacts:
        metadata = dict(artifact.metadata or {})
        metadata.setdefault("agent_id", verified_agent.agent_id)
        metadata.setdefault("agent_did", verified_agent.agent_did)
        metadata.setdefault("trust_score", verified_agent.trust_score)
        metadata.setdefault("trust_tier", verified_agent.trust_tier)
        metadata.setdefault("capabilities", verified_agent.capabilities)
        metadata.setdefault("public_key_fingerprint", verified_agent.public_key_fingerprint)
        artifact.metadata = metadata
    return enriched


def _extract_action_resource(payload: PublicGuardRequest) -> dict | None:
    if not payload.input.artifacts:
        return None
    artifact = payload.input.artifacts[0]
    metadata = artifact.metadata or {}
    return {
        "artifact_type": artifact.artifact_type,
        "name": artifact.name,
        "action": metadata.get("action"),
        "tool_name": metadata.get("tool_name"),
        "server_name": metadata.get("server_name"),
        "method": metadata.get("method"),
        "memory_scope": metadata.get("memory_scope"),
        "resource_id": metadata.get("resource_id"),
        "classification": metadata.get("classification"),
    }


def _agent_run_to_response(row: AgentRunSession) -> AgentRunSessionResponse:
    summary = _load_json(row.summary_json)
    return AgentRunSessionResponse(
        tenant_id=row.tenant_id,
        environment_id=row.environment_id,
        project_id=row.project_id,
        run_id=row.run_id,
        agent_id=row.agent_id,
        agent_did=row.agent_did,
        guardrail_id=row.guardrail_id,
        status=row.status,
        decision_action=row.decision_action,
        decision_severity=row.decision_severity,
        trust_score=row.trust_score,
        trust_tier=row.trust_tier,
        summary=summary if isinstance(summary, dict) else None,
        started_at=row.started_at,
        updated_at=row.updated_at,
        completed_at=row.completed_at,
    )


def _agent_step_to_response(row: AgentRunStep) -> AgentRunStepResponse:
    metadata = _load_json(row.metadata_json)
    return AgentRunStepResponse(
        run_id=row.run_id,
        step_id=row.step_id,
        parent_step_id=row.parent_step_id,
        sequence=row.sequence,
        event_type=row.event_type,
        phase=row.phase,
        status=row.status,
        agent_id=row.agent_id,
        agent_did=row.agent_did,
        action=row.action,
        resource_type=row.resource_type,
        resource_name=row.resource_name,
        decision_action=row.decision_action,
        decision_severity=row.decision_severity,
        decision_reason=row.decision_reason,
        policy_id=row.policy_id,
        matched_rule_id=row.matched_rule_id,
        latency_ms=row.latency_ms,
        payload_summary=row.payload_summary,
        metadata=metadata if isinstance(metadata, dict) else None,
        input_hash=row.input_hash,
        output_hash=row.output_hash,
        prev_step_hash=row.prev_step_hash,
        step_hash=row.step_hash,
        created_at=row.created_at,
    )


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
    x_umai_api_key: str | None,
    authorization: str | None,
):
    raw_key = _extract_api_key(x_umai_api_key, authorization)
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


async def _resolve_project_from_api_key(session: AsyncSession, api_key):
    tenant_id = api_key.tenant_id
    environment_id = api_key.environment_id
    project_id = api_key.project_id
    async with session.begin():
        async with tenant_scope(session, str(tenant_id)):
            await require_active_license(session, tenant_id)
            await resolve_environment(session, tenant_id, environment_id)
            await resolve_project(session, tenant_id, environment_id, project_id)
    return tenant_id, environment_id, project_id


async def _ensure_agent_run(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    environment_id: str,
    project_id: str,
    run_id: str,
    agent_id: str,
    agent_did: str,
    guardrail_id: str | None,
    trust_score: float | None,
    trust_tier: str | None,
) -> AgentRunSession:
    now = _utcnow()
    row = await session.get(
        AgentRunSession,
        (tenant_id, environment_id, project_id, run_id),
    )
    if row is None:
        row = AgentRunSession(
            tenant_id=tenant_id,
            environment_id=environment_id,
            project_id=project_id,
            run_id=run_id,
            agent_id=agent_id,
            agent_did=agent_did,
            guardrail_id=guardrail_id,
            status="RUNNING",
            trust_score=trust_score,
            trust_tier=trust_tier,
            started_at=now,
            updated_at=now,
        )
        session.add(row)
    else:
        row.agent_id = agent_id
        row.agent_did = agent_did
        row.guardrail_id = guardrail_id or row.guardrail_id
        row.trust_score = trust_score if trust_score is not None else row.trust_score
        row.trust_tier = trust_tier or row.trust_tier
        row.updated_at = now
    return row


async def _next_step_state(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    environment_id: str,
    project_id: str,
    run_id: str,
) -> tuple[int, str | None]:
    max_sequence = await session.execute(
        select(func.max(AgentRunStep.sequence)).where(
            AgentRunStep.tenant_id == tenant_id,
            AgentRunStep.environment_id == environment_id,
            AgentRunStep.project_id == project_id,
            AgentRunStep.run_id == run_id,
        )
    )
    sequence = int(max_sequence.scalar_one_or_none() or 0) + 1
    previous = await session.execute(
        select(AgentRunStep.step_hash)
        .where(
            AgentRunStep.tenant_id == tenant_id,
            AgentRunStep.environment_id == environment_id,
            AgentRunStep.project_id == project_id,
            AgentRunStep.run_id == run_id,
        )
        .order_by(AgentRunStep.sequence.desc())
        .limit(1)
    )
    return sequence, previous.scalar_one_or_none()


def _build_step_hash(row: AgentRunStep) -> str:
    return object_hash(
        {
            "tenant_id": str(row.tenant_id),
            "environment_id": row.environment_id,
            "project_id": row.project_id,
            "run_id": row.run_id,
            "step_id": row.step_id,
            "parent_step_id": row.parent_step_id,
            "sequence": row.sequence,
            "event_type": row.event_type,
            "phase": row.phase,
            "status": row.status,
            "agent_id": row.agent_id,
            "agent_did": row.agent_did,
            "action": row.action,
            "resource_type": row.resource_type,
            "resource_name": row.resource_name,
            "decision_action": row.decision_action,
            "decision_severity": row.decision_severity,
            "decision_reason": row.decision_reason,
            "policy_id": row.policy_id,
            "matched_rule_id": row.matched_rule_id,
            "input_hash": row.input_hash,
            "output_hash": row.output_hash,
            "prev_step_hash": row.prev_step_hash,
        }
    )


async def _append_agent_step(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    environment_id: str,
    project_id: str,
    run_id: str,
    step_id: str,
    parent_step_id: str | None,
    event_type: str,
    phase: str | None,
    status: str,
    agent_id: str,
    agent_did: str,
    action: str | None = None,
    resource_type: str | None = None,
    resource_name: str | None = None,
    decision_action: str | None = None,
    decision_severity: str | None = None,
    decision_reason: str | None = None,
    policy_id: str | None = None,
    matched_rule_id: str | None = None,
    latency_ms: float | None = None,
    payload_summary: str | None = None,
    metadata: dict | None = None,
    input_hash: str | None = None,
    output_hash: str | None = None,
) -> AgentRunStep:
    existing = await session.get(
        AgentRunStep,
        (tenant_id, environment_id, project_id, run_id, step_id),
    )
    if existing is not None:
        existing.parent_step_id = parent_step_id or existing.parent_step_id
        existing.event_type = event_type or existing.event_type
        existing.phase = phase or existing.phase
        existing.status = status or existing.status
        existing.action = action or existing.action
        existing.resource_type = resource_type or existing.resource_type
        existing.resource_name = resource_name or existing.resource_name
        existing.decision_action = decision_action or existing.decision_action
        existing.decision_severity = decision_severity or existing.decision_severity
        existing.decision_reason = decision_reason or existing.decision_reason
        existing.policy_id = policy_id or existing.policy_id
        existing.matched_rule_id = matched_rule_id or existing.matched_rule_id
        existing.latency_ms = latency_ms if latency_ms is not None else existing.latency_ms
        existing.payload_summary = payload_summary or existing.payload_summary
        existing.metadata_json = _json_or_none(metadata) or existing.metadata_json
        existing.input_hash = input_hash or existing.input_hash
        existing.output_hash = output_hash or existing.output_hash
        existing.step_hash = _build_step_hash(existing)
        return existing

    sequence, prev_step_hash = await _next_step_state(
        session,
        tenant_id=tenant_id,
        environment_id=environment_id,
        project_id=project_id,
        run_id=run_id,
    )
    row = AgentRunStep(
        tenant_id=tenant_id,
        environment_id=environment_id,
        project_id=project_id,
        run_id=run_id,
        step_id=step_id,
        parent_step_id=parent_step_id,
        sequence=sequence,
        event_type=event_type,
        phase=phase,
        status=status,
        agent_id=agent_id,
        agent_did=agent_did,
        action=action,
        resource_type=resource_type,
        resource_name=resource_name,
        decision_action=decision_action,
        decision_severity=decision_severity,
        decision_reason=decision_reason,
        policy_id=policy_id,
        matched_rule_id=matched_rule_id,
        latency_ms=latency_ms,
        payload_summary=payload_summary,
        metadata_json=_json_or_none(metadata),
        input_hash=input_hash,
        output_hash=output_hash,
        prev_step_hash=prev_step_hash,
    )
    row.step_hash = _build_step_hash(row)
    session.add(row)
    return row


def _decision_penalty(engine_response: EngineResponse) -> float:
    action = engine_response.decision.action
    if action == "BLOCK":
        return 0.08
    if action == "STEP_UP_APPROVAL":
        return 0.04
    if action in {"ALLOW_WITH_WARNINGS", "FLAG"}:
        return 0.02
    return 0.0


async def _apply_agent_decision(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    environment_id: str,
    project_id: str,
    agent_id: str,
    engine_response: EngineResponse,
) -> tuple[float, str] | None:
    registry = await session.get(
        AgentRegistryEntry,
        (tenant_id, environment_id, project_id, agent_id),
    )
    if registry is None:
        return None
    penalty = _decision_penalty(engine_response)
    if penalty:
        registry.trust_score = max(0.0, float(registry.trust_score or 0.0) - penalty)
        registry.trust_tier = trust_tier_for_score(float(registry.trust_score or 0.0))
    registry.last_seen_at = _utcnow()
    registry.updated_at = registry.last_seen_at
    return float(registry.trust_score or 0.0), registry.trust_tier


async def _record_guard_agent_step(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    environment_id: str,
    project_id: str,
    guardrail_id: str,
    context: AgentSignedContext,
    verified_agent,
    engine_response: EngineResponse,
    request_payload: PublicGuardRequest,
) -> None:
    if not context.run_id or not context.step_id:
        return

    trust_state = await _apply_agent_decision(
        session,
        tenant_id=tenant_id,
        environment_id=environment_id,
        project_id=project_id,
        agent_id=context.agent_id,
        engine_response=engine_response,
    )
    trust_score = trust_state[0] if trust_state else verified_agent.trust_score
    trust_tier = trust_state[1] if trust_state else verified_agent.trust_tier
    run = await _ensure_agent_run(
        session,
        tenant_id=tenant_id,
        environment_id=environment_id,
        project_id=project_id,
        run_id=context.run_id,
        agent_id=context.agent_id,
        agent_did=context.agent_did,
        guardrail_id=guardrail_id,
        trust_score=trust_score,
        trust_tier=trust_tier,
    )
    run.decision_action = engine_response.decision.action
    run.decision_severity = engine_response.decision.severity
    run.updated_at = _utcnow()

    policy_id = engine_response.triggering_policy.policy_id if engine_response.triggering_policy else None
    details = engine_response.triggering_policy.details if engine_response.triggering_policy else {}
    action_resource = _extract_action_resource(request_payload) or {}
    await _append_agent_step(
        session,
        tenant_id=tenant_id,
        environment_id=environment_id,
        project_id=project_id,
        run_id=context.run_id,
        step_id=context.step_id,
        parent_step_id=context.parent_step_id,
        event_type="guard_decision",
        phase=engine_response.phase,
        status="BLOCKED" if not engine_response.decision.allowed else "COMPLETED",
        agent_id=context.agent_id,
        agent_did=context.agent_did,
        action=str(action_resource.get("action") or "") or None,
        resource_type=str(action_resource.get("artifact_type") or "") or None,
        resource_name=str(
            action_resource.get("tool_name")
            or action_resource.get("server_name")
            or action_resource.get("memory_scope")
            or action_resource.get("name")
            or ""
        )
        or None,
        decision_action=engine_response.decision.action,
        decision_severity=engine_response.decision.severity,
        decision_reason=engine_response.decision.reason,
        policy_id=policy_id,
        matched_rule_id=str((details or {}).get("matched_rule_id") or "") or None,
        latency_ms=engine_response.latency_ms.total,
        payload_summary=(request_payload.input.artifacts[0].payload_summary if request_payload.input.artifacts else None),
        metadata={
            "trust_score": trust_score,
            "trust_tier": trust_tier,
            "policy_type": engine_response.triggering_policy.type if engine_response.triggering_policy else None,
            "action_resource": action_resource,
        },
        input_hash=object_hash(request_payload.model_dump(mode="json", exclude={"agent_context"})),
    )


@router.post("/guardrails/{guardrail_id}/guard", response_model=PublicGuardResponse)
async def guard(
    guardrail_id: str,
    payload: PublicGuardRequest,
    request: Request,
    x_umai_api_key: str | None = Header(default=None, alias="X-Umai-Api-Key"),
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

    api_key = await _authenticate_request_api_key(session, x_umai_api_key, authorization)
    tenant_id, environment_id, project_id, guardrail, allow_llm_calls = await _resolve_guard_context(
        session, api_key, guardrail_id
    )
    verified_agent = None
    payload_for_engine = payload
    if payload.agent_context:
        if payload.agent_context.run_id and len(payload.agent_context.run_id) > 64:
            raise ServiceError("AGENT_RUN_ID_INVALID", "Agent run_id must be 64 characters or less", 422)
        if payload.agent_context.step_id and len(payload.agent_context.step_id) > 64:
            raise ServiceError("AGENT_STEP_ID_INVALID", "Agent step_id must be 64 characters or less", 422)
        async with session.begin():
            async with tenant_scope(session, str(tenant_id)):
                verified_agent = await verify_agent_context(
                    session,
                    tenant_id=tenant_id,
                    environment_id=environment_id,
                    project_id=project_id,
                    context=payload.agent_context,
                    event="guard",
                    body_hash=_agent_context_body_hash(payload),
                    extra={"guardrail_id": guardrail_id, "phase": payload.phase},
                )
        payload_for_engine = _inject_agent_metadata(payload, verified_agent)

    timestamp = dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")
    engine_request = EngineRequest(
        request_id=request_id,
        timestamp=timestamp,
        tenant_id=str(tenant_id),
        environment_id=environment_id,
        project_id=project_id,
        guardrail_id=guardrail_id,
        guardrail_version=guardrail.current_version,
        phase=payload_for_engine.phase,
        input=payload_for_engine.input,
        timeout_ms=payload_for_engine.timeout_ms,
        flags=EngineFlags(allow_llm_calls=allow_llm_calls),
        agent_context=payload.agent_context.model_dump(mode="json") if payload.agent_context else None,
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
                request_payload=payload_for_engine,
                agent_context=payload.agent_context,
                action_resource=_extract_action_resource(payload_for_engine),
            )
            if payload.agent_context and verified_agent is not None:
                await _record_guard_agent_step(
                    session,
                    tenant_id=tenant_id,
                    environment_id=environment_id,
                    project_id=project_id,
                    guardrail_id=guardrail_id,
                    context=payload.agent_context,
                    verified_agent=verified_agent,
                    engine_response=engine_response,
                    request_payload=payload_for_engine,
                )
    return _to_public_response(engine_response)


@router.post("/guardrails/{guardrail_id}/guard/async", response_model=PublicGuardAsyncResponse)
async def guard_async(
    guardrail_id: str,
    payload: PublicGuardAsyncRequest,
    request: Request,
    x_umai_api_key: str | None = Header(default=None, alias="X-Umai-Api-Key"),
    authorization: str | None = Header(default=None, alias="Authorization"),
    session: AsyncSession = Depends(get_session),
) -> PublicGuardAsyncResponse:
    request_id = getattr(request.state, "request_id", None) or str(uuid.uuid4())
    api_key = await _authenticate_request_api_key(session, x_umai_api_key, authorization)
    tenant_id, environment_id, project_id, guardrail, _ = await _resolve_guard_context(
        session, api_key, guardrail_id
    )
    if payload.agent_context:
        async with session.begin():
            async with tenant_scope(session, str(tenant_id)):
                await verify_agent_context(
                    session,
                    tenant_id=tenant_id,
                    environment_id=environment_id,
                    project_id=project_id,
                    context=payload.agent_context,
                    event="guard",
                    body_hash=object_hash(payload.model_dump(mode="json", exclude={"agent_context"})),
                    extra={"guardrail_id": guardrail_id, "phase": payload.phase},
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
    x_umai_api_key: str | None,
    authorization: str | None,
) -> GuardrailJob:
    api_key = await _authenticate_request_api_key(session, x_umai_api_key, authorization)
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
    x_umai_api_key: str | None = Header(default=None, alias="X-Umai-Api-Key"),
    authorization: str | None = Header(default=None, alias="Authorization"),
    session: AsyncSession = Depends(get_session),
) -> GuardrailJobStatusResponse:
    job = await _load_scoped_job(session, job_id, x_umai_api_key, authorization)
    return _job_to_response(job)


@router.post("/guardrails/jobs/{job_id}/wait", response_model=GuardrailJobStatusResponse)
async def wait_guard_job(
    job_id: uuid.UUID,
    payload: GuardrailJobWaitRequest,
    x_umai_api_key: str | None = Header(default=None, alias="X-Umai-Api-Key"),
    authorization: str | None = Header(default=None, alias="Authorization"),
    session: AsyncSession = Depends(get_session),
) -> GuardrailJobStatusResponse:
    waited = 0
    while waited < payload.timeout_ms:
        job = await _load_scoped_job(session, job_id, x_umai_api_key, authorization)
        if job.status in TERMINAL_JOB_STATUSES:
            return _job_to_response(job)
        await asyncio.sleep(payload.poll_interval_ms / 1000.0)
        waited += payload.poll_interval_ms
    job = await _load_scoped_job(session, job_id, x_umai_api_key, authorization)
    return _job_to_response(job)


@router.post("/guardrails/jobs/{job_id}/cancel", response_model=GuardrailJobStatusResponse)
async def cancel_guard_job(
    job_id: uuid.UUID,
    x_umai_api_key: str | None = Header(default=None, alias="X-Umai-Api-Key"),
    authorization: str | None = Header(default=None, alias="Authorization"),
    session: AsyncSession = Depends(get_session),
) -> GuardrailJobStatusResponse:
    job = await _load_scoped_job(session, job_id, x_umai_api_key, authorization)
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


@router.post("/agent-identities/register", response_model=AgentIdentityRegisterResponse)
async def register_agent_identity(
    payload: AgentIdentityRegisterRequest,
    x_umai_api_key: str | None = Header(default=None, alias="X-Umai-Api-Key"),
    authorization: str | None = Header(default=None, alias="Authorization"),
    session: AsyncSession = Depends(get_session),
) -> AgentIdentityRegisterResponse:
    api_key = await _authenticate_request_api_key(session, x_umai_api_key, authorization)
    tenant_id, environment_id, project_id = await _resolve_project_from_api_key(session, api_key)
    now = _utcnow()
    token_hash = hash_secret(payload.bootstrap_token)
    fingerprint = public_key_fingerprint(payload.public_key_b64)
    agent_did = build_agent_did(
        tenant_id,
        environment_id,
        project_id,
        payload.agent_id,
        fingerprint,
    )

    async with session.begin():
        async with tenant_scope(session, str(tenant_id)):
            token_result = await session.execute(
                select(AgentIdentityBootstrapToken)
                .where(
                    AgentIdentityBootstrapToken.tenant_id == tenant_id,
                    AgentIdentityBootstrapToken.environment_id == environment_id,
                    AgentIdentityBootstrapToken.project_id == project_id,
                    AgentIdentityBootstrapToken.agent_id == payload.agent_id,
                    AgentIdentityBootstrapToken.token_hash == token_hash,
                    AgentIdentityBootstrapToken.used_at.is_(None),
                )
                .limit(1)
            )
            token = token_result.scalar_one_or_none()
            if token is None or _as_utc(token.expires_at) < now:
                raise ServiceError("AGENT_BOOTSTRAP_TOKEN_INVALID", "Agent bootstrap token is invalid or expired", 401)

            registry = await session.get(
                AgentRegistryEntry,
                (tenant_id, environment_id, project_id, payload.agent_id),
            )
            if registry is None:
                registry = AgentRegistryEntry(
                    tenant_id=tenant_id,
                    environment_id=environment_id,
                    project_id=project_id,
                    agent_id=payload.agent_id,
                    display_name=payload.display_name or payload.agent_id,
                    runtime=payload.runtime or "generic",
                    risk_tier="MEDIUM",
                    status="ACTIVE",
                    created_at=now,
                )
                session.add(registry)

            old_credentials = await session.execute(
                select(AgentIdentityCredential).where(
                    AgentIdentityCredential.tenant_id == tenant_id,
                    AgentIdentityCredential.environment_id == environment_id,
                    AgentIdentityCredential.project_id == project_id,
                    AgentIdentityCredential.agent_id == payload.agent_id,
                    AgentIdentityCredential.status == "ACTIVE",
                )
            )
            for credential in old_credentials.scalars().all():
                credential.status = "ROTATED"
                credential.revoked_at = now

            credential = AgentIdentityCredential(
                tenant_id=tenant_id,
                environment_id=environment_id,
                project_id=project_id,
                agent_id=payload.agent_id,
                agent_did=agent_did,
                public_key_b64=payload.public_key_b64,
                public_key_fingerprint=fingerprint,
                status="ACTIVE",
                bootstrap_token_id=token.id,
                created_at=now,
            )
            session.add(credential)
            token.used_at = now

            registry.display_name = payload.display_name or registry.display_name
            registry.runtime = payload.runtime or registry.runtime
            registry.agent_did = agent_did
            registry.public_key_fingerprint = fingerprint
            registry.capabilities_json = _json_or_none(payload.capabilities)
            registry.trust_score = max(float(registry.trust_score or 0.25), 0.25)
            registry.trust_tier = trust_tier_for_score(float(registry.trust_score or 0.25))
            registry.identity_status = "ACTIVE"
            registry.kill_switch_enabled = bool(registry.kill_switch_enabled)
            registry.metadata_json = _json_or_none(payload.metadata) or registry.metadata_json
            registry.last_seen_at = now
            registry.updated_at = now

    return AgentIdentityRegisterResponse(
        tenant_id=tenant_id,
        environment_id=environment_id,
        project_id=project_id,
        agent_id=payload.agent_id,
        agent_did=agent_did,
        public_key_fingerprint=fingerprint,
        trust_score=float(registry.trust_score or 0.0),
        trust_tier=registry.trust_tier,
        identity_status=registry.identity_status,
    )


@router.post("/agent-runs", response_model=AgentRunSessionResponse)
async def start_agent_run(
    payload: AgentRunStartRequest,
    x_umai_api_key: str | None = Header(default=None, alias="X-Umai-Api-Key"),
    authorization: str | None = Header(default=None, alias="Authorization"),
    session: AsyncSession = Depends(get_session),
) -> AgentRunSessionResponse:
    api_key = await _authenticate_request_api_key(session, x_umai_api_key, authorization)
    tenant_id, environment_id, project_id = await _resolve_project_from_api_key(session, api_key)
    context = payload.agent_context
    run_id = payload.run_id or context.run_id
    if not run_id:
        raise ServiceError("AGENT_RUN_ID_REQUIRED", "run_id or agent_context.run_id is required", 422)
    if context.run_id != run_id:
        raise ServiceError("AGENT_RUN_ID_MISMATCH", "agent_context.run_id must match run_id", 422)

    body_hash = object_hash(payload.model_dump(mode="json", exclude={"agent_context"}))
    async with session.begin():
        async with tenant_scope(session, str(tenant_id)):
            verified = await verify_agent_context(
                session,
                tenant_id=tenant_id,
                environment_id=environment_id,
                project_id=project_id,
                context=context,
                event="agent_run_start",
                body_hash=body_hash,
            )
            row = await _ensure_agent_run(
                session,
                tenant_id=tenant_id,
                environment_id=environment_id,
                project_id=project_id,
                run_id=run_id,
                agent_id=context.agent_id,
                agent_did=context.agent_did,
                guardrail_id=payload.guardrail_id,
                trust_score=verified.trust_score,
                trust_tier=verified.trust_tier,
            )
            row.summary_json = _json_or_none(payload.metadata) or row.summary_json
    return _agent_run_to_response(row)


@router.post("/agent-runs/{run_id}/steps", response_model=AgentRunStepResponse)
async def append_agent_run_step(
    run_id: str,
    payload: AgentRunStepCreateRequest,
    x_umai_api_key: str | None = Header(default=None, alias="X-Umai-Api-Key"),
    authorization: str | None = Header(default=None, alias="Authorization"),
    session: AsyncSession = Depends(get_session),
) -> AgentRunStepResponse:
    api_key = await _authenticate_request_api_key(session, x_umai_api_key, authorization)
    tenant_id, environment_id, project_id = await _resolve_project_from_api_key(session, api_key)
    context = payload.agent_context
    step_id = payload.step_id or context.step_id
    if context.run_id != run_id:
        raise ServiceError("AGENT_RUN_ID_MISMATCH", "agent_context.run_id must match path run_id", 422)
    if not step_id:
        raise ServiceError("AGENT_STEP_ID_REQUIRED", "step_id or agent_context.step_id is required", 422)
    if context.step_id != step_id:
        raise ServiceError("AGENT_STEP_ID_MISMATCH", "agent_context.step_id must match step_id", 422)

    body_hash = object_hash(payload.model_dump(mode="json", exclude={"agent_context"}))
    async with session.begin():
        async with tenant_scope(session, str(tenant_id)):
            verified = await verify_agent_context(
                session,
                tenant_id=tenant_id,
                environment_id=environment_id,
                project_id=project_id,
                context=context,
                event="agent_run_step",
                body_hash=body_hash,
            )
            await _ensure_agent_run(
                session,
                tenant_id=tenant_id,
                environment_id=environment_id,
                project_id=project_id,
                run_id=run_id,
                agent_id=context.agent_id,
                agent_did=context.agent_did,
                guardrail_id=None,
                trust_score=verified.trust_score,
                trust_tier=verified.trust_tier,
            )
            row = await _append_agent_step(
                session,
                tenant_id=tenant_id,
                environment_id=environment_id,
                project_id=project_id,
                run_id=run_id,
                step_id=step_id,
                parent_step_id=payload.parent_step_id or context.parent_step_id,
                event_type=payload.event_type,
                phase=payload.phase,
                status=payload.status,
                agent_id=context.agent_id,
                agent_did=context.agent_did,
                action=payload.action,
                resource_type=payload.resource_type,
                resource_name=payload.resource_name,
                decision_action=payload.decision_action,
                decision_severity=payload.decision_severity,
                decision_reason=payload.decision_reason,
                policy_id=payload.policy_id,
                matched_rule_id=payload.matched_rule_id,
                latency_ms=payload.latency_ms,
                payload_summary=payload.payload_summary,
                metadata=payload.metadata,
                input_hash=payload.input_hash,
                output_hash=payload.output_hash,
            )
    return _agent_step_to_response(row)


@router.patch("/agent-runs/{run_id}", response_model=AgentRunSessionResponse)
async def update_agent_run(
    run_id: str,
    payload: AgentRunPatchRequest,
    x_umai_api_key: str | None = Header(default=None, alias="X-Umai-Api-Key"),
    authorization: str | None = Header(default=None, alias="Authorization"),
    session: AsyncSession = Depends(get_session),
) -> AgentRunSessionResponse:
    api_key = await _authenticate_request_api_key(session, x_umai_api_key, authorization)
    tenant_id, environment_id, project_id = await _resolve_project_from_api_key(session, api_key)
    context = payload.agent_context
    if context.run_id != run_id:
        raise ServiceError("AGENT_RUN_ID_MISMATCH", "agent_context.run_id must match path run_id", 422)
    body_hash = object_hash(payload.model_dump(mode="json", exclude={"agent_context"}))
    async with session.begin():
        async with tenant_scope(session, str(tenant_id)):
            verified = await verify_agent_context(
                session,
                tenant_id=tenant_id,
                environment_id=environment_id,
                project_id=project_id,
                context=context,
                event="agent_run_update",
                body_hash=body_hash,
            )
            row = await _ensure_agent_run(
                session,
                tenant_id=tenant_id,
                environment_id=environment_id,
                project_id=project_id,
                run_id=run_id,
                agent_id=context.agent_id,
                agent_did=context.agent_did,
                guardrail_id=None,
                trust_score=verified.trust_score,
                trust_tier=verified.trust_tier,
            )
            row.status = payload.status
            row.decision_action = payload.decision_action
            row.decision_severity = payload.decision_severity
            row.summary_json = _json_or_none(payload.summary)
            row.updated_at = _utcnow()
            if payload.status in TERMINAL_JOB_STATUSES:
                row.completed_at = row.updated_at
    return _agent_run_to_response(row)


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
        issuer="UMAI",
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
