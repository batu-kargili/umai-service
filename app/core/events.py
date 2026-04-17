from __future__ import annotations

import asyncio
import json
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit_ledger import (
    compute_event_hash,
    redact_payload,
    redact_text,
    sign_event_hash,
)
from app.core.siem import emit_guardrail_event
from app.core.settings import settings
from app.models.db import ApprovalRequest, AuditEvent
from app.models.engine import EngineResponse
from app.models.public import PublicGuardRequest


def _extract_message(payload: PublicGuardRequest) -> str | None:
    messages = payload.input.messages
    if not messages:
        return None
    target_role = (
        "assistant" if payload.input.phase_focus == "LAST_ASSISTANT_MESSAGE" else "user"
    )
    for message in reversed(messages):
        if message.role == target_role:
            return message.content
    return messages[-1].content


def _extract_category(engine_response: EngineResponse) -> str | None:
    policy = engine_response.triggering_policy
    if not policy:
        return None
    details = policy.details or {}
    if "policy_category" in details and details.get("policy_category"):
        return str(details.get("policy_category"))
    return policy.type


async def record_audit_event(
    session: AsyncSession,
    tenant_id: uuid.UUID,
    environment_id: str,
    project_id: str,
    guardrail_id: str,
    guardrail_version: int,
    engine_response: EngineResponse,
    request_payload: PublicGuardRequest | None = None,
) -> None:
    request_payload_json = None
    message = None
    conversation_id = None
    redacted = False
    if request_payload is not None and settings.store_request_payloads:
        request_payload_obj = request_payload.model_dump()
        if settings.audit_redaction_enabled:
            request_payload_obj, payload_changed = redact_payload(
                request_payload_obj,
                custom_patterns_json=settings.audit_redaction_patterns_json,
            )
            redacted = redacted or payload_changed
        request_payload_json = json.dumps(
            request_payload_obj, separators=(",", ":"), ensure_ascii=True
        )
        message = _extract_message(request_payload)
        if settings.audit_redaction_enabled:
            message, message_changed = redact_text(
                message,
                custom_patterns_json=settings.audit_redaction_patterns_json,
            )
            redacted = redacted or message_changed
        conversation_id = request_payload.conversation_id
    response_payload_obj = engine_response.model_dump()
    if settings.audit_redaction_enabled:
        response_payload_obj, response_changed = redact_payload(
            response_payload_obj,
            custom_patterns_json=settings.audit_redaction_patterns_json,
        )
        redacted = redacted or response_changed
    response_payload_json = json.dumps(
        response_payload_obj, separators=(",", ":"), ensure_ascii=True
    )
    triggering_policy_json = None
    triggering_policy_payload = None
    if engine_response.triggering_policy:
        triggering_policy_obj = engine_response.triggering_policy.model_dump()
        if settings.audit_redaction_enabled:
            triggering_policy_obj, policy_changed = redact_payload(
                triggering_policy_obj,
                custom_patterns_json=settings.audit_redaction_patterns_json,
            )
            redacted = redacted or policy_changed
        triggering_policy_payload = triggering_policy_obj
        triggering_policy_json = json.dumps(
            triggering_policy_obj,
            separators=(",", ":"),
            ensure_ascii=True,
        )
    previous_result = await session.execute(
        select(AuditEvent.event_hash)
        .where(AuditEvent.tenant_id == tenant_id)
        .order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc())
        .limit(1)
    )
    prev_event_hash = previous_result.scalar_one_or_none()
    ledger_payload = {
        "tenant_id": str(tenant_id),
        "environment_id": environment_id,
        "project_id": project_id,
        "guardrail_id": guardrail_id,
        "guardrail_version": guardrail_version,
        "request_id": engine_response.request_id,
        "phase": engine_response.phase,
        "action": engine_response.decision.action,
        "allowed": engine_response.decision.allowed,
        "category": _extract_category(engine_response),
        "decision_severity": engine_response.decision.severity,
        "decision_reason": engine_response.decision.reason,
        "latency_ms": engine_response.latency_ms.total,
        "conversation_id": conversation_id,
        "message": message,
        "request_payload_json": request_payload_json,
        "response_payload_json": response_payload_json,
        "triggering_policy_json": triggering_policy_json,
    }
    event_hash = compute_event_hash(prev_event_hash, ledger_payload)
    event_signature, hash_key_id = sign_event_hash(
        event_hash,
        signing_key=settings.ledger_signing_key,
        key_id=settings.ledger_signing_key_id,
    )
    event = AuditEvent(
        tenant_id=tenant_id,
        environment_id=environment_id,
        project_id=project_id,
        guardrail_id=guardrail_id,
        guardrail_version=guardrail_version,
        request_id=engine_response.request_id,
        phase=engine_response.phase,
        action=engine_response.decision.action,
        allowed=engine_response.decision.allowed,
        category=_extract_category(engine_response),
        decision_severity=engine_response.decision.severity,
        decision_reason=engine_response.decision.reason,
        latency_ms=engine_response.latency_ms.total,
        conversation_id=conversation_id,
        message=message,
        request_payload_json=request_payload_json,
        response_payload_json=response_payload_json,
        triggering_policy_json=triggering_policy_json,
        prev_event_hash=prev_event_hash,
        event_hash=event_hash,
        event_signature=event_signature,
        hash_key_id=hash_key_id,
        redacted=redacted,
    )
    session.add(event)

    if engine_response.decision.action == "STEP_UP_APPROVAL":
        existing = await session.execute(
            select(ApprovalRequest).where(
                ApprovalRequest.tenant_id == tenant_id,
                ApprovalRequest.environment_id == environment_id,
                ApprovalRequest.project_id == project_id,
                ApprovalRequest.guardrail_id == guardrail_id,
                ApprovalRequest.guardrail_version == guardrail_version,
                ApprovalRequest.request_id == engine_response.request_id,
                ApprovalRequest.status == "PENDING",
            )
        )
        if existing.scalar_one_or_none() is None:
            session.add(
                ApprovalRequest(
                    tenant_id=tenant_id,
                    environment_id=environment_id,
                    project_id=project_id,
                    guardrail_id=guardrail_id,
                    guardrail_version=guardrail_version,
                    request_id=engine_response.request_id,
                    phase=engine_response.phase,
                    status="PENDING",
                    reason=engine_response.decision.reason,
                )
            )

    siem_event = {
        "schema": "duvarai.guardrail.decision.v1",
        "tenant_id": str(tenant_id),
        "environment_id": environment_id,
        "project_id": project_id,
        "guardrail_id": guardrail_id,
        "guardrail_version": guardrail_version,
        "request_id": engine_response.request_id,
        "phase": engine_response.phase,
        "action": engine_response.decision.action,
        "allowed": engine_response.decision.allowed,
        "severity": engine_response.decision.severity,
        "reason": engine_response.decision.reason,
        "latency_ms_total": engine_response.latency_ms.total,
        "triggering_policy": triggering_policy_payload,
        "errors": [error.model_dump() for error in engine_response.errors],
        "prev_event_hash": prev_event_hash,
        "event_hash": event_hash,
        "event_signature": event_signature,
        "hash_key_id": hash_key_id,
        "redacted": redacted,
    }
    asyncio.create_task(emit_guardrail_event(siem_event))
