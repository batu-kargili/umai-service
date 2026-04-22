from __future__ import annotations

import datetime as dt
import json
import logging
import secrets
import uuid
from collections import Counter

from fastapi import APIRouter, BackgroundTasks, Depends, File, Form, Header, Query, UploadFile
from fastapi.responses import PlainTextResponse
from pydantic import ValidationError
from sqlalchemy import and_, delete, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.admin_auth import (
    AdminPrincipal,
    ensure_tenant_access,
    get_admin_principal,
    require_admin_role,
)
from app.core.eval_gate import resolve_publish_gate
from app.core.agentic_builder import generate_agentic_guardrail
from app.core.auth import hash_api_key
from app.core.db import get_session, get_sessionmaker, tenant_scope
from app.core.eval_sets import get_eval_set, list_eval_sets
from app.core.engine_client import evaluate_engine
from app.core.errors import ServiceError
from app.core.events import record_audit_event
from app.core.license import (
    apply_license_payload,
    license_allows_llm_calls,
    require_active_license,
    verify_license_token,
)
from app.core.library import (
    get_guardrail_template,
    get_policy_template,
    list_guardrail_templates,
    list_policy_templates,
)
from app.core.redis import get_redis
from app.core.resolver import resolve_environment, resolve_guardrail, resolve_project
from app.core.settings import settings
from app.core.snapshots import build_snapshot_key, publish_snapshot
from app.core.snapshot_signing import pack_snapshot_record, sign_snapshot
from app.models import admin as admin_models
from app.models.engine import EngineFlags, EngineRequest
from app.models.db import (
    AgentRegistryEntry,
    ApprovalRequest,
    ApiKey,
    AuditEvent,
    EvidencePack,
    EvaluationCase,
    EvaluationRun,
    Environment,
    GuardrailJob,
    GuardrailPublishGate,
    Guardrail,
    GuardrailVersion,
    ModelRegistryEntry,
    Policy,
    License,
    Project,
    Tenant,
)
from app.models.public import ChatMessage, InputPayload

router = APIRouter(
    prefix="/api/v1/admin",
    tags=["admin"],
    dependencies=[Depends(get_admin_principal)],
)
logger = logging.getLogger("duvarai.service.admin")

DEFAULT_PREFLIGHT = {"target": "LAST_MESSAGE", "rules": [], "max_length": 8000}
PHASE_ORDER = (
    "PRE_LLM",
    "POST_LLM",
    "TOOL_INPUT",
    "TOOL_OUTPUT",
    "MCP_REQUEST",
    "MCP_RESPONSE",
    "MEMORY_WRITE",
)
EVAL_MAX_CASES = 500
EVAL_ALLOWED_ACTIONS = {
    "ALLOW",
    "BLOCK",
    "FLAG",
    "ALLOW_WITH_MODIFICATIONS",
    "ALLOW_WITH_WARNINGS",
    "STEP_UP_APPROVAL",
}
EVAL_ALLOWED_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


def _api_key_preview(raw_key: str) -> str:
    if len(raw_key) <= 8:
        return raw_key
    return f"{raw_key[:6]}...{raw_key[-4:]}"


def _api_key_to_response(
    api_key: ApiKey,
    raw_key: str | None = None,
) -> admin_models.ApiKeyResponse:
    return admin_models.ApiKeyResponse(
        id=api_key.id,
        tenant_id=api_key.tenant_id,
        environment_id=api_key.environment_id,
        project_id=api_key.project_id,
        api_key=raw_key,
        name=api_key.name,
        key_preview=api_key.key_preview,
        created_at=api_key.created_at,
        revoked=bool(api_key.revoked),
    )


def _normalize_phases(phases: list[str]) -> list[str]:
    return [phase for phase in PHASE_ORDER if phase in phases]


def _policy_duplicate_message(scope: str) -> str:
    if scope == "ORGANIZATION":
        return "Policy ID already exists for this tenant."
    if scope == "ENVIRONMENT":
        return "Policy ID already exists in this environment."
    return "Policy ID already exists in this project."


def _policy_duplicate_filters(
    payload: admin_models.PolicyCreateRequest,
    scope: str,
) -> list[object]:
    filters: list[object] = [
        Policy.tenant_id == payload.tenant_id,
        Policy.policy_id == payload.policy_id,
    ]
    if scope in {"ENVIRONMENT", "PROJECT"}:
        filters.append(Policy.environment_id == payload.environment_id)
    if scope == "PROJECT":
        filters.append(Policy.project_id == payload.project_id)
    return filters


def _require_tenant_access(
    principal: AdminPrincipal,
    tenant_id: uuid.UUID,
    required_role: str = "tenant-admin",
) -> None:
    ensure_tenant_access(principal, tenant_id)
    require_admin_role(principal, required_role)


async def _fetch_required_policies(
    session: AsyncSession,
    tenant_id: uuid.UUID,
    environment_id: str,
) -> list[Policy]:
    stmt = select(Policy).where(
        Policy.tenant_id == tenant_id,
        or_(
            Policy.scope == "ORGANIZATION",
            and_(Policy.scope == "ENVIRONMENT", Policy.environment_id == environment_id),
        ),
    )
    result = await session.execute(stmt)
    return result.scalars().all()


def _policy_to_response(policy: Policy) -> admin_models.PolicyResponse:
    return admin_models.PolicyResponse(
        tenant_id=policy.tenant_id,
        environment_id=policy.environment_id,
        project_id=policy.project_id,
        policy_id=policy.policy_id,
        name=policy.name,
        type=policy.type,
        enabled=policy.enabled,
        phases=json.loads(policy.phases_json),
        config=json.loads(policy.config_json),
        scope=policy.scope,
        created_at=policy.created_at,
    )


def _policy_to_snapshot(policy: Policy) -> dict:
    return {
        "id": policy.policy_id,
        "type": policy.type,
        "name": policy.name,
        "enabled": policy.enabled,
        "phases": json.loads(policy.phases_json),
        "config": json.loads(policy.config_json),
    }


def _normalize_llm_config(raw: object) -> dict:
    try:
        return admin_models.GuardrailLlmConfig.model_validate(raw).model_dump(
            mode="json",
            exclude_none=True,
        )
    except ValidationError as exc:
        raise ServiceError("INVALID_LLM_CONFIG", str(exc), 422) from exc


def _normalize_agt_config(raw: object) -> dict | None:
    if raw is None:
        return None
    try:
        return admin_models.AgtConfig.model_validate(raw).model_dump(
            mode="json",
            exclude_none=True,
        )
    except ValidationError as exc:
        raise ServiceError("INVALID_AGT_CONFIG", str(exc), 422) from exc


def _merge_snapshot_phases(
    policy_snapshots: list[dict],
    phases: list[str] | None,
    agt_config: dict | None,
) -> list[str]:
    phase_set = {phase for phase in phases or []}
    for policy in policy_snapshots:
        phase_set.update(policy.get("phases", []) or [])
    if agt_config and agt_config.get("enabled"):
        phase_set.update(agt_config.get("enforced_phases", []) or [])
    return _normalize_phases(list(phase_set))


def _coerce_bool(value: object) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "1", "yes", "y"}:
            return True
        if lowered in {"false", "0", "no", "n"}:
            return False
    return None


def _normalize_expected_action(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip().upper()
    return text if text in EVAL_ALLOWED_ACTIONS else None


def _normalize_expected_severity(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip().upper()
    return text if text in EVAL_ALLOWED_SEVERITIES else None


def _parse_eval_jsonl(raw_text: str) -> list[dict]:
    cases: list[dict] = []
    for line in raw_text.splitlines():
        trimmed = line.strip()
        if not trimmed:
            continue
        try:
            payload = json.loads(trimmed)
        except json.JSONDecodeError as exc:
            raise ServiceError("EVAL_BAD_JSON", "Invalid JSONL format", 400) from exc
        prompt = payload.get("prompt") or payload.get("text") or payload.get("input")
        if not prompt:
            continue
        expected_action = _normalize_expected_action(
            payload.get("expected_action") or payload.get("expected")
        )
        expected_allowed = _coerce_bool(payload.get("expected_allowed"))
        expected_severity = _normalize_expected_severity(payload.get("expected_severity"))
        label = payload.get("label") or payload.get("id")
        artifacts = payload.get("artifacts")
        if artifacts is not None:
            try:
                artifacts = [
                    item.model_dump(mode="json")
                    for item in InputPayload.model_validate(
                        {
                            "messages": [{"role": "user", "content": str(prompt)}],
                            "phase_focus": payload.get("phase_focus") or "LAST_USER_MESSAGE",
                            "content_type": payload.get("content_type") or "text",
                            "language": payload.get("language"),
                            "artifacts": artifacts,
                        }
                    ).artifacts
                ]
            except ValidationError as exc:
                raise ServiceError("EVAL_BAD_ARTIFACTS", str(exc), 400) from exc
        cases.append(
            {
                "prompt": str(prompt),
                "label": str(label) if label else None,
                "expected_action": expected_action,
                "expected_allowed": expected_allowed,
                "expected_severity": expected_severity,
                "phase_focus": payload.get("phase_focus"),
                "content_type": payload.get("content_type"),
                "language": payload.get("language"),
                "artifacts": artifacts,
            }
        )
    return cases


def _build_default_eval_artifact(phase: str, prompt: str, case: dict) -> dict | None:
    expected_action = str(case.get("expected_action") or "").upper()
    inferred_action = str(case.get("action") or "").strip().lower()
    if not inferred_action:
        inferred_action = "write" if expected_action == "STEP_UP_APPROVAL" else "read"

    metadata: dict[str, object] = {
        "agent_id": case.get("agent_id") or "eval-agent",
        "action": inferred_action,
        "capability": case.get("capability") or phase.lower(),
        "params": case.get("params") or {"summary": prompt},
        "classification": case.get("classification"),
        "resource_id": case.get("resource_id"),
        "side_effect": case.get("side_effect"),
    }
    if phase == "TOOL_INPUT":
        metadata["tool_name"] = case.get("tool_name") or "project.lookup"
    elif phase == "MCP_REQUEST":
        metadata["server_name"] = case.get("server_name") or "project-mcp"
        metadata["method"] = case.get("method") or ("delete" if inferred_action == "delete" else "read")
    elif phase == "MEMORY_WRITE":
        metadata["memory_scope"] = case.get("memory_scope") or "conversation"
    else:
        return None

    return {
        "artifact_type": phase,
        "name": case.get("artifact_name") or phase.lower(),
        "payload_summary": case.get("payload_summary") or prompt,
        "metadata": metadata,
    }


def _build_evaluation_input_payload(phase: str, prompt: str, case: dict) -> InputPayload:
    default_phase_focus = (
        "LAST_USER_MESSAGE"
        if phase in {"PRE_LLM", "TOOL_INPUT", "MCP_REQUEST", "MEMORY_WRITE"}
        else "LAST_ASSISTANT_MESSAGE"
    )
    artifacts = case.get("artifacts")
    if not artifacts and phase in {"TOOL_INPUT", "MCP_REQUEST", "MEMORY_WRITE"}:
        default_artifact = _build_default_eval_artifact(phase, prompt, case)
        artifacts = [default_artifact] if default_artifact else []

    role = (
        "user"
        if phase in {"PRE_LLM", "TOOL_INPUT", "MCP_REQUEST", "MEMORY_WRITE"}
        else "assistant"
    )
    return InputPayload(
        messages=[ChatMessage(role=role, content=prompt)],
        phase_focus=case.get("phase_focus") or default_phase_focus,
        content_type=case.get("content_type") or "text",
        language=case.get("language"),
        artifacts=artifacts or [],
    )


def _evaluation_run_to_response(run: EvaluationRun) -> admin_models.EvaluationRunResponse:
    metrics = json.loads(run.metrics_json) if run.metrics_json else None
    return admin_models.EvaluationRunResponse(
        id=run.id,
        tenant_id=run.tenant_id,
        environment_id=run.environment_id,
        project_id=run.project_id,
        guardrail_id=run.guardrail_id,
        guardrail_version=run.guardrail_version,
        name=run.name,
        dataset_id=run.dataset_id,
        phase=run.phase,
        status=run.status,
        total_cases=run.total_cases,
        processed_cases=run.processed_cases,
        metrics=metrics,
        error_message=run.error_message,
        created_at=run.created_at,
        completed_at=run.completed_at,
    )


def _evaluation_case_to_response(
    case: EvaluationCase,
) -> admin_models.EvaluationCaseResponse:
    expected_action_match = None
    if case.expected_action and case.decision_action:
        expected_action_match = case.expected_action == case.decision_action
    expected_allowed_match = None
    if case.expected_allowed is not None and case.decision_allowed is not None:
        expected_allowed_match = case.expected_allowed == case.decision_allowed
    expected_severity_match = None
    if case.expected_severity and case.decision_severity:
        expected_severity_match = case.expected_severity == case.decision_severity
    return admin_models.EvaluationCaseResponse(
        id=case.id,
        run_id=case.run_id,
        index=case.index,
        label=case.label,
        prompt=case.prompt,
        expected_action=case.expected_action,
        expected_allowed=case.expected_allowed,
        expected_severity=case.expected_severity,
        decision_action=case.decision_action,
        decision_allowed=case.decision_allowed,
        decision_severity=case.decision_severity,
        decision_reason=case.decision_reason,
        expected_action_match=expected_action_match,
        expected_allowed_match=expected_allowed_match,
        expected_severity_match=expected_severity_match,
        triggering_policy=json.loads(case.triggering_policy_json)
        if case.triggering_policy_json
        else None,
        latency_ms=case.latency_ms,
        errors=json.loads(case.errors_json) if case.errors_json else None,
    )


def _license_to_response(license_row: License) -> admin_models.LicenseResponse:
    features = (
        json.loads(license_row.features_json)
        if license_row.features_json
        else None
    )
    return admin_models.LicenseResponse(
        tenant_id=license_row.tenant_id,
        status=license_row.status,
        expires_at=license_row.expires_at,
        features_json=features,
    )


def _load_json(value: str | None) -> dict | None:
    if not value:
        return None
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return None


def _extract_message_from_payload(payload: dict | None) -> str | None:
    if not payload:
        return None
    input_payload = payload.get("input") or {}
    messages = input_payload.get("messages") or []
    if not messages:
        return None
    phase_focus = input_payload.get("phase_focus")
    target_role = "assistant" if phase_focus == "LAST_ASSISTANT_MESSAGE" else "user"
    for message in reversed(messages):
        if message.get("role") == target_role:
            return message.get("content")
    return messages[-1].get("content")


def _audit_event_to_alert(event: AuditEvent) -> admin_models.AlertResponse:
    request_payload = _load_json(event.request_payload_json)
    response_payload = _load_json(event.response_payload_json)
    triggering_policy = _load_json(event.triggering_policy_json)
    if triggering_policy is None and response_payload:
        triggering_policy = response_payload.get("triggering_policy") or None

    details = {}
    if triggering_policy and isinstance(triggering_policy, dict):
        details = triggering_policy.get("details") or {}

    category = event.category or details.get("policy_category")
    if not category and triggering_policy and isinstance(triggering_policy, dict):
        category = triggering_policy.get("type")
    if not category:
        category = "General"

    policy = "Unknown"
    if triggering_policy and isinstance(triggering_policy, dict):
        policy = triggering_policy.get("name") or triggering_policy.get("policy_id") or policy

    matched_rule = (
        details.get("matched_rule_id")
        or details.get("rule_id")
        or details.get("policy_category")
        or "N/A"
    )

    message = event.message or _extract_message_from_payload(request_payload) or "N/A"
    workflow = (request_payload or {}).get("conversation_id") or event.project_id or "N/A"
    flow = event.phase or "N/A"

    decision_action = event.action
    decision = {}
    if response_payload:
        decision = response_payload.get("decision") or {}
    severity = (event.decision_severity or decision.get("severity") or "LOW").upper()
    if severity not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        severity = "LOW"
    if decision_action not in {"BLOCK", "FLAG"}:
        decision_action = "FLAG"

    latency_ms = event.latency_ms
    if latency_ms is None and response_payload:
        latency = response_payload.get("latency_ms") or {}
        latency_ms = latency.get("total")
    if latency_ms is None:
        latency_ms = 0.0

    request_id = event.request_id or (response_payload or {}).get("request_id") or "N/A"

    return admin_models.AlertResponse(
        id=event.id,
        workflow=workflow,
        flow=flow,
        category=category,
        policy=policy,
        guardrail_id=event.guardrail_id,
        decision=decision_action,
        severity=severity,
        phase=event.phase,
        latency_ms=float(latency_ms),
        created_at=event.created_at,
        message=message,
        request_id=request_id,
        matched_rule=matched_rule,
    )


def _approval_to_response(approval: ApprovalRequest) -> admin_models.ApprovalResponse:
    return admin_models.ApprovalResponse(
        id=approval.id,
        tenant_id=approval.tenant_id,
        environment_id=approval.environment_id,
        project_id=approval.project_id,
        guardrail_id=approval.guardrail_id,
        guardrail_version=approval.guardrail_version,
        request_id=approval.request_id,
        phase=approval.phase,
        status=approval.status,
        reason=approval.reason,
        created_at=approval.created_at,
        resolved_at=approval.resolved_at,
        resolved_by=approval.resolved_by,
    )


def _publish_gate_to_response(gate: GuardrailPublishGate) -> admin_models.PublishGateResponse:
    return admin_models.PublishGateResponse(
        tenant_id=gate.tenant_id,
        environment_id=gate.environment_id,
        project_id=gate.project_id,
        guardrail_id=gate.guardrail_id,
        min_expected_action_accuracy=gate.min_expected_action_accuracy,
        min_expected_allowed_accuracy=gate.min_expected_allowed_accuracy,
        min_eval_cases=gate.min_eval_cases,
        max_p95_latency_ms=gate.max_p95_latency_ms,
        updated_at=gate.updated_at,
    )


def _audit_event_to_response(event: AuditEvent) -> admin_models.AuditEventResponse:
    triggering_policy = _load_json(event.triggering_policy_json)
    return admin_models.AuditEventResponse(
        id=event.id,
        tenant_id=event.tenant_id,
        environment_id=event.environment_id,
        project_id=event.project_id,
        guardrail_id=event.guardrail_id,
        guardrail_version=event.guardrail_version,
        request_id=event.request_id,
        phase=event.phase,
        action=event.action,
        allowed=event.allowed,
        category=event.category,
        decision_severity=event.decision_severity,
        decision_reason=event.decision_reason,
        latency_ms=event.latency_ms,
        conversation_id=event.conversation_id,
        message=event.message,
        triggering_policy=triggering_policy,
        redacted=bool(event.redacted),
        prev_event_hash=event.prev_event_hash,
        event_hash=event.event_hash,
        event_signature=event.event_signature,
        hash_key_id=event.hash_key_id,
        created_at=event.created_at,
    )


def _build_evidence_summary(
    events: list[AuditEvent],
    approvals: list[ApprovalRequest],
    versions: list[GuardrailVersion],
) -> tuple[dict, dict]:
    action_counter = Counter(event.action for event in events)
    phase_counter = Counter(event.phase for event in events)
    severity_counter = Counter((event.decision_severity or "UNKNOWN") for event in events)
    policy_counter: Counter[str] = Counter()
    for event in events:
        policy = _load_json(event.triggering_policy_json)
        if isinstance(policy, dict):
            policy_id = policy.get("policy_id") or policy.get("name")
            if policy_id:
                policy_counter[str(policy_id)] += 1
    approval_counter = Counter(approval.status for approval in approvals)

    summary = {
        "total_events": len(events),
        "actions": dict(action_counter),
        "phases": dict(phase_counter),
        "severities": dict(severity_counter),
        "top_policies": policy_counter.most_common(10),
        "approvals": dict(approval_counter),
        "guardrail_versions": len(versions),
        "signed_versions": sum(1 for version in versions if bool(version.signature)),
    }
    artifact = {
        "summary": summary,
        "ledger": {
            "sample_event_hashes": [
                {
                    "event_id": str(event.id),
                    "prev_event_hash": event.prev_event_hash,
                    "event_hash": event.event_hash,
                    "hash_key_id": event.hash_key_id,
                }
                for event in events[:50]
            ],
        },
        "controls": {
            "AI_ACT": {
                "logging": summary["total_events"],
                "oversight_events": summary["actions"].get("STEP_UP_APPROVAL", 0),
            },
            "GDPR": {
                "redacted_events": sum(1 for event in events if bool(event.redacted)),
                "data_minimization_mode": settings.audit_redaction_enabled,
            },
            "CPRA_ADMT": {
                "decisioning_events": summary["actions"].get("BLOCK", 0)
                + summary["actions"].get("STEP_UP_APPROVAL", 0),
                "approvals": summary["approvals"],
            },
            "SEC_CYBER": {
                "high_severity_events": summary["severities"].get("HIGH", 0)
                + summary["severities"].get("CRITICAL", 0),
            },
        },
    }
    return summary, artifact


def _evidence_pack_to_response(
    row: EvidencePack,
    include_artifact: bool = False,
) -> admin_models.EvidencePackResponse:
    artifact = _load_json(row.artifact_json) or {}
    summary = artifact.get("summary") or {}
    return admin_models.EvidencePackResponse(
        id=row.id,
        tenant_id=row.tenant_id,
        environment_id=row.environment_id,
        project_id=row.project_id,
        regime=row.regime,
        status=row.status,
        timeframe_start=row.timeframe_start,
        timeframe_end=row.timeframe_end,
        summary=summary,
        artifact=artifact if include_artifact else None,
        created_by=row.created_by,
        created_at=row.created_at,
    )


def _model_registry_to_response(row: ModelRegistryEntry) -> admin_models.ModelRegistryResponse:
    return admin_models.ModelRegistryResponse(
        tenant_id=row.tenant_id,
        environment_id=row.environment_id,
        project_id=row.project_id,
        model_id=row.model_id,
        display_name=row.display_name,
        provider=row.provider,
        model_type=row.model_type,
        owner=row.owner,
        risk_tier=row.risk_tier,
        status=row.status,
        metadata=_load_json(row.metadata_json),
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _agent_registry_to_response(row: AgentRegistryEntry) -> admin_models.AgentRegistryResponse:
    return admin_models.AgentRegistryResponse(
        tenant_id=row.tenant_id,
        environment_id=row.environment_id,
        project_id=row.project_id,
        agent_id=row.agent_id,
        display_name=row.display_name,
        runtime=row.runtime,
        owner=row.owner,
        risk_tier=row.risk_tier,
        status=row.status,
        metadata=_load_json(row.metadata_json),
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


@router.post("/tenants", response_model=admin_models.TenantResponse)
async def create_tenant(
    payload: admin_models.TenantCreateRequest,
    session: AsyncSession = Depends(get_session),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> admin_models.TenantResponse:
    require_admin_role(principal, "platform-admin")
    tenant_id = payload.tenant_id or uuid.uuid4()
    tenant = Tenant(tenant_id=tenant_id, name=payload.name, status="active")
    async with session.begin():
        session.add(tenant)
    logger.info("admin.tenant.created tenant_id=%s name=%s", tenant.tenant_id, tenant.name)
    return admin_models.TenantResponse(
        tenant_id=tenant.tenant_id,
        name=tenant.name,
        status=tenant.status,
        created_at=tenant.created_at,
    )


@router.get("/tenants", response_model=list[admin_models.TenantResponse])
async def list_tenants(
    session: AsyncSession = Depends(get_session),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> list[admin_models.TenantResponse]:
    require_admin_role(principal, "platform-admin")
    result = await session.execute(select(Tenant))
    tenants = result.scalars().all()
    return [
        admin_models.TenantResponse(
            tenant_id=t.tenant_id,
            name=t.name,
            status=t.status,
            created_at=t.created_at,
        )
        for t in tenants
    ]


@router.post("/tenants/{tenant_id}/license", response_model=admin_models.LicenseResponse)
async def upsert_license(
    tenant_id: uuid.UUID,
    payload: admin_models.LicenseCreateRequest,
    session: AsyncSession = Depends(get_session),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> admin_models.LicenseResponse:
    _require_tenant_access(principal, tenant_id, required_role="license-admin")
    if tenant_id != payload.tenant_id:
        raise ServiceError("FORBIDDEN", "tenant_id mismatch", 403)
    features_json = (
        json.dumps(payload.features_json, separators=(",", ":"), ensure_ascii=True)
        if payload.features_json is not None
        else None
    )
    async with session.begin():
        async with tenant_scope(session, str(tenant_id)):
            license_row = await session.get(License, tenant_id)
            if license_row is None:
                license_row = License(
                    tenant_id=tenant_id,
                    expires_at=payload.expires_at,
                    status=payload.status,
                    features_json=features_json,
                )
                session.add(license_row)
            else:
                license_row.expires_at = payload.expires_at
                license_row.status = payload.status
                license_row.features_json = features_json
    logger.info("admin.license.upserted tenant_id=%s status=%s", tenant_id, payload.status)
    license_row = await session.get(License, tenant_id)
    if license_row is None:
        raise ServiceError("LICENSE_NOT_FOUND", "License not found", 404)
    return _license_to_response(license_row)


@router.get("/tenants/{tenant_id}/license", response_model=admin_models.LicenseResponse)
async def get_license(
    tenant_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> admin_models.LicenseResponse:
    _require_tenant_access(principal, tenant_id, required_role="tenant-auditor")
    async with session.begin():
        async with tenant_scope(session, str(tenant_id)):
            license_row = await session.get(License, tenant_id)
            if license_row is None:
                raise ServiceError("LICENSE_NOT_FOUND", "License not found", 404)
    return _license_to_response(license_row)


@router.post("/licenses/apply", response_model=admin_models.LicenseResponse)
async def apply_license(
    payload: admin_models.LicenseTokenApplyRequest,
    session: AsyncSession = Depends(get_session),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> admin_models.LicenseResponse:
    require_admin_role(principal, "license-admin")
    license_payload, key_id = verify_license_token(payload.token)
    _require_tenant_access(
        principal, license_payload.tenant_id, required_role="license-admin"
    )
    async with session.begin():
        async with tenant_scope(session, str(license_payload.tenant_id)):
            await apply_license_payload(session, license_payload, key_id)
            license_row = await session.get(License, license_payload.tenant_id)
            if license_row is None:
                raise ServiceError("LICENSE_NOT_FOUND", "License not found", 404)
    logger.info(
        "admin.license.applied tenant_id=%s license_id=%s",
        license_payload.tenant_id,
        license_payload.license_id,
    )
    return _license_to_response(license_row)


@router.post("/api-keys", response_model=admin_models.ApiKeyResponse)
async def create_api_key(
    payload: admin_models.ApiKeyCreateRequest,
    session: AsyncSession = Depends(get_session),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> admin_models.ApiKeyResponse:
    _require_tenant_access(principal, payload.tenant_id)
    raw_key = payload.api_key or secrets.token_urlsafe(32)
    key_hash = hash_api_key(raw_key)
    key_preview = _api_key_preview(raw_key)
    api_key = ApiKey(
        tenant_id=payload.tenant_id,
        environment_id=payload.environment_id,
        project_id=payload.project_id,
        name=payload.name,
        key_preview=key_preview,
        key_hash=key_hash,
    )
    async with session.begin():
        async with tenant_scope(session, str(payload.tenant_id)):
            session.add(api_key)
    logger.info(
        "admin.apikey.created tenant_id=%s env=%s project=%s",
        api_key.tenant_id,
        api_key.environment_id,
        api_key.project_id,
    )
    return _api_key_to_response(api_key, raw_key=raw_key)


@router.get("/api-keys", response_model=list[admin_models.ApiKeyResponse])
async def list_api_keys(
    environment_id: str | None = None,
    project_id: str | None = None,
    session: AsyncSession = Depends(get_session),
    x_tenant_id: uuid.UUID = Header(alias="X-Tenant-Id"),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> list[admin_models.ApiKeyResponse]:
    _require_tenant_access(principal, x_tenant_id, required_role="tenant-auditor")
    stmt = select(ApiKey).where(ApiKey.tenant_id == x_tenant_id)
    if environment_id:
        stmt = stmt.where(ApiKey.environment_id == environment_id)
    if project_id:
        stmt = stmt.where(ApiKey.project_id == project_id)
    stmt = stmt.order_by(ApiKey.created_at.desc())
    async with tenant_scope(session, str(x_tenant_id)):
        result = await session.execute(stmt)
        keys = result.scalars().all()
    return [_api_key_to_response(key) for key in keys]


@router.delete("/api-keys/{key_id}", response_model=admin_models.ApiKeyResponse)
async def revoke_api_key(
    key_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    x_tenant_id: uuid.UUID = Header(alias="X-Tenant-Id"),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> admin_models.ApiKeyResponse:
    _require_tenant_access(principal, x_tenant_id)
    async with session.begin():
        async with tenant_scope(session, str(x_tenant_id)):
            result = await session.execute(
                select(ApiKey).where(ApiKey.id == key_id, ApiKey.tenant_id == x_tenant_id)
            )
            api_key = result.scalar_one_or_none()
            if api_key is None:
                raise ServiceError("API_KEY_NOT_FOUND", "API key not found", 404)
            api_key.revoked = True
    logger.info("admin.apikey.revoked tenant_id=%s key_id=%s", x_tenant_id, key_id)
    return _api_key_to_response(api_key)


async def _fetch_environments(
    session: AsyncSession,
    tenant_id: uuid.UUID,
) -> list[admin_models.EnvironmentResponse]:
    async with tenant_scope(session, str(tenant_id)):
        result = await session.execute(
            select(Environment).where(Environment.tenant_id == tenant_id)
        )
        envs = result.scalars().all()
    return [
        admin_models.EnvironmentResponse(
            tenant_id=e.tenant_id,
            environment_id=e.environment_id,
            name=e.name,
        )
        for e in envs
    ]


@router.get("/environments", response_model=list[admin_models.EnvironmentResponse])
async def list_environments_for_tenant(
    session: AsyncSession = Depends(get_session),
    x_tenant_id: uuid.UUID = Header(alias="X-Tenant-Id"),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> list[admin_models.EnvironmentResponse]:
    _require_tenant_access(principal, x_tenant_id, required_role="tenant-auditor")
    return await _fetch_environments(session, x_tenant_id)


@router.get("/environments/{tenant_id}", response_model=list[admin_models.EnvironmentResponse])
async def list_environments(
    tenant_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> list[admin_models.EnvironmentResponse]:
    _require_tenant_access(principal, tenant_id, required_role="tenant-auditor")
    return await _fetch_environments(session, tenant_id)


@router.post("/environments", response_model=admin_models.EnvironmentResponse)
async def create_environment(
    payload: admin_models.EnvironmentCreateRequest,
    session: AsyncSession = Depends(get_session),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> admin_models.EnvironmentResponse:
    _require_tenant_access(principal, payload.tenant_id)
    env = Environment(
        tenant_id=payload.tenant_id,
        environment_id=payload.environment_id,
        name=payload.name,
    )
    async with session.begin():
        async with tenant_scope(session, str(payload.tenant_id)):
            session.add(env)
    logger.info(
        "admin.environment.created tenant_id=%s env=%s",
        payload.tenant_id,
        payload.environment_id,
    )
    return admin_models.EnvironmentResponse(
        tenant_id=env.tenant_id,
        environment_id=env.environment_id,
        name=env.name,
    )


@router.get(
    "/projects/{tenant_id}/{environment_id}", response_model=list[admin_models.ProjectResponse]
)
async def list_projects(
    tenant_id: uuid.UUID,
    environment_id: str,
    session: AsyncSession = Depends(get_session),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> list[admin_models.ProjectResponse]:
    _require_tenant_access(principal, tenant_id, required_role="tenant-auditor")
    async with tenant_scope(session, str(tenant_id)):
        result = await session.execute(
            select(Project).where(
                Project.tenant_id == tenant_id,
                Project.environment_id == environment_id,
            )
        )
        projects = result.scalars().all()
    return [
        admin_models.ProjectResponse(
            tenant_id=p.tenant_id,
            environment_id=p.environment_id,
            project_id=p.project_id,
            name=p.name,
        )
        for p in projects
    ]


@router.post("/projects", response_model=admin_models.ProjectResponse)
async def create_project(
    payload: admin_models.ProjectCreateRequest,
    session: AsyncSession = Depends(get_session),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> admin_models.ProjectResponse:
    _require_tenant_access(principal, payload.tenant_id)
    project = Project(
        tenant_id=payload.tenant_id,
        environment_id=payload.environment_id,
        project_id=payload.project_id,
        name=payload.name,
    )
    async with session.begin():
        async with tenant_scope(session, str(payload.tenant_id)):
            session.add(project)
    logger.info(
        "admin.project.created tenant_id=%s env=%s project=%s",
        payload.tenant_id,
        payload.environment_id,
        payload.project_id,
    )
    return admin_models.ProjectResponse(
        tenant_id=project.tenant_id,
        environment_id=project.environment_id,
        project_id=project.project_id,
        name=project.name,
    )


@router.post("/policies", response_model=admin_models.PolicyResponse)
async def create_policy(
    payload: admin_models.PolicyCreateRequest,
    session: AsyncSession = Depends(get_session),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> admin_models.PolicyResponse:
    _require_tenant_access(principal, payload.tenant_id)
    scope = payload.scope or "PROJECT"
    phases_json = json.dumps(payload.phases, separators=(",", ":"), ensure_ascii=True)
    config_json = json.dumps(payload.config, separators=(",", ":"), ensure_ascii=True)
    duplicate_message = _policy_duplicate_message(scope)
    policy = Policy(
        tenant_id=payload.tenant_id,
        environment_id=payload.environment_id,
        project_id=payload.project_id,
        policy_id=payload.policy_id,
        name=payload.name,
        type=payload.type,
        enabled=payload.enabled,
        scope=scope,
        phases_json=phases_json,
        config_json=config_json,
    )
    try:
        async with session.begin():
            async with tenant_scope(session, str(payload.tenant_id)):
                existing = await session.execute(
                    select(Policy).where(*_policy_duplicate_filters(payload, scope))
                )
                if existing.scalar_one_or_none() is not None:
                    raise ServiceError("POLICY_ALREADY_EXISTS", duplicate_message, 409)
                session.add(policy)
    except IntegrityError as exc:
        raise ServiceError("POLICY_ALREADY_EXISTS", duplicate_message, 409) from exc
    logger.info(
        "admin.policy.created tenant_id=%s env=%s project=%s policy_id=%s",
        payload.tenant_id,
        payload.environment_id,
        payload.project_id,
        payload.policy_id,
    )
    return _policy_to_response(policy)


@router.get(
    "/policies/{environment_id}/{project_id}",
    response_model=list[admin_models.PolicyResponse],
)
async def list_policies(
    environment_id: str,
    project_id: str,
    session: AsyncSession = Depends(get_session),
    x_tenant_id: uuid.UUID = Header(alias="X-Tenant-Id"),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> list[admin_models.PolicyResponse]:
    _require_tenant_access(principal, x_tenant_id, required_role="tenant-auditor")
    async with tenant_scope(session, str(x_tenant_id)):
        result = await session.execute(
            select(Policy).where(
                Policy.tenant_id == x_tenant_id,
                or_(
                    and_(
                        Policy.scope == "PROJECT",
                        Policy.environment_id == environment_id,
                        Policy.project_id == project_id,
                    ),
                    and_(
                        Policy.scope == "ENVIRONMENT",
                        Policy.environment_id == environment_id,
                    ),
                    Policy.scope == "ORGANIZATION",
                ),
            )
        )
        policies = result.scalars().all()
    return [_policy_to_response(policy) for policy in policies]


@router.patch(
    "/policies/{environment_id}/{project_id}/{policy_id}",
    response_model=admin_models.PolicyResponse,
)
async def update_policy(
    environment_id: str,
    project_id: str,
    policy_id: str,
    payload: admin_models.PolicyUpdateRequest,
    session: AsyncSession = Depends(get_session),
    x_tenant_id: uuid.UUID = Header(alias="X-Tenant-Id"),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> admin_models.PolicyResponse:
    _require_tenant_access(principal, x_tenant_id)
    async with session.begin():
        async with tenant_scope(session, str(x_tenant_id)):
            policy = await session.get(
                Policy, (x_tenant_id, environment_id, project_id, policy_id)
            )
            if policy is None:
                raise ServiceError("POLICY_NOT_FOUND", "Policy not found", 404)
            if payload.name is not None:
                policy.name = payload.name
            if payload.enabled is not None:
                policy.enabled = payload.enabled
            if payload.phases is not None:
                policy.phases_json = json.dumps(
                    payload.phases, separators=(",", ":"), ensure_ascii=True
                )
            if payload.config is not None:
                policy.config_json = json.dumps(
                    payload.config, separators=(",", ":"), ensure_ascii=True
                )
    logger.info(
        "admin.policy.updated tenant_id=%s env=%s project=%s policy_id=%s",
        x_tenant_id,
        environment_id,
        project_id,
        policy_id,
    )
    return _policy_to_response(policy)


@router.get("/library/policies", response_model=list[admin_models.PolicyLibraryItem])
async def list_policy_library() -> list[admin_models.PolicyLibraryItem]:
    return [admin_models.PolicyLibraryItem(**template) for template in list_policy_templates()]


@router.post("/library/policies/deploy", response_model=admin_models.PolicyResponse)
async def deploy_policy_library(
    payload: admin_models.PolicyLibraryDeployRequest,
    session: AsyncSession = Depends(get_session),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> admin_models.PolicyResponse:
    _require_tenant_access(principal, payload.tenant_id)
    template = get_policy_template(payload.template_id)
    if template is None:
        raise ServiceError("POLICY_TEMPLATE_NOT_FOUND", "Policy template not found", 404)
    policy_id = payload.policy_id or template["default_policy_id"]
    name = payload.name or template["name"]
    phases_json = json.dumps(template["phases"], separators=(",", ":"), ensure_ascii=True)
    config_json = json.dumps(template["config"], separators=(",", ":"), ensure_ascii=True)
    policy = Policy(
        tenant_id=payload.tenant_id,
        environment_id=payload.environment_id,
        project_id=payload.project_id,
        policy_id=policy_id,
        name=name,
        type=template["type"],
        enabled=template["enabled"],
        scope="PROJECT",
        phases_json=phases_json,
        config_json=config_json,
    )
    async with session.begin():
        async with tenant_scope(session, str(payload.tenant_id)):
            existing = await session.get(
                Policy,
                (payload.tenant_id, payload.environment_id, payload.project_id, policy_id),
            )
            if existing is not None:
                raise ServiceError("POLICY_ALREADY_EXISTS", "Policy already exists", 409)
            session.add(policy)
    logger.info(
        "admin.policy_library.deployed tenant_id=%s env=%s project=%s policy_id=%s template_id=%s",
        payload.tenant_id,
        payload.environment_id,
        payload.project_id,
        policy_id,
        payload.template_id,
    )
    return _policy_to_response(policy)


@router.get(
    "/guardrails/{environment_id}/{project_id}",
    response_model=list[admin_models.GuardrailResponse],
)
async def list_guardrails(
    environment_id: str,
    project_id: str,
    session: AsyncSession = Depends(get_session),
    x_tenant_id: uuid.UUID = Header(alias="X-Tenant-Id"),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> list[admin_models.GuardrailResponse]:
    _require_tenant_access(principal, x_tenant_id, required_role="tenant-auditor")
    async with tenant_scope(session, str(x_tenant_id)):
        result = await session.execute(
            select(Guardrail).where(
                Guardrail.tenant_id == x_tenant_id,
                Guardrail.environment_id == environment_id,
                Guardrail.project_id == project_id,
            )
        )
        guardrails = result.scalars().all()
    return [
        admin_models.GuardrailResponse(
            tenant_id=guardrail.tenant_id,
            environment_id=guardrail.environment_id,
            project_id=guardrail.project_id,
            guardrail_id=guardrail.guardrail_id,
            name=guardrail.name,
            mode=guardrail.mode,
            current_version=guardrail.current_version,
        )
        for guardrail in guardrails
    ]


@router.post(
    "/guardrails/agentic",
    response_model=admin_models.AgenticGuardrailResponse,
)
async def build_agentic_guardrail(
    payload: admin_models.AgenticGuardrailRequest,
    session: AsyncSession = Depends(get_session),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> admin_models.AgenticGuardrailResponse:
    _require_tenant_access(principal, payload.tenant_id)
    async with session.begin():
        async with tenant_scope(session, str(payload.tenant_id)):
            await resolve_environment(
                session, payload.tenant_id, payload.environment_id
            )
            await resolve_project(
                session, payload.tenant_id, payload.environment_id, payload.project_id
            )

    plan = await generate_agentic_guardrail(payload.model_dump())
    return admin_models.AgenticGuardrailResponse(**plan)


@router.post("/test/guard", response_model=admin_models.GuardrailTestResponse)
async def test_guardrail(
    payload: admin_models.GuardrailTestRequest,
    session: AsyncSession = Depends(get_session),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> admin_models.GuardrailTestResponse:
    _require_tenant_access(principal, payload.tenant_id)
    request_id = str(uuid.uuid4())
    allow_llm_calls = payload.allow_llm_calls
    async with session.begin():
        async with tenant_scope(session, str(payload.tenant_id)):
            license_row = await require_active_license(session, payload.tenant_id)
            allow_llm_calls = allow_llm_calls and license_allows_llm_calls(license_row)
            await resolve_environment(
                session, payload.tenant_id, payload.environment_id
            )
            await resolve_project(
                session, payload.tenant_id, payload.environment_id, payload.project_id
            )
            guardrail = await resolve_guardrail(
                session,
                payload.tenant_id,
                payload.environment_id,
                payload.project_id,
                payload.guardrail_id,
            )
            guardrail_version = payload.guardrail_version or guardrail.current_version
            version_row = await session.get(
                GuardrailVersion,
                (
                    payload.tenant_id,
                    payload.environment_id,
                    payload.project_id,
                    payload.guardrail_id,
                    guardrail_version,
                ),
            )
            if version_row is None:
                raise ServiceError(
                    "GUARDRAIL_VERSION_NOT_FOUND",
                    "Guardrail version not found",
                    404,
                )
    timestamp = dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")
    engine_request = EngineRequest(
        request_id=request_id,
        timestamp=timestamp,
        tenant_id=str(payload.tenant_id),
        environment_id=payload.environment_id,
        project_id=payload.project_id,
        guardrail_id=payload.guardrail_id,
        guardrail_version=guardrail_version,
        phase=payload.phase,
        input=payload.input,
        timeout_ms=payload.timeout_ms,
        flags=EngineFlags(allow_llm_calls=allow_llm_calls),
    )
    engine_response = await evaluate_engine(engine_request)
    async with session.begin():
        async with tenant_scope(session, str(payload.tenant_id)):
            await record_audit_event(
                session,
                tenant_id=payload.tenant_id,
                environment_id=payload.environment_id,
                project_id=payload.project_id,
                guardrail_id=payload.guardrail_id,
                guardrail_version=guardrail_version,
                engine_response=engine_response,
                request_payload=None,
            )
    triggering_policy = None
    if engine_response.triggering_policy:
        triggering_policy = admin_models.GuardrailTestTriggeringPolicy(
            policy_id=engine_response.triggering_policy.policy_id,
            type=engine_response.triggering_policy.type,
            name=engine_response.triggering_policy.name,
            status=engine_response.triggering_policy.status,
            severity=engine_response.triggering_policy.severity,
            score=engine_response.triggering_policy.score,
            details=engine_response.triggering_policy.details,
            latency_ms=engine_response.triggering_policy.latency_ms,
        )
    return admin_models.GuardrailTestResponse(
        request_id=engine_response.request_id,
        guardrail_id=payload.guardrail_id,
        guardrail_version=guardrail_version,
        phase=engine_response.phase,
        decision=admin_models.GuardrailTestDecision(
            action=engine_response.decision.action,
            allowed=engine_response.decision.allowed,
            severity=engine_response.decision.severity,
            reason=engine_response.decision.reason,
        ),
        triggering_policy=triggering_policy,
        latency_ms=admin_models.GuardrailTestLatency(
            total=engine_response.latency_ms.total,
            preflight=engine_response.latency_ms.preflight,
        ),
        errors=[err.model_dump() for err in engine_response.errors],
    )


@router.get(
    "/alerts/{environment_id}/{project_id}",
    response_model=list[admin_models.AlertResponse],
)
async def list_alerts(
    environment_id: str,
    project_id: str,
    limit: int = 50,
    session: AsyncSession = Depends(get_session),
    x_tenant_id: uuid.UUID = Header(alias="X-Tenant-Id"),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> list[admin_models.AlertResponse]:
    _require_tenant_access(principal, x_tenant_id, required_role="tenant-auditor")
    limit = max(1, min(limit, 250))
    async with session.begin():
        async with tenant_scope(session, str(x_tenant_id)):
            result = await session.execute(
                select(AuditEvent)
                .where(
                    AuditEvent.tenant_id == x_tenant_id,
                    AuditEvent.environment_id == environment_id,
                    AuditEvent.project_id == project_id,
                    AuditEvent.action.in_(["BLOCK", "FLAG", "STEP_UP_APPROVAL"]),
                )
                .order_by(AuditEvent.created_at.desc())
                .limit(limit)
            )
            events = result.scalars().all()
    return [_audit_event_to_alert(event) for event in events]


@router.get("/evaluations/sets", response_model=list[admin_models.EvaluationSetResponse])
async def list_evaluation_sets() -> list[admin_models.EvaluationSetResponse]:
    return [admin_models.EvaluationSetResponse(**item) for item in list_eval_sets()]


@router.get("/evaluations", response_model=list[admin_models.EvaluationRunResponse])
async def list_evaluations(
    environment_id: str | None = Query(default=None),
    project_id: str | None = Query(default=None),
    session: AsyncSession = Depends(get_session),
    x_tenant_id: uuid.UUID = Header(alias="X-Tenant-Id"),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> list[admin_models.EvaluationRunResponse]:
    _require_tenant_access(principal, x_tenant_id, required_role="tenant-auditor")
    stmt = select(EvaluationRun).where(EvaluationRun.tenant_id == x_tenant_id)
    if environment_id:
        stmt = stmt.where(EvaluationRun.environment_id == environment_id)
    if project_id:
        stmt = stmt.where(EvaluationRun.project_id == project_id)
    stmt = stmt.order_by(EvaluationRun.created_at.desc())
    async with session.begin():
        async with tenant_scope(session, str(x_tenant_id)):
            result = await session.execute(stmt)
            runs = result.scalars().all()
    return [_evaluation_run_to_response(run) for run in runs]


@router.get(
    "/evaluations/{run_id}",
    response_model=admin_models.EvaluationRunDetailResponse,
)
async def get_evaluation(
    run_id: uuid.UUID,
    limit: int = Query(default=50, ge=1, le=500),
    session: AsyncSession = Depends(get_session),
    x_tenant_id: uuid.UUID = Header(alias="X-Tenant-Id"),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> admin_models.EvaluationRunDetailResponse:
    _require_tenant_access(principal, x_tenant_id, required_role="tenant-auditor")
    async with session.begin():
        async with tenant_scope(session, str(x_tenant_id)):
            run = await session.get(EvaluationRun, run_id)
            if run is None or run.tenant_id != x_tenant_id:
                raise ServiceError("EVALUATION_NOT_FOUND", "Evaluation run not found", 404)
            result = await session.execute(
                select(EvaluationCase)
                .where(EvaluationCase.run_id == run_id)
                .order_by(EvaluationCase.index.asc())
                .limit(limit)
            )
            cases = result.scalars().all()
    return admin_models.EvaluationRunDetailResponse(
        **_evaluation_run_to_response(run).model_dump(),
        cases=[_evaluation_case_to_response(case) for case in cases],
    )


@router.post("/evaluations", response_model=admin_models.EvaluationRunResponse)
async def create_evaluation(
    background_tasks: BackgroundTasks,
    environment_id: str = Form(...),
    project_id: str = Form(...),
    guardrail_id: str = Form(...),
    phase: str = Form("PRE_LLM"),
    guardrail_version: int | None = Form(default=None),
    name: str | None = Form(default=None),
    dataset_id: str | None = Form(default=None),
    file: UploadFile | None = File(default=None),
    session: AsyncSession = Depends(get_session),
    x_tenant_id: uuid.UUID = Header(alias="X-Tenant-Id"),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> admin_models.EvaluationRunResponse:
    _require_tenant_access(principal, x_tenant_id)
    phase = phase.upper()
    if phase not in PHASE_ORDER:
        raise ServiceError("INVALID_PHASE", f"Phase must be one of: {', '.join(PHASE_ORDER)}", 400)

    if dataset_id and file:
        raise ServiceError("EVAL_INPUT_CONFLICT", "Provide dataset_id or file, not both", 400)

    cases: list[dict]
    if dataset_id:
        dataset = get_eval_set(dataset_id)
        if not dataset:
            raise ServiceError("EVAL_SET_NOT_FOUND", "Evaluation set not found", 404)
        cases = dataset.get("cases", [])
    elif file is not None:
        raw = (await file.read()).decode("utf-8", errors="ignore")
        cases = _parse_eval_jsonl(raw)
    else:
        raise ServiceError("EVAL_INPUT_MISSING", "Provide dataset_id or upload a JSONL file", 400)

    if not cases:
        raise ServiceError("EVAL_NO_CASES", "No valid prompts found in evaluation file", 400)
    if len(cases) > EVAL_MAX_CASES:
        raise ServiceError(
            "EVAL_TOO_LARGE",
            f"Evaluation file too large. Max {EVAL_MAX_CASES} prompts.",
            400,
        )

    async with session.begin():
        async with tenant_scope(session, str(x_tenant_id)):
            await resolve_environment(session, x_tenant_id, environment_id)
            await resolve_project(session, x_tenant_id, environment_id, project_id)
            guardrail = await resolve_guardrail(
                session, x_tenant_id, environment_id, project_id, guardrail_id
            )
            resolved_version = guardrail_version or guardrail.current_version
            version_row = await session.get(
                GuardrailVersion,
                (x_tenant_id, environment_id, project_id, guardrail_id, resolved_version),
            )
            if version_row is None:
                raise ServiceError(
                    "GUARDRAIL_VERSION_NOT_FOUND",
                    "Guardrail version not found",
                    404,
                )

            run = EvaluationRun(
                tenant_id=x_tenant_id,
                environment_id=environment_id,
                project_id=project_id,
                guardrail_id=guardrail_id,
                guardrail_version=resolved_version,
                name=name,
                dataset_id=dataset_id,
                phase=phase,
                status="PENDING",
                total_cases=len(cases),
                processed_cases=0,
            )
            session.add(run)
        await session.flush()
        run_id = run.id

    background_tasks.add_task(
        _run_evaluation_background,
        run_id,
        x_tenant_id,
        environment_id,
        project_id,
        guardrail_id,
        guardrail_version or guardrail.current_version,
        phase,
        cases,
    )

    return _evaluation_run_to_response(run)


async def _run_evaluation_background(
    run_id: uuid.UUID,
    tenant_id: uuid.UUID,
    environment_id: str,
    project_id: str,
    guardrail_id: str,
    guardrail_version: int,
    phase: str,
    cases: list[dict],
) -> None:
    session_maker = get_sessionmaker()
    metrics = {
        "total": 0,
        "allowed": 0,
        "blocked": 0,
        "flagged": 0,
        "actions": {},
        "expected_action_total": 0,
        "expected_action_matches": 0,
        "expected_action_accuracy": None,
        "expected_allowed_total": 0,
        "expected_allowed_matches": 0,
        "expected_allowed_accuracy": None,
        "expected_severity_total": 0,
        "expected_severity_matches": 0,
        "expected_severity_accuracy": None,
        "action_confusion": {},
    }

    try:
        async with session_maker() as session:
            async with session.begin():
                async with tenant_scope(session, str(tenant_id)):
                    run = await session.get(EvaluationRun, run_id)
                    if run is None:
                        return
                    run.status = "RUNNING"
                    run.processed_cases = 0

        allow_llm_calls = False
        async with session_maker() as session:
            async with session.begin():
                async with tenant_scope(session, str(tenant_id)):
                    license_row = await require_active_license(session, tenant_id)
                    allow_llm_calls = license_allows_llm_calls(license_row)
                    await resolve_environment(session, tenant_id, environment_id)
                    await resolve_project(session, tenant_id, environment_id, project_id)
                    guardrail = await resolve_guardrail(
                        session, tenant_id, environment_id, project_id, guardrail_id
                    )
                    guardrail_version = guardrail_version or guardrail.current_version

        for index, case in enumerate(cases, start=1):
            prompt = str(case.get("prompt", ""))
            request_id = str(uuid.uuid4())
            timestamp = dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")
            input_payload = _build_evaluation_input_payload(phase, prompt, case)
            engine_request = EngineRequest(
                request_id=request_id,
                timestamp=timestamp,
                tenant_id=str(tenant_id),
                environment_id=environment_id,
                project_id=project_id,
                guardrail_id=guardrail_id,
                guardrail_version=guardrail_version,
                phase=phase,
                input=input_payload,
                timeout_ms=1500,
                flags=EngineFlags(allow_llm_calls=allow_llm_calls),
            )

            engine_response = await evaluate_engine(engine_request)
            decision = engine_response.decision
            action = decision.action
            metrics["total"] += 1
            metrics["actions"][action] = metrics["actions"].get(action, 0) + 1
            if decision.allowed:
                metrics["allowed"] += 1
            if action == "BLOCK":
                metrics["blocked"] += 1
            if action == "FLAG":
                metrics["flagged"] += 1

            expected_action = case.get("expected_action")
            expected_allowed = case.get("expected_allowed")
            expected_severity = case.get("expected_severity")
            if expected_action:
                metrics["expected_action_total"] += 1
                if expected_action == action:
                    metrics["expected_action_matches"] += 1
                metrics["action_confusion"].setdefault(expected_action, {})
                metrics["action_confusion"][expected_action][action] = (
                    metrics["action_confusion"][expected_action].get(action, 0) + 1
                )
            if expected_allowed is not None:
                metrics["expected_allowed_total"] += 1
                if expected_allowed == decision.allowed:
                    metrics["expected_allowed_matches"] += 1
            if expected_severity:
                metrics["expected_severity_total"] += 1
                if expected_severity == decision.severity:
                    metrics["expected_severity_matches"] += 1

            async with session_maker() as session:
                async with session.begin():
                    async with tenant_scope(session, str(tenant_id)):
                        session.add(
                            EvaluationCase(
                                run_id=run_id,
                                tenant_id=tenant_id,
                                environment_id=environment_id,
                                project_id=project_id,
                                guardrail_id=guardrail_id,
                                guardrail_version=guardrail_version,
                                index=index,
                                label=case.get("label"),
                                prompt=prompt,
                                expected_action=expected_action,
                                expected_allowed=expected_allowed,
                                expected_severity=expected_severity,
                                decision_action=action,
                                decision_allowed=decision.allowed,
                                decision_severity=decision.severity,
                                decision_reason=decision.reason,
                                triggering_policy_json=json.dumps(
                                    engine_response.triggering_policy.model_dump()
                                )
                                if engine_response.triggering_policy
                                else None,
                                latency_ms=engine_response.latency_ms.total,
                                errors_json=json.dumps(
                                    [err.model_dump() for err in engine_response.errors]
                                )
                                if engine_response.errors
                                else None,
                            )
                        )
                        run = await session.get(EvaluationRun, run_id)
                        if run is not None:
                            run.processed_cases = index

        if metrics["expected_action_total"]:
            metrics["expected_action_accuracy"] = (
                metrics["expected_action_matches"] / metrics["expected_action_total"]
            )
        if metrics["expected_allowed_total"]:
            metrics["expected_allowed_accuracy"] = (
                metrics["expected_allowed_matches"] / metrics["expected_allowed_total"]
            )
        if metrics["expected_severity_total"]:
            metrics["expected_severity_accuracy"] = (
                metrics["expected_severity_matches"] / metrics["expected_severity_total"]
            )

        async with session_maker() as session:
            async with session.begin():
                async with tenant_scope(session, str(tenant_id)):
                    run = await session.get(EvaluationRun, run_id)
                    if run is not None:
                        run.status = "COMPLETED"
                        run.metrics_json = json.dumps(metrics)
                        run.completed_at = dt.datetime.now(dt.timezone.utc)
                        run.processed_cases = run.total_cases
    except Exception as exc:  # pylint: disable=broad-except
        logger.exception("evaluation.run.failed run_id=%s", run_id)
        async with session_maker() as session:
            async with session.begin():
                async with tenant_scope(session, str(tenant_id)):
                    run = await session.get(EvaluationRun, run_id)
                    if run is not None:
                        run.status = "FAILED"
                        run.error_message = str(exc)
                        run.completed_at = dt.datetime.now(dt.timezone.utc)


@router.get("/library/guardrails", response_model=list[admin_models.GuardrailLibraryItem])
async def list_guardrail_library() -> list[admin_models.GuardrailLibraryItem]:
    return [
        admin_models.GuardrailLibraryItem(**template)
        for template in list_guardrail_templates()
    ]


@router.post(
    "/library/guardrails/deploy",
    response_model=admin_models.GuardrailLibraryDeployResponse,
)
async def deploy_guardrail_library(
    payload: admin_models.GuardrailLibraryDeployRequest,
    session: AsyncSession = Depends(get_session),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> admin_models.GuardrailLibraryDeployResponse:
    _require_tenant_access(principal, payload.tenant_id)
    template = get_guardrail_template(payload.template_id)
    if template is None:
        raise ServiceError("GUARDRAIL_TEMPLATE_NOT_FOUND", "Guardrail template not found", 404)
    guardrail_id = payload.guardrail_id or template["default_guardrail_id"]
    guardrail_name = payload.name or template["name"]
    guardrail_mode = payload.mode or template["mode"]
    version = template["version"]
    policy_ids: list[str] = []
    policy_snapshots: list[dict] = []
    normalized_agt = _normalize_agt_config(template.get("agt"))
    redis_key: str | None = None
    published = False
    async with session.begin():
        async with tenant_scope(session, str(payload.tenant_id)):
            existing_guardrail = await session.get(
                Guardrail,
                (
                    payload.tenant_id,
                    payload.environment_id,
                    payload.project_id,
                    guardrail_id,
                ),
            )
            if existing_guardrail is not None:
                raise ServiceError("GUARDRAIL_ALREADY_EXISTS", "Guardrail already exists", 409)
            for policy_template in template["policies"]:
                policy_id = policy_template["default_policy_id"]
                policy_ids.append(policy_id)
                policy = await session.get(
                    Policy,
                    (
                        payload.tenant_id,
                        payload.environment_id,
                        payload.project_id,
                        policy_id,
                    ),
                )
                if policy is None:
                    policy = Policy(
                        tenant_id=payload.tenant_id,
                        environment_id=payload.environment_id,
                        project_id=payload.project_id,
                        policy_id=policy_id,
                        name=policy_template["name"],
                        type=policy_template["type"],
                        enabled=policy_template["enabled"],
                        scope="PROJECT",
                        phases_json=json.dumps(
                            policy_template["phases"], separators=(",", ":"), ensure_ascii=True
                        ),
                        config_json=json.dumps(
                            policy_template["config"], separators=(",", ":"), ensure_ascii=True
                        ),
                    )
                    session.add(policy)
                policy_snapshots.append(_policy_to_snapshot(policy))
            required_policies = await _fetch_required_policies(
                session, payload.tenant_id, payload.environment_id
            )
            existing_ids = {policy.get("id") for policy in policy_snapshots}
            for policy in required_policies:
                if policy.policy_id not in existing_ids:
                    policy_snapshots.append(_policy_to_snapshot(policy))
                    existing_ids.add(policy.policy_id)
            phases = _merge_snapshot_phases(
                policy_snapshots,
                template.get("phases"),
                normalized_agt,
            )
            guardrail = Guardrail(
                tenant_id=payload.tenant_id,
                environment_id=payload.environment_id,
                project_id=payload.project_id,
                guardrail_id=guardrail_id,
                name=guardrail_name,
                mode=guardrail_mode,
                current_version=version,
            )
            session.add(guardrail)
            snapshot_payload = {
                "guardrail_id": guardrail_id,
                "version": version,
                "mode": guardrail_mode,
                "phases": phases,
                "preflight": template["preflight"],
                "policies": policy_snapshots,
                "llm_config": _normalize_llm_config(template["llm_config"]),
            }
            if normalized_agt is not None:
                snapshot_payload["agt"] = normalized_agt
            signature, key_id = sign_snapshot(snapshot_payload)
            snapshot_json = json.dumps(
                snapshot_payload, separators=(",", ":"), ensure_ascii=True
            )
            version_row = GuardrailVersion(
                tenant_id=payload.tenant_id,
                environment_id=payload.environment_id,
                project_id=payload.project_id,
                guardrail_id=guardrail_id,
                version=version,
                snapshot_json=snapshot_json,
                signature=signature,
                key_id=key_id,
                created_by="library",
                approved_by="library",
                approved_at=dt.datetime.now(dt.timezone.utc),
            )
            session.add(version_row)
            if payload.publish:
                try:
                    redis = get_redis()
                except RuntimeError as exc:
                    raise ServiceError("REDIS_UNAVAILABLE", str(exc), 503) from exc
                redis_key = build_snapshot_key(
                    str(payload.tenant_id),
                    payload.environment_id,
                    payload.project_id,
                    guardrail_id,
                    version,
                )
                await publish_snapshot(
                    redis,
                    redis_key,
                    pack_snapshot_record(snapshot_payload, signature, key_id),
                )
                published = True
    logger.info(
        "admin.guardrail_library.deployed tenant_id=%s env=%s project=%s guardrail_id=%s template_id=%s",
        payload.tenant_id,
        payload.environment_id,
        payload.project_id,
        guardrail_id,
        payload.template_id,
    )
    return admin_models.GuardrailLibraryDeployResponse(
        guardrail=admin_models.GuardrailResponse(
            tenant_id=payload.tenant_id,
            environment_id=payload.environment_id,
            project_id=payload.project_id,
            guardrail_id=guardrail_id,
            name=guardrail_name,
            mode=guardrail_mode,
            current_version=version,
        ),
        version=admin_models.GuardrailVersionResponse(
            tenant_id=payload.tenant_id,
            environment_id=payload.environment_id,
            project_id=payload.project_id,
            guardrail_id=guardrail_id,
            version=version,
            created_at=version_row.created_at,
            created_by=version_row.created_by,
            approved_by=version_row.approved_by,
            approved_at=version_row.approved_at,
            signature_present=bool(version_row.signature),
        ),
        policy_ids=policy_ids,
        published=published,
        redis_key=redis_key,
    )


@router.get(
    "/guardrails/{environment_id}/{project_id}/{guardrail_id}/versions",
    response_model=list[admin_models.GuardrailVersionResponse],
)
async def list_guardrail_versions(
    environment_id: str,
    project_id: str,
    guardrail_id: str,
    session: AsyncSession = Depends(get_session),
    x_tenant_id: uuid.UUID = Header(alias="X-Tenant-Id"),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> list[admin_models.GuardrailVersionResponse]:
    _require_tenant_access(principal, x_tenant_id, required_role="tenant-auditor")
    async with tenant_scope(session, str(x_tenant_id)):
        result = await session.execute(
            select(GuardrailVersion).where(
                GuardrailVersion.tenant_id == x_tenant_id,
                GuardrailVersion.environment_id == environment_id,
                GuardrailVersion.project_id == project_id,
                GuardrailVersion.guardrail_id == guardrail_id,
            )
        )
        versions = result.scalars().all()
    return [
        admin_models.GuardrailVersionResponse(
            tenant_id=version.tenant_id,
            environment_id=version.environment_id,
            project_id=version.project_id,
            guardrail_id=version.guardrail_id,
            version=version.version,
            created_at=version.created_at,
            created_by=version.created_by,
            approved_by=version.approved_by,
            approved_at=version.approved_at,
            signature_present=bool(version.signature),
        )
        for version in versions
    ]


@router.get("/guardrails/{environment_id}/{project_id}/{guardrail_id}/snapshot/{version}")
async def get_guardrail_snapshot(
    environment_id: str,
    project_id: str,
    guardrail_id: str,
    version: int,
    session: AsyncSession = Depends(get_session),
    x_tenant_id: uuid.UUID = Header(alias="X-Tenant-Id"),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> dict:
    _require_tenant_access(principal, x_tenant_id, required_role="tenant-auditor")
    async with tenant_scope(session, str(x_tenant_id)):
        version_row = await session.get(
            GuardrailVersion,
            (x_tenant_id, environment_id, project_id, guardrail_id, version),
        )
        if version_row is None:
            raise ServiceError("GUARDRAIL_NOT_FOUND", "Guardrail version not found", 404)
    redis_available = True
    redis_present = False
    redis_key = build_snapshot_key(
        str(x_tenant_id),
        environment_id,
        project_id,
        guardrail_id,
        version,
    )
    try:
        redis = get_redis()
        redis_present = bool(await redis.exists(redis_key))
    except RuntimeError:
        redis_available = False
    snapshot_payload = json.loads(version_row.snapshot_json)
    return {
        "tenant_id": str(x_tenant_id),
        "environment_id": environment_id,
        "project_id": project_id,
        "guardrail_id": guardrail_id,
        "version": version,
        "redis_key": redis_key,
        "redis_available": redis_available,
        "redis_present": redis_present,
        "signature": version_row.signature,
        "key_id": version_row.key_id,
        "snapshot": snapshot_payload,
    }


@router.post("/guardrails", response_model=admin_models.GuardrailResponse)
async def create_guardrail(
    payload: admin_models.GuardrailCreateRequest,
    session: AsyncSession = Depends(get_session),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> admin_models.GuardrailResponse:
    _require_tenant_access(principal, payload.tenant_id)
    duplicate_message = "Guardrail already exists"
    guardrail = Guardrail(
        tenant_id=payload.tenant_id,
        environment_id=payload.environment_id,
        project_id=payload.project_id,
        guardrail_id=payload.guardrail_id,
        name=payload.name,
        mode=payload.mode,
        current_version=payload.current_version,
    )
    try:
        async with session.begin():
            async with tenant_scope(session, str(payload.tenant_id)):
                existing = await session.get(
                    Guardrail,
                    (
                        payload.tenant_id,
                        payload.environment_id,
                        payload.project_id,
                        payload.guardrail_id,
                    ),
                )
                if existing is not None:
                    raise ServiceError("GUARDRAIL_ALREADY_EXISTS", duplicate_message, 409)
                session.add(guardrail)
    except IntegrityError as exc:
        raise ServiceError("GUARDRAIL_ALREADY_EXISTS", duplicate_message, 409) from exc
    logger.info(
        "admin.guardrail.created tenant_id=%s env=%s project=%s guardrail_id=%s version=%s",
        payload.tenant_id,
        payload.environment_id,
        payload.project_id,
        payload.guardrail_id,
        payload.current_version,
    )
    return admin_models.GuardrailResponse(
        tenant_id=guardrail.tenant_id,
        environment_id=guardrail.environment_id,
        project_id=guardrail.project_id,
        guardrail_id=guardrail.guardrail_id,
        name=guardrail.name,
        mode=guardrail.mode,
        current_version=guardrail.current_version,
    )


@router.post(
    "/guardrails/{guardrail_id}/versions",
    response_model=admin_models.GuardrailVersionResponse,
)
async def create_guardrail_version(
    guardrail_id: str,
    payload: admin_models.GuardrailVersionCreateRequest,
    session: AsyncSession = Depends(get_session),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> admin_models.GuardrailVersionResponse:
    _require_tenant_access(principal, payload.tenant_id)
    if payload.snapshot_json is not None and payload.policy_ids is not None:
        raise ServiceError("INVALID_REQUEST", "Provide snapshot_json or policy_ids, not both", 422)
    if payload.snapshot_json is not None and payload.agt is not None:
        raise ServiceError(
            "INVALID_REQUEST",
            "Provide AGT config inside snapshot_json or payload.agt, not both",
            422,
        )
    auto_published = False
    redis_key: str | None = None
    try:
        async with session.begin():
            async with tenant_scope(session, str(payload.tenant_id)):
                guardrail = await session.get(
                    Guardrail,
                    (payload.tenant_id, payload.environment_id, payload.project_id, guardrail_id),
                )
                if guardrail is None:
                    raise ServiceError("GUARDRAIL_NOT_FOUND", "Guardrail not found", 404)
                existing_version = await session.execute(
                    select(GuardrailVersion.version)
                    .where(
                        GuardrailVersion.tenant_id == payload.tenant_id,
                        GuardrailVersion.environment_id == payload.environment_id,
                        GuardrailVersion.project_id == payload.project_id,
                        GuardrailVersion.guardrail_id == guardrail_id,
                    )
                    .limit(1)
                )
                has_existing_versions = existing_version.scalar_one_or_none() is not None
                required_policies = await _fetch_required_policies(
                    session, payload.tenant_id, payload.environment_id
                )
                required_policy_ids = {policy.policy_id for policy in required_policies}
                snapshot_payload = payload.snapshot_json
                normalized_agt = _normalize_agt_config(payload.agt)
                if snapshot_payload is None:
                    if not payload.policy_ids:
                        raise ServiceError(
                            "INVALID_REQUEST",
                            "policy_ids required when snapshot_json is omitted",
                            422,
                        )
                    if payload.llm_config is None:
                        raise ServiceError(
                            "LLM_CONFIG_REQUIRED",
                            "llm_config is required when snapshot_json is omitted",
                            422,
                        )
                    if required_policy_ids:
                        conflict_result = await session.execute(
                            select(Policy.policy_id).where(
                                Policy.tenant_id == payload.tenant_id,
                                Policy.environment_id == payload.environment_id,
                                Policy.project_id == payload.project_id,
                                Policy.scope == "PROJECT",
                                Policy.policy_id.in_(required_policy_ids),
                            )
                        )
                        conflicts = list(conflict_result.scalars().all())
                        if conflicts:
                            raise ServiceError(
                                "POLICY_SCOPE_CONFLICT",
                                "Policy IDs conflict with required organization/environment policies: "
                                + ", ".join(sorted(set(conflicts))),
                                409,
                            )
                    result = await session.execute(
                        select(Policy).where(
                            Policy.tenant_id == payload.tenant_id,
                            Policy.environment_id == payload.environment_id,
                            Policy.project_id == payload.project_id,
                            Policy.scope == "PROJECT",
                            Policy.policy_id.in_(payload.policy_ids),
                        )
                    )
                    policies = result.scalars().all()
                    policy_map = {policy.policy_id: policy for policy in policies}
                    missing = [
                        policy_id
                        for policy_id in payload.policy_ids
                        if policy_id not in policy_map and policy_id not in required_policy_ids
                    ]
                    if missing:
                        raise ServiceError(
                            "POLICY_NOT_FOUND",
                            f"Policies not found: {', '.join(missing)}",
                            404,
                        )
                    policy_snapshots: list[dict] = []
                    seen_ids: set[str] = set()
                    for policy_id in payload.policy_ids:
                        policy = policy_map.get(policy_id)
                        if policy and policy_id not in seen_ids:
                            policy_snapshots.append(_policy_to_snapshot(policy))
                            seen_ids.add(policy_id)
                    for policy in required_policies:
                        if policy.policy_id not in seen_ids:
                            policy_snapshots.append(_policy_to_snapshot(policy))
                            seen_ids.add(policy.policy_id)
                    phases = _merge_snapshot_phases(
                        policy_snapshots,
                        payload.phases,
                        normalized_agt,
                    )
                    if not phases:
                        raise ServiceError(
                            "INVALID_REQUEST",
                            "phases required or derived from policies",
                            422,
                        )
                    snapshot_payload = {
                        "guardrail_id": guardrail_id,
                        "version": payload.version,
                        "mode": guardrail.mode,
                        "phases": phases,
                        "preflight": payload.preflight or DEFAULT_PREFLIGHT,
                        "policies": policy_snapshots,
                        "llm_config": _normalize_llm_config(payload.llm_config),
                    }
                    if normalized_agt is not None:
                        snapshot_payload["agt"] = normalized_agt
                else:
                    if not isinstance(snapshot_payload, dict):
                        raise ServiceError(
                            "INVALID_REQUEST",
                            "snapshot_json must be an object",
                            422,
                        )
                    policies_list = snapshot_payload.get("policies")
                    if not isinstance(policies_list, list):
                        raise ServiceError(
                            "INVALID_REQUEST",
                            "snapshot_json.policies must be a list",
                            422,
                        )
                    existing_ids = {
                        policy.get("id")
                        for policy in policies_list
                        if isinstance(policy, dict) and policy.get("id")
                    }
                    for policy in required_policies:
                        if policy.policy_id not in existing_ids:
                            policies_list.append(_policy_to_snapshot(policy))
                            existing_ids.add(policy.policy_id)
                    normalized_agt = _normalize_agt_config(snapshot_payload.get("agt"))
                    snapshot_payload["phases"] = _merge_snapshot_phases(
                        policies_list,
                        snapshot_payload.get("phases", []) or [],
                        normalized_agt,
                    )
                    snapshot_payload["policies"] = policies_list
                    snapshot_payload["llm_config"] = _normalize_llm_config(
                        snapshot_payload.get("llm_config")
                    )
                    if normalized_agt is not None:
                        snapshot_payload["agt"] = normalized_agt
                    else:
                        snapshot_payload.pop("agt", None)
                signature, key_id = sign_snapshot(snapshot_payload)
                snapshot_json = json.dumps(
                    snapshot_payload, separators=(",", ":"), ensure_ascii=True
                )
                version_row = GuardrailVersion(
                    tenant_id=payload.tenant_id,
                    environment_id=payload.environment_id,
                    project_id=payload.project_id,
                    guardrail_id=guardrail_id,
                    version=payload.version,
                    snapshot_json=snapshot_json,
                    signature=signature,
                    key_id=key_id,
                    created_by=payload.created_by,
                )
                session.add(version_row)
                if not has_existing_versions:
                    try:
                        redis = get_redis()
                    except RuntimeError as exc:
                        raise ServiceError("REDIS_UNAVAILABLE", str(exc), 503) from exc
                    version_row.approved_by = payload.created_by or "system"
                    version_row.approved_at = dt.datetime.now(dt.timezone.utc)
                    redis_key = build_snapshot_key(
                        str(payload.tenant_id),
                        payload.environment_id,
                        payload.project_id,
                        guardrail_id,
                        payload.version,
                    )
                    await publish_snapshot(
                        redis,
                        redis_key,
                        pack_snapshot_record(snapshot_payload, signature, key_id),
                    )
                    guardrail.current_version = payload.version
                    auto_published = True
    except IntegrityError as exc:
        error_text = str(exc).upper()
        if "GUARDRAIL_VERSIONS" in error_text and "VERSION" in error_text:
            raise ServiceError(
                "VERSION_EXISTS",
                f"Guardrail version {payload.version} already exists for {guardrail_id}",
                409,
            ) from exc
        raise
    logger.info(
        "admin.guardrail_version.created tenant_id=%s env=%s project=%s guardrail_id=%s version=%s",
        payload.tenant_id,
        payload.environment_id,
        payload.project_id,
        guardrail_id,
        payload.version,
    )
    if auto_published:
        logger.info(
            "admin.guardrail_version.published tenant_id=%s env=%s project=%s guardrail_id=%s version=%s redis_key=%s",
            payload.tenant_id,
            payload.environment_id,
            payload.project_id,
            guardrail_id,
            payload.version,
            redis_key,
        )
    return admin_models.GuardrailVersionResponse(
        tenant_id=payload.tenant_id,
        environment_id=payload.environment_id,
        project_id=payload.project_id,
        guardrail_id=guardrail_id,
        version=payload.version,
        created_at=version_row.created_at,
        created_by=version_row.created_by,
        approved_by=version_row.approved_by,
        approved_at=version_row.approved_at,
        signature_present=bool(version_row.signature),
    )


@router.post(
    "/guardrails/{guardrail_id}/publish/{version}",
    response_model=admin_models.PublishResponse,
)
async def publish_guardrail_version(
    guardrail_id: str,
    version: int,
    payload: admin_models.PublishRequest,
    session: AsyncSession = Depends(get_session),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> admin_models.PublishResponse:
    _require_tenant_access(principal, payload.tenant_id)
    try:
        redis = get_redis()
    except RuntimeError as exc:
        raise ServiceError("REDIS_UNAVAILABLE", str(exc), 503) from exc
    key = ""
    signature: str | None = None
    key_id: str | None = None
    async with session.begin():
        async with tenant_scope(session, str(payload.tenant_id)):
            version_row = await session.get(
                GuardrailVersion,
                (
                    payload.tenant_id,
                    payload.environment_id,
                    payload.project_id,
                    guardrail_id,
                    version,
                ),
            )
            if version_row is None:
                raise ServiceError("GUARDRAIL_NOT_FOUND", "Guardrail version not found", 404)
            if payload.break_glass_reason:
                logger.warning(
                    "admin.guardrail_version.break_glass tenant_id=%s env=%s project=%s guardrail_id=%s version=%s reason=%s",
                    payload.tenant_id,
                    payload.environment_id,
                    payload.project_id,
                    guardrail_id,
                    version,
                    payload.break_glass_reason,
                )
            else:
                if version_row.created_by and payload.approver_id is None:
                    raise ServiceError(
                        "APPROVER_REQUIRED",
                        "approver_id is required for non-break-glass publish",
                        422,
                    )
                if (
                    version_row.created_by
                    and payload.approver_id
                    and version_row.created_by == payload.approver_id
                ):
                    raise ServiceError(
                        "FOUR_EYES_REQUIRED",
                        "approver_id must be different from created_by",
                        409,
                    )
                if payload.approver_id:
                    version_row.approved_by = payload.approver_id
                    version_row.approved_at = dt.datetime.now(dt.timezone.utc)
            guardrail = await session.get(
                Guardrail,
                (
                    payload.tenant_id,
                    payload.environment_id,
                    payload.project_id,
                    guardrail_id,
                ),
            )
            if guardrail is None:
                raise ServiceError("GUARDRAIL_NOT_FOUND", "Guardrail not found", 404)
            guardrail.current_version = version
            snapshot_payload = json.loads(version_row.snapshot_json)
            if not version_row.signature:
                computed_signature, computed_key_id = sign_snapshot(snapshot_payload)
                version_row.signature = computed_signature
                version_row.key_id = computed_key_id
            signature = version_row.signature
            key_id = version_row.key_id
            key = build_snapshot_key(
                str(payload.tenant_id),
                payload.environment_id,
                payload.project_id,
                guardrail_id,
                version,
            )
            await publish_snapshot(
                redis,
                key,
                pack_snapshot_record(snapshot_payload, signature, key_id),
            )
    logger.info(
        "admin.guardrail_version.published tenant_id=%s env=%s project=%s guardrail_id=%s version=%s",
        payload.tenant_id,
        payload.environment_id,
        payload.project_id,
        guardrail_id,
        version,
    )
    return admin_models.PublishResponse(redis_key=key, signature=signature, key_id=key_id)


@router.get("/approvals", response_model=list[admin_models.ApprovalResponse])
async def list_approvals(
    environment_id: str | None = Query(default=None),
    project_id: str | None = Query(default=None),
    status: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    session: AsyncSession = Depends(get_session),
    x_tenant_id: uuid.UUID = Header(alias="X-Tenant-Id"),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> list[admin_models.ApprovalResponse]:
    _require_tenant_access(principal, x_tenant_id, required_role="tenant-auditor")
    stmt = select(ApprovalRequest).where(ApprovalRequest.tenant_id == x_tenant_id)
    if environment_id:
        stmt = stmt.where(ApprovalRequest.environment_id == environment_id)
    if project_id:
        stmt = stmt.where(ApprovalRequest.project_id == project_id)
    if status:
        stmt = stmt.where(ApprovalRequest.status == status.upper())
    stmt = stmt.order_by(ApprovalRequest.created_at.desc()).limit(limit)
    async with session.begin():
        async with tenant_scope(session, str(x_tenant_id)):
            result = await session.execute(stmt)
            rows = result.scalars().all()
    return [_approval_to_response(row) for row in rows]


@router.post("/approvals/{approval_id}/approve", response_model=admin_models.ApprovalResponse)
async def approve_request(
    approval_id: uuid.UUID,
    payload: admin_models.ApprovalResolveRequest,
    session: AsyncSession = Depends(get_session),
    x_tenant_id: uuid.UUID = Header(alias="X-Tenant-Id"),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> admin_models.ApprovalResponse:
    _require_tenant_access(principal, x_tenant_id)
    async with session.begin():
        async with tenant_scope(session, str(x_tenant_id)):
            row = await session.get(ApprovalRequest, approval_id)
            if row is None or row.tenant_id != x_tenant_id:
                raise ServiceError("APPROVAL_NOT_FOUND", "Approval not found", 404)
            row.status = "APPROVED"
            row.reason = payload.reason
            row.resolved_by = payload.resolved_by
            row.resolved_at = dt.datetime.now(dt.timezone.utc)
    return _approval_to_response(row)


@router.post("/approvals/{approval_id}/deny", response_model=admin_models.ApprovalResponse)
async def deny_request(
    approval_id: uuid.UUID,
    payload: admin_models.ApprovalResolveRequest,
    session: AsyncSession = Depends(get_session),
    x_tenant_id: uuid.UUID = Header(alias="X-Tenant-Id"),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> admin_models.ApprovalResponse:
    _require_tenant_access(principal, x_tenant_id)
    async with session.begin():
        async with tenant_scope(session, str(x_tenant_id)):
            row = await session.get(ApprovalRequest, approval_id)
            if row is None or row.tenant_id != x_tenant_id:
                raise ServiceError("APPROVAL_NOT_FOUND", "Approval not found", 404)
            row.status = "DENIED"
            row.reason = payload.reason
            row.resolved_by = payload.resolved_by
            row.resolved_at = dt.datetime.now(dt.timezone.utc)
    return _approval_to_response(row)


@router.get("/jobs", response_model=list[dict])
async def list_guardrail_jobs(
    environment_id: str | None = Query(default=None),
    project_id: str | None = Query(default=None),
    status: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    session: AsyncSession = Depends(get_session),
    x_tenant_id: uuid.UUID = Header(alias="X-Tenant-Id"),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> list[dict]:
    _require_tenant_access(principal, x_tenant_id, required_role="tenant-auditor")
    stmt = select(GuardrailJob).where(GuardrailJob.tenant_id == x_tenant_id)
    if environment_id:
        stmt = stmt.where(GuardrailJob.environment_id == environment_id)
    if project_id:
        stmt = stmt.where(GuardrailJob.project_id == project_id)
    if status:
        stmt = stmt.where(GuardrailJob.status == status.upper())
    stmt = stmt.order_by(GuardrailJob.created_at.desc()).limit(limit)
    async with session.begin():
        async with tenant_scope(session, str(x_tenant_id)):
            result = await session.execute(stmt)
            rows = result.scalars().all()
    return [
        {
            "id": str(row.id),
            "request_id": row.request_id,
            "environment_id": row.environment_id,
            "project_id": row.project_id,
            "guardrail_id": row.guardrail_id,
            "guardrail_version": row.guardrail_version,
            "phase": row.phase,
            "status": row.status,
            "created_at": row.created_at,
            "completed_at": row.completed_at,
            "error_message": row.error_message,
        }
        for row in rows
    ]


@router.put(
    "/guardrails/{environment_id}/{project_id}/{guardrail_id}/publish-gate",
    response_model=admin_models.PublishGateResponse,
)
async def upsert_publish_gate(
    environment_id: str,
    project_id: str,
    guardrail_id: str,
    payload: admin_models.PublishGateUpsertRequest,
    session: AsyncSession = Depends(get_session),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> admin_models.PublishGateResponse:
    _require_tenant_access(principal, payload.tenant_id)
    if (
        payload.environment_id != environment_id
        or payload.project_id != project_id
        or payload.guardrail_id != guardrail_id
    ):
        raise ServiceError("INVALID_REQUEST", "Path and payload identifiers must match", 422)
    async with session.begin():
        async with tenant_scope(session, str(payload.tenant_id)):
            row = await session.get(
                GuardrailPublishGate,
                (payload.tenant_id, environment_id, project_id, guardrail_id),
            )
            if row is None:
                row = GuardrailPublishGate(
                    tenant_id=payload.tenant_id,
                    environment_id=environment_id,
                    project_id=project_id,
                    guardrail_id=guardrail_id,
                )
                session.add(row)
            row.min_expected_action_accuracy = payload.min_expected_action_accuracy
            row.min_expected_allowed_accuracy = payload.min_expected_allowed_accuracy
            row.min_eval_cases = payload.min_eval_cases
            row.max_p95_latency_ms = payload.max_p95_latency_ms
            row.updated_at = dt.datetime.now(dt.timezone.utc)
    return _publish_gate_to_response(row)


@router.get(
    "/guardrails/{environment_id}/{project_id}/{guardrail_id}/publish-gate",
    response_model=admin_models.PublishGateResponse,
)
async def get_publish_gate(
    environment_id: str,
    project_id: str,
    guardrail_id: str,
    session: AsyncSession = Depends(get_session),
    x_tenant_id: uuid.UUID = Header(alias="X-Tenant-Id"),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> admin_models.PublishGateResponse:
    _require_tenant_access(principal, x_tenant_id, required_role="tenant-auditor")
    async with session.begin():
        async with tenant_scope(session, str(x_tenant_id)):
            gate = await session.get(
                GuardrailPublishGate,
                (x_tenant_id, environment_id, project_id, guardrail_id),
            )
            if gate is not None:
                return _publish_gate_to_response(gate)
            default_gate = await resolve_publish_gate(
                session,
                x_tenant_id,
                environment_id,
                project_id,
                guardrail_id,
            )
    return admin_models.PublishGateResponse(
        tenant_id=x_tenant_id,
        environment_id=environment_id,
        project_id=project_id,
        guardrail_id=guardrail_id,
        min_expected_action_accuracy=default_gate.min_expected_action_accuracy,
        min_expected_allowed_accuracy=default_gate.min_expected_allowed_accuracy,
        min_eval_cases=default_gate.min_eval_cases,
        max_p95_latency_ms=default_gate.max_p95_latency_ms,
        updated_at=None,
    )


@router.get("/audit-events", response_model=list[admin_models.AuditEventResponse])
async def list_audit_events(
    environment_id: str | None = Query(default=None),
    project_id: str | None = Query(default=None),
    guardrail_id: str | None = Query(default=None),
    action: str | None = Query(default=None),
    phase: str | None = Query(default=None),
    start_at: dt.datetime | None = Query(default=None),
    end_at: dt.datetime | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    session: AsyncSession = Depends(get_session),
    x_tenant_id: uuid.UUID = Header(alias="X-Tenant-Id"),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> list[admin_models.AuditEventResponse]:
    _require_tenant_access(principal, x_tenant_id, required_role="tenant-auditor")
    stmt = select(AuditEvent).where(AuditEvent.tenant_id == x_tenant_id)
    if environment_id:
        stmt = stmt.where(AuditEvent.environment_id == environment_id)
    if project_id:
        stmt = stmt.where(AuditEvent.project_id == project_id)
    if guardrail_id:
        stmt = stmt.where(AuditEvent.guardrail_id == guardrail_id)
    if action:
        stmt = stmt.where(AuditEvent.action == action.upper())
    if phase:
        stmt = stmt.where(AuditEvent.phase == phase.upper())
    if start_at:
        stmt = stmt.where(AuditEvent.created_at >= start_at)
    if end_at:
        stmt = stmt.where(AuditEvent.created_at <= end_at)
    stmt = stmt.order_by(AuditEvent.created_at.desc()).limit(limit)
    async with session.begin():
        async with tenant_scope(session, str(x_tenant_id)):
            result = await session.execute(stmt)
            rows = result.scalars().all()
    return [_audit_event_to_response(row) for row in rows]


@router.get("/audit-events/export", response_class=PlainTextResponse)
async def export_audit_events(
    environment_id: str | None = Query(default=None),
    project_id: str | None = Query(default=None),
    guardrail_id: str | None = Query(default=None),
    action: str | None = Query(default=None),
    phase: str | None = Query(default=None),
    start_at: dt.datetime | None = Query(default=None),
    end_at: dt.datetime | None = Query(default=None),
    limit: int = Query(default=1000, ge=1, le=5000),
    session: AsyncSession = Depends(get_session),
    x_tenant_id: uuid.UUID = Header(alias="X-Tenant-Id"),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> PlainTextResponse:
    _require_tenant_access(principal, x_tenant_id, required_role="tenant-auditor")
    stmt = select(AuditEvent).where(AuditEvent.tenant_id == x_tenant_id)
    if environment_id:
        stmt = stmt.where(AuditEvent.environment_id == environment_id)
    if project_id:
        stmt = stmt.where(AuditEvent.project_id == project_id)
    if guardrail_id:
        stmt = stmt.where(AuditEvent.guardrail_id == guardrail_id)
    if action:
        stmt = stmt.where(AuditEvent.action == action.upper())
    if phase:
        stmt = stmt.where(AuditEvent.phase == phase.upper())
    if start_at:
        stmt = stmt.where(AuditEvent.created_at >= start_at)
    if end_at:
        stmt = stmt.where(AuditEvent.created_at <= end_at)
    stmt = stmt.order_by(AuditEvent.created_at.desc()).limit(limit)
    async with session.begin():
        async with tenant_scope(session, str(x_tenant_id)):
            result = await session.execute(stmt)
            rows = result.scalars().all()
    lines = [
        json.dumps(
            _audit_event_to_response(row).model_dump(mode="json"),
            separators=(",", ":"),
            ensure_ascii=True,
        )
        for row in rows
    ]
    filename = f"audit-events-{x_tenant_id}.jsonl"
    return PlainTextResponse(
        content="\n".join(lines),
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/audit-events/purge", response_model=admin_models.AuditEventPurgeResponse)
async def purge_audit_events(
    payload: admin_models.AuditEventPurgeRequest,
    session: AsyncSession = Depends(get_session),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> admin_models.AuditEventPurgeResponse:
    _require_tenant_access(principal, payload.tenant_id)
    cutoff = payload.before
    if cutoff is None:
        retain_days = payload.retain_days or settings.audit_default_retention_days
        if retain_days is None:
            raise ServiceError(
                "INVALID_REQUEST",
                "Provide before or retain_days (or configure DUVARAI_AUDIT_DEFAULT_RETENTION_DAYS)",
                422,
            )
        cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=retain_days)
    stmt = delete(AuditEvent).where(
        AuditEvent.tenant_id == payload.tenant_id,
        AuditEvent.created_at < cutoff,
    )
    if payload.environment_id:
        stmt = stmt.where(AuditEvent.environment_id == payload.environment_id)
    if payload.project_id:
        stmt = stmt.where(AuditEvent.project_id == payload.project_id)
    async with session.begin():
        async with tenant_scope(session, str(payload.tenant_id)):
            result = await session.execute(stmt)
            deleted_count = int(result.rowcount or 0)
    return admin_models.AuditEventPurgeResponse(
        deleted_count=deleted_count,
        cutoff=cutoff,
    )


@router.post("/evidence-packs", response_model=admin_models.EvidencePackResponse)
async def create_evidence_pack(
    payload: admin_models.EvidencePackCreateRequest,
    session: AsyncSession = Depends(get_session),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> admin_models.EvidencePackResponse:
    _require_tenant_access(principal, payload.tenant_id, required_role="tenant-auditor")
    timeframe_end = payload.timeframe_end or dt.datetime.now(dt.timezone.utc)
    timeframe_start = payload.timeframe_start or (timeframe_end - dt.timedelta(days=30))
    if timeframe_start > timeframe_end:
        raise ServiceError(
            "INVALID_REQUEST",
            "timeframe_start cannot be after timeframe_end",
            422,
        )
    event_stmt = select(AuditEvent).where(
        AuditEvent.tenant_id == payload.tenant_id,
        AuditEvent.created_at >= timeframe_start,
        AuditEvent.created_at <= timeframe_end,
    )
    approval_stmt = select(ApprovalRequest).where(
        ApprovalRequest.tenant_id == payload.tenant_id,
        ApprovalRequest.created_at >= timeframe_start,
        ApprovalRequest.created_at <= timeframe_end,
    )
    version_stmt = select(GuardrailVersion).where(
        GuardrailVersion.tenant_id == payload.tenant_id,
    )
    if payload.environment_id:
        event_stmt = event_stmt.where(AuditEvent.environment_id == payload.environment_id)
        approval_stmt = approval_stmt.where(
            ApprovalRequest.environment_id == payload.environment_id
        )
        version_stmt = version_stmt.where(
            GuardrailVersion.environment_id == payload.environment_id
        )
    if payload.project_id:
        event_stmt = event_stmt.where(AuditEvent.project_id == payload.project_id)
        approval_stmt = approval_stmt.where(ApprovalRequest.project_id == payload.project_id)
        version_stmt = version_stmt.where(GuardrailVersion.project_id == payload.project_id)
    event_stmt = event_stmt.order_by(AuditEvent.created_at.desc()).limit(5000)
    approval_stmt = approval_stmt.order_by(ApprovalRequest.created_at.desc()).limit(5000)
    version_stmt = version_stmt.order_by(GuardrailVersion.created_at.desc()).limit(5000)
    async with session.begin():
        async with tenant_scope(session, str(payload.tenant_id)):
            events_result = await session.execute(event_stmt)
            approvals_result = await session.execute(approval_stmt)
            versions_result = await session.execute(version_stmt)
            events = events_result.scalars().all()
            approvals = approvals_result.scalars().all()
            versions = versions_result.scalars().all()
            summary, artifact_body = _build_evidence_summary(events, approvals, versions)
            artifact = {
                "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                "regime": payload.regime,
                "scope": {
                    "tenant_id": str(payload.tenant_id),
                    "environment_id": payload.environment_id,
                    "project_id": payload.project_id,
                },
                "timeframe": {
                    "start": timeframe_start.isoformat(),
                    "end": timeframe_end.isoformat(),
                },
                **artifact_body,
            }
            row = EvidencePack(
                tenant_id=payload.tenant_id,
                environment_id=payload.environment_id,
                project_id=payload.project_id,
                regime=payload.regime,
                status="READY",
                timeframe_start=timeframe_start,
                timeframe_end=timeframe_end,
                artifact_json=json.dumps(artifact, separators=(",", ":"), ensure_ascii=True),
                created_by=payload.created_by,
            )
            session.add(row)
    response = _evidence_pack_to_response(row, include_artifact=True)
    response.summary = summary
    return response


@router.get("/evidence-packs", response_model=list[admin_models.EvidencePackResponse])
async def list_evidence_packs(
    environment_id: str | None = Query(default=None),
    project_id: str | None = Query(default=None),
    regime: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    session: AsyncSession = Depends(get_session),
    x_tenant_id: uuid.UUID = Header(alias="X-Tenant-Id"),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> list[admin_models.EvidencePackResponse]:
    _require_tenant_access(principal, x_tenant_id, required_role="tenant-auditor")
    stmt = select(EvidencePack).where(EvidencePack.tenant_id == x_tenant_id)
    if environment_id:
        stmt = stmt.where(EvidencePack.environment_id == environment_id)
    if project_id:
        stmt = stmt.where(EvidencePack.project_id == project_id)
    if regime:
        stmt = stmt.where(EvidencePack.regime == regime.upper())
    stmt = stmt.order_by(EvidencePack.created_at.desc()).limit(limit)
    async with session.begin():
        async with tenant_scope(session, str(x_tenant_id)):
            result = await session.execute(stmt)
            rows = result.scalars().all()
    return [_evidence_pack_to_response(row, include_artifact=False) for row in rows]


@router.get("/evidence-packs/{pack_id}", response_model=admin_models.EvidencePackResponse)
async def get_evidence_pack(
    pack_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    x_tenant_id: uuid.UUID = Header(alias="X-Tenant-Id"),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> admin_models.EvidencePackResponse:
    _require_tenant_access(principal, x_tenant_id, required_role="tenant-auditor")
    async with session.begin():
        async with tenant_scope(session, str(x_tenant_id)):
            row = await session.get(EvidencePack, pack_id)
            if row is None or row.tenant_id != x_tenant_id:
                raise ServiceError("EVIDENCE_PACK_NOT_FOUND", "Evidence pack not found", 404)
    return _evidence_pack_to_response(row, include_artifact=True)


@router.post(
    "/guardrails/{guardrail_id}/simulate",
    response_model=admin_models.PolicySimulationResponse,
)
async def simulate_guardrail_policy(
    guardrail_id: str,
    payload: admin_models.PolicySimulationRequest,
    session: AsyncSession = Depends(get_session),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> admin_models.PolicySimulationResponse:
    _require_tenant_access(principal, payload.tenant_id, required_role="tenant-auditor")
    async with session.begin():
        async with tenant_scope(session, str(payload.tenant_id)):
            guardrail = await resolve_guardrail(
                session,
                payload.tenant_id,
                payload.environment_id,
                payload.project_id,
                guardrail_id,
            )
            license_row = await require_active_license(session, payload.tenant_id)
            allow_llm_calls = license_allows_llm_calls(license_row)
            target_version = payload.guardrail_version or guardrail.current_version
            result = await session.execute(
                select(AuditEvent)
                .where(
                    AuditEvent.tenant_id == payload.tenant_id,
                    AuditEvent.environment_id == payload.environment_id,
                    AuditEvent.project_id == payload.project_id,
                    AuditEvent.guardrail_id == guardrail_id,
                    AuditEvent.phase == payload.phase,
                    AuditEvent.request_payload_json.is_not(None),
                )
                .order_by(AuditEvent.created_at.desc())
                .limit(min(payload.limit * 4, 1000))
            )
            source_events = result.scalars().all()
    simulated_results: list[admin_models.PolicySimulationCaseResponse] = []
    skipped_cases = 0
    for event in source_events:
        if len(simulated_results) >= payload.limit:
            break
        raw_request = _load_json(event.request_payload_json)
        if not raw_request:
            skipped_cases += 1
            continue
        raw_input = raw_request.get("input")
        if not raw_input:
            skipped_cases += 1
            continue
        try:
            input_payload = InputPayload.model_validate(raw_input)
        except Exception:
            skipped_cases += 1
            continue
        engine_request = EngineRequest(
            request_id=f"sim-{event.request_id}-{event.id.hex[:8]}",
            timestamp=dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
            tenant_id=str(payload.tenant_id),
            environment_id=payload.environment_id,
            project_id=payload.project_id,
            guardrail_id=guardrail_id,
            guardrail_version=target_version,
            phase=payload.phase,
            input=input_payload,
            timeout_ms=1500,
            flags=EngineFlags(allow_llm_calls=allow_llm_calls),
        )
        try:
            simulated = await evaluate_engine(engine_request)
        except ServiceError:
            skipped_cases += 1
            continue
        match = (
            event.action == simulated.decision.action
            and bool(event.allowed) == bool(simulated.decision.allowed)
        )
        simulated_results.append(
            admin_models.PolicySimulationCaseResponse(
                audit_event_id=event.id,
                request_id=event.request_id,
                previous_action=event.action,
                simulated_action=simulated.decision.action,
                previous_allowed=bool(event.allowed),
                simulated_allowed=bool(simulated.decision.allowed),
                match=match,
                severity=simulated.decision.severity,
                reason=simulated.decision.reason,
                latency_ms=simulated.latency_ms.total,
                created_at=event.created_at,
            )
        )
    matches = sum(1 for row in simulated_results if row.match)
    compared_cases = len(simulated_results)
    mismatches = compared_cases - matches
    match_rate = 0.0 if compared_cases == 0 else matches / compared_cases
    return admin_models.PolicySimulationResponse(
        compared_cases=compared_cases,
        matches=matches,
        mismatches=mismatches,
        match_rate=match_rate,
        skipped_cases=skipped_cases,
        results=simulated_results,
    )


@router.put(
    "/registry/models/{model_id}",
    response_model=admin_models.ModelRegistryResponse,
)
async def upsert_model_registry_entry(
    model_id: str,
    payload: admin_models.ModelRegistryUpsertRequest,
    session: AsyncSession = Depends(get_session),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> admin_models.ModelRegistryResponse:
    _require_tenant_access(principal, payload.tenant_id)
    if payload.model_id != model_id:
        raise ServiceError("INVALID_REQUEST", "Path model_id and payload model_id must match", 422)
    async with session.begin():
        async with tenant_scope(session, str(payload.tenant_id)):
            row = await session.get(
                ModelRegistryEntry,
                (
                    payload.tenant_id,
                    payload.environment_id,
                    payload.project_id,
                    payload.model_id,
                ),
            )
            if row is None:
                row = ModelRegistryEntry(
                    tenant_id=payload.tenant_id,
                    environment_id=payload.environment_id,
                    project_id=payload.project_id,
                    model_id=payload.model_id,
                    created_at=dt.datetime.now(dt.timezone.utc),
                )
                session.add(row)
            row.display_name = payload.display_name
            row.provider = payload.provider
            row.model_type = payload.model_type
            row.owner = payload.owner
            row.risk_tier = payload.risk_tier
            row.status = payload.status
            row.metadata_json = (
                json.dumps(payload.metadata, separators=(",", ":"), ensure_ascii=True)
                if payload.metadata is not None
                else None
            )
            row.updated_at = dt.datetime.now(dt.timezone.utc)
    return _model_registry_to_response(row)


@router.get(
    "/registry/models",
    response_model=list[admin_models.ModelRegistryResponse],
)
async def list_model_registry_entries(
    environment_id: str | None = Query(default=None),
    project_id: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    session: AsyncSession = Depends(get_session),
    x_tenant_id: uuid.UUID = Header(alias="X-Tenant-Id"),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> list[admin_models.ModelRegistryResponse]:
    _require_tenant_access(principal, x_tenant_id, required_role="tenant-auditor")
    stmt = select(ModelRegistryEntry).where(ModelRegistryEntry.tenant_id == x_tenant_id)
    if environment_id:
        stmt = stmt.where(ModelRegistryEntry.environment_id == environment_id)
    if project_id:
        stmt = stmt.where(ModelRegistryEntry.project_id == project_id)
    stmt = stmt.order_by(ModelRegistryEntry.updated_at.desc()).limit(limit)
    async with session.begin():
        async with tenant_scope(session, str(x_tenant_id)):
            result = await session.execute(stmt)
            rows = result.scalars().all()
    return [_model_registry_to_response(row) for row in rows]


@router.put(
    "/registry/agents/{agent_id}",
    response_model=admin_models.AgentRegistryResponse,
)
async def upsert_agent_registry_entry(
    agent_id: str,
    payload: admin_models.AgentRegistryUpsertRequest,
    session: AsyncSession = Depends(get_session),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> admin_models.AgentRegistryResponse:
    _require_tenant_access(principal, payload.tenant_id)
    if payload.agent_id != agent_id:
        raise ServiceError("INVALID_REQUEST", "Path agent_id and payload agent_id must match", 422)
    async with session.begin():
        async with tenant_scope(session, str(payload.tenant_id)):
            row = await session.get(
                AgentRegistryEntry,
                (
                    payload.tenant_id,
                    payload.environment_id,
                    payload.project_id,
                    payload.agent_id,
                ),
            )
            if row is None:
                row = AgentRegistryEntry(
                    tenant_id=payload.tenant_id,
                    environment_id=payload.environment_id,
                    project_id=payload.project_id,
                    agent_id=payload.agent_id,
                    created_at=dt.datetime.now(dt.timezone.utc),
                )
                session.add(row)
            row.display_name = payload.display_name
            row.runtime = payload.runtime
            row.owner = payload.owner
            row.risk_tier = payload.risk_tier
            row.status = payload.status
            row.metadata_json = (
                json.dumps(payload.metadata, separators=(",", ":"), ensure_ascii=True)
                if payload.metadata is not None
                else None
            )
            row.updated_at = dt.datetime.now(dt.timezone.utc)
    return _agent_registry_to_response(row)


@router.get(
    "/registry/agents",
    response_model=list[admin_models.AgentRegistryResponse],
)
async def list_agent_registry_entries(
    environment_id: str | None = Query(default=None),
    project_id: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    session: AsyncSession = Depends(get_session),
    x_tenant_id: uuid.UUID = Header(alias="X-Tenant-Id"),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> list[admin_models.AgentRegistryResponse]:
    _require_tenant_access(principal, x_tenant_id, required_role="tenant-auditor")
    stmt = select(AgentRegistryEntry).where(AgentRegistryEntry.tenant_id == x_tenant_id)
    if environment_id:
        stmt = stmt.where(AgentRegistryEntry.environment_id == environment_id)
    if project_id:
        stmt = stmt.where(AgentRegistryEntry.project_id == project_id)
    stmt = stmt.order_by(AgentRegistryEntry.updated_at.desc()).limit(limit)
    async with session.begin():
        async with tenant_scope(session, str(x_tenant_id)):
            result = await session.execute(stmt)
            rows = result.scalars().all()
    return [_agent_registry_to_response(row) for row in rows]
