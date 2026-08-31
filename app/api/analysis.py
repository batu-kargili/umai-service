"""Internal endpoints for the analysis worker.

The analyser is a pull-based worker: it asks for work, fetches the transcript,
and posts a result. It never accepts an inbound connection, which is what makes
it deployable inside a customer network without an ingress rule.

These endpoints are service-to-service and authenticate with a shared worker
token, not a user session.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import hmac
import json
import logging
import uuid
from typing import Any

from fastapi import APIRouter, Depends, Header, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import finding_schema
from app.core.db import get_session, tenant_scope
from app.core.errors import ServiceError
from app.core.finding_events import build_finding_event
from app.core.posture_rules import finding_key
from app.core.settings import settings
from app.core.siem import emit_event
from app.core.transcript_store import get_transcript_store
from app.models.db import AiSession, Finding

logger = logging.getLogger("umai.service.analysis")

analysis_router = APIRouter(prefix="/internal/analysis", tags=["analysis"])

# Stage -> (status a session must be in to be claimed, status while claimed)
STAGE_TRANSITIONS = {
    "triage": ("ingested", "triaging"),
    "reason": ("triage_suspicious", "reasoning"),
}


class _BaseModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ClaimRequest(_BaseModel):
    stage: str
    worker_id: str
    limit: int = Field(default=10, ge=1, le=200)
    tenant_id: uuid.UUID | None = None


class ClaimedSession(_BaseModel):
    tenant_id: uuid.UUID
    session_key: str
    source: str
    source_session_id: str
    model: str | None = None
    project_path: str | None = None
    actor_user: str | None = None
    message_count: int
    tool_call_count: int
    posture: dict[str, Any] | None = None
    observed_at: dt.datetime
    threat_tactic: str | None = None


class ClaimResponse(_BaseModel):
    stage: str
    sessions: list[ClaimedSession] = Field(default_factory=list)


class ResultRequest(_BaseModel):
    tenant_id: uuid.UUID
    session_key: str
    stage: str
    verdict: str
    threat_tactic: str | None = None
    confidence: float | None = None
    reason: str | None = None
    model: str | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    cost_usd: float | None = None


class ResultResponse(_BaseModel):
    session_key: str
    analysis_status: str
    finding_raised: bool


def _authenticate_worker(authorization: str | None) -> None:
    expected = (settings.analysis_worker_token or "").strip()
    if not expected:
        raise ServiceError("AUTH_MISCONFIGURED", "Analysis worker auth is not configured", 500)
    if not authorization or not authorization.lower().startswith("bearer "):
        raise ServiceError("UNAUTHENTICATED", "Bearer token required for analysis access", 401)
    if not hmac.compare_digest(authorization.split(" ", 1)[1].strip(), expected):
        raise ServiceError("TOKEN_INVALID", "Analysis worker token is invalid", 401)


def _parse_posture(raw: str | None) -> dict[str, Any] | None:
    if not raw:
        return None
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


@analysis_router.post("/claim", response_model=ClaimResponse)
async def claim_sessions(
    payload: ClaimRequest,
    authorization: str | None = Header(default=None, alias="Authorization"),
    session: AsyncSession = Depends(get_session),
) -> ClaimResponse:
    """Lease a batch of sessions for one analysis stage."""
    _authenticate_worker(authorization)

    transition = STAGE_TRANSITIONS.get(payload.stage)
    if transition is None:
        raise ServiceError("INVALID_REQUEST", f"Unknown analysis stage: {payload.stage}", 422)
    ready_status, claimed_status = transition

    now = dt.datetime.now(dt.timezone.utc)
    lease_cutoff = now - dt.timedelta(seconds=max(settings.analysis_claim_lease_seconds, 60))

    claimed: list[ClaimedSession] = []
    async with session.begin():
        stmt = select(AiSession).where(AiSession.analysis_status == ready_status)
        if payload.tenant_id is not None:
            stmt = stmt.where(AiSession.tenant_id == payload.tenant_id)
        stmt = stmt.order_by(AiSession.observed_at.asc()).limit(payload.limit)
        rows = list((await session.execute(stmt)).scalars().all())

        # Reclaim leases from workers that died mid-stage.
        if len(rows) < payload.limit:
            stale = select(AiSession).where(
                AiSession.analysis_status == claimed_status,
                AiSession.claimed_at < lease_cutoff,
            )
            if payload.tenant_id is not None:
                stale = stale.where(AiSession.tenant_id == payload.tenant_id)
            stale = stale.limit(payload.limit - len(rows))
            rows.extend((await session.execute(stale)).scalars().all())

        for row in rows:
            row.analysis_status = claimed_status
            row.claimed_at = now
            row.claimed_by = payload.worker_id[:64]
            claimed.append(
                ClaimedSession(
                    tenant_id=row.tenant_id,
                    session_key=row.session_key,
                    source=row.source,
                    source_session_id=row.source_session_id,
                    model=row.model,
                    project_path=row.project_path,
                    actor_user=row.actor_user,
                    message_count=row.message_count,
                    tool_call_count=row.tool_call_count,
                    posture=_parse_posture(row.posture_json),
                    observed_at=row.observed_at,
                    threat_tactic=row.threat_tactic,
                )
            )

    if claimed:
        logger.info(
            "analysis.claimed stage=%s worker=%s count=%s",
            payload.stage,
            payload.worker_id,
            len(claimed),
        )
    return ClaimResponse(stage=payload.stage, sessions=claimed)


@analysis_router.get("/transcript/{tenant_id}/{session_key}")
async def fetch_transcript(
    tenant_id: uuid.UUID,
    session_key: str,
    authorization: str | None = Header(default=None, alias="Authorization"),
    session: AsyncSession = Depends(get_session),
) -> Response:
    """Return the stored transcript for a claimed session."""
    _authenticate_worker(authorization)

    async with session.begin():
        async with tenant_scope(session, str(tenant_id)):
            row = await session.get(AiSession, (tenant_id, session_key))
            if row is None:
                raise ServiceError("NOT_FOUND", "Session not found", 404)
            transcript_ref = row.transcript_ref

    try:
        payload = await get_transcript_store().get(transcript_ref)
    except (OSError, ValueError) as exc:
        raise ServiceError("NOT_FOUND", "Transcript is no longer available", 404) from exc

    return Response(content=payload, media_type="application/json")


@analysis_router.post("/result", response_model=ResultResponse)
async def record_analysis_result(
    payload: ResultRequest,
    authorization: str | None = Header(default=None, alias="Authorization"),
    session: AsyncSession = Depends(get_session),
) -> ResultResponse:
    """Record a stage verdict and advance the session's analysis status."""
    _authenticate_worker(authorization)

    if payload.stage not in STAGE_TRANSITIONS:
        raise ServiceError("INVALID_REQUEST", f"Unknown analysis stage: {payload.stage}", 422)

    now = dt.datetime.now(dt.timezone.utc)
    siem_events: list[dict[str, Any]] = []
    finding_raised = False

    async with session.begin():
        async with tenant_scope(session, str(payload.tenant_id)):
            row = await session.get(AiSession, (payload.tenant_id, payload.session_key))
            if row is None:
                raise ServiceError("NOT_FOUND", "Session not found", 404)

            row.claimed_at = None
            row.claimed_by = None
            row.threat_tactic = payload.threat_tactic or row.threat_tactic
            row.confidence = payload.confidence
            row.analyzed_at = now

            if payload.stage == "triage":
                # Triage is a filter, not a verdict: benign ends the pipeline,
                # suspicious hands off to the reasoning stage.
                if payload.verdict == "suspicious":
                    row.analysis_status = "triage_suspicious"
                    row.verdict = None
                else:
                    row.analysis_status = "triage_benign"
                    row.verdict = "benign"
            else:
                row.analysis_status = "analyzed"
                row.verdict = payload.verdict

            # Only the reasoning stage raises a finding. Triage is tuned for
            # recall, so acting on it directly would surface exactly the false
            # positives the second stage exists to remove.
            if payload.stage == "reason" and payload.verdict == "malicious":
                finding_raised, events = await _raise_analysis_finding(
                    session, row=row, payload=payload, now=now
                )
                siem_events.extend(events)

    for event in siem_events:
        asyncio.create_task(emit_event(event))

    logger.info(
        "analysis.result stage=%s session=%s verdict=%s tactic=%s",
        payload.stage,
        payload.session_key,
        payload.verdict,
        payload.threat_tactic,
    )

    return ResultResponse(
        session_key=payload.session_key,
        analysis_status=row.analysis_status,
        finding_raised=finding_raised,
    )


async def _raise_analysis_finding(
    session: AsyncSession,
    *,
    row: AiSession,
    payload: ResultRequest,
    now: dt.datetime,
) -> tuple[bool, list[dict[str, Any]]]:
    """Record the finding produced by the reasoning stage."""
    rule_id = f"detector.{payload.threat_tactic or 'unspecified'}"
    key = finding_key(row.session_key, rule_id)

    existing = (
        await session.execute(
            select(Finding).where(
                Finding.tenant_id == row.tenant_id,
                Finding.finding_key == key,
            )
        )
    ).scalar_one_or_none()

    attributes = {
        "session_key": row.session_key,
        "rule_id": rule_id,
        "technique_id": None,
        "technique_name": None,
        "tactic": payload.threat_tactic,
        "severity": "high",
        "title": "Agent session classified as malicious by the reasoning stage",
        "summary": payload.reason,
        "evidence_json": json.dumps(
            {
                "confidence": payload.confidence,
                "model": payload.model,
                "input_tokens": payload.input_tokens,
                "output_tokens": payload.output_tokens,
                "cost_usd": payload.cost_usd,
            },
            ensure_ascii=False,
        ),
        # The channel, not the AI tool. `row.source` holds the tool
        # (`claude`, `cursor`, …) and stays reachable through `session_key`.
        "source": finding_schema.SOURCE_ADR,
        "category": finding_schema.derive_category(rule_id),
        "actor_user": row.actor_user,
        "actor_device_id": row.actor_device_id,
        "project_path": row.project_path,
        "observed_at": row.observed_at,
        "detector": finding_schema.DETECTOR_REASONING,
    }

    if existing is not None:
        for attribute, value in attributes.items():
            setattr(existing, attribute, value)
        return False, []

    session.add(Finding(tenant_id=row.tenant_id, finding_key=key, status="open", **attributes))
    return True, [build_finding_event(tenant_id=row.tenant_id, finding_key=key, **attributes)]
