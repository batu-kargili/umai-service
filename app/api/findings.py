"""Operator API for the finding queue.

The queue is what a SOC analyst actually works from, so it is one canonical
list across every channel — ADR, extension, SDK, red team — filtered rather
than split (contract §4.1, UMA-40).

Read access requires `tenant-auditor` or `tenant-admin`; the lifecycle transitions in UMA-46
require more.
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import uuid
from typing import Any

from fastapi import APIRouter, Depends, Header, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import finding_schema
from app.core.admin_auth import AdminPrincipal, get_admin_principal
from app.core.db import get_session, tenant_scope
from app.core.errors import ServiceError
from app.core.siem_drain import replay as replay_delivery
from app.core.siem_outbox import (
    STATUS_DEAD_LETTER,
    STATUS_DELIVERED,
    STATUS_PENDING,
    delivery_status,
)
from app.models.db import AiSession, Finding, FindingStatusEvent, SiemOutbox

logger = logging.getLogger("umai.service.findings")

findings_admin_router = APIRouter(
    prefix="/api/v1/admin",
    tags=["findings"],
    dependencies=[Depends(get_admin_principal)],
)

# A page big enough to be useful, small enough that one tenant cannot pull the
# whole table in a single request.
DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 200


class _BaseModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class FindingSummary(_BaseModel):
    finding_key: str
    session_key: str
    rule_id: str
    title: str
    severity: str
    category: str
    status: str
    source: str
    detector: str
    technique_id: str | None = None
    technique_name: str | None = None
    tactic: str | None = None
    actor_user: str | None = None
    actor_device_id: str | None = None
    project_path: str | None = None
    assignee: str | None = None
    observed_at: dt.datetime | None = None
    detected_at: dt.datetime | None = None
    emitted_at: dt.datetime | None = None


class StatusEvent(_BaseModel):
    from_status: str | None = None
    to_status: str
    actor: str
    note: str | None = None
    occurred_at: dt.datetime


class SessionContext(_BaseModel):
    """Just enough of the session to orient the analyst before drilling in."""

    source: str
    source_session_id: str
    model: str | None = None
    message_count: int
    tool_call_count: int
    analysis_status: str
    verdict: str | None = None
    confidence: float | None = None
    observed_at: dt.datetime


class DeliveryStatus(_BaseModel):
    """Where this finding's SIEM delivery stands.

    Answers the question a SOC lead actually asks: did QRadar get it?
    """

    status: str
    attempts: int
    last_error: str | None = None
    next_attempt_at: dt.datetime | None = None
    delivered_at: dt.datetime | None = None
    replayed_at: dt.datetime | None = None
    replayed_by: str | None = None


class FindingDetail(FindingSummary):
    summary: str | None = None
    evidence: dict[str, Any] | None = None
    remediation: dict[str, Any] | None = None
    history: list[StatusEvent] = Field(default_factory=list)
    session: SessionContext | None = None
    delivery: DeliveryStatus | None = None


class FindingPage(_BaseModel):
    items: list[FindingSummary]
    total: int
    limit: int
    offset: int


def _require_read_access(principal: AdminPrincipal, tenant_id: uuid.UUID) -> None:
    from app.core.admin_auth import ensure_tenant_access, require_any_admin_role

    ensure_tenant_access(principal, tenant_id)
    require_any_admin_role(principal, "tenant-auditor", "tenant-admin")


def _loads(raw: str | None) -> dict[str, Any] | None:
    if not raw:
        return None
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        # Evidence is written by detectors. Malformed JSON is their bug, but
        # it must not take the queue down for the analyst.
        return None
    return parsed if isinstance(parsed, dict) else None


def _summary(row: Finding) -> FindingSummary:
    return FindingSummary(
        finding_key=row.finding_key,
        session_key=row.session_key,
        rule_id=row.rule_id,
        title=row.title,
        severity=row.severity,
        category=row.category,
        status=row.status,
        source=row.source,
        detector=row.detector,
        technique_id=row.technique_id,
        technique_name=row.technique_name,
        tactic=row.tactic,
        actor_user=row.actor_user,
        actor_device_id=row.actor_device_id,
        project_path=row.project_path,
        assignee=row.assignee,
        observed_at=row.observed_at,
        detected_at=row.detected_at,
        emitted_at=row.emitted_at,
    )


def _validate(name: str, value: str | None, allowed: frozenset[str]) -> None:
    """Reject an unknown filter value instead of returning an empty page.

    An empty page reads as "nothing matched"; a typo in a filter should not be
    indistinguishable from a clean queue.
    """
    if value is not None and value not in allowed:
        raise ServiceError(
            "INVALID_REQUEST",
            f"Unknown {name}: {value}. Expected one of {sorted(allowed)}.",
            422,
        )


async def query_findings(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    status: str | None = None,
    severity: str | None = None,
    category: str | None = None,
    source: str | None = None,
    detector: str | None = None,
    actor_user: str | None = None,
    actor_device_id: str | None = None,
    session_key: str | None = None,
    assignee: str | None = None,
    detected_after: dt.datetime | None = None,
    detected_before: dt.datetime | None = None,
    limit: int = DEFAULT_PAGE_SIZE,
    offset: int = 0,
) -> FindingPage:
    """The finding queue, filtered.

    Plain function rather than route body so the query behaviour is testable
    without standing up HTTP and auth, matching the pattern already used for
    the applications dashboard.
    """
    _validate("status", status, finding_schema.STATUSES)
    _validate("severity", severity, finding_schema.SEVERITIES)
    _validate("category", category, finding_schema.CATEGORIES)
    _validate("source", source, finding_schema.SOURCES)
    _validate("detector", detector, finding_schema.DETECTORS)

    filters = [Finding.tenant_id == tenant_id]
    for column, value in (
        (Finding.status, status),
        (Finding.severity, severity),
        (Finding.category, category),
        (Finding.source, source),
        (Finding.detector, detector),
        (Finding.actor_user, actor_user),
        (Finding.actor_device_id, actor_device_id),
        (Finding.session_key, session_key),
        (Finding.assignee, assignee),
    ):
        if value is not None:
            filters.append(column == value)
    if detected_after is not None:
        filters.append(Finding.detected_at >= detected_after)
    if detected_before is not None:
        filters.append(Finding.detected_at < detected_before)

    # `finding_key` breaks ties so paging cannot show or skip a row when two
    # findings share a timestamp — which they routinely do, because one ingest
    # batch raises them together.
    stmt = (
        select(Finding)
        .where(*filters)
        .order_by(Finding.detected_at.desc(), Finding.finding_key.asc())
        .limit(limit)
        .offset(offset)
    )
    count_stmt = select(func.count()).select_from(Finding).where(*filters)

    async with session.begin():
        async with tenant_scope(session, str(tenant_id)):
            rows = list((await session.execute(stmt)).scalars().all())
            total = int((await session.execute(count_stmt)).scalar_one())

    return FindingPage(
        items=[_summary(row) for row in rows], total=total, limit=limit, offset=offset
    )


async def load_finding(
    session: AsyncSession, *, tenant_id: uuid.UUID, finding_key: str
) -> FindingDetail:
    """One finding with its evidence, its audit trail and its session context."""
    x_tenant_id = tenant_id
    async with session.begin():
        async with tenant_scope(session, str(x_tenant_id)):
            row = await session.get(Finding, (x_tenant_id, finding_key))
            if row is None:
                raise ServiceError("NOT_FOUND", "Finding not found", 404)

            history = list(
                (
                    await session.execute(
                        select(FindingStatusEvent)
                        .where(
                            FindingStatusEvent.tenant_id == x_tenant_id,
                            FindingStatusEvent.finding_key == finding_key,
                        )
                        .order_by(FindingStatusEvent.occurred_at.desc())
                    )
                )
                .scalars()
                .all()
            )
            ai_session = await session.get(AiSession, (x_tenant_id, row.session_key))
            outbox = await delivery_status(session, tenant_id=x_tenant_id, event_id=finding_key)

    detail = FindingDetail(
        **_summary(row).model_dump(),
        summary=row.summary,
        evidence=_loads(row.evidence_json),
        remediation=_loads(row.remediation_json),
        history=[
            StatusEvent(
                from_status=event.from_status,
                to_status=event.to_status,
                actor=event.actor,
                note=event.note,
                occurred_at=event.occurred_at,
            )
            for event in history
        ],
    )

    if outbox is not None:
        detail.delivery = DeliveryStatus(
            status=outbox.status,
            attempts=outbox.attempts,
            last_error=outbox.last_error,
            next_attempt_at=outbox.next_attempt_at,
            delivered_at=outbox.delivered_at,
            replayed_at=outbox.replayed_at,
            replayed_by=outbox.replayed_by,
        )

    if ai_session is not None:
        detail.session = SessionContext(
            source=ai_session.source,
            source_session_id=ai_session.source_session_id,
            model=ai_session.model,
            message_count=ai_session.message_count,
            tool_call_count=ai_session.tool_call_count,
            analysis_status=ai_session.analysis_status,
            verdict=ai_session.verdict,
            confidence=ai_session.confidence,
            observed_at=ai_session.observed_at,
        )

    return detail


# --- lifecycle --------------------------------------------------------------


class TransitionRequest(_BaseModel):
    to_status: str
    note: str | None = None


class AssignRequest(_BaseModel):
    # Explicit null clears the assignment.
    assignee: str | None = None


def _require_write_access(principal: AdminPrincipal, tenant_id: uuid.UUID) -> None:
    from app.api.admin import _require_tenant_access

    _require_tenant_access(principal, tenant_id, required_role="tenant-admin")


async def _get_for_update(
    session: AsyncSession, tenant_id: uuid.UUID, finding_key: str
) -> Finding:
    row = await session.get(Finding, (tenant_id, finding_key))
    if row is None:
        raise ServiceError("NOT_FOUND", "Finding not found", 404)
    return row


async def transition_finding(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    finding_key: str,
    to_status: str,
    actor: str,
    note: str | None = None,
) -> FindingDetail:
    """Move a finding through its lifecycle, recording who and why.

    The audit row is written in the same transaction as the status change, so
    the trail cannot end up missing a step that actually happened.
    """
    _validate("status", to_status, finding_schema.STATUSES)

    async with session.begin():
        async with tenant_scope(session, str(tenant_id)):
            row = await _get_for_update(session, tenant_id, finding_key)
            from_status = row.status

            if to_status == from_status:
                raise ServiceError(
                    "INVALID_REQUEST",
                    f"Finding is already {to_status}",
                    409,
                )

            allowed = finding_schema.allowed_transitions(from_status)
            if to_status not in allowed:
                raise ServiceError(
                    "INVALID_TRANSITION",
                    f"Cannot move a finding from {from_status} to {to_status}. "
                    f"Allowed: {sorted(allowed)}.",
                    409,
                )

            if finding_schema.transition_requires_note(from_status, to_status) and not (
                note or ""
            ).strip():
                raise ServiceError(
                    "NOTE_REQUIRED",
                    f"Moving from {from_status} to {to_status} requires a note",
                    422,
                )

            row.status = to_status
            session.add(
                FindingStatusEvent(
                    id=uuid.uuid4(),
                    tenant_id=tenant_id,
                    finding_key=finding_key,
                    from_status=from_status,
                    to_status=to_status,
                    actor=actor,
                    note=(note or None),
                    # Set here, not left to the column default: CURRENT_TIMESTAMP
                    # is second-granular on SQLite, so two transitions a second
                    # apart would share a timestamp and the trail would lose its
                    # order. An operator can easily click twice in one second.
                    occurred_at=dt.datetime.now(dt.timezone.utc),
                )
            )

    logger.info(
        "finding.transition tenant=%s finding=%s %s->%s actor=%s",
        tenant_id,
        finding_key[:12],
        from_status,
        to_status,
        actor,
    )
    return await load_finding(session, tenant_id=tenant_id, finding_key=finding_key)


async def assign_finding(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    finding_key: str,
    assignee: str | None,
    actor: str,
) -> FindingDetail:
    """Put the finding on someone's plate, or take it off.

    Assignment is not a status change and is not audited in the status trail:
    it says who is looking, not what was decided.
    """
    async with session.begin():
        async with tenant_scope(session, str(tenant_id)):
            row = await _get_for_update(session, tenant_id, finding_key)
            row.assignee = (assignee or None)

    logger.info(
        "finding.assign tenant=%s finding=%s assignee=%s actor=%s",
        tenant_id,
        finding_key[:12],
        assignee,
        actor,
    )
    return await load_finding(session, tenant_id=tenant_id, finding_key=finding_key)


# --- HTTP surface -----------------------------------------------------------
# Thin wrappers: auth, then delegate. Keeping the query logic in plain
# functions above is what lets it be tested without HTTP.


@findings_admin_router.get("/findings", response_model=FindingPage)
async def list_findings_endpoint(
    status: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    category: str | None = Query(default=None),
    source: str | None = Query(default=None),
    detector: str | None = Query(default=None),
    actor_user: str | None = Query(default=None),
    actor_device_id: str | None = Query(default=None),
    session_key: str | None = Query(default=None),
    assignee: str | None = Query(default=None),
    detected_after: dt.datetime | None = Query(default=None),
    detected_before: dt.datetime | None = Query(default=None),
    limit: int = Query(default=DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
    offset: int = Query(default=0, ge=0),
    session: AsyncSession = Depends(get_session),
    x_tenant_id: uuid.UUID = Header(alias="X-Tenant-Id"),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> FindingPage:
    _require_read_access(principal, x_tenant_id)
    return await query_findings(
        session,
        tenant_id=x_tenant_id,
        status=status,
        severity=severity,
        category=category,
        source=source,
        detector=detector,
        actor_user=actor_user,
        actor_device_id=actor_device_id,
        session_key=session_key,
        assignee=assignee,
        detected_after=detected_after,
        detected_before=detected_before,
        limit=limit,
        offset=offset,
    )


@findings_admin_router.get("/findings/{finding_key}", response_model=FindingDetail)
async def get_finding_endpoint(
    finding_key: str,
    session: AsyncSession = Depends(get_session),
    x_tenant_id: uuid.UUID = Header(alias="X-Tenant-Id"),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> FindingDetail:
    _require_read_access(principal, x_tenant_id)
    return await load_finding(session, tenant_id=x_tenant_id, finding_key=finding_key)


@findings_admin_router.post(
    "/findings/{finding_key}/status", response_model=FindingDetail
)
async def transition_finding_endpoint(
    finding_key: str,
    payload: TransitionRequest,
    session: AsyncSession = Depends(get_session),
    x_tenant_id: uuid.UUID = Header(alias="X-Tenant-Id"),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> FindingDetail:
    _require_write_access(principal, x_tenant_id)
    return await transition_finding(
        session,
        tenant_id=x_tenant_id,
        finding_key=finding_key,
        to_status=payload.to_status,
        actor=principal.subject or "unknown",
        note=payload.note,
    )


@findings_admin_router.post(
    "/findings/{finding_key}/assignee", response_model=FindingDetail
)
async def assign_finding_endpoint(
    finding_key: str,
    payload: AssignRequest,
    session: AsyncSession = Depends(get_session),
    x_tenant_id: uuid.UUID = Header(alias="X-Tenant-Id"),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> FindingDetail:
    _require_write_access(principal, x_tenant_id)
    return await assign_finding(
        session,
        tenant_id=x_tenant_id,
        finding_key=finding_key,
        assignee=payload.assignee,
        actor=principal.subject or "unknown",
    )


class DeliveryStats(_BaseModel):
    """Operator-facing health of the SIEM integration.

    Published here rather than as Prometheus metrics: a scrape surface is
    G3's job (UMA-88). What an operator needs today is whether findings are
    reaching the SOC and how old the backlog is.
    """

    pending: int
    delivered: int
    dead_letter: int
    oldest_pending_age_seconds: float | None = None


async def delivery_stats(
    session: AsyncSession, *, tenant_id: uuid.UUID, now: dt.datetime | None = None
) -> DeliveryStats:
    now = now or dt.datetime.now(dt.timezone.utc)
    async with session.begin():
        async with tenant_scope(session, str(tenant_id)):
            rows = (
                await session.execute(
                    select(SiemOutbox.status, func.count(), func.min(SiemOutbox.created_at))
                    .where(SiemOutbox.tenant_id == tenant_id)
                    .group_by(SiemOutbox.status)
                )
            ).all()

    counts = {status: count for status, count, _ in rows}
    oldest_pending = next(
        (oldest for status, _, oldest in rows if status == STATUS_PENDING), None
    )

    age = None
    if oldest_pending is not None:
        # SQLite hands back naive datetimes for timezone-aware columns.
        if oldest_pending.tzinfo is None:
            oldest_pending = oldest_pending.replace(tzinfo=dt.timezone.utc)
        age = max((now - oldest_pending).total_seconds(), 0.0)

    return DeliveryStats(
        pending=counts.get(STATUS_PENDING, 0),
        delivered=counts.get(STATUS_DELIVERED, 0),
        dead_letter=counts.get(STATUS_DEAD_LETTER, 0),
        oldest_pending_age_seconds=age,
    )


@findings_admin_router.get("/siem-delivery/stats", response_model=DeliveryStats)
async def delivery_stats_endpoint(
    session: AsyncSession = Depends(get_session),
    x_tenant_id: uuid.UUID = Header(alias="X-Tenant-Id"),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> DeliveryStats:
    _require_read_access(principal, x_tenant_id)
    return await delivery_stats(session, tenant_id=x_tenant_id)


@findings_admin_router.post(
    "/findings/{finding_key}/replay-delivery", response_model=FindingDetail
)
async def replay_delivery_endpoint(
    finding_key: str,
    session: AsyncSession = Depends(get_session),
    x_tenant_id: uuid.UUID = Header(alias="X-Tenant-Id"),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> FindingDetail:
    """Requeue a dead-lettered delivery. Recorded against the row."""
    _require_write_access(principal, x_tenant_id)
    moved = await replay_delivery(
        session,
        tenant_id=x_tenant_id,
        event_id=finding_key,
        actor=principal.subject or "unknown",
    )
    if not moved:
        raise ServiceError(
            "NOT_REPLAYABLE",
            "No dead-lettered delivery for this finding",
            409,
        )
    return await load_finding(session, tenant_id=x_tenant_id, finding_key=finding_key)
