"""Operator API for agent sessions and their transcripts.

Drill-down from a finding to the evidence behind it. What comes back depends
on the tenant's collection mode: asking for content a tenant never agreed to
collect gets a clear answer, not an empty one
(contract: transcript-data-modes.md §6).

Every read of transcript content is audited. Read-only collection does not
mean low-sensitivity data — these are the employee's own words, the
customer's data and the company's code.
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import uuid
from typing import Any

from fastapi import APIRouter, Body, Depends, Header, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import finding_schema
from app.core.admin_auth import (
    AdminPrincipal,
    ensure_tenant_access,
    get_admin_principal,
    require_admin_role,
    require_any_admin_role,
)
from app.core.db import get_session, tenant_scope
from app.core.errors import ServiceError
from app.core.transcript_retention import (
    ACTION_READ,
    delete_transcript,
    record_audit_event,
)
from app.core.transcript_store import (
    TranscriptDecryptionError,
    get_transcript_store,
)
from app.models.db import AiSession, Finding, Tenant

logger = logging.getLogger("umai.service.sessions")

sessions_admin_router = APIRouter(
    prefix="/api/v1/admin",
    tags=["sessions"],
    dependencies=[Depends(get_admin_principal)],
)

DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 200


class _BaseModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SessionSummary(_BaseModel):
    session_key: str
    source: str
    source_session_id: str
    actor_user: str | None = None
    actor_device_id: str | None = None
    hostname: str | None = None
    model: str | None = None
    project_path: str | None = None
    title: str | None = None
    message_count: int
    tool_call_count: int
    analysis_status: str
    verdict: str | None = None
    confidence: float | None = None
    threat_tactic: str | None = None
    observed_at: dt.datetime
    ingested_at: dt.datetime | None = None
    collector_name: str | None = None
    collector_version: str | None = None
    finding_count: int = 0


class SessionDetail(SessionSummary):
    # What the session was configured to be allowed to do. Available in every
    # mode: it is configuration, not content.
    posture: dict[str, Any] | None = None
    transcript_available: bool = False
    transcript_bytes: int | None = None
    collection_mode: str


class SessionPage(_BaseModel):
    items: list[SessionSummary]
    total: int
    limit: int
    offset: int


class TranscriptResponse(_BaseModel):
    session_key: str
    collection_mode: str
    transcript: dict[str, Any]


class DeleteTranscriptRequest(_BaseModel):
    # Required. Deleting evidence on request is a decision someone has to own,
    # and a reason is the only part of it a reader months later can use.
    reason: str = Field(min_length=3, max_length=2000)


class DeleteTranscriptResponse(_BaseModel):
    session_key: str
    deleted: bool


async def _tenant_mode(session: AsyncSession, tenant_id: uuid.UUID) -> str:
    """The tenant's collection mode, defaulting to the most restrictive.

    A tenant row that cannot be read is not a reason to hand back content.
    """
    tenant = await session.get(Tenant, tenant_id)
    mode = getattr(tenant, "collection_mode", None)
    if mode in finding_schema.COLLECTION_MODES:
        return mode
    return finding_schema.MODE_POSTURE_ONLY


def _require_read_access(principal: AdminPrincipal, tenant_id: uuid.UUID) -> None:
    ensure_tenant_access(principal, tenant_id)
    require_any_admin_role(principal, "tenant-auditor", "tenant-admin")


def _loads(raw: str | None) -> dict[str, Any] | None:
    if not raw:
        return None
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _summary(row: AiSession, finding_count: int = 0) -> SessionSummary:
    return SessionSummary(
        session_key=row.session_key,
        source=row.source,
        source_session_id=row.source_session_id,
        actor_user=row.actor_user,
        actor_device_id=row.actor_device_id,
        hostname=row.hostname,
        model=row.model,
        project_path=row.project_path,
        title=row.title,
        message_count=row.message_count,
        tool_call_count=row.tool_call_count,
        analysis_status=row.analysis_status,
        verdict=row.verdict,
        confidence=row.confidence,
        threat_tactic=row.threat_tactic,
        observed_at=row.observed_at,
        ingested_at=row.ingested_at,
        collector_name=row.collector_name,
        collector_version=row.collector_version,
        finding_count=finding_count,
    )


async def query_sessions(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    source: str | None = None,
    actor_user: str | None = None,
    actor_device_id: str | None = None,
    analysis_status: str | None = None,
    verdict: str | None = None,
    observed_after: dt.datetime | None = None,
    observed_before: dt.datetime | None = None,
    limit: int = DEFAULT_PAGE_SIZE,
    offset: int = 0,
) -> SessionPage:
    """Sessions for a tenant, newest first."""
    filters = [AiSession.tenant_id == tenant_id]
    for column, value in (
        (AiSession.source, source),
        (AiSession.actor_user, actor_user),
        (AiSession.actor_device_id, actor_device_id),
        (AiSession.analysis_status, analysis_status),
        (AiSession.verdict, verdict),
    ):
        if value is not None:
            filters.append(column == value)
    if observed_after is not None:
        filters.append(AiSession.observed_at >= observed_after)
    if observed_before is not None:
        filters.append(AiSession.observed_at < observed_before)

    stmt = (
        select(AiSession)
        .where(*filters)
        # `session_key` breaks ties: one collector run ingests a batch with
        # timestamps that can collide, and paging must not skip or repeat.
        .order_by(AiSession.observed_at.desc(), AiSession.session_key.asc())
        .limit(limit)
        .offset(offset)
    )

    async with session.begin():
        async with tenant_scope(session, str(tenant_id)):
            rows = list((await session.execute(stmt)).scalars().all())
            total = int(
                (
                    await session.execute(
                        select(func.count()).select_from(AiSession).where(*filters)
                    )
                ).scalar_one()
            )
            counts: dict[str, int] = {}
            if rows:
                keys = [row.session_key for row in rows]
                for key, count in (
                    await session.execute(
                        select(Finding.session_key, func.count())
                        .where(
                            Finding.tenant_id == tenant_id,
                            Finding.session_key.in_(keys),
                        )
                        .group_by(Finding.session_key)
                    )
                ).all():
                    counts[key] = count

    return SessionPage(
        items=[_summary(row, counts.get(row.session_key, 0)) for row in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


async def load_session(
    session: AsyncSession, *, tenant_id: uuid.UUID, session_key: str
) -> SessionDetail:
    """One session with its posture and whether its transcript is still there."""
    async with session.begin():
        async with tenant_scope(session, str(tenant_id)):
            row = await session.get(AiSession, (tenant_id, session_key))
            if row is None:
                raise ServiceError("NOT_FOUND", "Session not found", 404)
            mode = await _tenant_mode(session, tenant_id)
            finding_count = int(
                (
                    await session.execute(
                        select(func.count())
                        .select_from(Finding)
                        .where(
                            Finding.tenant_id == tenant_id,
                            Finding.session_key == session_key,
                        )
                    )
                ).scalar_one()
            )

    detail = SessionDetail(
        **_summary(row, finding_count).model_dump(),
        posture=_loads(row.posture_json),
        # Retention deletes transcripts while the session row stays. The UI
        # must be able to say "evidence expired" rather than showing an error.
        transcript_available=bool(row.transcript_ref)
        and mode in finding_schema.MODES_WITH_CONTENT,
        transcript_bytes=row.transcript_bytes,
        collection_mode=mode,
    )
    return detail


async def load_transcript(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    session_key: str,
    actor: str,
) -> TranscriptResponse:
    """The session transcript, if this tenant collects content at all."""
    async with session.begin():
        async with tenant_scope(session, str(tenant_id)):
            row = await session.get(AiSession, (tenant_id, session_key))
            if row is None:
                raise ServiceError("NOT_FOUND", "Session not found", 404)
            mode = await _tenant_mode(session, tenant_id)
            transcript_ref = row.transcript_ref

    if mode not in finding_schema.MODES_WITH_CONTENT:
        # Deliberately not 404: the session exists, and "we do not collect
        # content for you" is a different fact from "no such session". An
        # operator chasing missing evidence deserves to know which.
        raise ServiceError(
            "CONTENT_NOT_COLLECTED",
            f"This tenant collects transcripts in `{mode}` mode, which stores no "
            "message or tool content.",
            409,
        )

    if not transcript_ref:
        raise ServiceError(
            "TRANSCRIPT_UNAVAILABLE",
            "The transcript for this session is no longer stored.",
            410,
        )

    try:
        payload = await get_transcript_store().get(transcript_ref)
    except TranscriptDecryptionError as exc:
        # The evidence is on disk and the deployment is misconfigured. Calling
        # that "expired" would quietly lose it.
        raise ServiceError("TRANSCRIPT_UNREADABLE", str(exc), 500) from exc
    except (OSError, ValueError, KeyError) as exc:
        # Retention removed it, or the blob store lost it. Either way the
        # finding survives without its evidence body.
        raise ServiceError(
            "TRANSCRIPT_UNAVAILABLE",
            "The transcript for this session is no longer stored.",
            410,
        ) from exc

    # Audited because it is content: who read whose session, and when. The row
    # is what makes the claim checkable; the log line is for operations.
    async with session.begin():
        record_audit_event(
            session,
            tenant_id=tenant_id,
            session_key=session_key,
            action=ACTION_READ,
            actor=actor,
            transcript_bytes=len(payload),
        )
    logger.info(
        "transcript.read tenant=%s session=%s actor=%s bytes=%s",
        tenant_id,
        session_key[:12],
        actor,
        len(payload),
    )

    return TranscriptResponse(
        session_key=session_key,
        collection_mode=mode,
        transcript=json.loads(payload),
    )


async def remove_transcript(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    session_key: str,
    actor: str,
    reason: str,
) -> DeleteTranscriptResponse:
    """Delete the stored transcript for one session, on request.

    Idempotent: a session whose transcript is already gone reports
    ``deleted=False`` rather than failing, so a retried request from a data
    subject workflow does not look like an error.
    """
    deleted = await delete_transcript(
        session,
        tenant_id=tenant_id,
        session_key=session_key,
        actor=actor,
        reason=reason,
    )
    return DeleteTranscriptResponse(session_key=session_key, deleted=deleted)


# --- HTTP surface -----------------------------------------------------------


@sessions_admin_router.get("/sessions", response_model=SessionPage)
async def list_sessions_endpoint(
    source: str | None = Query(default=None),
    actor_user: str | None = Query(default=None),
    actor_device_id: str | None = Query(default=None),
    analysis_status: str | None = Query(default=None),
    verdict: str | None = Query(default=None),
    observed_after: dt.datetime | None = Query(default=None),
    observed_before: dt.datetime | None = Query(default=None),
    limit: int = Query(default=DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
    offset: int = Query(default=0, ge=0),
    session: AsyncSession = Depends(get_session),
    x_tenant_id: uuid.UUID = Header(alias="X-Tenant-Id"),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> SessionPage:
    _require_read_access(principal, x_tenant_id)
    return await query_sessions(
        session,
        tenant_id=x_tenant_id,
        source=source,
        actor_user=actor_user,
        actor_device_id=actor_device_id,
        analysis_status=analysis_status,
        verdict=verdict,
        observed_after=observed_after,
        observed_before=observed_before,
        limit=limit,
        offset=offset,
    )


@sessions_admin_router.get("/sessions/{session_key}", response_model=SessionDetail)
async def get_session_endpoint(
    session_key: str,
    session: AsyncSession = Depends(get_session),
    x_tenant_id: uuid.UUID = Header(alias="X-Tenant-Id"),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> SessionDetail:
    _require_read_access(principal, x_tenant_id)
    return await load_session(session, tenant_id=x_tenant_id, session_key=session_key)


@sessions_admin_router.get(
    "/sessions/{session_key}/transcript", response_model=TranscriptResponse
)
async def get_transcript_endpoint(
    session_key: str,
    session: AsyncSession = Depends(get_session),
    x_tenant_id: uuid.UUID = Header(alias="X-Tenant-Id"),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> TranscriptResponse:
    _require_read_access(principal, x_tenant_id)
    return await load_transcript(
        session,
        tenant_id=x_tenant_id,
        session_key=session_key,
        actor=principal.subject or "unknown",
    )


@sessions_admin_router.delete(
    "/sessions/{session_key}/transcript", response_model=DeleteTranscriptResponse
)
async def delete_transcript_endpoint(
    session_key: str,
    body: DeleteTranscriptRequest = Body(...),
    session: AsyncSession = Depends(get_session),
    x_tenant_id: uuid.UUID = Header(alias="X-Tenant-Id"),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> DeleteTranscriptResponse:
    # Deletion is destructive and outward-facing in the sense that matters
    # here: the evidence behind a finding stops existing. Auditor is not
    # enough.
    ensure_tenant_access(principal, x_tenant_id)
    require_admin_role(principal, "tenant-admin")
    return await remove_transcript(
        session,
        tenant_id=x_tenant_id,
        session_key=session_key,
        actor=principal.subject or "unknown",
        reason=body.reason,
    )
