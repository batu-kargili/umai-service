"""Deleting transcripts: on a schedule, and on request.

Transcripts age out long before the sessions and findings that reference them
(contract: transcript-data-modes.md §7 — transcript 30 days, sessions and
findings 13 months). A finding whose evidence has expired is still a finding;
it just says the transcript is gone.

Two callers, one path. The retention sweep is the clock deleting content
nobody asked about; on-demand deletion is a person deleting content someone
did ask about, which is why it demands a reason. Both write to the same audit
trail, because "we deleted it" is a claim that has to be checkable.
"""

from __future__ import annotations

import datetime as dt
import logging
import uuid
from dataclasses import dataclass

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.settings import settings
from app.core.transcript_store import TranscriptStore, get_transcript_store
from app.models.db import AiSession, Tenant, TranscriptAuditEvent

logger = logging.getLogger("umai.service.transcript_retention")

ACTION_READ = "read"
ACTION_DELETE_ON_DEMAND = "delete_on_demand"
ACTION_DELETE_RETENTION = "delete_retention"

DEFAULT_RETENTION_DAYS = 30

# A sweep deletes evidence, so it works in bounded batches: a bug that
# mis-computes the cut-off takes out one batch before anyone can stop it,
# not the whole store.
DEFAULT_BATCH = 200


@dataclass
class ReapResult:
    scanned: int = 0
    deleted: int = 0
    blobs_removed: int = 0
    # Deleting the pointer while the blob survives is correct when another
    # session still references the same content.
    blobs_shared: int = 0
    failed: int = 0


def record_audit_event(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    session_key: str,
    action: str,
    actor: str | None = None,
    reason: str | None = None,
    transcript_bytes: int | None = None,
    now: dt.datetime | None = None,
) -> TranscriptAuditEvent:
    """Add an audit row to the caller's transaction.

    Deliberately not committing: the audit entry and the thing it describes
    have to land together, or an operator reads a deletion that never happened.
    `occurred_at` is stamped in Python rather than left to the database so two
    events in the same second keep their order.
    """
    event = TranscriptAuditEvent(
        tenant_id=tenant_id,
        session_key=session_key,
        action=action,
        actor=actor,
        reason=reason,
        transcript_bytes=transcript_bytes,
        occurred_at=now or dt.datetime.now(dt.timezone.utc),
    )
    db.add(event)
    return event


async def _blob_is_shared(
    db: AsyncSession, *, tenant_id: uuid.UUID, transcript_ref: str, session_key: str
) -> bool:
    """Whether another session points at the same blob.

    Storage is content-addressed, so two identical transcripts are one file.
    Deleting the file because one of them expired would silently destroy the
    other one's evidence.
    """
    count = (
        await db.execute(
            select(func.count())
            .select_from(AiSession)
            .where(
                AiSession.tenant_id == tenant_id,
                AiSession.transcript_ref == transcript_ref,
                AiSession.session_key != session_key,
            )
        )
    ).scalar_one()
    return bool(count)


async def _detach_transcript(
    db: AsyncSession,
    row: AiSession,
    *,
    store: TranscriptStore,
    action: str,
    actor: str | None,
    reason: str | None,
    now: dt.datetime,
) -> tuple[bool, bool]:
    """Remove one transcript. Returns (blob_removed, blob_shared).

    Order matters: the blob goes first. A crash between the two leaves a row
    pointing at nothing, which the API already reports as expired. The reverse
    order would leave content on disk that nothing references and nothing will
    ever clean up.
    """
    ref = row.transcript_ref
    shared = await _blob_is_shared(
        db, tenant_id=row.tenant_id, transcript_ref=ref, session_key=row.session_key
    )

    removed = False
    if not shared:
        removed = await store.delete(ref)

    record_audit_event(
        db,
        tenant_id=row.tenant_id,
        session_key=row.session_key,
        action=action,
        actor=actor,
        reason=reason,
        transcript_bytes=row.transcript_bytes,
        now=now,
    )

    row.transcript_ref = None
    row.transcript_sha256 = None
    row.transcript_bytes = None
    return removed, shared


async def delete_transcript(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    session_key: str,
    actor: str,
    reason: str,
    store: TranscriptStore | None = None,
    now: dt.datetime | None = None,
) -> bool:
    """Delete one transcript on request. Returns whether anything was deleted.

    Idempotent: deleting an already-deleted transcript is not an error, and
    does not add a second audit entry for a deletion that did not happen.
    """
    store = store or get_transcript_store()
    now = now or dt.datetime.now(dt.timezone.utc)

    async with db.begin():
        row = await db.get(AiSession, (tenant_id, session_key))
        if row is None or not row.transcript_ref:
            return False
        await _detach_transcript(
            db,
            row,
            store=store,
            action=ACTION_DELETE_ON_DEMAND,
            actor=actor,
            reason=reason,
            now=now,
        )

    logger.info(
        "transcript.deleted tenant=%s session=%s actor=%s",
        tenant_id,
        session_key[:12],
        actor,
    )
    return True


async def reap_expired_transcripts(
    db: AsyncSession,
    *,
    store: TranscriptStore | None = None,
    now: dt.datetime | None = None,
    limit: int = DEFAULT_BATCH,
) -> ReapResult:
    """Delete transcripts past their tenant's retention window.

    Age is measured from `observed_at` — when the conversation happened —
    rather than from ingest. A collector that uploads a backlog after being
    offline for a month must not restart the clock on content that is already
    older than the customer agreed to keep.
    """
    store = store or get_transcript_store()
    now = now or dt.datetime.now(dt.timezone.utc)
    result = ReapResult()

    async with db.begin():
        retention: dict[uuid.UUID, int] = {
            tenant_id: days or DEFAULT_RETENTION_DAYS
            for tenant_id, days in (
                await db.execute(
                    select(Tenant.tenant_id, Tenant.transcript_retention_days)
                )
            ).all()
        }

        rows = list(
            (
                await db.execute(
                    select(AiSession)
                    .where(AiSession.transcript_ref.is_not(None))
                    .order_by(AiSession.observed_at.asc())
                    .limit(limit)
                )
            )
            .scalars()
            .all()
        )

        for row in rows:
            result.scanned += 1
            days = retention.get(row.tenant_id, DEFAULT_RETENTION_DAYS)
            if _age_days(row.observed_at, now) < days:
                continue

            try:
                removed, shared = await _detach_transcript(
                    db,
                    row,
                    store=store,
                    action=ACTION_DELETE_RETENTION,
                    actor=None,
                    reason=f"retention: {days} days",
                    now=now,
                )
            except Exception:  # noqa: BLE001 - one unreadable blob must not stall the sweep
                result.failed += 1
                logger.exception(
                    "transcript_retention.delete_failed tenant=%s session=%s",
                    row.tenant_id,
                    row.session_key[:12],
                )
                continue

            result.deleted += 1
            result.blobs_removed += int(removed)
            result.blobs_shared += int(shared)

    if result.deleted or result.failed:
        logger.info(
            "transcript_retention.sweep scanned=%s deleted=%s blobs=%s shared=%s failed=%s",
            result.scanned,
            result.deleted,
            result.blobs_removed,
            result.blobs_shared,
            result.failed,
        )
    return result


def _age_days(observed_at: dt.datetime | None, now: dt.datetime) -> float:
    """Age in days, tolerant of a naive timestamp.

    SQLite hands back naive datetimes for timezone-aware columns; comparing
    one to an aware `now` raises. The stored value is UTC either way.
    """
    if observed_at is None:
        # The column is NOT NULL today, so this is insurance rather than a
        # path anyone reaches. No observation time means no defensible
        # retention decision, and keeping the row is the safe error.
        return -1.0
    if observed_at.tzinfo is None:
        observed_at = observed_at.replace(tzinfo=dt.timezone.utc)
    return (now - observed_at).total_seconds() / 86400.0


async def run_retention_loop(
    session_factory,
    *,
    interval_s: float | None = None,
    stop=None,
) -> None:
    """Background sweep. Started in the app lifespan when enabled.

    Off by default: an upgrade must not delete evidence a customer never
    agreed to lose.
    """
    import asyncio  # noqa: PLC0415

    stop = stop or asyncio.Event()
    interval = interval_s or settings.transcript_retention_interval_seconds
    while not stop.is_set():
        try:
            async with session_factory() as db:
                await reap_expired_transcripts(db)
        except Exception:  # noqa: BLE001
            logger.exception("transcript_retention.loop_error")
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval)
        except asyncio.TimeoutError:
            pass
