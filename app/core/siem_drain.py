"""Drain the SIEM outbox.

Enqueueing (UMA-54) guarantees a delivery is never lost. This is what makes it
actually arrive: claim what is due, try it, and either mark it delivered or
schedule the next attempt. A delivery that keeps failing ends in `dead_letter`
where an operator can see it, rather than being retried forever in silence.

The sender is injected so the retry policy can be tested without a SIEM.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import json
import logging
import random
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.siem import emit_event
from app.core.pipeline_metrics import (
    record_retention_failure,
    record_retention_sweep,
    record_siem_delivery,
)
from app.core.settings import settings
from app.core.siem_outbox import STATUS_DEAD_LETTER, STATUS_DELIVERED, STATUS_PENDING
from app.models.db import SiemOutbox

logger = logging.getLogger("umai.service.siem_drain")

# After this many failures the delivery stops being retried and becomes
# visible as a dead letter. Retrying forever hides a broken integration.
MAX_ATTEMPTS = 8

# Backoff between attempts, capped so a long outage still gets a try every few
# minutes rather than drifting into hours.
BASE_BACKOFF_S = 5.0
MAX_BACKOFF_S = 300.0

Sender = Callable[[dict], Awaitable[None]]


class PermanentDeliveryError(Exception):
    """The SIEM rejected the event in a way that retrying cannot fix.

    A malformed payload or a refused schema does not become valid by being
    sent again; burning eight attempts on it only delays the ones behind it.
    """


@dataclass
class DrainResult:
    attempted: int = 0
    delivered: int = 0
    retried: int = 0
    dead_lettered: int = 0


def next_attempt_delay(attempts: int) -> float:
    """Exponential backoff with jitter, capped.

    Jitter matters here: a QRadar coming back after an outage would otherwise
    take the whole backlog in one synchronised burst.
    """
    delay = min(BASE_BACKOFF_S * (2 ** max(attempts - 1, 0)), MAX_BACKOFF_S)
    return delay * (0.8 + random.random() * 0.4)


async def _default_sender(event: dict) -> None:
    await emit_event(event)


async def drain_once(
    db: AsyncSession,
    *,
    sender: Sender | None = None,
    limit: int = 100,
    now: dt.datetime | None = None,
) -> DrainResult:
    """Attempt every delivery that is due. Returns what happened."""
    send = sender or _default_sender
    now = now or dt.datetime.now(dt.timezone.utc)
    result = DrainResult()

    async with db.begin():
        rows = list(
            (
                await db.execute(
                    select(SiemOutbox)
                    .where(
                        SiemOutbox.status == STATUS_PENDING,
                        # A row whose next attempt is unset has never been
                        # scheduled and is due immediately.
                        (SiemOutbox.next_attempt_at.is_(None))
                        | (SiemOutbox.next_attempt_at <= now),
                    )
                    .order_by(SiemOutbox.created_at.asc())
                    .limit(limit)
                )
            )
            .scalars()
            .all()
        )

        for row in rows:
            result.attempted += 1
            row.attempts += 1
            try:
                await send(json.loads(row.payload_json))
            except PermanentDeliveryError as exc:
                row.status = STATUS_DEAD_LETTER
                row.last_error = f"permanent: {exc}"
                result.dead_lettered += 1
                logger.warning(
                    "siem_drain.dead_letter event=%s reason=permanent error=%s",
                    row.event_id[:16],
                    exc,
                )
                continue
            except Exception as exc:  # noqa: BLE001 - one bad row must not stop the batch
                row.last_error = f"{type(exc).__name__}: {exc}"
                if row.attempts >= MAX_ATTEMPTS:
                    row.status = STATUS_DEAD_LETTER
                    result.dead_lettered += 1
                    logger.warning(
                        "siem_drain.dead_letter event=%s attempts=%s error=%s",
                        row.event_id[:16],
                        row.attempts,
                        exc,
                    )
                else:
                    row.next_attempt_at = now + dt.timedelta(
                        seconds=next_attempt_delay(row.attempts)
                    )
                    result.retried += 1
                continue

            row.status = STATUS_DELIVERED
            row.delivered_at = now
            row.last_error = None
            result.delivered += 1

    # Recorded after the batch so the counters and the transaction agree: a rollback
    # would otherwise leave metrics claiming deliveries the database never kept.
    record_siem_delivery("delivered", result.delivered)
    record_siem_delivery("retry", result.retried)
    record_siem_delivery("dead_letter", result.dead_lettered)

    if result.attempted:
        logger.info(
            "siem_drain.batch attempted=%s delivered=%s retried=%s dead=%s",
            result.attempted,
            result.delivered,
            result.retried,
            result.dead_lettered,
        )
    return result


async def replay(
    db: AsyncSession,
    *,
    tenant_id,
    event_id: str,
    actor: str | None = None,
    now: dt.datetime | None = None,
) -> bool:
    """Put a dead letter back in the queue. Returns whether anything moved.

    Attempts are reset: a dead letter is replayed after someone fixed the
    thing that broke, so it deserves the full retry budget again.
    """
    now = now or dt.datetime.now(dt.timezone.utc)
    async with db.begin():
        row = (
            await db.execute(
                select(SiemOutbox).where(
                    SiemOutbox.tenant_id == tenant_id,
                    SiemOutbox.event_id == event_id,
                    SiemOutbox.status == STATUS_DEAD_LETTER,
                )
            )
        ).scalars().first()
        if row is None:
            return False
        row.status = STATUS_PENDING
        row.attempts = 0
        row.next_attempt_at = now
        row.last_error = None
        row.replayed_at = now
        row.replayed_by = actor

    logger.info(
        "siem_drain.replay tenant=%s event=%s actor=%s", tenant_id, event_id[:16], actor
    )
    return True


def classify_http_status(status_code: int) -> None:
    """Raise the right error for a SIEM response the sender got.

    4xx other than 408/429 mean the request itself is wrong: retrying an
    identical payload produces an identical rejection.
    """
    if status_code < 400:
        return
    if 400 <= status_code < 500 and status_code not in (408, 429):
        raise PermanentDeliveryError(f"HTTP {status_code}")
    raise httpx.HTTPError(f"HTTP {status_code}")


async def prune_delivered(
    db: AsyncSession,
    *,
    retention_days: int | None = None,
    now: dt.datetime | None = None,
    limit: int = 1000,
) -> int:
    """Delete outbox rows that were delivered long enough ago to be uninteresting.

    Nothing removed these before, so the outbox grew for the life of the deployment: one
    row per finding, each carrying the finding's full payload, kept forever after it had
    been delivered. It is the fastest-growing table the platform owns and the only one
    whose contents are pure duplication — the finding itself is in `findings`, and a
    delivered row is a receipt.

    Deliberately narrow. `pending` rows are undelivered work and `dead_letter` rows are a
    finding the SOC has never seen, which an operator has to replay; deleting either would
    be losing a security event to a cleanup job.

    Idempotent: rows already gone are simply not selected, so re-running deletes nothing
    and reports zero.
    """
    now = now or dt.datetime.now(dt.timezone.utc)
    if retention_days is None:
        retention_days = int(settings.siem_outbox_retention_days)
    if retention_days <= 0:
        return 0

    cutoff = now - dt.timedelta(days=retention_days)
    async with db.begin():
        rows = list(
            (
                await db.execute(
                    select(SiemOutbox)
                    .where(
                        SiemOutbox.status == STATUS_DELIVERED,
                        SiemOutbox.delivered_at.is_not(None),
                        SiemOutbox.delivered_at < cutoff,
                    )
                    .order_by(SiemOutbox.delivered_at.asc())
                    .limit(limit)
                )
            )
            .scalars()
            .all()
        )
        for row in rows:
            await db.delete(row)

    record_retention_sweep("siem_outbox", deleted=len(rows), now=now)
    if rows:
        logger.info("siem_outbox.pruned deleted=%s older_than_days=%s", len(rows), retention_days)
    return len(rows)


async def run_drain_loop(
    session_factory, *, interval_s: float = 5.0, stop: asyncio.Event | None = None
) -> None:
    """Background loop. Started in the app lifespan.

    Every failure is swallowed and logged: a drain that dies takes the SIEM
    integration down with it, and nothing would say so.
    """
    stop = stop or asyncio.Event()
    # The prune runs on its own, much slower clock. At the drain interval it would be
    # thousands of pointless queries a day against the table the drain needs to be fast.
    prune_every = max(1, int(settings.siem_outbox_prune_interval_seconds / max(interval_s, 1)))
    ticks = 0
    while not stop.is_set():
        try:
            async with session_factory() as db:
                await drain_once(db)
        except Exception:  # noqa: BLE001
            logger.exception("siem_drain.loop_error")

        ticks += 1
        if ticks % prune_every == 0:
            try:
                async with session_factory() as db:
                    await prune_delivered(db)
            except Exception:  # noqa: BLE001
                record_retention_failure("siem_outbox")
                logger.exception("siem_outbox.prune_error")
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval_s)
        except asyncio.TimeoutError:
            pass
