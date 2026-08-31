"""Enqueue SIEM deliveries durably.

The row goes in with the event it describes, in one transaction. Nothing is
sent from here — draining is the worker's job (UMA-55) — so a delivery cannot
be lost to a crash between committing a finding and posting it.
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.db import SiemOutbox

logger = logging.getLogger("umai.service.siem_outbox")

STATUS_PENDING = "pending"
STATUS_DELIVERED = "delivered"
STATUS_DEAD_LETTER = "dead_letter"


async def enqueue_event(
    db: AsyncSession, *, tenant_id: uuid.UUID, event: dict[str, Any]
) -> bool:
    """Queue one event for SIEM delivery. Returns whether a row was added.

    Idempotent per (tenant, event id, schema): re-analysis raises the same
    finding again, and that must not queue a second copy for the SOC.

    Must be called inside the caller's transaction. That is the entire point —
    if the finding rolls back, so does its delivery.
    """
    event_id = str(event.get("event_id") or "").strip()
    event_schema = str(event.get("schema") or "").strip()
    if not event_id or not event_schema:
        # A producer that cannot identify its own event cannot be made
        # idempotent, and a duplicate-paging SOC is worse than a loud failure.
        raise ValueError("SIEM events must carry `event_id` and `schema`")

    row = SiemOutbox(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        event_id=event_id[:128],
        event_schema=event_schema[:64],
        payload_json=json.dumps(event, ensure_ascii=False, default=str),
        status=STATUS_PENDING,
        attempts=0,
        next_attempt_at=dt.datetime.now(dt.timezone.utc),
    )

    try:
        async with db.begin_nested():
            db.add(row)
            await db.flush()
    except IntegrityError:
        # Already queued. Not an error: the producer is idempotent by design.
        logger.debug(
            "siem_outbox.duplicate tenant=%s event=%s", tenant_id, event_id[:16]
        )
        return False

    return True


async def delivery_status(
    db: AsyncSession, *, tenant_id: uuid.UUID, event_id: str
) -> SiemOutbox | None:
    """Where one event stands. Feeds the finding detail view (UMA-56)."""
    return (
        await db.execute(
            select(SiemOutbox).where(
                SiemOutbox.tenant_id == tenant_id,
                SiemOutbox.event_id == event_id,
            )
        )
    ).scalars().first()
