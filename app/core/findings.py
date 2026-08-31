"""Idempotent finding writes.

One upsert used by every producer, so re-analysis and concurrent workers
cannot turn one problem into several rows in the operator's queue.

Implements the idempotency rules frozen in
``docs/contracts/finding-and-worker-result-schema.md`` §4 (platform repo, UMA-40).
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.finding_events import build_finding_event
from app.models.db import Finding

# Columns a producer must never overwrite on re-analysis: they belong to the
# operator, not the detector. A finding someone already triaged does not jump
# back to `open` because the worker looked at the session again.
_OPERATOR_OWNED = frozenset({"status", "assignee"})


async def upsert_finding(
    db: AsyncSession,
    *,
    tenant_id: Any,
    finding_key: str,
    attributes: dict[str, Any],
) -> tuple[bool, dict[str, Any] | None]:
    """Create the finding, or refresh the detector's view of an existing one.

    Returns ``(created, siem_event)``. ``siem_event`` is ``None`` on update:
    a finding that is already in the queue does not need to be re-announced to
    the SOC every time the session is re-analysed.

    Known consequence, deliberately left as is: if re-analysis raises the
    severity of a finding an operator already resolved, the SOC is not told
    again. Changing that is a product decision about what deserves to page
    someone, not something to smuggle into the write path.
    """
    if _OPERATOR_OWNED & attributes.keys():
        # A caller passing `status` or `assignee` would silently undo operator
        # work on every re-analysis. Fail loudly instead.
        raise ValueError(
            "Producers must not set operator-owned fields: "
            f"{sorted(_OPERATOR_OWNED & attributes.keys())}"
        )

    existing = await _load(db, tenant_id, finding_key)
    if existing is not None:
        _apply(existing, attributes)
        return False, None

    # Two workers can claim different stages of the same session, and a retried
    # batch can race its own earlier attempt. Both reach here having seen no
    # row. The insert is wrapped in a savepoint so that losing the race rolls
    # back only the insert — without it, the IntegrityError poisons the whole
    # transaction on PostgreSQL and the surrounding unit of work is lost.
    try:
        async with db.begin_nested():
            db.add(Finding(tenant_id=tenant_id, finding_key=finding_key, status="open", **attributes))
            await db.flush()
    except IntegrityError:
        existing = await _load(db, tenant_id, finding_key)
        if existing is None:
            # The row is gone for a reason that is not a duplicate key.
            raise
        _apply(existing, attributes)
        return False, None

    return True, build_finding_event(
        tenant_id=tenant_id, finding_key=finding_key, **attributes
    )


async def _load(db: AsyncSession, tenant_id: Any, finding_key: str) -> Finding | None:
    return (
        await db.execute(
            select(Finding).where(
                Finding.tenant_id == tenant_id,
                Finding.finding_key == finding_key,
            )
        )
    ).scalar_one_or_none()


def _apply(finding: Finding, attributes: dict[str, Any]) -> None:
    """Refresh the detector's fields, leaving the operator's alone."""
    for attribute, value in attributes.items():
        setattr(finding, attribute, value)
