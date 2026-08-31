"""Durable SIEM enqueue (UMA-54).

Delivery used to be fire-and-forget: a QRadar restart or a network blip
dropped security findings and told nobody. These tests pin the guarantee that
replaced it — the delivery row lives or dies with the finding.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import json
import uuid

import pytest
from sqlalchemy import func, select

from app.core import finding_schema as fs
from app.core.findings import upsert_finding
from app.core.siem_outbox import STATUS_PENDING, delivery_status, enqueue_event
from app.models.db import Finding, SiemOutbox
from tests.conftest import db_session

TENANT = uuid.UUID("11111111-1111-1111-1111-111111111111")
KEY = "k" * 64
NOW = dt.datetime(2026, 8, 31, tzinfo=dt.timezone.utc)


def _event(event_id: str = KEY, **overrides: object) -> dict:
    base: dict = {
        "schema": "umai.finding.v1",
        "event_id": event_id,
        "tenant_id": str(TENANT),
        "severity": "high",
        "technique_id": "ADR.T0007",
    }
    base.update(overrides)
    return base


def _attributes() -> dict[str, object]:
    return {
        "session_key": "s" * 64,
        "rule_id": "detector.ADR.T0007",
        "technique_id": "ADR.T0007",
        "technique_name": "Indirect prompt injection",
        "tactic": "reasoning_data_manipulation",
        "severity": fs.SEVERITY_HIGH,
        "category": fs.CATEGORY_PROMPT_INJECTION,
        "title": "Indirect prompt injection",
        "summary": "why",
        "evidence_json": "{}",
        "source": fs.SOURCE_ADR,
        "actor_user": "someone@example.com",
        "actor_device_id": "device-1",
        "project_path": "/repo",
        "observed_at": NOW,
        "detector": fs.DETECTOR_REASONING,
    }


async def _outbox(db) -> list[SiemOutbox]:
    return list((await db.execute(select(SiemOutbox))).scalars().all())


class TestEnqueue:
    def test_queues_a_pending_delivery(self) -> None:
        async def scenario():
            async with db_session() as db:
                added = await enqueue_event(db, tenant_id=TENANT, event=_event())
                assert added is True
                rows = await _outbox(db)
                assert len(rows) == 1
                assert rows[0].status == STATUS_PENDING
                assert rows[0].attempts == 0
                assert json.loads(rows[0].payload_json)["technique_id"] == "ADR.T0007"

        asyncio.run(scenario())

    def test_the_same_event_is_never_queued_twice(self) -> None:
        # Re-analysis raises the same finding again; the SOC must not be paged
        # a second time for it.
        async def scenario():
            async with db_session() as db:
                first = await enqueue_event(db, tenant_id=TENANT, event=_event())
                second = await enqueue_event(db, tenant_id=TENANT, event=_event())
                assert (first, second) == (True, False)
                assert len(await _outbox(db)) == 1

        asyncio.run(scenario())

    def test_different_events_queue_separately(self) -> None:
        async def scenario():
            async with db_session() as db:
                await enqueue_event(db, tenant_id=TENANT, event=_event("a" * 64))
                await enqueue_event(db, tenant_id=TENANT, event=_event("b" * 64))
                assert len(await _outbox(db)) == 2

        asyncio.run(scenario())

    def test_an_unidentifiable_event_is_refused(self) -> None:
        # Without an id there is no way to be idempotent, and a SOC paged
        # twice for one problem is worse than a loud failure here.
        async def scenario():
            async with db_session() as db:
                with pytest.raises(ValueError):
                    await enqueue_event(db, tenant_id=TENANT, event={"schema": "x"})
                with pytest.raises(ValueError):
                    await enqueue_event(db, tenant_id=TENANT, event={"event_id": "x"})

        asyncio.run(scenario())


class TestAtomicity:
    def test_a_new_finding_queues_its_delivery(self) -> None:
        async def scenario():
            async with db_session() as db:
                created, event = await upsert_finding(
                    db, tenant_id=TENANT, finding_key=KEY, attributes=_attributes()
                )
                assert created is True and event is not None
                rows = await _outbox(db)
                assert len(rows) == 1
                assert rows[0].event_id == KEY

        asyncio.run(scenario())

    def test_re_raising_a_finding_does_not_queue_again(self) -> None:
        async def scenario():
            async with db_session() as db:
                await upsert_finding(
                    db, tenant_id=TENANT, finding_key=KEY, attributes=_attributes()
                )
                await upsert_finding(
                    db, tenant_id=TENANT, finding_key=KEY, attributes=_attributes()
                )
                assert len(await _outbox(db)) == 1

        asyncio.run(scenario())

    def test_a_rolled_back_finding_leaves_no_delivery(self) -> None:
        """The whole point: no delivery for a finding that never existed."""

        async def scenario():
            async with db_session() as db:
                await upsert_finding(
                    db, tenant_id=TENANT, finding_key=KEY, attributes=_attributes()
                )
                # Something later in the request fails.
                await db.rollback()
                # Ask the database, not the session's identity map: rolled-back
                # objects can still be reachable in memory.
                db.expunge_all()

                findings = int(
                    (await db.execute(select(func.count()).select_from(Finding))).scalar_one()
                )
                queued = int(
                    (await db.execute(select(func.count()).select_from(SiemOutbox))).scalar_one()
                )
                assert (findings, queued) == (0, 0)

        asyncio.run(scenario())


class TestStatusLookup:
    def test_reports_where_a_delivery_stands(self) -> None:
        async def scenario():
            async with db_session() as db:
                await enqueue_event(db, tenant_id=TENANT, event=_event())
                await db.commit()
                return await delivery_status(db, tenant_id=TENANT, event_id=KEY)

        row = asyncio.run(scenario())
        assert row is not None
        assert row.status == STATUS_PENDING

    def test_returns_nothing_for_an_unknown_event(self) -> None:
        async def scenario():
            async with db_session() as db:
                return await delivery_status(db, tenant_id=TENANT, event_id="nope")

        assert asyncio.run(scenario()) is None
