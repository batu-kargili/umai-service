"""Idempotent finding writes.

Guards ``docs/contracts/finding-and-worker-result-schema.md`` §4 (UMA-40),
implemented in ``app.core.findings`` for UMA-47.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import uuid

import pytest
from sqlalchemy import select

from app.core import finding_schema as fs
from app.core.findings import upsert_finding
from app.models.db import Finding
from tests.conftest import db_session

TENANT = uuid.UUID("11111111-1111-1111-1111-111111111111")
KEY = "k" * 64


def _attributes(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "session_key": "s" * 64,
        "rule_id": "posture.unapproved_mcp_server",
        "technique_id": "ADR.T0007",
        "technique_name": "Unapproved capability",
        "tactic": "reasoning_data_manipulation",
        "severity": "medium",
        "title": "Agent connected an unapproved MCP server",
        "summary": "first pass",
        "evidence_json": '{"confidence": 0.7}',
        "source": fs.SOURCE_ADR,
        "category": fs.CATEGORY_SHADOW_AI,
        "actor_user": "someone@example.com",
        "actor_device_id": "device-1",
        "project_path": "/repo",
        "observed_at": dt.datetime(2026, 8, 31, tzinfo=dt.timezone.utc),
        "detector": fs.DETECTOR_POSTURE,
    }
    base.update(overrides)
    return base


async def _count(db) -> int:
    rows = (await db.execute(select(Finding))).scalars().all()
    return len(rows)


class TestIdempotency:
    def test_first_write_creates_and_announces(self) -> None:
        async def scenario() -> None:
            async with db_session() as db:
                created, event = await upsert_finding(
                    db, tenant_id=TENANT, finding_key=KEY, attributes=_attributes()
                )
                assert created is True
                assert event is not None
                assert await _count(db) == 1

        asyncio.run(scenario())

    def test_reanalysis_updates_in_place_without_reannouncing(self) -> None:
        async def scenario() -> None:
            async with db_session() as db:
                await upsert_finding(
                    db, tenant_id=TENANT, finding_key=KEY, attributes=_attributes()
                )
                created, event = await upsert_finding(
                    db,
                    tenant_id=TENANT,
                    finding_key=KEY,
                    attributes=_attributes(severity="high", summary="second pass"),
                )

                assert created is False
                # Already in the queue; the SOC is not paged again.
                assert event is None
                assert await _count(db) == 1

                row = (await db.execute(select(Finding))).scalar_one()
                assert row.severity == "high"
                assert row.summary == "second pass"

        asyncio.run(scenario())

    def test_reanalysis_does_not_reopen_operator_decisions(self) -> None:
        async def scenario() -> None:
            async with db_session() as db:
                await upsert_finding(
                    db, tenant_id=TENANT, finding_key=KEY, attributes=_attributes()
                )
                row = (await db.execute(select(Finding))).scalar_one()
                row.status = fs.STATUS_FALSE_POSITIVE
                row.assignee = "analyst@example.com"
                await db.flush()

                await upsert_finding(
                    db, tenant_id=TENANT, finding_key=KEY, attributes=_attributes(severity="high")
                )

                row = (await db.execute(select(Finding))).scalar_one()
                # The detector refreshed its own view...
                assert row.severity == "high"
                # ...but the operator's judgement survived.
                assert row.status == fs.STATUS_FALSE_POSITIVE
                assert row.assignee == "analyst@example.com"

        asyncio.run(scenario())

    def test_producer_cannot_set_operator_owned_fields(self) -> None:
        async def scenario() -> None:
            async with db_session() as db:
                with pytest.raises(ValueError, match="operator-owned"):
                    await upsert_finding(
                        db,
                        tenant_id=TENANT,
                        finding_key=KEY,
                        attributes=_attributes(status="open"),
                    )

        asyncio.run(scenario())

    def test_concurrent_writers_produce_one_row(self) -> None:
        """Two workers racing the same finding must not duplicate the queue entry.

        Both see no row, both insert; the loser hits the primary key and has to
        fall back to an update instead of failing the whole unit of work.
        """

        async def scenario() -> None:
            async with db_session() as db:
                # Simulate the losing writer: the row lands between its read
                # and its insert.
                db.add(
                    Finding(
                        tenant_id=TENANT,
                        finding_key=KEY,
                        status=fs.STATUS_INVESTIGATING,
                        **_attributes(severity="low"),
                    )
                )
                await db.flush()

                created, event = await upsert_finding(
                    db,
                    tenant_id=TENANT,
                    finding_key=KEY,
                    attributes=_attributes(severity="critical"),
                )

                assert created is False
                assert event is None
                assert await _count(db) == 1

                row = (await db.execute(select(Finding))).scalar_one()
                assert row.severity == "critical"
                # The concurrent path must respect operator state too.
                assert row.status == fs.STATUS_INVESTIGATING

        asyncio.run(scenario())

    def test_distinct_rules_on_one_session_are_distinct_findings(self) -> None:
        async def scenario() -> None:
            async with db_session() as db:
                await upsert_finding(
                    db, tenant_id=TENANT, finding_key="a" * 64, attributes=_attributes()
                )
                await upsert_finding(
                    db,
                    tenant_id=TENANT,
                    finding_key="b" * 64,
                    attributes=_attributes(rule_id="posture.bypass_permissions"),
                )
                assert await _count(db) == 2

        asyncio.run(scenario())
