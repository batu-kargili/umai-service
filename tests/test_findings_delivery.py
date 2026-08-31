"""Delivery status, replay and operator stats (UMA-56)."""

from __future__ import annotations

import asyncio
import datetime as dt
import uuid

import httpx
import pytest

from app.api.findings import delivery_stats, load_finding, replay_delivery_endpoint
from app.core import finding_schema as fs
from app.core.findings import upsert_finding
from app.core.siem_drain import PermanentDeliveryError, drain_once
from app.core.siem_outbox import STATUS_DEAD_LETTER, STATUS_DELIVERED, STATUS_PENDING
from app.models.db import SiemOutbox
from sqlalchemy import select
from tests.conftest import db_session

TENANT = uuid.UUID("11111111-1111-1111-1111-111111111111")
KEY = "k" * 64
NOW = dt.datetime(2026, 8, 31, 12, 0, tzinfo=dt.timezone.utc)


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


async def _seed_finding(db) -> None:
    await upsert_finding(db, tenant_id=TENANT, finding_key=KEY, attributes=_attributes())
    for row in (await db.execute(select(SiemOutbox))).scalars().all():
        row.next_attempt_at = None
    await db.commit()


class TestDeliveryOnDetail:
    def test_a_new_finding_shows_a_pending_delivery(self) -> None:
        async def scenario():
            async with db_session() as db:
                await _seed_finding(db)
                return await load_finding(db, tenant_id=TENANT, finding_key=KEY)

        detail = asyncio.run(scenario())
        assert detail.delivery is not None
        assert detail.delivery.status == STATUS_PENDING
        assert detail.delivery.attempts == 0

    def test_shows_the_error_that_is_holding_it_up(self) -> None:
        async def failing(_: dict) -> None:
            raise httpx.ConnectError("QRadar is down")

        async def scenario():
            async with db_session() as db:
                await _seed_finding(db)
                await drain_once(db, sender=failing, now=NOW)
                return await load_finding(db, tenant_id=TENANT, finding_key=KEY)

        detail = asyncio.run(scenario())
        assert detail.delivery.status == STATUS_PENDING
        assert "ConnectError" in detail.delivery.last_error
        assert detail.delivery.next_attempt_at is not None

    def test_shows_delivery_once_it_lands(self) -> None:
        async def ok(_: dict) -> None:
            return None

        async def scenario():
            async with db_session() as db:
                await _seed_finding(db)
                await drain_once(db, sender=ok, now=NOW)
                return await load_finding(db, tenant_id=TENANT, finding_key=KEY)

        detail = asyncio.run(scenario())
        assert detail.delivery.status == STATUS_DELIVERED
        assert detail.delivery.delivered_at is not None


class TestReplay:
    def test_replay_records_who_did_it(self) -> None:
        async def failing(_: dict) -> None:
            raise PermanentDeliveryError("HTTP 400")

        async def scenario():
            async with db_session() as db:
                await _seed_finding(db)
                await drain_once(db, sender=failing, now=NOW)
                from app.core.admin_auth import AdminPrincipal

                return await replay_delivery_endpoint(
                    KEY,
                    session=db,
                    x_tenant_id=TENANT,
                    principal=AdminPrincipal(
                        tenant_id=TENANT, roles=["tenant-admin"], subject="soc@example.com"
                    ),
                )

        detail = asyncio.run(scenario())
        assert detail.delivery.status == STATUS_PENDING
        assert detail.delivery.attempts == 0
        assert detail.delivery.replayed_by == "soc@example.com"
        assert detail.delivery.replayed_at is not None

    def test_replaying_a_healthy_delivery_is_refused(self) -> None:
        from app.core.admin_auth import AdminPrincipal
        from app.core.errors import ServiceError

        async def scenario():
            async with db_session() as db:
                await _seed_finding(db)
                return await replay_delivery_endpoint(
                    KEY,
                    session=db,
                    x_tenant_id=TENANT,
                    principal=AdminPrincipal(
                        tenant_id=TENANT, roles=["tenant-admin"], subject="soc@example.com"
                    ),
                )

        with pytest.raises(ServiceError) as exc:
            asyncio.run(scenario())
        assert exc.value.status_code == 409


class TestStats:
    def test_counts_by_status_and_backlog_age(self) -> None:
        async def failing(_: dict) -> None:
            raise PermanentDeliveryError("HTTP 400")

        async def scenario():
            async with db_session() as db:
                await _seed_finding(db)
                # A second finding that will be delivered.
                attrs = _attributes() | {"rule_id": "detector.other"}
                await upsert_finding(
                    db, tenant_id=TENANT, finding_key="b" * 64, attributes=attrs
                )
                for row in (await db.execute(select(SiemOutbox))).scalars().all():
                    row.next_attempt_at = None
                    row.created_at = NOW - dt.timedelta(minutes=10)
                await db.commit()

                async def selective(event: dict) -> None:
                    if event["event_id"] == KEY:
                        raise PermanentDeliveryError("HTTP 400")

                await drain_once(db, sender=selective, now=NOW)
                return await delivery_stats(db, tenant_id=TENANT, now=NOW)

        stats = asyncio.run(scenario())
        assert stats.dead_letter == 1
        assert stats.delivered == 1
        assert stats.pending == 0

    def test_reports_how_stale_the_backlog_is(self) -> None:
        async def scenario():
            async with db_session() as db:
                await _seed_finding(db)
                for row in (await db.execute(select(SiemOutbox))).scalars().all():
                    row.created_at = NOW - dt.timedelta(minutes=30)
                await db.commit()
                return await delivery_stats(db, tenant_id=TENANT, now=NOW)

        stats = asyncio.run(scenario())
        assert stats.pending == 1
        assert stats.oldest_pending_age_seconds == pytest.approx(1800, abs=5)

    def test_an_empty_queue_reports_no_age(self) -> None:
        async def scenario():
            async with db_session() as db:
                return await delivery_stats(db, tenant_id=TENANT, now=NOW)

        stats = asyncio.run(scenario())
        assert (stats.pending, stats.delivered, stats.dead_letter) == (0, 0, 0)
        assert stats.oldest_pending_age_seconds is None
