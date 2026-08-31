"""Outbox drain: retry, backoff and dead-letter (UMA-55)."""

from __future__ import annotations

import asyncio
import datetime as dt
import json
import uuid

import httpx
import pytest
from sqlalchemy import select

from app.core.siem_drain import (
    MAX_ATTEMPTS,
    MAX_BACKOFF_S,
    PermanentDeliveryError,
    classify_http_status,
    drain_once,
    next_attempt_delay,
    replay,
)
from app.core.siem_outbox import (
    STATUS_DEAD_LETTER,
    STATUS_DELIVERED,
    STATUS_PENDING,
    enqueue_event,
)
from app.models.db import SiemOutbox
from tests.conftest import db_session

TENANT = uuid.UUID("11111111-1111-1111-1111-111111111111")
NOW = dt.datetime(2026, 8, 31, 12, 0, tzinfo=dt.timezone.utc)


def _event(event_id: str = "e1") -> dict:
    return {"schema": "umai.finding.v1", "event_id": event_id, "severity": "high"}


async def _seed(db, *count_ids: str) -> None:
    for event_id in count_ids or ("e1",):
        await enqueue_event(db, tenant_id=TENANT, event=_event(event_id))
    # Enqueue stamps `next_attempt_at` with wall-clock time; these tests drive
    # a fixed clock. Clearing it exercises the "never scheduled, so due now"
    # branch and keeps the tests independent of when they run.
    for row in await _rows(db):
        row.next_attempt_at = None
    await db.commit()


def _naive(value: dt.datetime | None) -> dt.datetime | None:
    """Drop tzinfo for comparison.

    SQLite does not store timezone on a DateTime(timezone=True) column and
    hands back naive values; PostgreSQL keeps them. The behaviour under test
    is the timestamp, not the driver's tz fidelity.
    """
    return value.replace(tzinfo=None) if value is not None else None


async def _rows(db) -> list[SiemOutbox]:
    return list((await db.execute(select(SiemOutbox))).scalars().all())


def _run(body):
    async def scenario():
        async with db_session() as db:
            await _seed(db)
            return await body(db)

    return asyncio.run(scenario())


class TestHappyPath:
    def test_a_delivered_event_is_marked_and_not_retried(self) -> None:
        sent: list[dict] = []

        async def sender(event: dict) -> None:
            sent.append(event)

        async def body(db):
            first = await drain_once(db, sender=sender, now=NOW)
            second = await drain_once(db, sender=sender, now=NOW)
            return first, second, await _rows(db)

        first, second, rows = _run(body)
        assert (first.delivered, first.attempted) == (1, 1)
        # Already delivered: the second pass has nothing due.
        assert second.attempted == 0
        assert rows[0].status == STATUS_DELIVERED
        assert _naive(rows[0].delivered_at) == _naive(NOW)
        assert len(sent) == 1

    def test_the_payload_reaches_the_sender_intact(self) -> None:
        seen: list[dict] = []

        async def sender(event: dict) -> None:
            seen.append(event)

        _run(lambda db: drain_once(db, sender=sender, now=NOW))
        assert seen[0]["event_id"] == "e1"
        assert seen[0]["schema"] == "umai.finding.v1"


class TestTransientFailure:
    def test_a_failure_schedules_a_later_attempt(self) -> None:
        async def sender(_: dict) -> None:
            raise httpx.ConnectError("QRadar is down")

        async def body(db):
            result = await drain_once(db, sender=sender, now=NOW)
            return result, await _rows(db)

        result, rows = _run(body)
        assert (result.retried, result.delivered) == (1, 0)
        assert rows[0].status == STATUS_PENDING
        assert rows[0].attempts == 1
        assert _naive(rows[0].next_attempt_at) > _naive(NOW)
        assert "ConnectError" in rows[0].last_error

    def test_a_row_not_yet_due_is_left_alone(self) -> None:
        async def sender(_: dict) -> None:
            raise httpx.ConnectError("down")

        async def body(db):
            await drain_once(db, sender=sender, now=NOW)
            # Immediately after: the backoff has not elapsed.
            return await drain_once(db, sender=sender, now=NOW)

        assert _run(body).attempted == 0

    def test_delivery_succeeds_once_the_siem_returns(self) -> None:
        calls = {"n": 0}

        async def sender(_: dict) -> None:
            calls["n"] += 1
            if calls["n"] == 1:
                raise httpx.ConnectError("down")

        async def body(db):
            await drain_once(db, sender=sender, now=NOW)
            later = NOW + dt.timedelta(hours=1)
            await drain_once(db, sender=sender, now=later)
            return await _rows(db)

        rows = _run(body)
        assert rows[0].status == STATUS_DELIVERED
        assert rows[0].last_error is None

    def test_pending_work_survives_a_restart(self) -> None:
        """A drain that never ran leaves the row due, not lost."""

        async def body(db):
            rows = await _rows(db)
            assert rows[0].status == STATUS_PENDING
            # Close the read before the drain opens its own transaction, the
            # way a fresh process would.
            await db.commit()
            # A fresh process picks it up with no in-memory state.
            sent: list[dict] = []

            async def sender(event: dict) -> None:
                sent.append(event)

            result = await drain_once(db, sender=sender, now=NOW)
            return result, sent

        result, sent = _run(body)
        assert result.delivered == 1 and len(sent) == 1


class TestPermanentFailure:
    def test_a_rejected_payload_goes_straight_to_dead_letter(self) -> None:
        async def sender(_: dict) -> None:
            raise PermanentDeliveryError("HTTP 400")

        async def body(db):
            result = await drain_once(db, sender=sender, now=NOW)
            return result, await _rows(db)

        result, rows = _run(body)
        # No retry budget burned on something that cannot become valid.
        assert result.dead_lettered == 1
        assert rows[0].status == STATUS_DEAD_LETTER
        assert rows[0].attempts == 1

    def test_persistent_transient_failure_eventually_stops(self) -> None:
        async def sender(_: dict) -> None:
            raise httpx.ConnectError("still down")

        async def body(db):
            when = NOW
            for _ in range(MAX_ATTEMPTS):
                await drain_once(db, sender=sender, now=when)
                when += dt.timedelta(hours=1)
            return await _rows(db)

        rows = _run(body)
        assert rows[0].status == STATUS_DEAD_LETTER
        assert rows[0].attempts == MAX_ATTEMPTS

    @pytest.mark.parametrize("status_code", [400, 401, 403, 404, 422])
    def test_client_errors_are_permanent(self, status_code: int) -> None:
        with pytest.raises(PermanentDeliveryError):
            classify_http_status(status_code)

    @pytest.mark.parametrize("status_code", [408, 429, 500, 502, 503])
    def test_overload_and_server_errors_are_worth_retrying(self, status_code: int) -> None:
        with pytest.raises(httpx.HTTPError):
            classify_http_status(status_code)

    def test_success_raises_nothing(self) -> None:
        classify_http_status(200)
        classify_http_status(204)


class TestBackoff:
    def test_grows_then_stops_growing(self) -> None:
        assert next_attempt_delay(1) < next_attempt_delay(4)
        assert next_attempt_delay(50) <= MAX_BACKOFF_S * 1.2

    def test_is_jittered(self) -> None:
        # A SIEM coming back must not be hit by the whole backlog at once.
        delays = {next_attempt_delay(3) for _ in range(20)}
        assert len(delays) > 1


class TestBatchIsolation:
    def test_one_bad_event_does_not_block_the_others(self) -> None:
        async def sender(event: dict) -> None:
            if event["event_id"] == "bad":
                raise httpx.ConnectError("down")

        async def scenario():
            async with db_session() as db:
                await enqueue_event(db, tenant_id=TENANT, event=_event("bad"))
                await enqueue_event(db, tenant_id=TENANT, event=_event("good"))
                for row in await _rows(db):
                    row.next_attempt_at = None
                await db.commit()
                result = await drain_once(db, sender=sender, now=NOW)
                return result, await _rows(db)

        result, rows = asyncio.run(scenario())
        assert (result.delivered, result.retried) == (1, 1)
        by_id = {r.event_id: r.status for r in rows}
        assert by_id["good"] == STATUS_DELIVERED
        assert by_id["bad"] == STATUS_PENDING


class TestReplay:
    def test_a_dead_letter_can_be_requeued_with_a_fresh_budget(self) -> None:
        async def failing(_: dict) -> None:
            raise PermanentDeliveryError("HTTP 400")

        async def scenario():
            async with db_session() as db:
                await _seed(db)
                await drain_once(db, sender=failing, now=NOW)
                moved = await replay(db, tenant_id=TENANT, event_id="e1", now=NOW)
                rows = await _rows(db)
                return moved, rows[0]

        moved, row = asyncio.run(scenario())
        assert moved is True
        assert row.status == STATUS_PENDING
        assert row.attempts == 0
        assert row.last_error is None

    def test_replaying_something_that_is_not_dead_does_nothing(self) -> None:
        async def body(db):
            return await replay(db, tenant_id=TENANT, event_id="e1", now=NOW)

        assert _run(body) is False
