"""Worker lease, reclaim and crash recovery (UMA-52)."""

from __future__ import annotations

import asyncio
import datetime as dt
import uuid

import pytest
from sqlalchemy import select

from app.api.analysis import ClaimRequest, _lock_rows, claim_sessions
from app.core.settings import settings
from app.models.db import AiSession
from tests.conftest import db_session

TENANT = uuid.UUID("11111111-1111-1111-1111-111111111111")
NOW = dt.datetime.now(dt.timezone.utc)
TOKEN = "test-worker-token"


def _session(key: str, *, status: str = "ingested", claimed_at=None, claimed_by=None) -> AiSession:
    return AiSession(
        tenant_id=TENANT,
        session_key=key,
        source="claude",
        source_session_id=key[:8],
        observed_at=NOW - dt.timedelta(minutes=10),
        message_count=5,
        tool_call_count=1,
        transcript_ref=f"{TENANT}/aa/{key}.json.gz",
        transcript_sha256=key,
        analysis_status=status,
        claimed_at=claimed_at,
        claimed_by=claimed_by,
    )


async def _claim(db, *, stage: str = "triage", limit: int = 10, worker: str = "w1"):
    return await claim_sessions(
        ClaimRequest(stage=stage, worker_id=worker, limit=limit, tenant_id=TENANT),
        authorization=f"Bearer {TOKEN}",
        session=db,
    )


def _run(body, *rows: AiSession):
    async def scenario():
        original = settings.analysis_worker_token
        settings.analysis_worker_token = TOKEN
        try:
            async with db_session() as db:
                db.add_all(rows)
                await db.commit()
                return await body(db)
        finally:
            settings.analysis_worker_token = original

    return asyncio.run(scenario())


class TestClaiming:
    def test_claims_ingested_sessions_and_marks_the_owner(self) -> None:
        async def body(db):
            response = await _claim(db)
            rows = list((await db.execute(select(AiSession))).scalars().all())
            return response, rows

        response, rows = _run(body, _session("a" * 64))
        assert len(response.sessions) == 1
        assert rows[0].analysis_status == "triaging"
        assert rows[0].claimed_by == "w1"
        assert rows[0].claimed_at is not None

    def test_a_claimed_session_is_not_claimed_again(self) -> None:
        async def body(db):
            await _claim(db, worker="w1")
            await db.commit()
            return await _claim(db, worker="w2")

        assert _run(body, _session("a" * 64)).sessions == []

    def test_oldest_first(self) -> None:
        old = _session("a" * 64)
        old.observed_at = NOW - dt.timedelta(hours=5)
        new = _session("b" * 64)
        new.observed_at = NOW - dt.timedelta(minutes=1)

        async def body(db):
            return await _claim(db, limit=1)

        response = _run(body, new, old)
        assert response.sessions[0].session_key == "a" * 64

    def test_reason_stage_only_takes_what_triage_escalated(self) -> None:
        async def body(db):
            return await _claim(db, stage="reason")

        response = _run(
            body,
            _session("a" * 64, status="ingested"),
            _session("b" * 64, status="triage_benign"),
            _session("c" * 64, status="triage_suspicious"),
        )
        assert [s.session_key for s in response.sessions] == ["c" * 64]


class TestCrashRecovery:
    def test_an_expired_lease_is_reclaimed(self) -> None:
        """A worker that died mid-stage must not park its batch forever."""
        expired = NOW - dt.timedelta(seconds=settings.analysis_claim_lease_seconds + 60)

        async def body(db):
            response = await _claim(db, worker="w2")
            rows = list((await db.execute(select(AiSession))).scalars().all())
            return response, rows

        response, rows = _run(
            body,
            _session("a" * 64, status="triaging", claimed_at=expired, claimed_by="dead-worker"),
        )
        assert len(response.sessions) == 1
        assert rows[0].claimed_by == "w2"

    def test_a_live_lease_is_left_alone(self) -> None:
        # Still inside the lease window: the other worker is presumed working.
        fresh = NOW - dt.timedelta(seconds=5)

        async def body(db):
            return await _claim(db, worker="w2")

        response = _run(
            body,
            _session("a" * 64, status="triaging", claimed_at=fresh, claimed_by="busy-worker"),
        )
        assert response.sessions == []

    def test_fresh_work_is_preferred_over_reclaiming(self) -> None:
        expired = NOW - dt.timedelta(seconds=settings.analysis_claim_lease_seconds + 60)

        async def body(db):
            return await _claim(db, limit=1)

        response = _run(
            body,
            _session("a" * 64, status="ingested"),
            _session("b" * 64, status="triaging", claimed_at=expired, claimed_by="dead"),
        )
        # Never-analysed sessions come first; reclaim fills the remaining slots.
        assert [s.session_key for s in response.sessions] == ["a" * 64]


class TestConcurrencyGuard:
    def test_locking_is_applied_where_the_database_supports_it(self) -> None:
        """Two workers reading the same batch would double the model spend."""

        class _Dialect:
            def __init__(self, name: str) -> None:
                self.name = name

        class _Bind:
            def __init__(self, name: str) -> None:
                self.dialect = _Dialect(name)

        class _Session:
            def __init__(self, name: str) -> None:
                self.bind = _Bind(name)

        base = select(AiSession)
        for dialect in ("postgresql", "oracle"):
            locked = _lock_rows(base, _Session(dialect))
            assert locked._for_update_arg is not None, dialect
            assert locked._for_update_arg.skip_locked is True

    def test_sqlite_is_left_unlocked_rather_than_failing(self) -> None:
        # SQLite has no row locks and no concurrent writers to guard against;
        # emitting the clause would raise instead of protecting anything.
        class _Session:
            bind = type("B", (), {"dialect": type("D", (), {"name": "sqlite"})()})()

        assert _lock_rows(select(AiSession), _Session())._for_update_arg is None
