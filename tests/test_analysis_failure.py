"""An analysis that did not finish must not read as clean (UMA-53).

Before this, any triage verdict other than `suspicious` became
`triage_benign`. A worker whose model timed out or ran out of budget therefore
cleared the session — the queue looked worked because the work never happened.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import uuid

import pytest
from sqlalchemy import select

from app.api.analysis import ResultRequest, record_analysis_result
from app.core.settings import settings
from app.models.db import AiSession, Finding
from tests.conftest import db_session

TENANT = uuid.UUID("11111111-1111-1111-1111-111111111111")
NOW = dt.datetime(2026, 8, 31, 12, 0, tzinfo=dt.timezone.utc)
TOKEN = "worker-token"
AUTH = f"Bearer {TOKEN}"


@pytest.fixture(autouse=True)
def worker_token(monkeypatch):
    monkeypatch.setattr(settings, "analysis_worker_token", TOKEN, raising=False)


async def _seed(
    db,
    *,
    session_key: str = "sess-1",
    analysis_status: str = "triaging",
    verdict: str | None = None,
    attempts: int = 0,
) -> None:
    db.add(
        AiSession(
            tenant_id=TENANT,
            session_key=session_key,
            source="claude_code",
            source_session_id=f"src-{session_key}",
            message_count=4,
            tool_call_count=1,
            analysis_status=analysis_status,
            verdict=verdict,
            observed_at=NOW,
            claimed_at=NOW,
            claimed_by="analyzer-1",
            analysis_attempts=attempts,
            transcript_ref="ref-a",
            transcript_sha256="deadbeef",
        )
    )
    await db.commit()


def _result(**overrides) -> ResultRequest:
    payload = {
        "tenant_id": TENANT,
        "session_key": "sess-1",
        "stage": "triage",
        "verdict": "error",
        "reason": "Model call timed out: after 60s",
        "model": "gpt-4o",
    }
    payload.update(overrides)
    return ResultRequest(**payload)


async def _row(db, session_key: str = "sess-1") -> AiSession:
    return (
        await db.execute(
            select(AiSession).where(
                AiSession.tenant_id == TENANT, AiSession.session_key == session_key
            )
        )
    ).scalar_one()


class TestFailedAnalysis:
    def test_a_timeout_is_recorded_as_failed_not_benign(self) -> None:
        async def scenario():
            async with db_session() as db:
                await _seed(db)
                response = await record_analysis_result(_result(), authorization=AUTH, session=db)
                return response, await _row(db)

        response, row = asyncio.run(scenario())
        assert response.analysis_status == "analysis_failed"
        assert row.analysis_status == "analysis_failed"
        # The crucial part: no verdict was reached, so none is claimed.
        assert row.verdict is None

    def test_the_reason_is_kept_where_an_operator_can_see_it(self) -> None:
        async def scenario():
            async with db_session() as db:
                await _seed(db)
                await record_analysis_result(_result(), authorization=AUTH, session=db)
                return await _row(db)

        assert "timed out" in asyncio.run(scenario()).analysis_error

    def test_a_failure_with_no_reason_still_says_something(self) -> None:
        async def scenario():
            async with db_session() as db:
                await _seed(db)
                await record_analysis_result(
                    _result(reason=None), authorization=AUTH, session=db
                )
                return await _row(db)

        assert asyncio.run(scenario()).analysis_error

    def test_the_lease_is_released_so_the_session_can_be_retried(self) -> None:
        async def scenario():
            async with db_session() as db:
                await _seed(db)
                await record_analysis_result(_result(), authorization=AUTH, session=db)
                return await _row(db)

        row = asyncio.run(scenario())
        assert row.claimed_at is None
        assert row.claimed_by is None

    def test_repeated_failures_are_counted(self) -> None:
        """A session failing forever has to become visible."""

        async def scenario():
            async with db_session() as db:
                await _seed(db, attempts=2)
                await record_analysis_result(_result(), authorization=AUTH, session=db)
                return await _row(db)

        assert asyncio.run(scenario()).analysis_attempts == 3

    def test_no_finding_is_raised_by_a_failure(self) -> None:
        async def scenario():
            async with db_session() as db:
                await _seed(db, analysis_status="reasoning")
                response = await record_analysis_result(
                    _result(stage="reason"), authorization=AUTH, session=db
                )
                findings = list((await db.execute(select(Finding))).scalars().all())
                return response, findings

        response, findings = asyncio.run(scenario())
        assert response.finding_raised is False
        assert findings == []

    def test_a_budget_overrun_lands_the_same_way(self) -> None:
        async def scenario():
            async with db_session() as db:
                await _seed(db)
                await record_analysis_result(
                    _result(reason="Batch budget of $5.0000 is spent"),
                    authorization=AUTH,
                    session=db,
                )
                return await _row(db)

        row = asyncio.run(scenario())
        assert row.analysis_status == "analysis_failed"
        assert "budget" in row.analysis_error

    def test_a_failure_does_not_overwrite_an_earlier_verdict(self) -> None:
        """A session that was analysed keeps what it found."""

        async def scenario():
            async with db_session() as db:
                await _seed(db, analysis_status="reasoning", verdict="malicious")
                await record_analysis_result(
                    _result(stage="reason"), authorization=AUTH, session=db
                )
                return await _row(db)

        assert asyncio.run(scenario()).verdict == "malicious"


class TestSuccessStillWorks:
    def test_a_suspicious_triage_result_advances_the_pipeline(self) -> None:
        async def scenario():
            async with db_session() as db:
                await _seed(db)
                response = await record_analysis_result(
                    _result(verdict="suspicious", threat_tactic="ADR.T1005", reason=None),
                    authorization=AUTH,
                    session=db,
                )
                return response, await _row(db)

        response, row = asyncio.run(scenario())
        assert response.analysis_status == "triage_suspicious"
        assert row.analysis_error is None

    def test_a_benign_triage_result_still_clears_the_session(self) -> None:
        async def scenario():
            async with db_session() as db:
                await _seed(db)
                await record_analysis_result(
                    _result(verdict="benign", reason=None), authorization=AUTH, session=db
                )
                return await _row(db)

        row = asyncio.run(scenario())
        assert (row.analysis_status, row.verdict) == ("triage_benign", "benign")

    def test_a_successful_retry_clears_the_recorded_failure(self) -> None:
        """The session is no longer waiting on anyone."""

        async def scenario():
            async with db_session() as db:
                await _seed(db)
                await record_analysis_result(_result(), authorization=AUTH, session=db)
                # Reclaimed and retried; this time the model answers.
                row = await _row(db)
                row.analysis_status = "triaging"
                await db.commit()
                await record_analysis_result(
                    _result(verdict="benign", reason=None), authorization=AUTH, session=db
                )
                return await _row(db)

        row = asyncio.run(scenario())
        assert row.analysis_error is None
        assert row.analysis_status == "triage_benign"
        # The attempt count is history and stays.
        assert row.analysis_attempts == 1
