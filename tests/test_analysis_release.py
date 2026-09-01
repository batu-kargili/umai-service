from __future__ import annotations

import asyncio
import datetime as dt
import uuid

from app.api import analysis
from app.models.db import AiSession
from tests.conftest import db_session

TENANT = uuid.UUID("11111111-1111-1111-1111-111111111111")
TOKEN = "worker-token"


def _session(key: str, worker: str = "worker-1") -> AiSession:
    return AiSession(
        tenant_id=TENANT,
        session_key=key,
        source="codex",
        source_session_id=key,
        message_count=1,
        tool_call_count=0,
        analysis_status="triaging",
        claimed_by=worker,
        claimed_at=dt.datetime.now(dt.timezone.utc),
        observed_at=dt.datetime.now(dt.timezone.utc),
    )


def test_graceful_release_only_returns_the_callers_own_leases(monkeypatch):
    monkeypatch.setattr(analysis.settings, "analysis_worker_token", TOKEN)

    async def scenario():
        async with db_session() as db:
            db.add_all([_session("a" * 64), _session("b" * 64, "worker-2")])
            await db.commit()
            result = await analysis.release_sessions(
                analysis.ReleaseRequest(
                    stage="triage",
                    worker_id="worker-1",
                    sessions=[(TENANT, "a" * 64), (TENANT, "b" * 64)],
                ),
                authorization=f"Bearer {TOKEN}",
                session=db,
            )
            first = await db.get(AiSession, (TENANT, "a" * 64))
            second = await db.get(AiSession, (TENANT, "b" * 64))
            return result, first, second

    result, first, second = asyncio.run(scenario())
    assert result.released == 1
    assert first.analysis_status == "ingested" and first.claimed_by is None
    assert second.analysis_status == "triaging" and second.claimed_by == "worker-2"
