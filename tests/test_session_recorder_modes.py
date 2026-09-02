"""Ingest honours the tenant collection mode (UMA-48 / UMA-41).

Refusing to *serve* content is not privacy if the content was written to disk
anyway. A collector that keeps sending full sessions after the tenant narrowed
its mode must not be able to leave that content behind.
"""

from __future__ import annotations

import asyncio
import uuid

import pytest

from app.core import finding_schema
from app.core.session_recorder import (
    STATUS_CONTENT_NOT_COLLECTED,
    record_agent_sessions,
)
from app.core.transcript_store import (
    get_transcript_store,
    reset_transcript_store,
    transcript_sha256,
)
from app.models.db import AiSession, Tenant
from tests.conftest import db_session

TENANT = uuid.UUID("11111111-1111-1111-1111-111111111111")

SESSION = {
    "source": "claude_code",
    "session_id": "abc-123",
    "timestamp": "2026-08-31T12:00:00Z",
    "model": "claude-opus-5",
    "chat_history": [
        {"role": "user", "content": "paste of the customer export"},
        {"role": "assistant", "content": "acknowledged"},
    ],
    "session_context": {"title": "export", "posture": {"bypass_permissions": True}},
}


async def _ingest(db, mode: str, payload: dict | None = None):
    reset_transcript_store()
    db.add(Tenant(tenant_id=TENANT, name="acme", collection_mode=mode))
    await db.commit()
    result = await record_agent_sessions(
        db,
        tenant_id=TENANT,
        device_id="dev-1",
        collector={"name": "umai-adr-collector", "version": "0.4.0"},
        sessions=[payload or SESSION],
    )
    await db.commit()
    row = (await db.execute(AiSession.__table__.select())).mappings().one()
    return result, row


def _run(mode: str, payload: dict | None = None):
    async def scenario():
        async with db_session() as db:
            return await _ingest(db, mode, payload)

    return asyncio.run(scenario())


class TestModeGating:
    def test_full_session_mode_stores_the_transcript(self) -> None:
        result, row = _run(finding_schema.MODE_FULL_SESSION)
        assert result.created == 1
        assert row["transcript_ref"]
        assert row["transcript_bytes"]

    @pytest.mark.parametrize(
        "mode", [finding_schema.MODE_POSTURE_ONLY, finding_schema.MODE_METADATA]
    )
    def test_modes_without_content_write_no_blob(self, mode: str) -> None:
        result, row = _run(mode)
        assert result.created == 1
        assert row["transcript_ref"] is None
        assert row["transcript_bytes"] is None

    @pytest.mark.parametrize(
        "mode", [finding_schema.MODE_POSTURE_ONLY, finding_schema.MODE_METADATA]
    )
    def test_metadata_survives_without_content(self, mode: str) -> None:
        """The session is still worth recording — that is the whole point."""
        _result, row = _run(mode)
        assert row["source"] == "claude_code"
        assert row["model"] == "claude-opus-5"
        assert row["message_count"] == 2
        # Posture is configuration, so it is kept in every mode.
        assert "bypass_permissions" in (row["posture_json"] or "")

    def test_an_unknown_tenant_defaults_to_storing_nothing(self) -> None:
        async def scenario():
            async with db_session() as db:
                # No tenant row at all.
                reset_transcript_store()
                await record_agent_sessions(
                    db,
                    tenant_id=TENANT,
                    device_id="dev-1",
                    collector=None,
                    sessions=[SESSION],
                )
                await db.commit()
                return (await db.execute(AiSession.__table__.select())).mappings().one()

        assert asyncio.run(scenario())["transcript_ref"] is None


class TestIdempotence:
    def test_re_ingesting_the_same_session_is_a_no_op_without_content(self) -> None:
        """The digest is of the payload, so dedup works with no blob stored."""

        async def scenario():
            async with db_session() as db:
                await _ingest(db, finding_schema.MODE_METADATA)
                second = await record_agent_sessions(
                    db,
                    tenant_id=TENANT,
                    device_id="dev-1",
                    collector=None,
                    sessions=[SESSION],
                )
                await db.commit()
                return second

        result = asyncio.run(scenario())
        assert (result.unchanged, result.created, result.updated) == (1, 0, 0)

    def test_the_digest_matches_the_one_the_blob_store_would_produce(self) -> None:
        """So a tenant switching modes does not re-ingest everything."""

        async def scenario():
            async with db_session() as db:
                _r, metadata_row = await _ingest(db, finding_schema.MODE_METADATA)
                return metadata_row["transcript_sha256"]

        metadata_digest = asyncio.run(scenario())

        async def stored():
            reset_transcript_store()
            import json

            payload = json.dumps(SESSION, ensure_ascii=False, sort_keys=True).encode()
            _ref, sha, _size = await get_transcript_store().put(TENANT, payload)
            return sha, transcript_sha256(payload)

        blob_digest, direct = asyncio.run(stored())
        assert metadata_digest == blob_digest == direct


class TestOnlyAnalysableSessionsAreQueued:
    """A session with no transcript must never enter the analysis queue.

    Both stages start by fetching the transcript. Below `full_session` there is
    none, so the fetch answers 404, the worker's batch loop leaves the lease to
    expire, the session is reclaimed and it goes round again — forever, while
    counting as queue depth the whole time. On a `metadata` tenant, which is
    the schema default, that is every session ever ingested.
    """

    def test_full_session_still_queues_for_triage(self) -> None:
        _result, row = _run(finding_schema.MODE_FULL_SESSION)
        assert row["analysis_status"] == "ingested"

    @pytest.mark.parametrize(
        "mode", [finding_schema.MODE_POSTURE_ONLY, finding_schema.MODE_METADATA]
    )
    def test_content_free_modes_land_in_a_terminal_state(self, mode: str) -> None:
        _result, row = _run(mode)

        assert row["analysis_status"] == STATUS_CONTENT_NOT_COLLECTED
        # Not `analysis_failed`: nothing failed. The tenant chose this, and an
        # operator has to be able to tell a policy outcome from a malfunction.
        assert row["analysis_status"] != "analysis_failed"

    def test_a_grown_session_is_requeued_only_when_there_is_content(self) -> None:
        """Re-ingest resets the status; it must not resurrect the loop."""

        async def scenario():
            async with db_session() as db:
                await _ingest(db, finding_schema.MODE_METADATA)
                bigger = {
                    **SESSION,
                    "chat_history": SESSION["chat_history"]
                    + [{"role": "user", "content": "and one more thing"}],
                }
                await record_agent_sessions(
                    db,
                    tenant_id=TENANT,
                    device_id="dev-1",
                    collector={"name": "umai-adr-collector", "version": "0.4.0"},
                    sessions=[bigger],
                )
                await db.commit()
                return (await db.execute(AiSession.__table__.select())).mappings().one()

        row = asyncio.run(scenario())

        assert row["message_count"] == 3
        assert row["analysis_status"] == STATUS_CONTENT_NOT_COLLECTED

    def test_the_status_is_not_counted_as_a_waiting_queue(self) -> None:
        from app.core.analysis_metrics import (
            CLAIMED_STATUSES,
            NOT_COLLECTED_STATUSES,
            WAITING_STATUSES,
        )

        # A permanent, un-drainable backlog on the dashboard would train the
        # operator to ignore the one gauge that says analysis is behind.
        assert STATUS_CONTENT_NOT_COLLECTED not in WAITING_STATUSES
        assert STATUS_CONTENT_NOT_COLLECTED not in CLAIMED_STATUSES
        assert STATUS_CONTENT_NOT_COLLECTED in NOT_COLLECTED_STATUSES
