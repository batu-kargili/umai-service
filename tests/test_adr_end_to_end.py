"""The ADR loop, driven end to end (UMA-59).

Every other test in this suite proves one component. This one proves they fit:
a collected session goes in at the ingest endpoint and comes out the other side
as a finding in an operator's queue and an event on its way to QRadar — through
the real recorder, the real claim/result endpoints, the real outbox and the real
drain.

The fixtures are the payloads the collector actually sends. They are generated
from `adr_sensor`'s own schema by `tests/fixtures/adr/generate.py` rather than
written by hand, so a schema change breaks the generator instead of quietly
making these tests assert something the collector never sends.

The failure half matters more than the happy path. A pipeline that loses a
finding when QRadar is down, or clears a session when a worker dies, fails in a
way nobody sees.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import json
import uuid
from pathlib import Path

import httpx
import pytest
from sqlalchemy import select

from app.api.analysis import (
    ClaimRequest,
    ResultRequest,
    claim_sessions,
    record_analysis_result,
)
from app.api.findings import query_findings, transition_finding
from app.api.sessions import load_session, load_transcript, query_sessions
from app.core.settings import settings
from app.core.siem_drain import MAX_ATTEMPTS, PermanentDeliveryError, drain_once, replay
from app.core.siem_outbox import STATUS_DEAD_LETTER, STATUS_DELIVERED, STATUS_PENDING
from app.core.session_recorder import record_agent_sessions
from app.core.transcript_store import reset_transcript_store
from app.models.db import AiSession, Finding, SiemOutbox, Tenant
from tests.conftest import db_session

TENANT = uuid.UUID("11111111-1111-1111-1111-111111111111")
WORKER_TOKEN = "worker-token"
AUTH = f"Bearer {WORKER_TOKEN}"
DEVICE = "dev-adr-01"
COLLECTOR = {"name": "umai-adr-collector", "version": "0.4.0"}

FIXTURES = Path(__file__).parent / "fixtures" / "adr"


def fixture(name: str) -> dict:
    return json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))


@pytest.fixture(autouse=True)
def worker_token(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "analysis_worker_token", WORKER_TOKEN, raising=False)
    # The MCP rule is deliberately inert without an allow-list. A deployment
    # that has not configured it is not a deployment these tests describe.
    monkeypatch.setattr(
        settings, "approved_mcp_servers", "filesystem,postgres", raising=False
    )
    # A per-test transcript root, so one test cannot read another's evidence.
    monkeypatch.setattr(settings, "transcript_store_path", str(tmp_path), raising=False)
    monkeypatch.setattr(settings, "transcript_encryption_key", None, raising=False)
    reset_transcript_store()


# --- the loop ---------------------------------------------------------------


async def ingest(db, *names: str, mode: str = "full_session"):
    """Enrol the tenant if needed and push the named fixtures through ingest."""
    if await db.get(Tenant, TENANT) is None:
        db.add(Tenant(tenant_id=TENANT, name="acme", collection_mode=mode))
        await db.commit()
    result = await record_agent_sessions(
        db,
        tenant_id=TENANT,
        device_id=DEVICE,
        collector=COLLECTOR,
        sessions=[fixture(name) for name in names],
    )
    await db.commit()
    return result


async def claim(db, stage: str, *, worker_id: str = "analyzer-1", limit: int = 10):
    response = await claim_sessions(
        ClaimRequest(stage=stage, worker_id=worker_id, limit=limit),
        authorization=AUTH,
        session=db,
    )
    return response.sessions


async def submit(db, **payload):
    return await record_analysis_result(
        ResultRequest(tenant_id=TENANT, **payload), authorization=AUTH, session=db
    )


async def rows(db, model):
    """Read a table and close the transaction behind it.

    Production gives every request its own session; a test that shares one has
    to hand the transaction back, or the next helper calling `session.begin()`
    finds one already open.
    """
    found = list((await db.execute(select(model))).scalars().all())
    await db.commit()
    return found


async def only_session(db) -> AiSession:
    found = await rows(db, AiSession)
    assert len(found) == 1
    return found[0]


async def reasoning_findings(db) -> list[Finding]:
    """Only what the reasoning stage raised.

    The codex fixture also trips posture rules at ingest, which is correct and
    is asserted separately. Tests about the analysis pipeline have to say which
    channel they mean.
    """
    return [f for f in await rows(db, Finding) if f.detector == "reasoning"]


async def reasoning_events(db) -> list[SiemOutbox]:
    queued = []
    for row in await rows(db, SiemOutbox):
        payload = json.loads(row.payload_json)
        if payload.get("detector") == "reasoning":
            queued.append(row)
    return queued


class TestBenignPath:
    """A session triage clears never reaches the reasoning stage."""

    def test_a_benign_session_ends_at_triage_with_no_finding(self) -> None:
        async def scenario():
            async with db_session() as db:
                await ingest(db, "claude_benign")
                claimed = await claim(db, "triage")
                await submit(
                    db,
                    session_key=claimed[0].session_key,
                    stage="triage",
                    verdict="benign",
                    model="gpt-4o",
                )
                # Nothing is waiting for the expensive stage.
                remaining = await claim(db, "reason")
                return await only_session(db), await rows(db, Finding), remaining

        session, findings, remaining = asyncio.run(scenario())
        assert session.analysis_status == "triage_benign"
        assert session.verdict == "benign"
        assert findings == []
        assert remaining == []

    def test_the_session_is_still_visible_to_an_operator(self) -> None:
        """Benign is not invisible: shadow-AI reporting is built on these."""

        async def scenario():
            async with db_session() as db:
                await ingest(db, "claude_benign")
                return await query_sessions(db, tenant_id=TENANT)

        page = asyncio.run(scenario())
        assert page.total == 1
        assert page.items[0].source == "claude"


class TestSuspiciousThenBenignPath:
    """Triage over-escalates on purpose; reasoning is what clears it."""

    def test_reasoning_can_clear_what_triage_flagged(self) -> None:
        async def scenario():
            async with db_session() as db:
                await ingest(db, "cursor_suspicious_benign")
                claimed = await claim(db, "triage")
                key = claimed[0].session_key
                await submit(
                    db,
                    session_key=key,
                    stage="triage",
                    verdict="suspicious",
                    threat_tactic="ADR.TA0010",
                    confidence=0.72,
                )
                handed_on = await claim(db, "reason")
                await submit(
                    db,
                    session_key=key,
                    stage="reason",
                    verdict="benign",
                    reason="Export stayed on the developer machine; no egress.",
                    confidence=0.88,
                )
                return handed_on, await only_session(db), await rows(db, Finding)

        handed_on, session, findings = asyncio.run(scenario())
        assert [s.session_key for s in handed_on] == [session.session_key]
        assert session.analysis_status == "analyzed"
        assert session.verdict == "benign"
        # The whole reason the second stage exists.
        assert findings == []

    def test_a_triage_verdict_alone_never_raises_a_finding(self) -> None:
        async def scenario():
            async with db_session() as db:
                await ingest(db, "cursor_suspicious_benign")
                claimed = await claim(db, "triage")
                await submit(
                    db,
                    session_key=claimed[0].session_key,
                    stage="triage",
                    verdict="suspicious",
                    threat_tactic="ADR.TA0010",
                )
                return await rows(db, Finding)

        assert asyncio.run(scenario()) == []


class TestMaliciousPath:
    """The path that has to work: evidence in, finding out, event queued."""

    async def _run(self, db):
        await ingest(db, "codex_malicious")
        claimed = await claim(db, "triage")
        key = claimed[0].session_key
        await submit(
            db,
            session_key=key,
            stage="triage",
            verdict="suspicious",
            threat_tactic="ADR.TA0010",
        )
        await claim(db, "reason")
        await submit(
            db,
            session_key=key,
            stage="reason",
            verdict="malicious",
            technique_id="ADR.T1005",
            technique_name="Bulk data collection and exfiltration",
            threat_tactic="ADR.TA0010",
            severity="critical",
            category="data_exposure",
            confidence=0.96,
            reason="Production dump uploaded to an external host, then the trail was cleared.",
            model="claude-sonnet-4-6",
        )
        return key

    def test_a_malicious_verdict_raises_a_finding(self) -> None:
        async def scenario():
            async with db_session() as db:
                await self._run(db)
                return await reasoning_findings(db)

        findings = asyncio.run(scenario())
        assert len(findings) == 1
        assert findings[0].severity == "critical"
        assert findings[0].category == "data_exposure"
        assert findings[0].status == "open"
        # The technique goes in its own column rather than being squeezed into
        # the tactic — the bug UMA-51 was about.
        assert findings[0].technique_id == "ADR.T1005"
        assert findings[0].tactic == "ADR.TA0010"

    def test_the_finding_reaches_the_operator_queue(self) -> None:
        async def scenario():
            async with db_session() as db:
                await self._run(db)
                return await query_findings(
                    db, tenant_id=TENANT, status="open", detector="reasoning"
                )

        page = asyncio.run(scenario())
        assert page.total == 1
        assert page.items[0].source == "adr"
        assert page.items[0].technique_id == "ADR.T1005"

    def test_an_operator_can_walk_from_the_finding_to_the_transcript(self) -> None:
        """The drill-down the console is built on, exercised for real."""

        async def scenario():
            async with db_session() as db:
                key = await self._run(db)
                found = (
                    await query_findings(db, tenant_id=TENANT, detector="reasoning")
                ).items[0]
                detail = await load_session(
                    db, tenant_id=TENANT, session_key=found.session_key
                )
                transcript = await load_transcript(
                    db, tenant_id=TENANT, session_key=key, actor="soc@acme"
                )
                return found, detail, transcript

        found, detail, transcript = asyncio.run(scenario())
        assert found.session_key == detail.session_key
        # Posture raised its own findings on this session; the count is the
        # session total, not just the reasoning one.
        assert detail.finding_count >= 1
        assert detail.transcript_available is True
        # The evidence that is actually in the fixture.
        rendered = json.dumps(transcript.transcript)
        assert "pg_dump" in rendered and "file-drop.example.net" in rendered

    def test_the_finding_is_queued_for_the_siem(self) -> None:
        async def scenario():
            async with db_session() as db:
                await self._run(db)
                return await reasoning_events(db)

        queued = asyncio.run(scenario())
        assert len(queued) == 1
        assert queued[0].status == STATUS_PENDING
        payload = json.loads(queued[0].payload_json)
        assert payload["technique_id"] == "ADR.T1005"

    def test_the_event_reaches_the_siem_when_the_drain_runs(self) -> None:
        sent: list[dict] = []

        async def sender(event: dict) -> None:
            sent.append(event)

        async def scenario():
            async with db_session() as db:
                await self._run(db)
                result = await drain_once(db, sender=sender)
                return result, await rows(db, SiemOutbox)

        result, queued = asyncio.run(scenario())
        # Everything queued in this run goes out together: the posture findings
        # raised at ingest and the reasoning finding.
        assert result.delivered == len(queued)
        assert all(row.status == STATUS_DELIVERED for row in queued)
        assert len(sent) == len(queued)


class TestPostureFindings:
    """Posture reads configuration, so it does not wait on the pipeline."""

    def test_a_bad_posture_raises_a_finding_at_ingest(self) -> None:
        async def scenario():
            async with db_session() as db:
                await ingest(db, "codex_malicious")
                return await rows(db, Finding), await only_session(db)

        findings, session = asyncio.run(scenario())
        # The fixture ran with permissions bypassed and an unapproved MCP
        # server; the session has not been analysed yet.
        assert session.analysis_status == "ingested"
        assert findings, "posture findings should not wait for triage"
        assert all(f.detector == "posture" for f in findings)

    def test_a_clean_posture_raises_nothing(self) -> None:
        async def scenario():
            async with db_session() as db:
                await ingest(db, "claude_benign")
                return await rows(db, Finding)

        assert asyncio.run(scenario()) == []


class TestDuplicateIngest:
    """A collector re-sending its backlog must not double anything."""

    def test_re_sending_an_unchanged_session_changes_nothing(self) -> None:
        async def scenario():
            async with db_session() as db:
                first = await ingest(db, "codex_malicious")
                second = await ingest(db, "codex_malicious")
                return first, second, await rows(db, AiSession), await rows(db, Finding)

        first, second, sessions, findings = asyncio.run(scenario())
        assert (first.created, first.updated, first.unchanged) == (1, 0, 0)
        assert (second.created, second.updated, second.unchanged) == (0, 0, 1)
        assert len(sessions) == 1
        # Not doubled: the finding key is derived, not generated.
        assert len({f.finding_key for f in findings}) == len(findings)

    def test_re_ingest_does_not_reset_a_completed_analysis(self) -> None:
        async def scenario():
            async with db_session() as db:
                await ingest(db, "claude_benign")
                claimed = await claim(db, "triage")
                await submit(
                    db,
                    session_key=claimed[0].session_key,
                    stage="triage",
                    verdict="benign",
                )
                await ingest(db, "claude_benign")
                return await only_session(db)

        assert asyncio.run(scenario()).analysis_status == "triage_benign"

    def test_three_different_tools_ingest_as_three_sessions(self) -> None:
        async def scenario():
            async with db_session() as db:
                await ingest(
                    db, "claude_benign", "cursor_suspicious_benign", "codex_malicious"
                )
                return await rows(db, AiSession)

        sessions = asyncio.run(scenario())
        assert {s.source for s in sessions} == {"claude", "cursor", "codex"}
        assert len({s.session_key for s in sessions}) == 3


class TestWorkerCrash:
    """A worker that dies mid-session must not take the session with it."""

    def test_a_claimed_session_is_reclaimed_after_its_lease_expires(self) -> None:
        async def scenario():
            async with db_session() as db:
                await ingest(db, "codex_malicious")
                first = await claim(db, "triage", worker_id="analyzer-dies")
                # The worker never reports. Age the lease past its window.
                session = await only_session(db)
                session.claimed_at = dt.datetime.now(dt.timezone.utc) - dt.timedelta(
                    seconds=settings.analysis_claim_lease_seconds + 3600
                )
                await db.commit()
                second = await claim(db, "triage", worker_id="analyzer-survives")
                return first, second, await only_session(db)

        first, second, session = asyncio.run(scenario())
        assert [s.session_key for s in first] == [s.session_key for s in second]
        assert session.claimed_by == "analyzer-survives"

    def test_a_live_lease_is_not_stolen_by_a_second_worker(self) -> None:
        async def scenario():
            async with db_session() as db:
                await ingest(db, "codex_malicious")
                await claim(db, "triage", worker_id="analyzer-1")
                return await claim(db, "triage", worker_id="analyzer-2")

        assert asyncio.run(scenario()) == []

    def test_a_worker_that_reports_a_failure_does_not_clear_the_session(self) -> None:
        """The failure mode UMA-53 closed, proved on the whole loop."""

        async def scenario():
            async with db_session() as db:
                await ingest(db, "codex_malicious")
                claimed = await claim(db, "triage")
                await submit(
                    db,
                    session_key=claimed[0].session_key,
                    stage="triage",
                    verdict="error",
                    reason="Model call timed out: after 60s",
                )
                return await only_session(db)

        session = asyncio.run(scenario())
        assert session.analysis_status == "analysis_failed"
        assert session.verdict is None
        assert "timed out" in session.analysis_error


class TestStorageFailure:
    """The blob store can lose a transcript. The finding must survive it."""

    def test_a_finding_outlives_the_transcript_behind_it(self) -> None:
        async def scenario():
            async with db_session() as db:
                await ingest(db, "codex_malicious")
                claimed = await claim(db, "triage")
                key = claimed[0].session_key
                await submit(
                    db, session_key=key, stage="triage", verdict="suspicious",
                    threat_tactic="ADR.TA0010",
                )
                await claim(db, "reason")
                await submit(
                    db,
                    session_key=key,
                    stage="reason",
                    verdict="malicious",
                    technique_id="ADR.T1005",
                    threat_tactic="ADR.TA0010",
                    confidence=0.95,
                )
                # Retention, or a lost volume.
                session = await only_session(db)
                session.transcript_ref = None
                session.transcript_sha256 = None
                await db.commit()

                findings = await query_findings(
                    db, tenant_id=TENANT, detector="reasoning"
                )
                detail = await load_session(db, tenant_id=TENANT, session_key=key)
                return findings, detail

        findings, detail = asyncio.run(scenario())
        assert findings.total == 1
        assert detail.transcript_available is False

    def test_the_worker_is_told_the_transcript_is_gone_rather_than_given_nothing(
        self,
    ) -> None:
        from app.core.errors import ServiceError

        async def scenario():
            async with db_session() as db:
                await ingest(db, "codex_malicious")
                session = await only_session(db)
                key = session.session_key
                session.transcript_ref = None
                await db.commit()
                with pytest.raises(ServiceError) as exc:
                    await load_transcript(
                        db, tenant_id=TENANT, session_key=key, actor="soc@acme"
                    )
                return exc.value

        error = asyncio.run(scenario())
        assert error.status_code == 410


class TestQRadarOutage:
    """QRadar goes down. Nothing may be lost, and someone has to be able to see it."""

    async def _queued(self, db) -> str:
        await ingest(db, "codex_malicious")
        claimed = await claim(db, "triage")
        key = claimed[0].session_key
        await submit(
            db, session_key=key, stage="triage", verdict="suspicious",
            threat_tactic="ADR.TA0010",
        )
        await claim(db, "reason")
        await submit(
            db,
            session_key=key,
            stage="reason",
            verdict="malicious",
            technique_id="ADR.T1005",
            threat_tactic="ADR.TA0010",
            confidence=0.96,
        )
        return key

    def test_an_outage_leaves_the_event_queued_rather_than_dropped(self) -> None:
        async def down(_: dict) -> None:
            raise httpx.ConnectError("QRadar is unreachable")

        async def scenario():
            async with db_session() as db:
                await self._queued(db)
                result = await drain_once(db, sender=down)
                return result, await rows(db, SiemOutbox)

        result, queued = asyncio.run(scenario())
        # Nothing was dropped: every queued event is still pending a retry.
        assert result.retried == len(queued)
        assert all(row.status == STATUS_PENDING for row in queued)
        assert all(row.attempts == 1 for row in queued)

    def test_the_event_is_delivered_once_qradar_comes_back(self) -> None:
        calls = {"n": 0}

        async def flaky(_: dict) -> None:
            calls["n"] += 1
            if calls["n"] <= 2:
                raise httpx.ConnectError("still down")

        async def scenario():
            async with db_session() as db:
                await self._queued(db)
                when = dt.datetime.now(dt.timezone.utc)
                for _ in range(3):
                    await drain_once(db, sender=flaky, now=when)
                    when += dt.timedelta(hours=1)
                return await rows(db, SiemOutbox)

        queued = asyncio.run(scenario())
        assert all(row.status == STATUS_DELIVERED for row in queued)
        assert all(row.last_error is None for row in queued)

    def test_a_permanent_rejection_becomes_a_visible_dead_letter(self) -> None:
        async def rejects(_: dict) -> None:
            raise PermanentDeliveryError("HTTP 422")

        async def scenario():
            async with db_session() as db:
                await self._queued(db)
                await drain_once(db, sender=rejects)
                from app.api.findings import delivery_stats

                return await rows(db, SiemOutbox), await delivery_stats(
                    db, tenant_id=TENANT
                )

        queued, stats = asyncio.run(scenario())
        assert all(row.status == STATUS_DEAD_LETTER for row in queued)
        # Visible to the operator, which is the whole point of not retrying
        # forever in silence.
        assert stats.dead_letter == len(queued)

    def test_a_long_outage_stops_retrying_and_can_be_replayed(self) -> None:
        state = {"up": False}

        async def sender(_: dict) -> None:
            if not state["up"]:
                raise httpx.ConnectError("down")

        async def scenario():
            async with db_session() as db:
                await self._queued(db)
                when = dt.datetime.now(dt.timezone.utc)
                for _ in range(MAX_ATTEMPTS):
                    await drain_once(db, sender=sender, now=when)
                    when += dt.timedelta(hours=1)
                dead = [row.status for row in await rows(db, SiemOutbox)]

                # Someone fixes QRadar and replays one event by hand.
                state["up"] = True
                event_id = (await reasoning_events(db))[0].event_id
                await replay(
                    db, tenant_id=TENANT, event_id=event_id, actor="soc@acme", now=when
                )
                await drain_once(db, sender=sender, now=when)
                return dead, (await reasoning_events(db))[0]

        dead, row = asyncio.run(scenario())
        assert set(dead) == {STATUS_DEAD_LETTER}
        assert row.status == STATUS_DELIVERED
        assert row.replayed_by == "soc@acme"

    def test_an_outage_does_not_stop_findings_being_worked(self) -> None:
        """The SOC queue is not blocked by the SIEM integration."""

        async def down(_: dict) -> None:
            raise httpx.ConnectError("down")

        async def scenario():
            async with db_session() as db:
                await self._queued(db)
                await drain_once(db, sender=down)
                found = (
                    await query_findings(
                        db, tenant_id=TENANT, status="open", detector="reasoning"
                    )
                ).items[0]
                await transition_finding(
                    db,
                    tenant_id=TENANT,
                    finding_key=found.finding_key,
                    to_status="investigating",
                    actor="soc@acme",
                )
                return await query_findings(db, tenant_id=TENANT, status="investigating")

        assert asyncio.run(scenario()).total == 1


class TestRestartPreservation:
    """Nothing in flight may depend on a process staying up."""

    def test_a_transcript_survives_a_restart(self) -> None:
        async def scenario():
            async with db_session() as db:
                await ingest(db, "codex_malicious")
                key = (await only_session(db)).session_key
                # A restart drops the memoized store, not the bytes.
                reset_transcript_store()
                return await load_transcript(
                    db, tenant_id=TENANT, session_key=key, actor="soc@acme"
                )

        assert "pg_dump" in json.dumps(asyncio.run(scenario()).transcript)

    def test_unanalysed_work_is_still_claimable_after_a_restart(self) -> None:
        async def scenario():
            async with db_session() as db:
                await ingest(db, "claude_benign", "codex_malicious")
                await db.commit()
                # A fresh process holds no in-memory queue.
                return await claim(db, "triage")

        assert len(asyncio.run(scenario())) == 2

    def test_an_undelivered_event_is_still_pending_after_a_restart(self) -> None:
        sent: list[dict] = []

        async def sender(event: dict) -> None:
            sent.append(event)

        async def scenario():
            async with db_session() as db:
                await ingest(db, "codex_malicious")
                claimed = await claim(db, "triage")
                key = claimed[0].session_key
                await submit(
                    db, session_key=key, stage="triage", verdict="suspicious",
                    threat_tactic="ADR.TA0010",
                )
                await claim(db, "reason")
                await submit(
                    db,
                    session_key=key,
                    stage="reason",
                    verdict="malicious",
                    technique_id="ADR.T1005",
                    threat_tactic="ADR.TA0010",
                    confidence=0.96,
                )
                # The drain never ran before the process died.
                queued = len(await rows(db, SiemOutbox))
                result = await drain_once(db, sender=sender)
                return queued, result, sent

        queued, result, sent = asyncio.run(scenario())
        assert queued >= 1
        assert result.delivered == queued
        assert len(sent) == queued

    def test_an_operator_decision_survives_a_restart(self) -> None:
        async def scenario():
            async with db_session() as db:
                await ingest(db, "codex_malicious")
                found = (await query_findings(db, tenant_id=TENANT)).items[0]
                # Posture raised this one at ingest; the decision an operator
                # records on it has to survive a restart just the same.
                await transition_finding(
                    db,
                    tenant_id=TENANT,
                    finding_key=found.finding_key,
                    to_status="accepted_risk",
                    actor="soc@acme",
                    note="Known migration job; the host is ours.",
                )
                await db.commit()
                detail = await query_findings(
                    db, tenant_id=TENANT, status="accepted_risk"
                )
                return detail

        page = asyncio.run(scenario())
        assert page.total >= 1
        assert page.items[0].status == "accepted_risk"


class TestModeAwareIngest:
    """A tenant that collects no content still gets the loop, minus evidence."""

    def test_metadata_mode_records_the_session_without_the_transcript(self) -> None:
        from app.core.errors import ServiceError

        async def scenario():
            async with db_session() as db:
                await ingest(db, "codex_malicious", mode="metadata")
                session = await only_session(db)
                with pytest.raises(ServiceError) as exc:
                    await load_transcript(
                        db,
                        tenant_id=TENANT,
                        session_key=session.session_key,
                        actor="soc@acme",
                    )
                return session, exc.value

        session, error = asyncio.run(scenario())
        assert session.transcript_ref is None
        assert session.message_count == 2
        assert error.error_type == "CONTENT_NOT_COLLECTED"

    def test_posture_findings_still_fire_without_content(self) -> None:
        """Posture is configuration, so the cheapest mode still detects it."""

        async def scenario():
            async with db_session() as db:
                await ingest(db, "codex_malicious", mode="posture_only")
                return await rows(db, Finding)

        assert asyncio.run(scenario())


class TestFixtures:
    """The fixtures are the contract with the collector, so guard their shape."""

    NAMES = ["claude_benign", "cursor_suspicious_benign", "codex_malicious"]

    def test_one_fixture_per_tool(self) -> None:
        sources = {fixture(name)["source"] for name in self.NAMES}
        assert sources == {"claude", "cursor", "codex"}

    @pytest.mark.parametrize("name", NAMES)
    def test_every_fixture_carries_what_ingest_requires(self, name: str) -> None:
        payload = fixture(name)
        # `source` and `session_id` are the two the recorder rejects a batch
        # without; the rest is what makes the session worth recording.
        assert payload["source"] and payload["session_id"]
        assert payload["timestamp"]
        assert payload["chat_history"]
        assert payload["session_context"]["posture"]

    @pytest.mark.parametrize("name", NAMES)
    def test_posture_uses_the_collector_field_names(self, name: str) -> None:
        """Invented field names would make the posture rules silently inert."""
        posture = fixture(name)["session_context"]["posture"]
        assert "permission_mode" in posture
        assert "remote_mcp_servers" in posture

    def test_no_fixture_carries_a_plausible_secret(self) -> None:
        """These are committed to a public repository."""
        for name in self.NAMES:
            rendered = json.dumps(fixture(name))
            for marker in ("sk-", "AKIA", "BEGIN PRIVATE KEY", "password="):
                assert marker not in rendered, f"{name} contains {marker}"
