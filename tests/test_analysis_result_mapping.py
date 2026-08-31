"""Worker result -> finding column mapping.

The reasoning worker used to pack its ADR technique id into `threat_tactic`,
and the service wrote that into `tactic` while hardcoding `technique_id` to
NULL and `severity` to "high". These tests pin the corrected mapping
(UMA-51) against the contract frozen in UMA-40.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import json
import uuid

import pytest
from sqlalchemy import select

from app.api.analysis import ResultRequest, _finding_title, _raise_analysis_finding
from app.core import finding_schema as fs
from app.models.db import AiSession, Finding
from tests.conftest import db_session

TENANT = uuid.UUID("11111111-1111-1111-1111-111111111111")
SESSION_KEY = "s" * 64
NOW = dt.datetime(2026, 8, 31, tzinfo=dt.timezone.utc)


def _session_row() -> AiSession:
    return AiSession(
        tenant_id=TENANT,
        session_key=SESSION_KEY,
        source="claude",
        source_session_id="abc-123",
        actor_user="someone@example.com",
        actor_device_id="device-1",
        project_path="/repo",
        observed_at=NOW,
        message_count=12,
        tool_call_count=3,
        transcript_ref=f"{TENANT}/aa/{'a' * 64}.json.gz",
        transcript_sha256="a" * 64,
        analysis_status="reasoning",
    )


def _result(**overrides: object) -> ResultRequest:
    payload: dict[str, object] = {
        "tenant_id": TENANT,
        "session_key": SESSION_KEY,
        "stage": "reason",
        "verdict": "malicious",
        "technique_id": "ADR.T0007",
        "technique_name": "Indirect prompt injection via tool output",
        "threat_tactic": "reasoning_data_manipulation",
        "confidence": 0.95,
        "reason": "tool output steered the agent",
        "model": "gpt-4o-mini",
    }
    payload.update(overrides)
    return ResultRequest(**payload)


async def _raise(db, payload: ResultRequest) -> Finding:
    row = _session_row()
    db.add(row)
    await db.flush()
    await _raise_analysis_finding(db, row=row, payload=payload, now=NOW)
    return (await db.execute(select(Finding))).scalar_one()


class TestTechniqueAndTactic:
    def test_technique_and_tactic_land_in_their_own_columns(self) -> None:
        async def scenario() -> None:
            async with db_session() as db:
                finding = await _raise(db, _result())
                assert finding.technique_id == "ADR.T0007"
                assert finding.technique_name == "Indirect prompt injection via tool output"
                assert finding.tactic == "reasoning_data_manipulation"

        asyncio.run(scenario())

    def test_technique_id_never_lands_in_tactic(self) -> None:
        """The exact regression: `tactic` holding ADR.TXXXX."""

        async def scenario() -> None:
            async with db_session() as db:
                finding = await _raise(db, _result())
                assert not (finding.tactic or "").startswith("ADR.T")
                assert finding.tactic != finding.technique_id

        asyncio.run(scenario())

    def test_tactic_only_result_still_works(self) -> None:
        # Triage escalates with a tactic and no technique; reasoning may fail
        # to name one.
        async def scenario() -> None:
            async with db_session() as db:
                finding = await _raise(db, _result(technique_id=None, technique_name=None))
                assert finding.technique_id is None
                assert finding.tactic == "reasoning_data_manipulation"

        asyncio.run(scenario())

    def test_rule_id_prefers_the_technique(self) -> None:
        # The rule id is part of the idempotency key, so two different
        # techniques on one session must not collapse into one finding.
        async def scenario() -> None:
            async with db_session() as db:
                finding = await _raise(db, _result())
                assert finding.rule_id == "detector.ADR.T0007"

        asyncio.run(scenario())


class TestSeverity:
    @pytest.mark.parametrize(
        "confidence,expected",
        [(0.95, "high"), (0.90, "high"), (0.80, "medium"), (0.70, "medium"), (0.40, "low")],
    )
    def test_derived_from_confidence_when_detector_is_silent(
        self, confidence: float, expected: str
    ) -> None:
        async def scenario() -> None:
            async with db_session() as db:
                finding = await _raise(db, _result(confidence=confidence))
                assert finding.severity == expected
                evidence = json.loads(finding.evidence_json)
                assert evidence["severity_basis"] == "confidence"

        asyncio.run(scenario())

    def test_detector_supplied_severity_wins(self) -> None:
        async def scenario() -> None:
            async with db_session() as db:
                finding = await _raise(db, _result(severity="critical", confidence=0.1))
                assert finding.severity == "critical"
                assert json.loads(finding.evidence_json)["severity_basis"] == "detector"

        asyncio.run(scenario())

    def test_critical_is_never_derived(self) -> None:
        # An automatic route to the top of the scale makes the top of the
        # scale meaningless.
        for confidence in (1.0, 0.99, 0.95):
            assert fs.derive_severity(None, confidence)[0] != "critical"

    def test_no_confidence_does_not_become_high(self) -> None:
        async def scenario() -> None:
            async with db_session() as db:
                finding = await _raise(db, _result(confidence=None))
                assert finding.severity == "medium"
                assert json.loads(finding.evidence_json)["severity_basis"] == "default"

        asyncio.run(scenario())

    def test_severity_is_not_hardcoded_high_anymore(self) -> None:
        async def scenario() -> None:
            async with db_session() as db:
                finding = await _raise(db, _result(confidence=0.2))
                assert finding.severity == "low"

        asyncio.run(scenario())


class TestTitle:
    def test_names_what_was_detected(self) -> None:
        assert _finding_title(_result()) == "Indirect prompt injection via tool output"

    def test_falls_back_through_technique_then_tactic(self) -> None:
        assert "ADR.T0007" in _finding_title(_result(technique_name=None))
        generic = _finding_title(_result(technique_id=None, technique_name=None))
        assert "reasoning_data_manipulation" in generic

    def test_last_resort_is_still_readable(self) -> None:
        bare = _result(technique_id=None, technique_name=None, threat_tactic=None)
        assert _finding_title(bare)


class TestChannelAndDetector:
    def test_source_is_the_channel_not_the_ai_tool(self) -> None:
        async def scenario() -> None:
            async with db_session() as db:
                finding = await _raise(db, _result())
                # The session's tool is `claude`; the finding's channel is adr.
                assert finding.source == fs.SOURCE_ADR
                assert finding.detector == fs.DETECTOR_REASONING

        asyncio.run(scenario())
