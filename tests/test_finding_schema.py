"""Canonical finding vocabulary and the SIEM payload built from it.

Guards the contract frozen in
``docs/contracts/finding-and-worker-result-schema.md`` (platform repo, UMA-40).
"""

from __future__ import annotations

import datetime as dt

import pytest

from app.core import finding_schema as fs
from app.core.finding_events import FINDING_EVENT_SCHEMA, build_finding_event


class TestVocabulary:
    def test_sources_are_channels_not_ai_tools(self) -> None:
        assert fs.SOURCES == {"adr", "extension", "sdk", "red_team", "policy"}
        # The AI tool belongs on the session, never here. Catching this keeps
        # the queue's main filter from silently becoming a tool list again.
        for tool in ("claude", "cursor", "codex", "cline", "warp"):
            assert tool not in fs.SOURCES

    def test_detectors(self) -> None:
        assert fs.DETECTORS == {"posture", "triage", "reasoning", "red_team", "policy"}
        # `adr` names the whole subsystem — posture findings are ADR too — so
        # it is not a detector value.
        assert "adr" not in fs.DETECTORS

    def test_lifecycle_states(self) -> None:
        assert fs.STATUSES == {
            "open",
            "investigating",
            "resolved",
            "false_positive",
            "accepted_risk",
        }

    def test_judgement_transitions_require_a_note(self) -> None:
        assert fs.STATUSES_REQUIRING_NOTE == {"false_positive", "accepted_risk"}
        assert fs.STATUSES_REQUIRING_NOTE < fs.STATUSES

    def test_every_status_fits_the_column(self) -> None:
        # findings.status is VARCHAR(16); a longer value would be truncated or
        # rejected depending on the engine.
        assert max(len(s) for s in fs.STATUSES) <= 16


class TestDeriveCategory:
    @pytest.mark.parametrize(
        "rule_id,expected",
        [
            ("posture.bypass_permissions", "unsafe_tool_use"),
            ("posture.browser_checks_skipped", "unsafe_tool_use"),
            ("posture.unapproved_mcp_server", "shadow_ai"),
        ],
    )
    def test_known_posture_rules(self, rule_id: str, expected: str) -> None:
        assert fs.derive_category(rule_id) == expected

    def test_unknown_rule_falls_back_to_other(self) -> None:
        # The reasoning path builds `detector.<tactic>` at runtime, so it lands
        # here until it sends an explicit category (UMA-51).
        assert fs.derive_category("detector.credential_access") == "other"
        assert fs.derive_category(None) == "other"

    def test_derived_category_is_always_in_the_closed_set(self) -> None:
        for rule_id in (None, "", "posture.bypass_permissions", "totally.unknown"):
            assert fs.derive_category(rule_id) in fs.CATEGORIES

    def test_unrecognised_supplied_category_is_not_passed_through(self) -> None:
        # Letting an unknown value through would widen a closed set and make
        # queue filters lie about what they cover.
        assert fs.normalize_category("made_up", "posture.bypass_permissions") == "unsafe_tool_use"
        assert fs.normalize_category("made_up", None) == "other"

    def test_recognised_supplied_category_wins_over_derivation(self) -> None:
        assert (
            fs.normalize_category("data_exposure", "posture.bypass_permissions")
            == "data_exposure"
        )


def _writer_attributes() -> dict[str, object]:
    """The attribute dict both finding producers build.

    Mirrors `api.analysis._raise_analysis_finding` and
    `core.session_recorder`, which splat this straight into both `Finding(...)`
    and `build_finding_event(...)`.
    """
    return {
        "session_key": "s" * 64,
        "rule_id": "posture.unapproved_mcp_server",
        "technique_id": "ADR.T0007",
        "technique_name": "Unapproved capability",
        "tactic": "reasoning_data_manipulation",
        "severity": "high",
        "title": "Agent connected an unapproved MCP server",
        "summary": "why",
        "evidence_json": '{"confidence": 0.9}',
        "source": fs.SOURCE_ADR,
        "category": fs.CATEGORY_SHADOW_AI,
        "actor_user": "someone@example.com",
        "actor_device_id": "device-1",
        "project_path": "/repo",
        "observed_at": dt.datetime(2026, 8, 31, tzinfo=dt.timezone.utc),
        "detector": fs.DETECTOR_POSTURE,
    }


class TestFindingEventPayload:
    def test_accepts_exactly_what_the_writers_build(self) -> None:
        # Regression guard: the writers splat their attribute dict into this
        # function. Adding a finding column without widening the signature
        # raises TypeError at runtime on the first finding — a path no other
        # test covers, because nothing here touches a database.
        event = build_finding_event(
            tenant_id="11111111-1111-1111-1111-111111111111",
            finding_key="k" * 64,
            **_writer_attributes(),
        )
        assert event["schema"] == FINDING_EVENT_SCHEMA

    def test_carries_the_axes_a_soc_filters_on(self) -> None:
        event = build_finding_event(
            tenant_id="11111111-1111-1111-1111-111111111111",
            finding_key="k" * 64,
            **_writer_attributes(),
        )
        assert event["source"] == "adr"
        assert event["category"] == "shadow_ai"
        assert event["status"] == "open"
        assert event["detector"] == "posture"

    def test_technique_survives_into_the_payload(self) -> None:
        # The whole point of the schema freeze: a QRadar rule must be able to
        # pivot on ADR.T0007 without parsing free text.
        event = build_finding_event(
            tenant_id="11111111-1111-1111-1111-111111111111",
            finding_key="k" * 64,
            **_writer_attributes(),
        )
        assert event["technique_id"] == "ADR.T0007"
        assert event["tactic"] == "reasoning_data_manipulation"
        assert event["technique_id"] != event["tactic"]
