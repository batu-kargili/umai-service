"""Tests for posture-derived findings."""

import pytest

from app.core import posture_rules
from app.core.posture_rules import evaluate_posture, finding_key

BYPASS = {"permission_mode": "bypassPermissions"}
ENFORCED = {"permission_mode": "acceptEdits"}
SENSITIVE_PATH = r"C:\Users\dev\projects\payments-core"


@pytest.fixture(autouse=True)
def _unconfigured(monkeypatch):
    """Default to no configured policy, which is the shipping default."""
    monkeypatch.setattr(posture_rules.settings, "sensitive_project_patterns", None, raising=False)
    monkeypatch.setattr(posture_rules.settings, "approved_mcp_servers", None, raising=False)


def _sensitive(monkeypatch):
    monkeypatch.setattr(
        posture_rules.settings, "sensitive_project_patterns", "*/payments-core*", raising=False
    )


def _allowlist(monkeypatch, value="github,jira"):
    monkeypatch.setattr(posture_rules.settings, "approved_mcp_servers", value, raising=False)


def rules(findings):
    return {f.rule_id for f in findings}


def by_rule(findings, rule_id):
    return next(f for f in findings if f.rule_id == rule_id)


class TestNoiseControl:
    def test_no_posture_raises_nothing(self):
        assert evaluate_posture(session_key="s", posture=None) == []
        assert evaluate_posture(session_key="s", posture={}) == []

    def test_bypass_alone_is_informational(self):
        """A permission mode by itself is a posture fact, not an actionable alert.

        It was set on two thirds of agent-mode sessions on the first machine
        measured; raising those as high would bury the feed.
        """
        found = evaluate_posture(session_key="s", posture=BYPASS)
        assert by_rule(found, "posture.bypass_permissions").severity == "info"

    def test_browser_skip_does_not_duplicate_the_bypass_finding(self):
        """The two settings are near-perfectly correlated, so only one finding."""
        posture = {**BYPASS, "chrome_permission_mode": "skip_all_permission_checks"}
        found = evaluate_posture(session_key="s", posture=posture)

        assert rules(found) == {"posture.bypass_permissions"}
        assert by_rule(found, "posture.bypass_permissions").evidence["browser_checks_skipped"] is True

    def test_browser_skip_stands_alone_when_permissions_were_enforced(self):
        posture = {**ENFORCED, "chrome_permission_mode": "skip_all_permission_checks"}
        found = evaluate_posture(session_key="s", posture=posture)

        assert rules(found) == {"posture.browser_checks_skipped"}

    def test_enforced_permissions_raise_nothing(self):
        assert evaluate_posture(session_key="s", posture=ENFORCED) == []


class TestEscalation:
    def test_sensitive_path_escalates_bypass_to_high(self, monkeypatch):
        _sensitive(monkeypatch)
        found = evaluate_posture(session_key="s", posture=BYPASS, project_path=SENSITIVE_PATH)

        finding = by_rule(found, "posture.bypass_permissions")
        assert finding.severity == "high"
        assert finding.evidence["sensitive_path"] is True

    def test_unapproved_server_escalates_bypass_to_high(self, monkeypatch):
        _allowlist(monkeypatch)
        posture = {**BYPASS, "remote_mcp_servers": [{"name": "Supabase"}]}
        found = evaluate_posture(session_key="s", posture=posture)

        assert by_rule(found, "posture.bypass_permissions").severity == "high"

    def test_both_conditions_reach_critical(self, monkeypatch):
        _sensitive(monkeypatch)
        _allowlist(monkeypatch)
        posture = {**BYPASS, "remote_mcp_servers": [{"name": "Canva"}]}
        found = evaluate_posture(session_key="s", posture=posture, project_path=SENSITIVE_PATH)

        assert by_rule(found, "posture.bypass_permissions").severity == "critical"

    def test_path_matching_is_separator_and_case_insensitive(self, monkeypatch):
        _sensitive(monkeypatch)
        for path in (SENSITIVE_PATH, SENSITIVE_PATH.replace("\\", "/"), SENSITIVE_PATH.upper()):
            found = evaluate_posture(session_key="s", posture=BYPASS, project_path=path)
            assert by_rule(found, "posture.bypass_permissions").severity == "high", path


class TestMcpAllowlist:
    def test_no_allowlist_means_no_finding(self):
        """An unconfigured control produces no findings, not false ones."""
        posture = {**ENFORCED, "remote_mcp_servers": [{"name": "Supabase"}, {"name": "Canva"}]}
        assert evaluate_posture(session_key="s", posture=posture) == []

    def test_approved_servers_are_not_flagged(self, monkeypatch):
        _allowlist(monkeypatch)
        posture = {**ENFORCED, "remote_mcp_servers": [{"name": "GitHub"}]}
        assert evaluate_posture(session_key="s", posture=posture) == []

    def test_unapproved_server_is_flagged_with_its_name(self, monkeypatch):
        _allowlist(monkeypatch)
        posture = {**ENFORCED, "remote_mcp_servers": [{"name": "Supabase"}, {"name": "jira"}]}
        found = evaluate_posture(session_key="s", posture=posture)

        finding = by_rule(found, "posture.unapproved_mcp_server")
        assert finding.severity == "medium"
        assert finding.evidence["unapproved_mcp_servers"] == ["Supabase"]
        assert finding.technique_id == "ADR.T0012"

    def test_bare_string_server_entries_are_handled(self, monkeypatch):
        _allowlist(monkeypatch)
        posture = {**ENFORCED, "remote_mcp_servers": ["Supabase"]}
        found = evaluate_posture(session_key="s", posture=posture)

        assert by_rule(found, "posture.unapproved_mcp_server").evidence[
            "unapproved_mcp_servers"
        ] == ["Supabase"]


class TestFindingKey:
    def test_key_is_stable_so_re_ingest_updates_rather_than_duplicates(self):
        assert finding_key("sess", "rule") == finding_key("sess", "rule")

    def test_key_differs_per_rule_and_per_session(self):
        keys = {
            finding_key("a", "rule.one"),
            finding_key("a", "rule.two"),
            finding_key("b", "rule.one"),
        }
        assert len(keys) == 3
