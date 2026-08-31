"""Findings derived from session posture, without reading any content.

Session posture — the permission mode a session ran under, which MCP servers it
connected to, whether browser permission checks were skipped — answers "what was
this session allowed to do". That question is answerable from a few hundred bytes
of metadata, needs no model, and is available the moment a session is ingested.

Severity is deliberately conservative. On a real fleet, `bypassPermissions` is
common — it was set on 16 of 24 agent-mode sessions on the first machine we
measured. Raising all of those as high-severity alerts would train a SOC to
ignore the feed within a week, which is the failure mode ADR's precision-first
design exists to avoid. A bare permission mode is therefore informational; it
escalates only when it coincides with something that changes the blast radius.

These are starting thresholds. Per-customer tuning belongs in the policy pack,
not in this module.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
from dataclasses import dataclass
from typing import Any

from app.core.settings import settings

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


def _escalate(severity: str, steps: int = 1) -> str:
    index = SEVERITY_ORDER.index(severity)
    return SEVERITY_ORDER[min(index + steps, len(SEVERITY_ORDER) - 1)]


def finding_key(session_key: str, rule_id: str) -> str:
    return hashlib.sha256(f"{session_key}|{rule_id}".encode("utf-8")).hexdigest()


@dataclass
class PostureFinding:
    rule_id: str
    technique_id: str
    technique_name: str
    tactic: str
    severity: str
    title: str
    summary: str
    evidence: dict[str, Any]

    def evidence_json(self) -> str:
        return json.dumps(self.evidence, ensure_ascii=False, sort_keys=True)


def _configured_list(raw: str | None) -> list[str]:
    if not raw:
        return []
    return [item.strip() for item in raw.split(",") if item.strip()]


def _is_sensitive(project_path: str | None) -> bool:
    """Whether the session operated somewhere the customer flagged as sensitive."""
    patterns = _configured_list(settings.sensitive_project_patterns)
    if not patterns or not project_path:
        return False
    normalized = project_path.replace("\\", "/").lower()
    return any(fnmatch.fnmatch(normalized, pattern.replace("\\", "/").lower()) for pattern in patterns)


def _unapproved_mcp_servers(posture: dict[str, Any]) -> list[str]:
    """MCP servers connected to a session that are not on the approved list.

    When no allow-list is configured we return nothing rather than flagging
    every server: an unconfigured control should produce no findings, not
    false ones.
    """
    approved = {name.lower() for name in _configured_list(settings.approved_mcp_servers)}
    if not approved:
        return []

    connected = posture.get("remote_mcp_servers") or []
    names = []
    for entry in connected:
        if isinstance(entry, dict):
            name = entry.get("name") or entry.get("url") or ""
        else:
            name = str(entry)
        if name and name.lower() not in approved:
            names.append(name)
    return names


def evaluate_posture(
    *,
    session_key: str,
    posture: dict[str, Any] | None,
    project_path: str | None = None,
    tool_call_count: int = 0,
) -> list[PostureFinding]:
    """Raise findings for a session's configuration. Pure — no I/O."""
    if not posture:
        return []

    findings: list[PostureFinding] = []
    sensitive = _is_sensitive(project_path)
    unapproved = _unapproved_mcp_servers(posture)

    permission_mode = posture.get("permission_mode")
    browser_checks_skipped = posture.get("chrome_permission_mode") == "skip_all_permission_checks"
    permissions_bypassed = permission_mode == "bypassPermissions"

    if permissions_bypassed:
        severity = "info"
        reasons = []
        if sensitive:
            severity = _escalate(severity, 3)  # info -> high
            reasons.append("operated in a path flagged as sensitive")
        if unapproved:
            severity = _escalate(severity, 3)
            reasons.append("connected an unapproved MCP server")

        findings.append(
            PostureFinding(
                rule_id="posture.bypass_permissions",
                technique_id="ADR.T0007",
                technique_name="Exploitation of Excessive Tool Permissions",
                tactic="permission_abuse",
                severity=severity,
                title="Agent session ran with permission checks bypassed",
                summary=(
                    "The session executed tools without per-action approval"
                    + (f"; {', and '.join(reasons)}." if reasons else ".")
                ),
                evidence={
                    "permission_mode": permission_mode,
                    "chrome_permission_mode": posture.get("chrome_permission_mode"),
                    "browser_checks_skipped": browser_checks_skipped,
                    "project_path": project_path,
                    "tool_call_count": tool_call_count,
                    "sensitive_path": sensitive,
                    "unapproved_mcp_servers": unapproved,
                },
            )
        )

    # Only worth its own finding when permissions were otherwise enforced.
    # The two settings are near-perfectly correlated in practice — on the first
    # fleet we measured, every session that skipped browser checks had already
    # bypassed permissions — so raising both would put two alerts on one desk
    # for a single underlying fact. When they coincide it rides along as
    # evidence on the finding above.
    if browser_checks_skipped and not permissions_bypassed:
        findings.append(
            PostureFinding(
                rule_id="posture.browser_checks_skipped",
                technique_id="ADR.T0007",
                technique_name="Exploitation of Excessive Tool Permissions",
                tactic="permission_abuse",
                severity="high" if sensitive else "low",
                title="Browser automation ran with all permission checks skipped",
                summary=(
                    "The session drove a browser with permission prompts disabled, so any "
                    "navigation or form interaction it performed was unattended."
                ),
                evidence={
                    "chrome_permission_mode": posture.get("chrome_permission_mode"),
                    "project_path": project_path,
                    "sensitive_path": sensitive,
                },
            )
        )

    if unapproved:
        findings.append(
            PostureFinding(
                rule_id="posture.unapproved_mcp_server",
                technique_id="ADR.T0012",
                technique_name="Unvetted MCP Server Connection",
                tactic="reasoning_data_manipulation",
                severity="high" if permissions_bypassed else "medium",
                title="Session connected an MCP server that is not on the approved list",
                summary=(
                    "Tools from an unvetted MCP server were available to the agent, which "
                    "widens the session's capability beyond what was reviewed."
                ),
                evidence={
                    "unapproved_mcp_servers": unapproved,
                    "permission_mode": permission_mode,
                    "project_path": project_path,
                },
            )
        )

    return findings
