"""SIEM payloads for security findings.

Findings are what a SOC analyst actually works from, so they are the events that
belong in QRadar. The existing LEEF encoder in `siem.py` reads a small set of
generic keys (`severity`, `event_type`, `user_email`, `device_id`, …); this
module maps a finding onto them and carries the ADR technique alongside, so a
QRadar rule can pivot on `ADR.T0007` without parsing free text.
"""

from __future__ import annotations

import datetime as dt
import json
from typing import Any

FINDING_EVENT_SCHEMA = "umai.finding.v1"


def build_finding_event(
    *,
    tenant_id: Any,
    finding_key: str,
    session_key: str,
    rule_id: str,
    technique_id: str | None,
    technique_name: str | None,
    tactic: str | None,
    severity: str,
    title: str,
    summary: str | None,
    evidence_json: str | None,
    source: str,
    category: str,
    actor_user: str | None,
    actor_device_id: str | None,
    project_path: str | None,
    observed_at: dt.datetime | None,
    detector: str,
    status: str = "open",
    assignee: str | None = None,
    remediation_json: str | None = None,
) -> dict[str, Any]:
    """Build the SIEM event for one finding."""
    try:
        evidence = json.loads(evidence_json) if evidence_json else {}
    except json.JSONDecodeError:
        evidence = {}

    occurred_at = observed_at or dt.datetime.now(dt.timezone.utc)

    return {
        "schema": FINDING_EVENT_SCHEMA,
        "tenant_id": str(tenant_id),
        "event_id": finding_key,
        "occurred_at": occurred_at.isoformat(),
        "ts": occurred_at.timestamp(),
        # `event_type` becomes the LEEF `cat`; the rule id is the most useful
        # thing to correlate and tune on.
        "event_type": rule_id,
        "severity": severity,
        "detector": detector,
        # The axes a SOC filters the queue on. `source` below is the channel
        # (adr, extension, sdk, red_team, policy), not the AI tool.
        "category": category,
        "status": status,
        # Identity and device: the LEEF encoder reads these key names directly.
        "user_email": actor_user,
        "device_id": actor_device_id,
        "reason": summary or title,
        "title": title,
        "session_key": session_key,
        "source": source,
        "project_path": project_path,
        "technique_id": technique_id,
        "technique_name": technique_name,
        "tactic": tactic,
        "evidence": evidence,
    }
