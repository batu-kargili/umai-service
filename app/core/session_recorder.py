"""Normalize collected agent sessions into `ai_sessions`.

The collector's wire format is ADR's `AgentEvent` — a transcript with ordered
messages and tool calls. This module is the translator into the platform's
session row plus a blob reference.

Deriving `umai.ai_event.v1` (RFC-1) rows from these sessions is a separate step;
the session is the analysis unit, the event is the query unit.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import uuid
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import finding_schema
from app.core.findings import upsert_finding
from app.core.posture_rules import evaluate_posture, finding_key
from app.core.transcript_store import get_transcript_store, transcript_sha256
from app.models.db import AiSession, Tenant


@dataclass
class RecordResult:
    created: int = 0
    updated: int = 0
    unchanged: int = 0
    findings: int = 0
    rejected: list[str] = field(default_factory=list)
    # SIEM payloads for findings raised in this batch. Emitted by the caller
    # *after* the transaction commits, so QRadar never sees a rolled-back row.
    siem_events: list[dict[str, Any]] = field(default_factory=list)

    @property
    def accepted(self) -> int:
        return self.created + self.updated + self.unchanged


def session_key(source: str, source_session_id: str, raw_log_path: str | None) -> str:
    """Stable identity for a collected session.

    Mirrors the collector's own state key. `session_id` alone is not unique:
    sub-agent (sidechain) runs carry their parent's session id in files of their
    own, so keying on it would collapse distinct runs into one row.
    """
    material = f"{source}|{source_session_id}|{raw_log_path or ''}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _parse_timestamp(value: Any) -> dt.datetime:
    if isinstance(value, dt.datetime):
        parsed = value
    else:
        try:
            parsed = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except (TypeError, ValueError):
            return dt.datetime.now(dt.timezone.utc)

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def _counts(chat_history: list[dict[str, Any]]) -> tuple[int, int]:
    messages = len(chat_history)
    tools = sum(len(message.get("tools") or []) for message in chat_history)
    return messages, tools


def _resolve_actor(payload: dict[str, Any], device_id: str | None) -> str | None:
    """Best available identity for the session.

    A normalization rule, not directory resolution — the sensor reports an OS
    username, not a corporate identity. Joining these to a directory is what
    turns them into people, and that lands with the identity connector.
    """
    username = (payload.get("username") or "").strip()
    if username:
        return username.lower()
    if device_id:
        return f"device:{device_id}"
    return None


async def record_agent_sessions(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    device_id: str | None,
    collector: dict[str, Any] | None,
    sessions: list[dict[str, Any]],
) -> RecordResult:
    """Persist a batch of collected sessions. Idempotent per content hash."""
    result = RecordResult()
    store = get_transcript_store()
    collector = collector or {}

    # The tenant's mode decides whether content is stored at all. A collector
    # that keeps sending full sessions after the mode was narrowed must not be
    # able to leave content on our disks: refusing to serve it later is no use
    # if it was written in the first place.
    tenant = await db.get(Tenant, tenant_id)
    mode = getattr(tenant, "collection_mode", None)
    if mode not in finding_schema.COLLECTION_MODES:
        mode = finding_schema.MODE_POSTURE_ONLY
    store_content = mode in finding_schema.MODES_WITH_CONTENT

    for index, payload in enumerate(sessions):
        source = (payload.get("source") or "").strip()
        source_session_id = (payload.get("session_id") or "").strip()

        if not source or not source_session_id:
            result.rejected.append(f"sessions[{index}]: source and session_id are required")
            continue

        raw_log_path = payload.get("raw_log_path")
        key = session_key(source, source_session_id, raw_log_path)

        transcript = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
        # The digest is computed in every mode: it is what makes re-ingest
        # idempotent, and a hash of content is not the content.
        sha = transcript_sha256(transcript)
        ref: str | None = None
        stored_bytes: int | None = None
        if store_content:
            ref, sha, stored_bytes = await store.put(tenant_id, transcript)

        existing = (
            await db.execute(
                select(AiSession).where(
                    AiSession.tenant_id == tenant_id,
                    AiSession.session_key == key,
                )
            )
        ).scalar_one_or_none()

        if existing is not None and existing.transcript_sha256 == sha:
            result.unchanged += 1
            continue

        chat_history = payload.get("chat_history") or []
        message_count, tool_call_count = _counts(chat_history)
        session_context = payload.get("session_context") or {}
        posture = session_context.get("posture")

        values = {
            "source": source,
            "source_session_id": source_session_id,
            "raw_log_path": raw_log_path,
            "actor_user": _resolve_actor(payload, device_id),
            "actor_device_id": device_id,
            "hostname": payload.get("hostname"),
            "username": payload.get("username"),
            "model": payload.get("model"),
            "project_path": payload.get("project_path"),
            "title": session_context.get("title"),
            "observed_at": _parse_timestamp(payload.get("timestamp")),
            "message_count": message_count,
            "tool_call_count": tool_call_count,
            "posture_json": json.dumps(posture, ensure_ascii=False) if posture else None,
            "transcript_ref": ref,
            "transcript_sha256": sha,
            "transcript_bytes": stored_bytes,
            "collector_name": collector.get("name"),
            "collector_version": collector.get("version"),
            "updated_at": dt.datetime.now(dt.timezone.utc),
        }

        if existing is None:
            db.add(
                AiSession(
                    tenant_id=tenant_id,
                    session_key=key,
                    analysis_status="ingested",
                    **values,
                )
            )
            result.created += 1
        else:
            for attribute, value in values.items():
                setattr(existing, attribute, value)
            # Content changed — the session grew, so it needs analysing again.
            existing.analysis_status = "ingested"
            existing.threat_tactic = None
            existing.verdict = None
            existing.confidence = None
            existing.analyzed_at = None
            result.updated += 1

        # Posture findings are available now: they read configuration, not
        # content, so they do not wait on the analysis pipeline.
        raised, events = await _record_posture_findings(
            db,
            tenant_id=tenant_id,
            session_key=key,
            posture=posture,
            values=values,
            tool_call_count=tool_call_count,
        )
        result.findings += raised
        result.siem_events.extend(events)

    return result


async def _record_posture_findings(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    session_key: str,
    posture: dict[str, Any] | None,
    values: dict[str, Any],
    tool_call_count: int,
) -> tuple[int, list[dict[str, Any]]]:
    """Upsert findings raised by the posture rules for one session.

    Returns (newly_raised, siem_events).
    """
    raised = evaluate_posture(
        session_key=session_key,
        posture=posture,
        project_path=values.get("project_path"),
        tool_call_count=tool_call_count,
    )
    if not raised:
        return 0, []

    recorded = 0
    events: list[dict[str, Any]] = []
    for finding in raised:
        key = finding_key(session_key, finding.rule_id)

        attributes = {
            "session_key": session_key,
            "rule_id": finding.rule_id,
            "technique_id": finding.technique_id,
            "technique_name": finding.technique_name,
            "tactic": finding.tactic,
            "severity": finding.severity,
            "title": finding.title,
            "summary": finding.summary,
            "evidence_json": finding.evidence_json(),
            # The channel, not the AI tool. `values["source"]` holds the tool
            # (`claude`, `cursor`, …) and stays reachable through `session_key`.
            "source": finding_schema.SOURCE_ADR,
            "category": finding_schema.derive_category(finding.rule_id),
            "actor_user": values.get("actor_user"),
            "actor_device_id": values.get("actor_device_id"),
            "project_path": values.get("project_path"),
            "observed_at": values.get("observed_at"),
            "detector": finding_schema.DETECTOR_POSTURE,
        }

        created, event = await upsert_finding(
            db, tenant_id=tenant_id, finding_key=key, attributes=attributes
        )
        if created:
            recorded += 1
        if event is not None:
            events.append(event)

    return recorded, events
