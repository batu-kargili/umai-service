"""Publish eval gate: a guardrail version must prove itself before it goes live.

``enforce_publish_gate`` is called by the explicit publish endpoint. It resolves the
thresholds (a tenant ``GuardrailPublishGate`` row, else service settings), loads the
latest ``COMPLETED`` evaluation run for the exact version being published, and either
lets the publish through, records an operator bypass, or raises ``EVAL_GATE_NOT_MET``.

Every outcome is returned as a ``PublishGateDecision`` so the caller can put it in the
publish log line and the ``umai.admin.publish.v1`` SIEM event — a bypass or a skipped
gate is never silent.
"""

from __future__ import annotations

import json
import logging
import math
import uuid
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import ServiceError
from app.core.settings import settings
from app.models.db import EvaluationCase, EvaluationRun, GuardrailPublishGate

logger = logging.getLogger(__name__)

GATE_PASSED = "passed"
GATE_BYPASSED = "bypassed"
GATE_SKIPPED = "skipped"


@dataclass
class PublishGateDefaults:
    """Publish gate thresholds (from a tenant row or from service settings)."""

    min_expected_action_accuracy: float | None
    min_expected_allowed_accuracy: float | None
    min_eval_cases: int
    max_p95_latency_ms: float | None


@dataclass
class PublishGateDecision:
    """What the gate decided, in a shape that goes straight into audit/SIEM."""

    status: str  # passed | bypassed | skipped
    reason: str | None = None
    bypass_kind: str | None = None  # bypass_eval_gate | break_glass
    run_id: str | None = None
    failed_checks: list[dict] = field(default_factory=list)

    @property
    def bypassed(self) -> bool:
        return self.status == GATE_BYPASSED

    def to_event(self) -> dict:
        return {
            "status": self.status,
            "reason": self.reason,
            "bypass_kind": self.bypass_kind,
            "run_id": self.run_id,
            "failed_checks": self.failed_checks,
        }


def skipped_gate(reason: str) -> PublishGateDecision:
    return PublishGateDecision(status=GATE_SKIPPED, reason=reason)


def validate_bypass_request(
    bypass_eval_gate: bool,
    bypass_reason: str | None,
    break_glass_reason: str | None = None,
) -> None:
    """Reject a bypass without a reason, whatever the gate would have decided."""
    if (
        bypass_eval_gate
        and not (break_glass_reason or "").strip()
        and not (bypass_reason or "").strip()
        and settings.publish_gate_require_bypass_reason
    ):
        raise ServiceError(
            "BYPASS_REASON_REQUIRED",
            "bypass_reason is required when bypass_eval_gate is true",
            422,
        )


async def resolve_publish_gate(
    session: AsyncSession,
    tenant_id: uuid.UUID,
    environment_id: str,
    project_id: str,
    guardrail_id: str,
) -> PublishGateDefaults:
    """Return publish gate defaults from service-level settings.

    Called when no tenant-specific ``GuardrailPublishGate`` row exists.
    """
    return PublishGateDefaults(
        min_expected_action_accuracy=settings.publish_gate_min_expected_action_accuracy,
        min_expected_allowed_accuracy=settings.publish_gate_min_expected_allowed_accuracy,
        min_eval_cases=settings.publish_gate_min_eval_cases,
        max_p95_latency_ms=settings.publish_gate_max_p95_latency_ms,
    )


async def load_publish_gate(
    session: AsyncSession,
    tenant_id: uuid.UUID,
    environment_id: str,
    project_id: str,
    guardrail_id: str,
) -> PublishGateDefaults:
    """The effective thresholds: the tenant's gate row if present, else defaults."""
    row = await session.get(
        GuardrailPublishGate, (tenant_id, environment_id, project_id, guardrail_id)
    )
    if row is None:
        return await resolve_publish_gate(
            session, tenant_id, environment_id, project_id, guardrail_id
        )
    return PublishGateDefaults(
        min_expected_action_accuracy=row.min_expected_action_accuracy,
        min_expected_allowed_accuracy=row.min_expected_allowed_accuracy,
        min_eval_cases=row.min_eval_cases,
        max_p95_latency_ms=row.max_p95_latency_ms,
    )


async def _latest_completed_run(
    session: AsyncSession,
    tenant_id: uuid.UUID,
    environment_id: str,
    project_id: str,
    guardrail_id: str,
    version: int,
) -> EvaluationRun | None:
    stmt = (
        select(EvaluationRun)
        .where(
            EvaluationRun.tenant_id == tenant_id,
            EvaluationRun.environment_id == environment_id,
            EvaluationRun.project_id == project_id,
            EvaluationRun.guardrail_id == guardrail_id,
            EvaluationRun.guardrail_version == version,
            EvaluationRun.status == "COMPLETED",
        )
        .order_by(EvaluationRun.completed_at.desc(), EvaluationRun.created_at.desc())
        .limit(1)
    )
    return (await session.execute(stmt)).scalars().first()


async def _run_p95_latency_ms(session: AsyncSession, run: EvaluationRun) -> float | None:
    """Nearest-rank p95 over the run's per-case engine latencies."""
    stmt = select(EvaluationCase.latency_ms).where(
        EvaluationCase.run_id == run.id,
        EvaluationCase.tenant_id == run.tenant_id,
        EvaluationCase.latency_ms.is_not(None),
    )
    latencies = sorted(value for value in (await session.execute(stmt)).scalars())
    if not latencies:
        return None
    rank = max(1, math.ceil(0.95 * len(latencies)))
    return float(latencies[rank - 1])


async def evaluate_publish_gate(
    session: AsyncSession,
    tenant_id: uuid.UUID,
    environment_id: str,
    project_id: str,
    guardrail_id: str,
    version: int,
) -> tuple[EvaluationRun | None, list[dict]]:
    """Return the run the gate judged and the checks it failed (empty = pass)."""
    gate = await load_publish_gate(session, tenant_id, environment_id, project_id, guardrail_id)
    run = await _latest_completed_run(
        session, tenant_id, environment_id, project_id, guardrail_id, version
    )
    if run is None:
        return None, [
            {
                "check": "eval_run",
                "required": "COMPLETED evaluation run for this version",
                "actual": None,
            }
        ]

    failed: list[dict] = []
    try:
        metrics = json.loads(run.metrics_json) if run.metrics_json else {}
    except ValueError:
        metrics = {}
    if not isinstance(metrics, dict):
        metrics = {}

    total_cases = int(metrics.get("total") or run.total_cases or 0)
    if total_cases < (gate.min_eval_cases or 0):
        failed.append(
            {"check": "min_eval_cases", "required": gate.min_eval_cases, "actual": total_cases}
        )

    for check, threshold in (
        ("min_expected_action_accuracy", gate.min_expected_action_accuracy),
        ("min_expected_allowed_accuracy", gate.min_expected_allowed_accuracy),
    ):
        if threshold is None:
            continue
        metric_key = check.removeprefix("min_")
        actual = metrics.get(metric_key)
        # A run with no labelled cases has no accuracy; that cannot satisfy a threshold.
        if actual is None or float(actual) < float(threshold):
            failed.append({"check": check, "required": threshold, "actual": actual})

    if gate.max_p95_latency_ms is not None:
        p95 = await _run_p95_latency_ms(session, run)
        if p95 is None or p95 > float(gate.max_p95_latency_ms):
            failed.append(
                {
                    "check": "max_p95_latency_ms",
                    "required": gate.max_p95_latency_ms,
                    "actual": p95,
                }
            )
    return run, failed


async def enforce_publish_gate(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    environment_id: str,
    project_id: str,
    guardrail_id: str,
    version: int,
    bypass_eval_gate: bool = False,
    bypass_reason: str | None = None,
    break_glass_reason: str | None = None,
) -> PublishGateDecision:
    """Allow, record a bypass for, or reject publishing one guardrail version.

    Raises ``BYPASS_REASON_REQUIRED`` (422) for a bypass without a reason when
    ``publish_gate_require_bypass_reason`` is on, and ``EVAL_GATE_NOT_MET`` (409),
    with the failed checks in ``details``, when the gate fails and nothing bypasses it.
    A break-glass publish counts as a bypass whose reason is the break-glass reason.
    """
    bypass_reason = (bypass_reason or "").strip() or None
    break_glass_reason = (break_glass_reason or "").strip() or None
    validate_bypass_request(bypass_eval_gate, bypass_reason, break_glass_reason)

    if not settings.publish_gate_enforced:
        return skipped_gate("gate_disabled")

    run, failed = await evaluate_publish_gate(
        session, tenant_id, environment_id, project_id, guardrail_id, version
    )
    run_id = str(run.id) if run is not None else None
    if not failed:
        return PublishGateDecision(status=GATE_PASSED, run_id=run_id)

    if break_glass_reason or bypass_eval_gate:
        kind = "break_glass" if break_glass_reason else "bypass_eval_gate"
        reason = break_glass_reason or bypass_reason
        logger.warning(
            "admin.guardrail_version.eval_gate_bypassed tenant_id=%s env=%s project=%s "
            "guardrail_id=%s version=%s kind=%s reason=%s failed_checks=%s",
            tenant_id,
            environment_id,
            project_id,
            guardrail_id,
            version,
            kind,
            reason,
            [item["check"] for item in failed],
        )
        return PublishGateDecision(
            status=GATE_BYPASSED,
            reason=reason,
            bypass_kind=kind,
            run_id=run_id,
            failed_checks=failed,
        )

    summary = ", ".join(item["check"] for item in failed)
    raise ServiceError(
        "EVAL_GATE_NOT_MET",
        f"Guardrail {guardrail_id} v{version} does not meet the publish eval gate "
        f"({summary}). Run an evaluation for this version, or publish with "
        "bypass_eval_gate=true and a bypass_reason.",
        409,
        details={"run_id": run_id, "failed_checks": failed},
    )
