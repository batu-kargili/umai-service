from __future__ import annotations

import uuid
from dataclasses import dataclass

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.settings import settings


@dataclass
class PublishGateDefaults:
    """Default publish gate thresholds derived from service settings."""

    min_expected_action_accuracy: float | None
    min_expected_allowed_accuracy: float | None
    min_eval_cases: int
    max_p95_latency_ms: float | None


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