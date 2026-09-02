"""Queue, lease, throughput, and model-cost metrics for the ADR analysis pipeline (UMA-87).

The pipeline is pull-based and two-stage: triage filters for recall, reasoning decides.
That shape produces the failures an operator actually has to catch:

* **A backlog that is not growing but is not moving either.** Depth alone cannot tell
  those apart, so the age of the oldest waiting session is reported as well. A queue of
  five sessions where the oldest has waited four hours is a worse state than a queue of
  five hundred that turns over in a minute.
* **A worker that died holding a lease.** Its batch sits in `*ing` forever and is never
  analysed — the failure nobody notices, because nothing errors. Reclaims are counted, so
  a rising reclaim rate names it.
* **Triage that stopped filtering.** If elimination collapses, every session escalates to
  the LLM stage and the model bill follows. Elimination and escalation are counted
  explicitly rather than left for a dashboard to derive.
* **Cost.** Tokens and spend are attributed per model, because "the bill went up" is only
  actionable once you know which model did it.

Queue depth and age are sampled by a background loop rather than computed when
`/metrics` is scraped. A scrape must not depend on the database: it would start failing
exactly when the database is in trouble, which is when the metrics matter most.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import logging

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.metrics import registry
from app.models.db import AiSession

logger = logging.getLogger("umai.service.analysis_metrics")

QUEUE_DEPTH = "umai_analysis_queue_depth"
QUEUE_OLDEST_AGE = "umai_analysis_queue_oldest_age_seconds"
CLAIMED = "umai_analysis_claimed_total"
LEASE_RECLAIMED = "umai_analysis_lease_reclaimed_total"
RELEASED = "umai_analysis_released_total"
RESULTS = "umai_analysis_result_total"
FAILURES = "umai_analysis_failed_total"
STAGE_DURATION = "umai_analysis_stage_duration_seconds"
TRIAGE_OUTCOME = "umai_analysis_triage_outcome_total"
TOKENS = "umai_analysis_tokens_total"
COST_USD = "umai_analysis_cost_usd_total"

TRIAGE_ELIMINATED = "eliminated"
TRIAGE_ESCALATED = "escalated"

# Statuses the sampler reports on, and the stage each belongs to. Named explicitly so a
# new status has to be added deliberately rather than appearing as an unlabelled series.
WAITING_STATUSES = {
    "ingested": "triage",
    "triage_suspicious": "reason",
}
CLAIMED_STATUSES = {
    "triaging": "triage",
    "reasoning": "reason",
}
TERMINAL_STATUSES = {
    "analysis_failed": "failed",
}
# Reported separately from the queue so a metadata-mode tenant does not read as
# a permanent backlog: these sessions were never queued and never will be.
NOT_COLLECTED_STATUSES = {
    "content_not_collected": "triage",
}

# Model names come from the worker's configuration, not from request data, so the set is
# small — but it is still external input, so it is capped.
_MODEL_CARDINALITY_CAP = 25

registry.describe(QUEUE_DEPTH, "Sessions waiting for or held by an analysis stage.")
registry.describe(
    QUEUE_OLDEST_AGE,
    "Age in seconds of the oldest session waiting for a stage. Depth alone cannot "
    "distinguish a queue that is moving from one that is stuck.",
)
registry.describe(CLAIMED, "Sessions leased to a worker.")
registry.describe(
    LEASE_RECLAIMED,
    "Leases reclaimed from workers that stopped without releasing them. A rising rate "
    "means workers are dying mid-stage.",
)
registry.describe(RELEASED, "Sessions returned to the queue by a graceful worker shutdown.")
registry.describe(RESULTS, "Stage results by verdict.")
registry.describe(FAILURES, "Stages that reported the error verdict, so nothing was analysed.")
registry.describe(STAGE_DURATION, "Time from lease to result, in seconds.")
registry.describe(
    TRIAGE_OUTCOME,
    "Triage outcomes: eliminated ends the pipeline, escalated goes on to reasoning.",
)
registry.describe(TOKENS, "LLM tokens consumed by the analysis pipeline, per model.")
registry.describe(COST_USD, "LLM spend in USD attributed to the analysis pipeline, per model.")
registry.declare_histogram(STAGE_DURATION)


def _model_label(model: str | None) -> str:
    if not model:
        return "unknown"
    return registry.bounded_label(TOKENS, "model", model, _MODEL_CARDINALITY_CAP)


def record_claim(stage: str, claimed: int, reclaimed: int) -> None:
    """A claim batch: how many were fresh, and how many were taken back from a dead worker."""
    if claimed:
        registry.increment(CLAIMED, {"stage": stage}, claimed)
    if reclaimed:
        registry.increment(LEASE_RECLAIMED, {"stage": stage}, reclaimed)


def record_release(stage: str, released: int) -> None:
    if released:
        registry.increment(RELEASED, {"stage": stage}, released)


def record_result(
    stage: str,
    verdict: str,
    *,
    held_seconds: float | None = None,
    model: str | None = None,
    input_tokens: int | None = None,
    output_tokens: int | None = None,
    cost_usd: float | None = None,
    failed: bool = False,
) -> None:
    registry.increment(RESULTS, {"stage": stage, "verdict": verdict})
    if failed:
        registry.increment(FAILURES, {"stage": stage})
    if held_seconds is not None and held_seconds >= 0:
        registry.observe(STAGE_DURATION, held_seconds, {"stage": stage})

    if stage == "triage" and not failed:
        outcome = TRIAGE_ESCALATED if verdict == "suspicious" else TRIAGE_ELIMINATED
        registry.increment(TRIAGE_OUTCOME, {"outcome": outcome})

    # Cost is recorded even for a failed stage: a timeout after the model has already
    # produced tokens still costs money, and omitting it would understate the bill.
    label = _model_label(model)
    if input_tokens:
        registry.increment(TOKENS, {"stage": stage, "model": label, "direction": "input"}, input_tokens)
    if output_tokens:
        registry.increment(TOKENS, {"stage": stage, "model": label, "direction": "output"}, output_tokens)
    if cost_usd:
        registry.increment(COST_USD, {"stage": stage, "model": label}, float(cost_usd))


async def sample_queue(session: AsyncSession, now: dt.datetime | None = None) -> None:
    """Refresh the queue gauges from one pass over the session table."""
    moment = now or dt.datetime.now(dt.timezone.utc)

    counts = dict(
        (
            await session.execute(
                select(AiSession.analysis_status, func.count())
                .group_by(AiSession.analysis_status)
            )
        ).all()
    )

    for status, stage in {
        **WAITING_STATUSES,
        **CLAIMED_STATUSES,
        **TERMINAL_STATUSES,
        **NOT_COLLECTED_STATUSES,
    }.items():
        state = (
            "waiting"
            if status in WAITING_STATUSES
            else "claimed"
            if status in CLAIMED_STATUSES
            else "not_collected"
            if status in NOT_COLLECTED_STATUSES
            else "failed"
        )
        registry.set_gauge(
            QUEUE_DEPTH, counts.get(status, 0), {"stage": stage, "state": state}
        )

    # Oldest waiting session per stage. Measured from observed_at — when the
    # conversation actually happened — so the age reflects how stale the evidence is,
    # not how long ago the row was written.
    for status, stage in WAITING_STATUSES.items():
        oldest = (
            await session.execute(
                select(func.min(AiSession.observed_at)).where(
                    AiSession.analysis_status == status
                )
            )
        ).scalar_one_or_none()
        if oldest is None:
            registry.set_gauge(QUEUE_OLDEST_AGE, 0, {"stage": stage})
            continue
        if oldest.tzinfo is None:
            oldest = oldest.replace(tzinfo=dt.timezone.utc)
        registry.set_gauge(
            QUEUE_OLDEST_AGE, max(0.0, (moment - oldest).total_seconds()), {"stage": stage}
        )


async def run_queue_sampler(sessionmaker, interval_s: float, stop: asyncio.Event) -> None:
    """Sample the queue gauges periodically.

    Errors are logged and the loop continues. A monitoring loop that dies on the first
    transient database error stops reporting silently, which is worse than a gap.
    """
    while not stop.is_set():
        try:
            async with sessionmaker() as session:
                await sample_queue(session)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.warning("analysis_metrics.sample_failed", exc_info=True)
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval_s)
        except asyncio.TimeoutError:
            continue
