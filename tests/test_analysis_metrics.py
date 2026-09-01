"""Queue, lease, throughput and model-cost metrics for the analysis pipeline (UMA-87)."""

from __future__ import annotations

import asyncio
import datetime as dt
import uuid

import pytest

from app.core.analysis_metrics import (
    CLAIMED,
    COST_USD,
    FAILURES,
    LEASE_RECLAIMED,
    QUEUE_DEPTH,
    QUEUE_OLDEST_AGE,
    RELEASED,
    RESULTS,
    STAGE_DURATION,
    TOKENS,
    TRIAGE_ELIMINATED,
    TRIAGE_ESCALATED,
    TRIAGE_OUTCOME,
    record_claim,
    record_release,
    record_result,
    sample_queue,
)
from app.core.metrics import registry
from app.models.db import AiSession, Tenant
from tests.conftest import db_session

TENANT = uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
NOW = dt.datetime(2026, 9, 1, 12, 0, tzinfo=dt.timezone.utc)


@pytest.fixture(autouse=True)
def clean_metrics() -> None:
    registry.reset()


def session_row(key: str, status: str, observed_at: dt.datetime) -> AiSession:
    return AiSession(
        tenant_id=TENANT,
        session_key=key,
        source="adr",
        source_session_id=f"src-{key}",
        observed_at=observed_at,
        ingested_at=observed_at,
        message_count=1,
        tool_call_count=0,
        analysis_status=status,
        analysis_attempts=0,
        updated_at=observed_at,
    )


class TestClaimAndLease:
    def test_a_fresh_claim_is_counted(self) -> None:
        record_claim("triage", claimed=7, reclaimed=0)
        assert registry.counter_value(CLAIMED, {"stage": "triage"}) == 7
        assert registry.counter_value(LEASE_RECLAIMED, {"stage": "triage"}) == 0

    def test_a_reclaim_is_counted_separately_from_a_fresh_claim(self) -> None:
        """A reclaim means a worker died holding work. Folding it into the claim count
        would hide the only signal that says so."""
        record_claim("reason", claimed=3, reclaimed=2)
        assert registry.counter_value(CLAIMED, {"stage": "reason"}) == 3
        assert registry.counter_value(LEASE_RECLAIMED, {"stage": "reason"}) == 2

    def test_an_empty_claim_records_nothing(self) -> None:
        record_claim("triage", claimed=0, reclaimed=0)
        assert registry.counter_value(CLAIMED, {"stage": "triage"}) == 0

    def test_a_graceful_release_is_counted(self) -> None:
        record_release("triage", released=4)
        assert registry.counter_value(RELEASED, {"stage": "triage"}) == 4

    def test_stages_are_counted_independently(self) -> None:
        record_claim("triage", claimed=1, reclaimed=0)
        record_claim("reason", claimed=5, reclaimed=0)
        assert registry.counter_value(CLAIMED, {"stage": "triage"}) == 1
        assert registry.counter_value(CLAIMED, {"stage": "reason"}) == 5


class TestThroughputAndFailure:
    def test_a_result_is_counted_by_stage_and_verdict(self) -> None:
        record_result("reason", "malicious")
        assert registry.counter_value(RESULTS, {"stage": "reason", "verdict": "malicious"}) == 1

    def test_the_error_verdict_is_counted_as_a_failure(self) -> None:
        record_result("reason", "error", failed=True)
        assert registry.counter_value(FAILURES, {"stage": "reason"}) == 1

    def test_a_normal_verdict_is_not_a_failure(self) -> None:
        record_result("reason", "benign")
        assert registry.counter_value(FAILURES, {"stage": "reason"}) == 0

    def test_the_time_a_worker_held_the_session_is_recorded(self) -> None:
        record_result("reason", "benign", held_seconds=42.0)
        assert registry.histogram_sum(STAGE_DURATION, {"stage": "reason"}) == pytest.approx(42.0)

    def test_a_missing_hold_time_is_simply_not_recorded(self) -> None:
        record_result("reason", "benign", held_seconds=None)
        assert registry.histogram_count(STAGE_DURATION, {"stage": "reason"}) == 0

    def test_a_negative_hold_time_is_discarded(self) -> None:
        """Clock skew between the claim and the result must not corrupt the histogram."""
        record_result("reason", "benign", held_seconds=-5.0)
        assert registry.histogram_count(STAGE_DURATION, {"stage": "reason"}) == 0


class TestTriageFilterRate:
    def test_a_benign_triage_is_an_elimination(self) -> None:
        record_result("triage", "benign")
        assert registry.counter_value(TRIAGE_OUTCOME, {"outcome": TRIAGE_ELIMINATED}) == 1

    def test_a_suspicious_triage_is_an_escalation(self) -> None:
        record_result("triage", "suspicious")
        assert registry.counter_value(TRIAGE_OUTCOME, {"outcome": TRIAGE_ESCALATED}) == 1

    def test_a_failed_triage_is_neither(self) -> None:
        """An error is not a filtering decision; counting it as one would make the
        elimination rate look healthy while nothing was actually triaged."""
        record_result("triage", "error", failed=True)
        assert registry.counter_value(TRIAGE_OUTCOME, {"outcome": TRIAGE_ELIMINATED}) == 0
        assert registry.counter_value(TRIAGE_OUTCOME, {"outcome": TRIAGE_ESCALATED}) == 0

    def test_the_reasoning_stage_does_not_report_a_triage_outcome(self) -> None:
        record_result("reason", "benign")
        assert registry.counter_value(TRIAGE_OUTCOME, {"outcome": TRIAGE_ELIMINATED}) == 0

    def test_the_elimination_rate_is_derivable(self) -> None:
        for _ in range(8):
            record_result("triage", "benign")
        for _ in range(2):
            record_result("triage", "suspicious")
        eliminated = registry.counter_value(TRIAGE_OUTCOME, {"outcome": TRIAGE_ELIMINATED})
        escalated = registry.counter_value(TRIAGE_OUTCOME, {"outcome": TRIAGE_ESCALATED})
        assert eliminated / (eliminated + escalated) == 0.8


class TestModelCost:
    def test_tokens_are_attributed_per_model_and_direction(self) -> None:
        record_result(
            "reason", "malicious", model="gpt-oss-safeguard-20b",
            input_tokens=1200, output_tokens=340, cost_usd=0.0042,
        )
        base = {"stage": "reason", "model": "gpt-oss-safeguard-20b"}
        assert registry.counter_value(TOKENS, {**base, "direction": "input"}) == 1200
        assert registry.counter_value(TOKENS, {**base, "direction": "output"}) == 340
        assert registry.counter_value(COST_USD, base) == pytest.approx(0.0042)

    def test_cost_accumulates_across_results(self) -> None:
        for _ in range(3):
            record_result("reason", "benign", model="m", cost_usd=0.01)
        assert registry.counter_value(COST_USD, {"stage": "reason", "model": "m"}) == pytest.approx(0.03)

    def test_two_models_are_billed_separately(self) -> None:
        record_result("reason", "benign", model="cheap", cost_usd=0.001)
        record_result("reason", "benign", model="expensive", cost_usd=0.5)
        assert registry.counter_value(COST_USD, {"stage": "reason", "model": "cheap"}) == pytest.approx(0.001)
        assert registry.counter_value(COST_USD, {"stage": "reason", "model": "expensive"}) == pytest.approx(0.5)

    def test_a_missing_model_is_labelled_unknown_not_dropped(self) -> None:
        record_result("reason", "benign", input_tokens=10, cost_usd=0.002)
        base = {"stage": "reason", "model": "unknown"}
        assert registry.counter_value(TOKENS, {**base, "direction": "input"}) == 10
        assert registry.counter_value(COST_USD, base) == pytest.approx(0.002)

    def test_a_failed_stage_still_reports_its_cost(self) -> None:
        """A timeout after the model produced tokens still costs money. Dropping it
        would understate the bill exactly when something is going wrong."""
        record_result(
            "reason", "error", failed=True, model="m",
            input_tokens=900, output_tokens=0, cost_usd=0.02,
        )
        assert registry.counter_value(COST_USD, {"stage": "reason", "model": "m"}) == pytest.approx(0.02)

    def test_the_model_label_is_capped(self) -> None:
        for index in range(30):
            record_result("reason", "benign", model=f"model-{index}", cost_usd=0.001)
        assert registry.cardinality(TOKENS, "model") <= 25

    def test_zero_tokens_do_not_create_a_series(self) -> None:
        record_result("reason", "benign", model="m", input_tokens=0, output_tokens=0)
        assert registry.counter_value(
            TOKENS, {"stage": "reason", "model": "m", "direction": "input"}
        ) == 0


class TestQueueSampling:
    def test_depth_is_reported_per_stage_and_state(self) -> None:
        async def run() -> None:
            async with db_session() as db:
                db.add(Tenant(tenant_id=TENANT, name="A", collection_mode="full_session"))
                db.add_all([
                    session_row("a" * 64, "ingested", NOW),
                    session_row("b" * 64, "ingested", NOW),
                    session_row("c" * 64, "triage_suspicious", NOW),
                    session_row("d" * 64, "triaging", NOW),
                    session_row("e" * 64, "analysis_failed", NOW),
                ])
                await db.commit()
                await sample_queue(db, now=NOW)

        asyncio.run(run())
        assert registry.gauge_value(QUEUE_DEPTH, {"stage": "triage", "state": "waiting"}) == 2
        assert registry.gauge_value(QUEUE_DEPTH, {"stage": "reason", "state": "waiting"}) == 1
        assert registry.gauge_value(QUEUE_DEPTH, {"stage": "triage", "state": "claimed"}) == 1
        assert registry.gauge_value(QUEUE_DEPTH, {"stage": "failed", "state": "failed"}) == 1

    def test_the_oldest_waiting_age_distinguishes_stuck_from_busy(self) -> None:
        """Depth alone cannot tell a moving queue from a stalled one."""

        async def run() -> None:
            async with db_session() as db:
                db.add(Tenant(tenant_id=TENANT, name="A", collection_mode="full_session"))
                db.add_all([
                    session_row("a" * 64, "ingested", NOW - dt.timedelta(hours=4)),
                    session_row("b" * 64, "ingested", NOW - dt.timedelta(minutes=1)),
                ])
                await db.commit()
                await sample_queue(db, now=NOW)

        asyncio.run(run())
        assert registry.gauge_value(QUEUE_OLDEST_AGE, {"stage": "triage"}) == pytest.approx(4 * 3600)

    def test_an_empty_queue_reports_zero_age_not_a_missing_series(self) -> None:
        """A missing series looks like a broken exporter; zero is a fact."""

        async def run() -> None:
            async with db_session() as db:
                await sample_queue(db, now=NOW)

        asyncio.run(run())
        assert registry.gauge_value(QUEUE_OLDEST_AGE, {"stage": "triage"}) == 0
        assert registry.gauge_value(QUEUE_DEPTH, {"stage": "triage", "state": "waiting"}) == 0

    def test_a_claimed_session_is_not_counted_as_waiting(self) -> None:
        async def run() -> None:
            async with db_session() as db:
                db.add(Tenant(tenant_id=TENANT, name="A", collection_mode="full_session"))
                db.add(session_row("a" * 64, "reasoning", NOW - dt.timedelta(hours=9)))
                await db.commit()
                await sample_queue(db, now=NOW)

        asyncio.run(run())
        assert registry.gauge_value(QUEUE_DEPTH, {"stage": "reason", "state": "claimed"}) == 1
        assert registry.gauge_value(QUEUE_DEPTH, {"stage": "reason", "state": "waiting"}) == 0
        # A held session is not "waiting", so it must not inflate the waiting age.
        assert registry.gauge_value(QUEUE_OLDEST_AGE, {"stage": "reason"}) == 0

    def test_sampling_is_idempotent(self) -> None:
        """Gauges are set, not incremented: two samples must not double the depth."""

        async def run() -> None:
            async with db_session() as db:
                db.add(Tenant(tenant_id=TENANT, name="A", collection_mode="full_session"))
                db.add(session_row("a" * 64, "ingested", NOW))
                await db.commit()
                await sample_queue(db, now=NOW)
                await sample_queue(db, now=NOW)

        asyncio.run(run())
        assert registry.gauge_value(QUEUE_DEPTH, {"stage": "triage", "state": "waiting"}) == 1

    def test_an_unfinished_status_does_not_appear_as_an_unlabelled_series(self) -> None:
        """A status nobody added to the map is simply not reported, rather than
        reported under an empty stage label."""

        async def run() -> None:
            async with db_session() as db:
                db.add(Tenant(tenant_id=TENANT, name="A", collection_mode="full_session"))
                db.add(session_row("a" * 64, "analyzed", NOW))
                await db.commit()
                await sample_queue(db, now=NOW)

        asyncio.run(run())
        rendered = registry.render()
        assert 'stage=""' not in rendered
        assert "analyzed" not in rendered


class TestExposition:
    def test_the_queue_and_cost_metrics_render(self) -> None:
        record_result("reason", "malicious", model="m", input_tokens=5, cost_usd=0.01)
        registry.set_gauge(QUEUE_DEPTH, 3, {"stage": "triage", "state": "waiting"})
        rendered = registry.render()
        assert f'{QUEUE_DEPTH}{{stage="triage",state="waiting"}} 3' in rendered
        assert f'{TOKENS}{{direction="input",model="m",stage="reason"}} 5' in rendered
        assert f"# TYPE {COST_USD} counter" in rendered
