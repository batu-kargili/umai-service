"""Latency, timeout, and fallback metrics for the decision path (UMA-86).

The SLOs treat the deterministic and LLM paths as separate products, so the tests care
most about two things: that the tiers really are separate series, and that the label
cardinality cannot grow with traffic.
"""

from __future__ import annotations

import asyncio

import pytest

from app.core.metrics import DEFAULT_BUCKETS, registry
from app.core.request_metrics import (
    API_BY_TENANT,
    API_DURATION,
    ENGINE_CALL_DURATION,
    ENGINE_FAILURE_MODE,
    ENGINE_OUTCOME,
    ENGINE_TIER_DURATION,
    GUARDRAIL_DECISION,
    MODE_FAIL_CLOSED,
    MODE_FAIL_OPEN,
    OUTCOME_OK,
    OUTCOME_TIMEOUT,
    OUTCOME_UNREACHABLE,
    TIER_L0,
    TIER_L1,
    TIER_L2,
    UNMATCHED_ROUTE,
    RequestMetricsMiddleware,
    observe_engine_failure,
    observe_engine_response,
    tier_for_policy_type,
)
from app.core.settings import settings
from app.models.engine import (
    EngineDecision,
    EngineLatency,
    EngineResponse,
    EngineTriggeringPolicy,
)


@pytest.fixture(autouse=True)
def clean_metrics() -> None:
    registry.reset()


def engine_response(policy_type: str | None, total_ms: float, preflight_ms: float | None = None):
    policy = (
        EngineTriggeringPolicy(
            policy_id="pol-1",
            type=policy_type,
            name="A policy",
            status="TRIGGERED",
            severity="HIGH",
            details={},
            latency_ms=total_ms,
        )
        if policy_type
        else None
    )
    return EngineResponse(
        request_id="req-1",
        tenant_id="tenant-1",
        environment_id="env",
        project_id="proj",
        guardrail_id="gr-1",
        guardrail_version=1,
        phase="input",
        decision=EngineDecision(action="BLOCK", allowed=False, severity="HIGH", reason="because"),
        triggering_policy=policy,
        latency_ms=EngineLatency(total=total_ms, preflight=preflight_ms),
    )


class TestTierAttribution:
    @pytest.mark.parametrize("policy_type", ["HEURISTIC", "DETERMINISTIC", "REGEX", "PII"])
    def test_deterministic_policies_are_l1(self, policy_type: str) -> None:
        assert tier_for_policy_type(policy_type) == TIER_L1

    @pytest.mark.parametrize("policy_type", ["CONTEXT_AWARE", "LLM", "LLM_JUDGE"])
    def test_llm_policies_are_l2(self, policy_type: str) -> None:
        assert tier_for_policy_type(policy_type) == TIER_L2

    def test_case_and_whitespace_do_not_change_the_tier(self) -> None:
        assert tier_for_policy_type("  context_aware  ") == TIER_L2

    def test_an_unknown_policy_type_is_attributed_to_the_slower_tier(self) -> None:
        """Guessing L1 would let a new LLM policy breach the fast SLO while looking fine."""
        assert tier_for_policy_type("SOME_NEW_THING") == TIER_L2

    def test_no_triggering_policy_means_the_deterministic_path_allowed_it(self) -> None:
        assert tier_for_policy_type(None) == TIER_L1


class TestEngineObservation:
    def test_the_tiers_are_separate_series(self) -> None:
        observe_engine_response(engine_response("HEURISTIC", 120.0), 0.13)
        observe_engine_response(engine_response("CONTEXT_AWARE", 4200.0), 4.3)
        assert registry.histogram_count(ENGINE_TIER_DURATION, {"tier": TIER_L1}) == 1
        assert registry.histogram_count(ENGINE_TIER_DURATION, {"tier": TIER_L2}) == 1

    def test_latency_is_converted_from_milliseconds_to_seconds(self) -> None:
        observe_engine_response(engine_response("HEURISTIC", 250.0), 0.26)
        assert registry.histogram_sum(ENGINE_TIER_DURATION, {"tier": TIER_L1}) == pytest.approx(0.25)

    def test_preflight_is_reported_as_l0_whichever_tier_decided(self) -> None:
        """Preflight runs on every request, so its SLO is independent of the outcome."""
        observe_engine_response(engine_response("CONTEXT_AWARE", 3000.0, preflight_ms=8.0), 3.1)
        assert registry.histogram_count(ENGINE_TIER_DURATION, {"tier": TIER_L0}) == 1
        assert registry.histogram_sum(ENGINE_TIER_DURATION, {"tier": TIER_L0}) == pytest.approx(0.008)

    def test_no_preflight_reported_means_no_l0_sample(self) -> None:
        observe_engine_response(engine_response("HEURISTIC", 100.0, preflight_ms=None), 0.11)
        assert registry.histogram_count(ENGINE_TIER_DURATION, {"tier": TIER_L0}) == 0

    def test_a_successful_call_counts_as_ok(self) -> None:
        observe_engine_response(engine_response("HEURISTIC", 100.0), 0.11)
        assert registry.counter_value(ENGINE_OUTCOME, {"outcome": OUTCOME_OK}) == 1

    def test_the_decision_is_counted_with_its_deciding_tier(self) -> None:
        observe_engine_response(engine_response("CONTEXT_AWARE", 900.0), 1.0)
        assert registry.counter_value(GUARDRAIL_DECISION, {"action": "block", "tier": TIER_L2}) == 1

    def test_the_service_observed_duration_is_recorded_separately(self) -> None:
        """The engine's self-reported latency excludes connection setup; a caller waits
        for both, so the service times the whole call as well."""
        observe_engine_response(engine_response("HEURISTIC", 100.0), 0.35)
        assert registry.histogram_sum(ENGINE_CALL_DURATION, {"outcome": OUTCOME_OK}) == pytest.approx(0.35)


class TestFailureModes:
    @pytest.mark.parametrize("outcome", [OUTCOME_TIMEOUT, OUTCOME_UNREACHABLE, "http_error"])
    def test_each_failure_outcome_is_counted(self, outcome: str) -> None:
        observe_engine_failure(outcome, 1.5)
        assert registry.counter_value(ENGINE_OUTCOME, {"outcome": outcome}) == 1

    def test_a_failure_is_recorded_as_fail_closed(self) -> None:
        observe_engine_failure(OUTCOME_TIMEOUT, 1.5)
        assert registry.counter_value(ENGINE_FAILURE_MODE, {"mode": MODE_FAIL_CLOSED}) == 1

    def test_fail_open_is_never_recorded(self) -> None:
        """The series exists so a dashboard can assert it stays at zero. A non-zero
        value would mean something started letting traffic past an unanswered engine."""
        for outcome in (OUTCOME_TIMEOUT, OUTCOME_UNREACHABLE, "http_error"):
            observe_engine_failure(outcome, 1.0)
        assert registry.counter_value(ENGINE_FAILURE_MODE, {"mode": MODE_FAIL_OPEN}) == 0

    def test_failure_latency_is_recorded_under_its_outcome(self) -> None:
        observe_engine_failure(OUTCOME_TIMEOUT, 13.5)
        assert registry.histogram_sum(
            ENGINE_CALL_DURATION, {"outcome": OUTCOME_TIMEOUT}
        ) == pytest.approx(13.5)
        # And not muddled into the success series.
        assert registry.histogram_count(ENGINE_CALL_DURATION, {"outcome": OUTCOME_OK}) == 0


class TestQuantiles:
    def test_p50_p95_and_p99_are_all_reportable(self) -> None:
        for _ in range(90):
            registry.observe(API_DURATION, 0.05, {"route": "/x"})
        for _ in range(9):
            registry.observe(API_DURATION, 0.3, {"route": "/x"})
        registry.observe(API_DURATION, 20.0, {"route": "/x"})

        labels = {"route": "/x"}
        assert registry.quantile(API_DURATION, 0.5, labels) == 0.05
        assert registry.quantile(API_DURATION, 0.95, labels) == 0.3
        assert registry.quantile(API_DURATION, 0.99, labels) == 0.3

    def test_the_buckets_bracket_the_deterministic_slo(self) -> None:
        """The published target is p95 <= 400 ms, so 0.4 must be a bucket edge or the
        histogram cannot answer whether the SLO was met."""
        assert 0.4 in DEFAULT_BUCKETS

    def test_an_unobserved_series_has_no_quantile(self) -> None:
        assert registry.quantile(API_DURATION, 0.95, {"route": "/never"}) is None


# ------------------------------------------------------------------- middleware


async def _drive(middleware, path: str, *, route_template: str | None, status: int = 200,
                 headers: list[tuple[bytes, bytes]] | None = None) -> None:
    class FakeRoute:
        path_format = route_template

    async def app(scope, receive, send) -> None:
        # The router sets scope["route"] once it has matched; nothing is set otherwise.
        if route_template is not None:
            scope["route"] = FakeRoute()
        await send({"type": "http.response.start", "status": status, "headers": []})
        await send({"type": "http.response.body", "body": b"{}"})

    async def receive() -> dict:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(_message) -> None:
        return None

    instance = RequestMetricsMiddleware(app)
    await instance(
        {"type": "http", "method": "GET", "path": path, "headers": headers or [],
         "client": ("10.0.0.1", 5000)},
        receive,
        send,
    )


class TestMiddlewareCardinality:
    def test_the_route_template_is_the_label_not_the_path(self) -> None:
        """One series per route, not one per session key."""

        async def run() -> None:
            middleware_app = RequestMetricsMiddleware
            for key in ("aaa", "bbb", "ccc"):
                await _drive(
                    middleware_app,
                    f"/v1/admin/sessions/{key}",
                    route_template="/v1/admin/sessions/{session_key}",
                )

        asyncio.run(run())
        labels = {"route": "/v1/admin/sessions/{session_key}", "method": "GET", "status": "200"}
        assert registry.histogram_count(API_DURATION, labels) == 3
        assert registry.cardinality(API_DURATION, "route") == 1

    def test_an_unmatched_path_collapses_to_one_series(self) -> None:
        """Otherwise a scanner probing random URLs creates a series per probe."""

        async def run() -> None:
            for index in range(25):
                await _drive(
                    RequestMetricsMiddleware, f"/nope/{index}", route_template=None, status=404
                )

        asyncio.run(run())
        labels = {"route": UNMATCHED_ROUTE, "method": "GET", "status": "404"}
        assert registry.histogram_count(API_DURATION, labels) == 25
        assert registry.cardinality(API_DURATION, "route") == 1

    def test_the_route_cap_collapses_further_routes_into_other(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(settings, "metrics_route_cardinality_cap", 3)

        async def run() -> None:
            for index in range(6):
                await _drive(
                    RequestMetricsMiddleware, f"/v1/r{index}", route_template=f"/v1/r{index}"
                )

        asyncio.run(run())
        assert registry.cardinality(API_DURATION, "route") == 3
        other = {"route": "other", "method": "GET", "status": "200"}
        assert registry.histogram_count(API_DURATION, other) == 3

    def test_the_status_is_recorded(self) -> None:
        async def run() -> None:
            await _drive(RequestMetricsMiddleware, "/v1/x", route_template="/v1/x", status=503)

        asyncio.run(run())
        labels = {"route": "/v1/x", "method": "GET", "status": "503"}
        assert registry.histogram_count(API_DURATION, labels) == 1

    def test_tenant_is_not_labelled_by_default(self) -> None:
        """Per-tenant latency would multiply every histogram's series count."""

        async def run() -> None:
            await _drive(
                RequestMetricsMiddleware,
                "/v1/x",
                route_template="/v1/x",
                headers=[(b"x-tenant-id", b"tenant-1")],
            )

        asyncio.run(run())
        assert registry.counter_value(API_BY_TENANT, {"tenant": "tenant-1"}) == 0

    def test_tenant_can_be_enabled_and_stays_capped(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(settings, "metrics_tenant_label_enabled", True)
        monkeypatch.setattr(settings, "metrics_tenant_cardinality_cap", 2)

        async def run() -> None:
            for index in range(5):
                await _drive(
                    RequestMetricsMiddleware,
                    "/v1/x",
                    route_template="/v1/x",
                    headers=[(b"x-tenant-id", f"tenant-{index}".encode())],
                )

        asyncio.run(run())
        assert registry.cardinality(API_BY_TENANT, "tenant") == 2
        assert registry.counter_value(API_BY_TENANT, {"tenant": "other"}) == 3

    def test_a_request_that_raises_is_still_timed(self) -> None:
        """A 500 is exactly when latency matters most, so the timer is in a finally."""

        async def failing(scope, receive, send) -> None:
            scope["route"] = type("R", (), {"path_format": "/v1/boom"})()
            raise RuntimeError("handler exploded")

        async def receive() -> dict:
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(_message) -> None:
            return None

        async def run() -> None:
            with pytest.raises(RuntimeError):
                await RequestMetricsMiddleware(failing)(
                    {"type": "http", "method": "POST", "path": "/v1/boom", "headers": [],
                     "client": ("10.0.0.1", 1)},
                    receive,
                    send,
                )

        asyncio.run(run())
        # No response.start was sent, so the status defaults to 500 rather than 200.
        labels = {"route": "/v1/boom", "method": "POST", "status": "500"}
        assert registry.histogram_count(API_DURATION, labels) == 1

    def test_a_non_http_scope_is_passed_through_untimed(self) -> None:
        seen: list[str] = []

        async def app(scope, receive, send) -> None:
            seen.append(scope["type"])

        asyncio.run(RequestMetricsMiddleware(app)({"type": "lifespan"}, None, None))
        assert seen == ["lifespan"]
        assert registry.render() == ""


class TestExposition:
    def test_a_histogram_renders_cumulative_buckets_with_inf_sum_and_count(self) -> None:
        for value in (0.01, 0.3, 90.0):
            registry.observe(API_DURATION, value, {"route": "/x"})
        rendered = registry.render()
        assert f"# TYPE {API_DURATION} histogram" in rendered
        assert f'{API_DURATION}_bucket{{route="/x",le="+Inf"}} 3' in rendered
        assert f'{API_DURATION}_count{{route="/x"}} 3' in rendered
        # Cumulative: the 0.4 bucket holds both the 0.01 and 0.3 samples.
        assert f'{API_DURATION}_bucket{{route="/x",le="0.4"}} 2' in rendered

    def test_bucket_edges_render_as_stable_strings(self) -> None:
        registry.observe(API_DURATION, 0.01, {"route": "/x"})
        rendered = registry.render()
        assert 'le="1"' in rendered
        assert 'le="0.005"' in rendered
