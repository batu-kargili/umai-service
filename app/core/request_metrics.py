"""Latency, timeout, and fallback metrics for the synchronous decision path (UMA-86).

The published SLOs treat the deterministic and LLM paths as different products: the
L0/L1 path targets an end-to-end p95 at or under 400 ms, while L2 gets its own budget
measured in seconds. Reporting one combined latency figure would hide both — a healthy
deterministic path buried under LLM tail latency, or a degraded one masked by it. So the
tiers are separate series:

    L0  deterministic preflight and early decision
    L1  deterministic, heuristic, and PII classification
    L2  LLM-backed context-aware judge

**On cardinality.** A metrics label fed from request data grows one time series per
distinct value, and eventually takes the scrape endpoint down with it. Two guards:

* Route labels use the *route template* from the ASGI scope, never the request path, so
  `/v1/sessions/{session_key}` is one series rather than one per session. A request that
  matched no route reports `<unmatched>`, which is a single series regardless of what a
  scanner throws at the service.
* Tenant is **not** a label on any histogram. Per-tenant latency would multiply the
  histogram series count by the tenant count, and a histogram is already ~19 series per
  label set. Tenant appears only on a flat request counter, off by default, and capped —
  past the cap further tenants collapse into `other` rather than growing without bound.
"""

from __future__ import annotations

import time

from app.core.metrics import registry

API_DURATION = "umai_api_request_duration_seconds"
API_BY_TENANT = "umai_api_requests_by_tenant_total"
ENGINE_TIER_DURATION = "umai_engine_evaluation_duration_seconds"
ENGINE_CALL_DURATION = "umai_engine_call_duration_seconds"
ENGINE_OUTCOME = "umai_engine_outcome_total"
ENGINE_FAILURE_MODE = "umai_engine_failure_mode_total"
GUARDRAIL_DECISION = "umai_guardrail_decision_total"

TIER_L0 = "l0"
TIER_L1 = "l1"
TIER_L2 = "l2"

OUTCOME_OK = "ok"
OUTCOME_TIMEOUT = "timeout"
OUTCOME_UNREACHABLE = "unreachable"
OUTCOME_HTTP_ERROR = "http_error"

# The service refuses the guarded call when the engine cannot answer. `fail_open` exists
# in the metric so a dashboard can assert it stays at zero: a non-zero value would mean
# something started allowing traffic past an engine that never rendered a verdict.
MODE_FAIL_CLOSED = "fail_closed"
MODE_FAIL_OPEN = "fail_open"

UNMATCHED_ROUTE = "<unmatched>"

# Policy types the engine reports, mapped to the tier that owns their SLO.
_DETERMINISTIC_POLICY_TYPES = frozenset({"HEURISTIC", "DETERMINISTIC", "REGEX", "PII"})
_LLM_POLICY_TYPES = frozenset({"CONTEXT_AWARE", "LLM", "LLM_JUDGE"})

registry.describe(API_DURATION, "End-to-end API request latency in seconds.")
registry.describe(API_BY_TENANT, "API requests per tenant. Capped; excess reports as 'other'.")
registry.describe(
    ENGINE_TIER_DURATION,
    "Engine evaluation latency in seconds, split by decision tier (l0/l1/l2).",
)
registry.describe(
    ENGINE_CALL_DURATION,
    "Service-to-engine call latency in seconds as the service observes it, by outcome.",
)
registry.describe(ENGINE_OUTCOME, "Engine call outcomes: ok, timeout, unreachable, http_error.")
registry.describe(
    ENGINE_FAILURE_MODE,
    "What the service did when the engine could not answer. fail_open must stay at zero.",
)
registry.describe(GUARDRAIL_DECISION, "Guardrail decisions by action and deciding tier.")
registry.declare_histogram(API_DURATION)
registry.declare_histogram(ENGINE_TIER_DURATION)
registry.declare_histogram(ENGINE_CALL_DURATION)


def tier_for_policy_type(policy_type: str | None) -> str:
    """Which tier's SLO a decision belongs to.

    An unrecognised policy type is attributed to L2, the slower budget. Guessing the
    fast tier would let a new LLM-backed policy quietly breach the deterministic SLO
    while appearing to meet it.
    """
    if not policy_type:
        return TIER_L1
    normalised = policy_type.strip().upper()
    if normalised in _DETERMINISTIC_POLICY_TYPES:
        return TIER_L1
    if normalised in _LLM_POLICY_TYPES:
        return TIER_L2
    return TIER_L2


def observe_engine_response(response, elapsed_seconds: float) -> None:
    """Record tier latency and the decision from a successful engine evaluation."""
    registry.increment(ENGINE_OUTCOME, {"outcome": OUTCOME_OK})
    registry.observe(ENGINE_CALL_DURATION, elapsed_seconds, {"outcome": OUTCOME_OK})

    latency = getattr(response, "latency_ms", None)
    policy = getattr(response, "triggering_policy", None)
    tier = tier_for_policy_type(getattr(policy, "type", None) if policy else None)

    # L0 is reported whenever the engine measured a preflight, whichever tier decided:
    # preflight runs on every request, so its own SLO is independent of the outcome.
    preflight_ms = getattr(latency, "preflight", None) if latency else None
    if preflight_ms is not None:
        registry.observe(ENGINE_TIER_DURATION, float(preflight_ms) / 1000.0, {"tier": TIER_L0})

    total_ms = getattr(latency, "total", None) if latency else None
    if total_ms is not None:
        registry.observe(ENGINE_TIER_DURATION, float(total_ms) / 1000.0, {"tier": tier})

    decision = getattr(response, "decision", None)
    if decision is not None:
        registry.increment(
            GUARDRAIL_DECISION,
            {"action": str(getattr(decision, "action", "unknown")).lower(), "tier": tier},
        )


def observe_engine_failure(outcome: str, elapsed_seconds: float) -> None:
    """Record a call the engine could not answer, and what the service did about it."""
    registry.increment(ENGINE_OUTCOME, {"outcome": outcome})
    registry.observe(ENGINE_CALL_DURATION, elapsed_seconds, {"outcome": outcome})
    # The service raises, so the guarded call does not proceed: fail-closed.
    registry.increment(ENGINE_FAILURE_MODE, {"mode": MODE_FAIL_CLOSED})


class RequestMetricsMiddleware:
    """Times every request and labels it by route template, not by path.

    Pure ASGI because the route template only appears in the scope *after* the router
    has matched, which a `@app.middleware("http")` function cannot see.
    """

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        from app.core.settings import settings

        status_holder = {"status": 500}

        async def wrapped_send(message) -> None:
            if message.get("type") == "http.response.start":
                status_holder["status"] = message.get("status", 500)
            await send(message)

        started = time.perf_counter()
        try:
            await self.app(scope, receive, wrapped_send)
        finally:
            elapsed = time.perf_counter() - started
            route = scope.get("route")
            template = getattr(route, "path_format", None) or UNMATCHED_ROUTE
            template = registry.bounded_label(
                API_DURATION, "route", template, settings.metrics_route_cardinality_cap
            )
            registry.observe(
                API_DURATION,
                elapsed,
                {
                    "route": template,
                    "method": scope.get("method", "GET"),
                    "status": str(status_holder["status"]),
                },
            )
            if settings.metrics_tenant_label_enabled:
                _observe_tenant(scope)


def _observe_tenant(scope) -> None:
    from app.core.settings import settings

    tenant = ""
    for name, value in scope.get("headers") or ():
        if name == b"x-tenant-id":
            tenant = value.decode("latin-1")
            break
    if not tenant:
        return
    bounded = registry.bounded_label(
        API_BY_TENANT, "tenant", tenant, settings.metrics_tenant_cardinality_cap
    )
    registry.increment(API_BY_TENANT, {"tenant": bounded})
