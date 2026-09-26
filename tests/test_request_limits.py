"""Rate, body-size, and concurrency limits (UMA-83).

Three resources fail in three different ways, so each dimension is tested on its own,
and then together through the ASGI middleware — which is where the interesting bugs
live, because a limit that raises in middleware bypasses FastAPI's exception handlers.
"""

from __future__ import annotations

import asyncio
import json

import pytest

from app.core.errors import ServiceError
from app.core import limits
from app.core.limits import (
    CLASS_ADMIN,
    CLASS_BOOTSTRAP,
    CLASS_INGEST,
    CLASS_OPS,
    CLASS_PUBLIC,
    CLASS_WORKER,
    LimitPolicy,
    RequestLimiter,
    RequestLimitsMiddleware,
    caller_key,
    classify,
)
from app.core.metrics import LIMIT_REJECTED, REQUESTS_TOTAL, registry
from app.core.settings import settings


def policies(**overrides: LimitPolicy) -> dict[str, LimitPolicy]:
    base = {
        CLASS_INGEST: LimitPolicy(3, 100, 2),
        CLASS_BOOTSTRAP: LimitPolicy(2, 50, 1),
        CLASS_ADMIN: LimitPolicy(5, 50, 4),
        CLASS_WORKER: LimitPolicy(10, 100, 2),
        CLASS_PUBLIC: LimitPolicy(5, 50, 4),
        CLASS_OPS: LimitPolicy(None, None, None),
    }
    return {**base, **overrides}


@pytest.fixture(autouse=True)
def clean_metrics() -> None:
    registry.reset()


class TestClassification:
    """A request must land in exactly one class, and a new route must not be unlimited."""

    @pytest.mark.parametrize(
        ("path", "expected"),
        [
            ("/v1/adr/sessions", CLASS_INGEST),
            ("/v1/extension/events", CLASS_INGEST),
            ("/v1/adr/bootstrap", CLASS_BOOTSTRAP),
            ("/v1/adr/token/renew", CLASS_BOOTSTRAP),
            ("/v1/extension/enroll", CLASS_BOOTSTRAP),
            ("/v1/analysis/claim", CLASS_WORKER),
            ("/v1/admin/findings", CLASS_ADMIN),
            ("/healthz", CLASS_OPS),
            ("/metrics", CLASS_OPS),
            ("/v1/guardrails/evaluate", CLASS_PUBLIC),
        ],
    )
    def test_paths_map_to_their_class(self, path: str, expected: str) -> None:
        assert classify(path) == expected

    def test_bootstrap_wins_over_the_ingest_prefix(self) -> None:
        # Both patterns match /v1/adr/bootstrap; the tighter one has to win.
        assert classify("/v1/adr/bootstrap") == CLASS_BOOTSTRAP

    def test_an_unrecognised_path_is_limited_not_exempt(self) -> None:
        assert classify("/v1/something/brand/new") == CLASS_PUBLIC

    def test_every_class_has_a_configured_policy(self) -> None:
        from app.core.limits import build_policies

        built = build_policies()
        for name in (CLASS_INGEST, CLASS_BOOTSTRAP, CLASS_ADMIN, CLASS_WORKER,
                     CLASS_PUBLIC, CLASS_OPS):
            assert name in built

    def test_ops_is_the_only_unlimited_class(self) -> None:
        from app.core.limits import build_policies

        for name, policy in build_policies().items():
            unlimited = policy == LimitPolicy(None, None, None)
            assert unlimited == (name == CLASS_OPS), name


class TestBodySize:
    def limiter(self) -> RequestLimiter:
        return RequestLimiter(policies())

    def test_a_declared_length_within_the_cap_passes(self) -> None:
        self.limiter().check_body_size(CLASS_INGEST, 100)

    def test_a_declared_length_over_the_cap_is_refused(self) -> None:
        with pytest.raises(ServiceError) as caught:
            self.limiter().check_body_size(CLASS_INGEST, 101)
        assert caught.value.status_code == 413
        assert caught.value.error_type == "BODY_TOO_LARGE"

    def test_an_absent_length_is_not_pre_judged(self) -> None:
        # A chunked request declares nothing; the streaming counter handles it.
        self.limiter().check_body_size(CLASS_INGEST, None)

    def test_a_class_with_no_body_cap_accepts_anything(self) -> None:
        RequestLimiter(policies()).check_body_size(CLASS_OPS, 10**9)

    def test_a_refusal_is_counted(self) -> None:
        with pytest.raises(ServiceError):
            self.limiter().check_body_size(CLASS_INGEST, 999)
        assert registry.counter_value(
            LIMIT_REJECTED, {"limit_class": CLASS_INGEST, "limit": "body_size"}
        ) == 1


class TestRate:
    def test_requests_up_to_the_budget_pass(self) -> None:
        limiter = RequestLimiter(policies())

        async def run() -> None:
            for _ in range(3):
                await limiter.check_rate(CLASS_INGEST, "tenant:a", now=1000.0)

        asyncio.run(run())

    def test_the_request_past_the_budget_is_refused(self) -> None:
        limiter = RequestLimiter(policies())

        async def run() -> None:
            for _ in range(3):
                await limiter.check_rate(CLASS_INGEST, "tenant:a", now=1000.0)
            with pytest.raises(ServiceError) as caught:
                await limiter.check_rate(CLASS_INGEST, "tenant:a", now=1000.0)
            assert caught.value.status_code == 429
            assert caught.value.error_type == "RATE_LIMITED"

        asyncio.run(run())

    def test_the_budget_refills_in_the_next_window(self) -> None:
        limiter = RequestLimiter(policies())

        async def run() -> None:
            for _ in range(3):
                await limiter.check_rate(CLASS_INGEST, "tenant:a", now=1000.0)
            with pytest.raises(ServiceError):
                await limiter.check_rate(CLASS_INGEST, "tenant:a", now=1030.0)
            # 60s after the window opened, the caller starts again.
            await limiter.check_rate(CLASS_INGEST, "tenant:a", now=1060.0)

        asyncio.run(run())

    def test_one_caller_cannot_starve_another(self) -> None:
        """The point of keying by caller: a noisy collector must not throttle the fleet."""
        limiter = RequestLimiter(policies())

        async def run() -> None:
            for _ in range(3):
                await limiter.check_rate(CLASS_INGEST, "tenant:noisy", now=1000.0)
            with pytest.raises(ServiceError):
                await limiter.check_rate(CLASS_INGEST, "tenant:noisy", now=1000.0)
            await limiter.check_rate(CLASS_INGEST, "tenant:quiet", now=1000.0)

        asyncio.run(run())

    def test_budgets_are_per_class(self) -> None:
        limiter = RequestLimiter(policies())

        async def run() -> None:
            for _ in range(2):
                await limiter.check_rate(CLASS_BOOTSTRAP, "tenant:a", now=1000.0)
            with pytest.raises(ServiceError):
                await limiter.check_rate(CLASS_BOOTSTRAP, "tenant:a", now=1000.0)
            # The same caller still has its ingest budget.
            await limiter.check_rate(CLASS_INGEST, "tenant:a", now=1000.0)

        asyncio.run(run())

    def test_an_unlimited_class_is_never_throttled(self) -> None:
        limiter = RequestLimiter(policies())

        async def run() -> None:
            for _ in range(50):
                await limiter.check_rate(CLASS_OPS, "ip:1.2.3.4", now=1000.0)

        asyncio.run(run())

    def test_idle_callers_are_forgotten(self) -> None:
        """Otherwise the bucket map grows without bound on a many-caller surface."""
        limiter = RequestLimiter(policies())

        async def run() -> None:
            await limiter.check_rate(CLASS_INGEST, "ip:one", now=1000.0)
            await limiter.check_rate(CLASS_INGEST, "ip:two", now=1000.0)
            # Five windows later, a third caller arrives and the stale two are evicted.
            await limiter.check_rate(CLASS_INGEST, "ip:three", now=1000.0 + 60 * 6)
            assert set(limiter._state[CLASS_INGEST].buckets) == {"ip:three"}

        asyncio.run(run())


class TestConcurrency:
    def test_slots_up_to_the_limit_are_granted(self) -> None:
        limiter = RequestLimiter(policies())

        async def run() -> None:
            async with limiter.acquire(CLASS_INGEST):
                async with limiter.acquire(CLASS_INGEST):
                    assert limiter.in_flight(CLASS_INGEST) == 2

        asyncio.run(run())

    def test_in_flight_returns_to_zero(self) -> None:
        limiter = RequestLimiter(policies())

        async def run() -> None:
            async with limiter.acquire(CLASS_INGEST):
                pass
            assert limiter.in_flight(CLASS_INGEST) == 0

        asyncio.run(run())

    def test_a_slot_is_released_even_when_the_request_fails(self) -> None:
        limiter = RequestLimiter(policies())

        async def run() -> None:
            with pytest.raises(RuntimeError):
                async with limiter.acquire(CLASS_INGEST):
                    raise RuntimeError("handler blew up")
            assert limiter.in_flight(CLASS_INGEST) == 0
            # The slot is genuinely back, not just the counter.
            async with limiter.acquire(CLASS_BOOTSTRAP):
                pass

        asyncio.run(run())

    def test_exhaustion_is_refused_with_503(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import app.core.limits as limits_module

        # A real wait would take the acquire timeout; shorten it for the test.
        monkeypatch.setattr(limits_module, "_ACQUIRE_TIMEOUT_SECONDS", 0.05)
        limiter = RequestLimiter(policies())

        async def run() -> None:
            async with limiter.acquire(CLASS_BOOTSTRAP):  # limit is 1
                with pytest.raises(ServiceError) as caught:
                    async with limiter.acquire(CLASS_BOOTSTRAP):
                        pass
            assert caught.value.status_code == 503
            assert caught.value.error_type == "CONCURRENCY_LIMITED"
            assert registry.counter_value(
                LIMIT_REJECTED, {"limit_class": CLASS_BOOTSTRAP, "limit": "concurrency"}
            ) == 1

        asyncio.run(run())

    def test_a_waiter_is_admitted_once_a_slot_frees(self) -> None:
        """Concurrency limiting must queue briefly, not refuse immediately."""
        limiter = RequestLimiter(policies())
        order: list[str] = []

        async def run() -> None:
            async def holder() -> None:
                async with limiter.acquire(CLASS_BOOTSTRAP):
                    order.append("holder-in")
                    await asyncio.sleep(0.02)
                order.append("holder-out")

            async def waiter() -> None:
                await asyncio.sleep(0.005)
                async with limiter.acquire(CLASS_BOOTSTRAP):
                    order.append("waiter-in")

            await asyncio.gather(holder(), waiter())

        asyncio.run(run())
        assert order == ["holder-in", "holder-out", "waiter-in"]

    def test_an_unlimited_class_has_no_ceiling(self) -> None:
        limiter = RequestLimiter(policies())

        async def run() -> None:
            slots = [limiter.acquire(CLASS_OPS) for _ in range(20)]
            for slot in slots:
                await slot.__aenter__()
            for slot in slots:
                await slot.__aexit__()

        asyncio.run(run())


class TestCallerKey:
    def test_tenant_is_preferred(self) -> None:
        assert caller_key("1.2.3.4", "Bearer abc", "tenant-1") == "tenant:tenant-1"

    def test_a_credential_is_fingerprinted_never_stored(self) -> None:
        key = caller_key("1.2.3.4", "Bearer super-secret-token", None)
        assert key.startswith("cred:")
        assert "super-secret-token" not in key

    def test_distinct_credentials_get_distinct_keys(self) -> None:
        first = caller_key(None, "Bearer one", None)
        second = caller_key(None, "Bearer two", None)
        assert first != second

    def test_the_peer_address_is_the_last_resort(self) -> None:
        assert caller_key("1.2.3.4", None, None) == "ip:1.2.3.4"

    def test_an_anonymous_caller_still_gets_a_bucket(self) -> None:
        assert caller_key(None, None, None) == "ip:unknown"


# --------------------------------------------------------------------- middleware


async def _call(
    middleware: RequestLimitsMiddleware,
    path: str,
    *,
    headers: list[tuple[bytes, bytes]] | None = None,
    body_chunks: list[bytes] | None = None,
) -> tuple[int, dict]:
    """Drive the middleware as an ASGI app and collect the response."""
    scope = {
        "type": "http",
        "method": "POST",
        "path": path,
        "headers": headers or [],
        "client": ("10.0.0.1", 5000),
    }
    chunks = list(body_chunks or [b""])
    sent: list[dict] = []

    async def receive() -> dict:
        if chunks:
            chunk = chunks.pop(0)
            return {"type": "http.request", "body": chunk, "more_body": bool(chunks)}
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict) -> None:
        sent.append(message)

    await middleware(scope, receive, send)
    status = next((m["status"] for m in sent if m["type"] == "http.response.start"), None)
    raw = b"".join(m.get("body") or b"" for m in sent if m["type"] == "http.response.body")
    payload = json.loads(raw) if raw else {}
    return status, payload


def _ok_app(reads_body: bool = False):
    async def app(scope, receive, send) -> None:
        if reads_body:
            while True:
                message = await receive()
                if not message.get("more_body"):
                    break
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"{}"})

    return app


class TestMiddleware:
    """The middleware is where a limit failure must still look like a normal error.

    A ServiceError raised in user middleware never reaches FastAPI's exception handler,
    so the middleware has to render the error envelope itself.
    """

    def middleware(self, app=None) -> RequestLimitsMiddleware:
        return RequestLimitsMiddleware(app or _ok_app(), limiter=RequestLimiter(policies()))

    def test_a_request_within_every_limit_passes_through(self) -> None:
        status, _ = asyncio.run(_call(self.middleware(), "/v1/adr/sessions"))
        assert status == 200

    def test_an_oversized_declared_body_is_refused_before_the_app_runs(self) -> None:
        reached = []

        async def app(scope, receive, send) -> None:
            reached.append(True)
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"{}"})

        status, payload = asyncio.run(
            _call(
                RequestLimitsMiddleware(app, limiter=RequestLimiter(policies())),
                "/v1/adr/sessions",
                headers=[(b"content-length", b"999")],
            )
        )
        assert status == 413
        assert payload["error"]["type"] == "BODY_TOO_LARGE"
        assert reached == [], "the handler must never see an oversized request"

    def test_the_error_envelope_matches_the_service_wide_shape(self) -> None:
        _, payload = asyncio.run(
            _call(
                self.middleware(),
                "/v1/adr/sessions",
                headers=[(b"content-length", b"999")],
            )
        )
        assert set(payload) == {"error"}
        assert {"type", "message"} <= set(payload["error"])

    def test_a_chunked_body_over_the_cap_is_caught_while_streaming(self) -> None:
        """Content-Length alone is bypassable, so the stream is counted too."""
        middleware = RequestLimitsMiddleware(
            _ok_app(reads_body=True), limiter=RequestLimiter(policies())
        )
        status, payload = asyncio.run(
            _call(
                middleware,
                "/v1/adr/sessions",
                body_chunks=[b"x" * 60, b"x" * 60],  # 120 > 100 cap
            )
        )
        assert status == 413
        assert payload["error"]["type"] == "BODY_TOO_LARGE"

    def test_a_chunked_body_within_the_cap_streams_through(self) -> None:
        middleware = RequestLimitsMiddleware(
            _ok_app(reads_body=True), limiter=RequestLimiter(policies())
        )
        status, _ = asyncio.run(
            _call(middleware, "/v1/adr/sessions", body_chunks=[b"x" * 40, b"x" * 40])
        )
        assert status == 200

    def test_rate_exhaustion_returns_429_with_retry_after(self) -> None:
        middleware = self.middleware()
        sent_headers: list[tuple[bytes, bytes]] = []

        async def run() -> int:
            for _ in range(3):
                status, _ = await _call(middleware, "/v1/adr/sessions")
                assert status == 200
            scope = {
                "type": "http",
                "method": "POST",
                "path": "/v1/adr/sessions",
                "headers": [],
                "client": ("10.0.0.1", 5000),
            }

            async def receive() -> dict:
                return {"type": "http.request", "body": b"", "more_body": False}

            async def send(message: dict) -> None:
                if message["type"] == "http.response.start":
                    sent_headers.extend(message["headers"])

            await middleware(scope, receive, send)
            return next(
                int(value) for name, value in sent_headers if name == b"retry-after"
            )

        assert asyncio.run(run()) == 60

    def test_ops_paths_are_never_limited(self) -> None:
        middleware = self.middleware()

        async def run() -> None:
            # Far more than any configured budget, with a huge declared body.
            for _ in range(30):
                status, _ = await _call(
                    middleware, "/healthz", headers=[(b"content-length", b"999999999")]
                )
                assert status == 200

        asyncio.run(run())

    def test_admitted_requests_are_counted(self) -> None:
        asyncio.run(_call(self.middleware(), "/v1/adr/sessions"))
        assert registry.counter_value(REQUESTS_TOTAL, {"limit_class": CLASS_INGEST}) == 1

    def test_limits_can_be_switched_off(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(settings, "request_limits_enabled", False)
        status, _ = asyncio.run(
            _call(
                self.middleware(),
                "/v1/adr/sessions",
                headers=[(b"content-length", b"999999")],
            )
        )
        assert status == 200

    def test_a_non_http_scope_is_passed_straight_through(self) -> None:
        seen: list[str] = []

        async def app(scope, receive, send) -> None:
            seen.append(scope["type"])

        middleware = RequestLimitsMiddleware(app, limiter=RequestLimiter(policies()))
        asyncio.run(middleware({"type": "lifespan"}, None, None))
        assert seen == ["lifespan"]

    def test_a_malformed_content_length_is_not_a_free_pass(self) -> None:
        """An unparseable header must fall back to counting, not skip the cap."""
        middleware = RequestLimitsMiddleware(
            _ok_app(reads_body=True), limiter=RequestLimiter(policies())
        )
        status, payload = asyncio.run(
            _call(
                middleware,
                "/v1/adr/sessions",
                headers=[(b"content-length", b"not-a-number")],
                body_chunks=[b"x" * 200],
            )
        )
        assert status == 413
        assert payload["error"]["type"] == "BODY_TOO_LARGE"

    def test_the_tenant_header_scopes_the_rate_budget(self) -> None:
        middleware = self.middleware()

        async def run() -> None:
            for _ in range(3):
                status, _ = await _call(
                    middleware, "/v1/adr/sessions", headers=[(b"x-tenant-id", b"one")]
                )
                assert status == 200
            status, payload = await _call(
                middleware, "/v1/adr/sessions", headers=[(b"x-tenant-id", b"one")]
            )
            assert status == 429
            # A different tenant still has its own budget.
            status, _ = await _call(
                middleware, "/v1/adr/sessions", headers=[(b"x-tenant-id", b"two")]
            )
            assert status == 200

        asyncio.run(run())


class TestMetricsRendering:
    def test_a_counter_renders_in_prometheus_format(self) -> None:
        registry.increment(LIMIT_REJECTED, {"limit_class": "ingest", "limit": "rate"})
        rendered = registry.render()
        assert f"# TYPE {LIMIT_REJECTED} counter" in rendered
        assert f'{LIMIT_REJECTED}{{limit="rate",limit_class="ingest"}} 1' in rendered

    def test_labels_are_ordered_so_output_is_stable(self) -> None:
        registry.increment("umai_test_total", {"b": "2", "a": "1"})
        assert 'umai_test_total{a="1",b="2"} 1' in registry.render()

    def test_a_gauge_reports_its_latest_value(self) -> None:
        registry.set_gauge("umai_test_gauge", 3)
        registry.set_gauge("umai_test_gauge", 1)
        assert registry.gauge_value("umai_test_gauge") == 1

    def test_a_counter_cannot_decrease(self) -> None:
        with pytest.raises(ValueError):
            registry.increment("umai_test_total", amount=-1)

    def test_label_values_are_escaped(self) -> None:
        registry.increment("umai_test_total", {"path": 'a"b\\c'})
        assert 'path="a\\"b\\\\c"' in registry.render()

    def test_an_empty_registry_renders_nothing(self) -> None:
        assert registry.render() == ""


class TestRoutesAreClassifiedAtTheirRealPaths:
    """The patterns must match the paths this service actually mounts.

    Every router mounts under `/api/v1/...`, and the class patterns were
    anchored at `^/v1/`. Nothing matched, so ADR ingest, extension ingest, the
    analysis workers and all 68 admin routes fell through to `CLASS_PUBLIC`.
    That applied the 1 MB default body cap where the ADR contract advertises
    32 MB — the first collector run against a real machine died with
    `BODY_TOO_LARGE ... for public requests` — and ran the admin API on the
    public rate limit and concurrency budget.

    Asserted on literal paths copied from the OpenAPI document, because the
    failure mode was a pattern that looked right in isolation.
    """

    @pytest.mark.parametrize(
        "path,expected",
        [
            # Ingest: the surface that carries session bodies.
            ("/api/v1/adr/sessions", limits.CLASS_INGEST),
            ("/api/v1/adr/heartbeat", limits.CLASS_INGEST),
            ("/api/v1/adr/renew", limits.CLASS_INGEST),
            ("/api/v1/ext/evaluate", limits.CLASS_INGEST),
            ("/api/v1/ext/policy", limits.CLASS_INGEST),
            # Enrolment is tighter than ingest and must win the ordering.
            ("/api/v1/adr/bootstrap", limits.CLASS_BOOTSTRAP),
            ("/api/v1/ext/bootstrap", limits.CLASS_BOOTSTRAP),
            # Workers post results and pull transcripts; both need the big cap.
            ("/internal/analysis/claim", limits.CLASS_WORKER),
            ("/internal/analysis/result", limits.CLASS_WORKER),
            ("/internal/analysis/transcript/t/s", limits.CLASS_WORKER),
            # Admin.
            ("/api/v1/admin/adr/devices", limits.CLASS_ADMIN),
            ("/api/v1/admin/guardrails", limits.CLASS_ADMIN),
            ("/api/v1/admin/evaluations", limits.CLASS_ADMIN),
            # Ops.
            ("/healthz", limits.CLASS_OPS),
            ("/metrics", limits.CLASS_OPS),
            # Genuinely public runtime surfaces stay public.
            ("/api/v1/guardrails/gr-1/guard", limits.CLASS_PUBLIC),
            ("/api/v1/agent-runs", limits.CLASS_PUBLIC),
        ],
    )
    def test_real_mounted_paths(self, path: str, expected: str) -> None:
        assert limits.classify(path) == expected

    @pytest.mark.parametrize(
        "path,expected",
        [
            ("/v1/adr/sessions", limits.CLASS_INGEST),
            ("/v1/adr/bootstrap", limits.CLASS_BOOTSTRAP),
            ("/v1/admin/guardrails", limits.CLASS_ADMIN),
        ],
    )
    def test_a_proxy_that_strips_the_api_prefix_still_classifies(
        self, path: str, expected: str
    ) -> None:
        # A deployment fronted by a proxy that rewrites `/api/v1` to `/v1`
        # presents the short form to this process; both must work.
        assert limits.classify(path) == expected

    def test_the_ingest_cap_is_the_contract_cap(self) -> None:
        from app.api.adr import ADR_BODY_SIZE_LIMIT
        from app.core.settings import Settings

        # The collector is entitled to send what the contract promises. These
        # two numbers drifting apart is what made a documented limit
        # unreachable.
        assert Settings().max_body_bytes_ingest == ADR_BODY_SIZE_LIMIT
