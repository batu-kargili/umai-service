"""Rate, body-size, and concurrency limits for the critical request surfaces (UMA-83).

Three different resources need protecting, and they fail in different ways:

* **Body size** protects memory. A 500 MB transcript upload should be refused at the
  header, before it is buffered, not after.
* **Rate** protects downstream work — the engine, the database, an LLM judge. It is
  enforced per caller so one noisy collector cannot starve the rest of a fleet.
* **Concurrency** protects the event loop and the connection pool. A burst that arrives
  inside one window passes a rate limit but can still exhaust the pool, so the two are
  not interchangeable.

**The rate and concurrency limits are per worker process.** There is no shared counter, so
a deployment running N workers admits N times the configured rate. That is a deliberate
choice — a cross-process limiter would put Redis on the path of every request — but it
means the configured number is a per-worker number, and the setting names say so. Fleet
capacity is workers x limit; size the limit accordingly.
"""

from __future__ import annotations

import asyncio
import re
import time
from dataclasses import dataclass, field

from app.core.errors import ServiceError
from app.core.metrics import (
    LIMIT_CONCURRENCY_IN_FLIGHT,
    LIMIT_REJECTED,
    REQUESTS_TOTAL,
    registry,
)

# Limit classes. A request belongs to exactly one, chosen by the first pattern that
# matches its path, so a new endpoint inherits a sensible default instead of being
# unlimited by omission.
CLASS_INGEST = "ingest"
CLASS_BOOTSTRAP = "bootstrap"
CLASS_ADMIN = "admin"
CLASS_WORKER = "worker"
CLASS_PUBLIC = "public"
CLASS_OPS = "ops"

_ROUTE_CLASSES: tuple[tuple[re.Pattern[str], str], ...] = (
    # Ordered: the more specific bootstrap paths must win over the ingest prefixes.
    (re.compile(r"^/v1/(adr|extension)/(bootstrap|enroll|register|token)"), CLASS_BOOTSTRAP),
    (re.compile(r"^/v1/(adr|extension)/"), CLASS_INGEST),
    (re.compile(r"^/v1/analysis/"), CLASS_WORKER),
    (re.compile(r"^/(healthz|readyz|livez|metrics)$"), CLASS_OPS),
    (re.compile(r"^/v1/admin/"), CLASS_ADMIN),
)


@dataclass(frozen=True)
class LimitPolicy:
    """One limit class's budget. ``None`` disables that dimension."""

    requests_per_minute: int | None
    max_body_bytes: int | None
    max_concurrent: int | None


@dataclass
class _Bucket:
    """A fixed-window counter. Cheap, and its reset behaviour is easy to reason about."""

    window_started_at: float
    count: int = 0


@dataclass
class _ClassState:
    buckets: dict[str, _Bucket] = field(default_factory=dict)
    semaphore: asyncio.Semaphore | None = None
    in_flight: int = 0


WINDOW_SECONDS = 60.0
# A caller that has been quiet for several windows is forgotten, so the bucket map cannot
# grow without bound on a surface with many distinct callers.
_BUCKET_IDLE_EVICTION_SECONDS = WINDOW_SECONDS * 5


def classify(path: str) -> str:
    for pattern, name in _ROUTE_CLASSES:
        if pattern.match(path):
            return name
    return CLASS_PUBLIC


class RequestLimiter:
    """Enforces one policy set. One instance per process."""

    def __init__(self, policies: dict[str, LimitPolicy]) -> None:
        self._policies = policies
        self._state: dict[str, _ClassState] = {name: _ClassState() for name in policies}
        self._lock = asyncio.Lock()

    def policy_for(self, limit_class: str) -> LimitPolicy | None:
        return self._policies.get(limit_class)

    # ---------------------------------------------------------------- body size

    def check_body_size(self, limit_class: str, declared_length: int | None) -> None:
        policy = self._policies.get(limit_class)
        if policy is None or policy.max_body_bytes is None:
            return
        if declared_length is not None and declared_length > policy.max_body_bytes:
            self._reject(limit_class, "body_size")
            raise ServiceError(
                "BODY_TOO_LARGE",
                f"Request body exceeds the {policy.max_body_bytes} byte limit "
                f"for {limit_class} requests",
                413,
            )

    def body_budget(self, limit_class: str) -> int | None:
        """The cap to enforce while streaming, when no Content-Length was declared."""
        policy = self._policies.get(limit_class)
        return policy.max_body_bytes if policy else None

    def reject_oversized_stream(self, limit_class: str) -> ServiceError:
        policy = self._policies.get(limit_class)
        cap = policy.max_body_bytes if policy else None
        self._reject(limit_class, "body_size")
        return ServiceError(
            "BODY_TOO_LARGE",
            f"Request body exceeds the {cap} byte limit for {limit_class} requests",
            413,
        )

    # --------------------------------------------------------------------- rate

    async def check_rate(self, limit_class: str, caller: str, now: float | None = None) -> None:
        policy = self._policies.get(limit_class)
        if policy is None or policy.requests_per_minute is None:
            return
        moment = time.monotonic() if now is None else now

        async with self._lock:
            state = self._state[limit_class]
            self._evict_idle(state, moment)
            bucket = state.buckets.get(caller)
            if bucket is None or moment - bucket.window_started_at >= WINDOW_SECONDS:
                state.buckets[caller] = _Bucket(window_started_at=moment, count=1)
                return
            if bucket.count >= policy.requests_per_minute:
                retry_after = max(1, int(WINDOW_SECONDS - (moment - bucket.window_started_at)))
                self._reject(limit_class, "rate")
                raise ServiceError(
                    "RATE_LIMITED",
                    f"Rate limit of {policy.requests_per_minute} requests per minute "
                    f"for {limit_class} requests exceeded; retry in {retry_after}s",
                    429,
                )
            bucket.count += 1

    @staticmethod
    def _evict_idle(state: _ClassState, moment: float) -> None:
        stale = [
            caller
            for caller, bucket in state.buckets.items()
            if moment - bucket.window_started_at > _BUCKET_IDLE_EVICTION_SECONDS
        ]
        for caller in stale:
            del state.buckets[caller]

    # -------------------------------------------------------------- concurrency

    def acquire(self, limit_class: str) -> "_ConcurrencySlot":
        return _ConcurrencySlot(self, limit_class)

    def _semaphore(self, limit_class: str) -> asyncio.Semaphore | None:
        policy = self._policies.get(limit_class)
        if policy is None or policy.max_concurrent is None:
            return None
        state = self._state[limit_class]
        if state.semaphore is None:
            # Created lazily: a Semaphore binds to the running loop, and the limiter is
            # built at import time when there is no loop yet.
            state.semaphore = asyncio.Semaphore(policy.max_concurrent)
        return state.semaphore

    def _enter(self, limit_class: str) -> None:
        state = self._state[limit_class]
        state.in_flight += 1
        registry.set_gauge(
            LIMIT_CONCURRENCY_IN_FLIGHT, state.in_flight, {"limit_class": limit_class}
        )

    def _exit(self, limit_class: str) -> None:
        state = self._state[limit_class]
        state.in_flight = max(0, state.in_flight - 1)
        registry.set_gauge(
            LIMIT_CONCURRENCY_IN_FLIGHT, state.in_flight, {"limit_class": limit_class}
        )

    def in_flight(self, limit_class: str) -> int:
        return self._state[limit_class].in_flight

    # ------------------------------------------------------------------ metrics

    @staticmethod
    def _reject(limit_class: str, dimension: str) -> None:
        registry.increment(LIMIT_REJECTED, {"limit_class": limit_class, "limit": dimension})

    @staticmethod
    def record_admitted(limit_class: str) -> None:
        registry.increment(REQUESTS_TOTAL, {"limit_class": limit_class})


class _ConcurrencySlot:
    """Holds a concurrency slot for the duration of one request."""

    def __init__(self, limiter: RequestLimiter, limit_class: str) -> None:
        self._limiter = limiter
        self._limit_class = limit_class
        self._semaphore: asyncio.Semaphore | None = None

    async def __aenter__(self) -> "_ConcurrencySlot":
        self._semaphore = self._limiter._semaphore(self._limit_class)
        if self._semaphore is not None:
            policy = self._limiter.policy_for(self._limit_class)
            timeout = _ACQUIRE_TIMEOUT_SECONDS
            try:
                await asyncio.wait_for(self._semaphore.acquire(), timeout=timeout)
            except asyncio.TimeoutError as exc:
                self._semaphore = None
                self._limiter._reject(self._limit_class, "concurrency")
                limit = policy.max_concurrent if policy else None
                # 503 rather than 429: the caller did nothing wrong, the server is full.
                raise ServiceError(
                    "CONCURRENCY_LIMITED",
                    f"Concurrency limit of {limit} in-flight {self._limit_class} "
                    f"requests reached; retry shortly",
                    503,
                ) from exc
        self._limiter._enter(self._limit_class)
        return self

    async def __aexit__(self, *_exc_info: object) -> None:
        self._limiter._exit(self._limit_class)
        if self._semaphore is not None:
            self._semaphore.release()


# How long a request waits for a slot before the server admits it is full. Long enough to
# ride out a brief spike, short enough that a caller is not left hanging.
_ACQUIRE_TIMEOUT_SECONDS = 5.0


def build_policies() -> dict[str, LimitPolicy]:
    """Read the configured budgets. Every class gets an entry, so none is unlimited."""
    from app.core.settings import settings

    return {
        CLASS_INGEST: LimitPolicy(
            settings.rate_limit_ingest_per_minute,
            settings.max_body_bytes_ingest,
            settings.max_concurrent_ingest,
        ),
        # Enrolment is the credential-issuing surface, so it is the tightest.
        CLASS_BOOTSTRAP: LimitPolicy(
            settings.rate_limit_bootstrap_per_minute,
            settings.max_body_bytes_default,
            settings.max_concurrent_bootstrap,
        ),
        CLASS_ADMIN: LimitPolicy(
            settings.rate_limit_admin_per_minute,
            settings.max_body_bytes_default,
            settings.max_concurrent_admin,
        ),
        CLASS_WORKER: LimitPolicy(
            settings.rate_limit_worker_per_minute,
            settings.max_body_bytes_ingest,
            settings.max_concurrent_worker,
        ),
        CLASS_PUBLIC: LimitPolicy(
            settings.rate_limit_public_per_minute,
            settings.max_body_bytes_default,
            settings.max_concurrent_public,
        ),
        # Health and metrics are never limited: throttling them turns a load spike into
        # a false outage, because the probe fails before the service does.
        CLASS_OPS: LimitPolicy(None, None, None),
    }


def error_payload(exc: ServiceError) -> dict[str, object]:
    return {"error": exc.to_dict()}


class RequestLimitsMiddleware:
    """Pure ASGI, so the request body can be counted as it streams.

    A ``Content-Length`` header is checked before the body is read, which stops the
    ordinary oversized upload at no cost. A chunked request declares no length, so the
    wrapped ``receive`` also counts bytes and fails the request once it passes the cap —
    otherwise the header check would be trivially bypassable.
    """

    def __init__(self, app, limiter: RequestLimiter) -> None:
        self.app = app
        self.limiter = limiter

    async def __call__(self, scope, receive, send) -> None:
        from app.core.settings import settings

        if scope.get("type") != "http" or not settings.request_limits_enabled:
            await self.app(scope, receive, send)
            return

        limit_class = classify(scope.get("path", ""))
        if limit_class == CLASS_OPS:
            await self.app(scope, receive, send)
            return

        headers = {
            name.decode("latin-1").lower(): value.decode("latin-1")
            for name, value in scope.get("headers") or ()
        }
        started = _ResponseTracker(send)
        try:
            self.limiter.check_body_size(limit_class, _declared_length(headers))
            client = scope.get("client")
            await self.limiter.check_rate(
                limit_class,
                caller_key(
                    client[0] if client else None,
                    headers.get("authorization"),
                    headers.get("x-tenant-id"),
                ),
            )
            async with self.limiter.acquire(limit_class):
                self.limiter.record_admitted(limit_class)
                await self.app(scope, self._counted(receive, limit_class), started.send)
        except ServiceError as exc:
            # A streaming body cap can fire after the handler has begun responding. The
            # status line is already on the wire by then, so a second one cannot be sent;
            # the connection is closed instead and the rejection is left in the metric.
            if started.response_started:
                raise
            await _send_error(send, exc)

    def _counted(self, receive, limit_class: str):
        cap = self.limiter.body_budget(limit_class)
        if cap is None:
            return receive
        seen = 0

        async def wrapped():
            nonlocal seen
            message = await receive()
            if message.get("type") == "http.request":
                seen += len(message.get("body") or b"")
                if seen > cap:
                    raise self.limiter.reject_oversized_stream(limit_class)
            return message

        return wrapped


class _ResponseTracker:
    """Remembers whether the response line has gone out, so it is not sent twice."""

    def __init__(self, send) -> None:
        self._send = send
        self.response_started = False

    async def send(self, message) -> None:
        if message.get("type") == "http.response.start":
            self.response_started = True
        await self._send(message)


def _declared_length(headers: dict[str, str]) -> int | None:
    raw = headers.get("content-length")
    if raw is None:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


async def _send_error(send, exc: ServiceError) -> None:
    import json

    body = json.dumps(error_payload(exc)).encode("utf-8")
    response_headers = [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(body)).encode("ascii")),
    ]
    if exc.status_code in (429, 503):
        # Tell a well-behaved client when to come back instead of leaving it to guess.
        response_headers.append((b"retry-after", b"60" if exc.status_code == 429 else b"5"))
    await send(
        {"type": "http.response.start", "status": exc.status_code, "headers": response_headers}
    )
    await send({"type": "http.response.body", "body": body})


def caller_key(client_host: str | None, authorization: str | None, tenant: str | None) -> str:
    """Identify the caller for rate-limiting, without storing a credential.

    Prefers the tenant, then a short fingerprint of the presented credential, then the
    peer address. A credential is never used verbatim: the bucket map would otherwise hold
    live tokens in memory.
    """
    if tenant:
        return f"tenant:{tenant}"
    if authorization:
        import hashlib

        fingerprint = hashlib.sha256(authorization.encode("utf-8")).hexdigest()[:16]
        return f"cred:{fingerprint}"
    return f"ip:{client_host or 'unknown'}"
