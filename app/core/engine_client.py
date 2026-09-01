from __future__ import annotations

import logging
import time

import httpx

from app.core.errors import ServiceError
from app.core.request_metrics import (
    OUTCOME_HTTP_ERROR,
    OUTCOME_TIMEOUT,
    OUTCOME_UNREACHABLE,
    observe_engine_failure,
    observe_engine_response,
)
from app.core.settings import settings
from app.models.engine import EngineRequest, EngineResponse

logger = logging.getLogger("umai.service.engine")


def _engine_url() -> str:
    if not settings.ai_engine_base_url:
        raise ServiceError("AI_ENGINE_UNREACHABLE", "AI Engine base URL not configured", 503, True)
    return settings.ai_engine_base_url.rstrip("/") + "/internal/ai-engine/v1/evaluate"


# Headroom added on top of the per-LLM-call budget: the engine may run several
# policies sequentially and retry transient upstream rate-limits (HTTP 429),
# so the service->engine HTTP timeout must be larger than a single call budget
# or it will spuriously 504 while the engine is still legitimately working.
_ENGINE_TIMEOUT_HEADROOM_S = 12.0


async def evaluate_engine(request: EngineRequest) -> EngineResponse:
    url = _engine_url()
    timeout_s = (request.timeout_ms or 1500) / 1000.0 + _ENGINE_TIMEOUT_HEADROOM_S
    logger.info("engine.call.start request_id=%s url=%s", request.request_id, url)
    # Measured around the whole call so the metric reflects what a caller waits for,
    # including connection setup — not just the engine's self-reported latency.
    started = time.perf_counter()
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(timeout_s)) as client:
            response = await client.post(url, json=request.model_dump())
            response.raise_for_status()
    except httpx.ReadTimeout as exc:
        logger.warning("engine.call.timeout request_id=%s", request.request_id)
        observe_engine_failure(OUTCOME_TIMEOUT, time.perf_counter() - started)
        raise ServiceError("AI_ENGINE_TIMEOUT", "AI Engine request timed out", 504, True) from exc
    except httpx.HTTPStatusError as exc:
        # Before RequestError: HTTPStatusError is not a RequestError subclass, but
        # ordering these two deliberately keeps the intent obvious to the next reader.
        logger.warning(
            "engine.call.http_error request_id=%s status=%s",
            request.request_id,
            exc.response.status_code,
        )
        observe_engine_failure(OUTCOME_HTTP_ERROR, time.perf_counter() - started)
        raise ServiceError(
            "AI_ENGINE_UNREACHABLE",
            f"AI Engine returned HTTP {exc.response.status_code}",
            502,
            False,
        ) from exc
    except httpx.RequestError as exc:
        logger.warning("engine.call.unreachable request_id=%s error=%s", request.request_id, exc)
        observe_engine_failure(OUTCOME_UNREACHABLE, time.perf_counter() - started)
        raise ServiceError("AI_ENGINE_UNREACHABLE", f"AI Engine unreachable: {exc}", 503, True) from exc
    elapsed = time.perf_counter() - started
    payload = EngineResponse.model_validate(response.json())
    observe_engine_response(payload, elapsed)
    logger.info(
        "engine.call.ok request_id=%s action=%s allowed=%s",
        payload.request_id,
        payload.decision.action,
        payload.decision.allowed,
    )
    return payload
