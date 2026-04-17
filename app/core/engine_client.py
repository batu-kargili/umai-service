from __future__ import annotations

import logging

import httpx

from app.core.errors import ServiceError
from app.core.settings import settings
from app.models.engine import EngineRequest, EngineResponse

logger = logging.getLogger("duvarai.service.engine")


def _engine_url() -> str:
    if not settings.ai_engine_base_url:
        raise ServiceError("AI_ENGINE_UNREACHABLE", "AI Engine base URL not configured", 503, True)
    return settings.ai_engine_base_url.rstrip("/") + "/internal/ai-engine/v1/evaluate"


async def evaluate_engine(request: EngineRequest) -> EngineResponse:
    url = _engine_url()
    timeout_s = (request.timeout_ms or 1500) / 1000.0
    logger.info("engine.call.start request_id=%s url=%s", request.request_id, url)
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(timeout_s)) as client:
            response = await client.post(url, json=request.model_dump())
            response.raise_for_status()
    except httpx.ReadTimeout as exc:
        logger.warning("engine.call.timeout request_id=%s", request.request_id)
        raise ServiceError("AI_ENGINE_TIMEOUT", "AI Engine request timed out", 504, True) from exc
    except httpx.RequestError as exc:
        logger.warning("engine.call.unreachable request_id=%s error=%s", request.request_id, exc)
        raise ServiceError("AI_ENGINE_UNREACHABLE", f"AI Engine unreachable: {exc}", 503, True) from exc
    except httpx.HTTPStatusError as exc:
        logger.warning(
            "engine.call.http_error request_id=%s status=%s",
            request.request_id,
            exc.response.status_code,
        )
        raise ServiceError(
            "AI_ENGINE_UNREACHABLE",
            f"AI Engine returned HTTP {exc.response.status_code}",
            502,
            False,
        ) from exc
    payload = EngineResponse.model_validate(response.json())
    logger.info(
        "engine.call.ok request_id=%s action=%s allowed=%s",
        payload.request_id,
        payload.decision.action,
        payload.decision.allowed,
    )
    return payload
