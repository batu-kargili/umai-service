import logging

import httpx
from fastapi import APIRouter
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.core.db import get_engine
from app.core.redis import get_redis
from app.core.settings import settings

router = APIRouter()
logger = logging.getLogger("umai.service.ops")


@router.get("/healthz")
async def healthz() -> dict:
    return {"status": "ok"}


async def _check_db() -> dict:
    try:
        engine = get_engine()
    except RuntimeError as exc:
        return {"ok": False, "error": str(exc)}
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        return {"ok": True}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


async def _check_redis() -> dict:
    if not settings.redis_url:
        return {"ok": True, "skipped": True}
    try:
        redis = get_redis()
        pong = await redis.ping()
        return {"ok": bool(pong)}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


async def _check_engine() -> dict:
    if not settings.ai_engine_base_url:
        return {"ok": True, "skipped": True}
    base_url = settings.ai_engine_base_url.rstrip("/")
    probes: list[tuple[str, tuple[int, ...]]] = [
        ("/healthz", (200,)),
        ("/readyz", (200,)),
        ("/openapi.json", (200,)),
        # A GET against this POST endpoint should reliably return 405 when alive.
        ("/internal/ai-engine/v1/evaluate", (405,)),
    ]
    errors: list[str] = []
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(2.0)) as client:
            for path, ok_statuses in probes:
                url = base_url + path
                try:
                    resp = await client.get(url)
                    if resp.status_code in ok_statuses:
                        return {"ok": True, "probe": path}
                    errors.append(f"{path} returned {resp.status_code}")
                except Exception as exc:
                    errors.append(f"{path} failed: {exc}")
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
    return {"ok": False, "error": "; ".join(errors)}


@router.get("/readyz")
async def readyz() -> dict:
    db_status = await _check_db()
    redis_status = await _check_redis()
    engine_status = await _check_engine()
    ok = db_status.get("ok") and redis_status.get("ok") and engine_status.get("ok")
    payload = {
        "status": "ok" if ok else "degraded",
        "dependencies": {
            "db": db_status,
            "redis": redis_status,
            "ai_engine": engine_status,
        },
    }
    logger.info("readyz status=%s", payload["status"])
    if ok:
        return payload
    return JSONResponse(status_code=503, content=payload)
