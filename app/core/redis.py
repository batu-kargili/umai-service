from __future__ import annotations

from redis.asyncio import Redis

from app.core.settings import settings

_redis: Redis | None = None


def get_redis() -> Redis:
    global _redis
    if _redis is None:
        if not settings.redis_url:
            raise RuntimeError("UMAI_REDIS_URL is not set")
        _redis = Redis.from_url(settings.redis_url, decode_responses=True)
    return _redis
