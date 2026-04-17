from __future__ import annotations

from redis.asyncio import Redis


def build_snapshot_key(
    tenant_id: str,
    environment_id: str,
    project_id: str,
    guardrail_id: str,
    version: int,
) -> str:
    return f"guardrail:{tenant_id}:{environment_id}:{project_id}:{guardrail_id}:{version}"


async def publish_snapshot(redis: Redis, key: str, snapshot_json: str) -> None:
    await redis.set(key, snapshot_json)
