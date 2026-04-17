from __future__ import annotations

import hashlib

from sqlalchemy import select, false
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import ServiceError
from app.models.db import ApiKey


def hash_api_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


async def authenticate_api_key(session: AsyncSession, raw_key: str | None) -> ApiKey:
    if not raw_key:
        raise ServiceError("AUTH_MISSING", "API key is required", 401)
    key_hash = hash_api_key(raw_key)
    stmt = select(ApiKey).where(ApiKey.key_hash == key_hash, ApiKey.revoked == false())
    result = await session.execute(stmt)
    api_key = result.scalar_one_or_none()
    if not api_key:
        raise ServiceError("AUTH_INVALID", "API key is invalid", 401)
    return api_key
