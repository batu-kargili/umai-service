"""Shared test helpers.

The suite is otherwise pure unit tests. Some behaviour — idempotent writes,
concurrent inserts, lifecycle transitions — only exists at the database, so
this provides a real session against in-memory SQLite.

Tests stay synchronous and drive the async code with ``asyncio.run``, matching
the style of the rest of the suite and avoiding a pytest-asyncio dependency.
"""

from __future__ import annotations

import contextlib
from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from app.models.db import Base


@contextlib.asynccontextmanager
async def db_session() -> AsyncIterator[AsyncSession]:
    """An empty database with the real schema, one session, torn down after.

    StaticPool keeps every checkout on the same connection: an in-memory
    SQLite database belongs to its connection, so without it each checkout
    would see a different, empty database.
    """
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        factory = async_sessionmaker(engine, expire_on_commit=False)
        async with factory() as session:
            yield session
    finally:
        await engine.dispose()
