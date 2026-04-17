from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.settings import settings

_engine: AsyncEngine | None = None
_sessionmaker: async_sessionmaker[AsyncSession] | None = None


def get_engine() -> AsyncEngine:
    global _engine
    if _engine is None:
        if not settings.database_url:
            raise RuntimeError("DUVARAI_DATABASE_URL is not set")
        drivername = make_url(settings.database_url).drivername.lower()
        engine_kwargs: dict[str, object] = {
            "pool_pre_ping": True,
            "pool_size": settings.database_pool_size,
            "max_overflow": settings.database_max_overflow,
        }
        connect_timeout = settings.database_connect_timeout_seconds
        if connect_timeout:
            connect_args: dict[str, object] = {}
            if drivername == "postgresql+asyncpg":
                connect_args["timeout"] = connect_timeout
            elif drivername == "oracle+oracledb_async":
                connect_args["tcp_connect_timeout"] = connect_timeout
            if connect_args:
                engine_kwargs["connect_args"] = connect_args
        _engine = create_async_engine(settings.database_url, **engine_kwargs)
    return _engine


def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    global _sessionmaker
    if _sessionmaker is None:
        _sessionmaker = async_sessionmaker(get_engine(), expire_on_commit=False)
    return _sessionmaker


async def get_session() -> AsyncIterator[AsyncSession]:
    session_maker = get_sessionmaker()
    async with session_maker() as session:
        yield session


async def set_tenant_context(session: AsyncSession, tenant_id: str) -> None:
    dialect = session.get_bind().dialect.name

    if dialect.startswith("mssql"):
        await session.execute(
            text("EXEC sp_set_session_context @key=N'tenant_id', @value=:tenant_id"),
            {"tenant_id": tenant_id},
        )
        return

    if dialect == "postgresql":
        await session.execute(
            text("SELECT set_config('app.tenant_id', :tenant_id, false)"),
            {"tenant_id": tenant_id},
        )
        return
    # Other dialects rely on explicit tenant_id filters in queries for now.
    return


async def clear_tenant_context(session: AsyncSession) -> None:
    dialect = session.get_bind().dialect.name

    if dialect.startswith("mssql"):
        await session.execute(
            text("EXEC sp_set_session_context @key=N'tenant_id', @value=NULL")
        )
        return

    if dialect == "postgresql":
        await session.execute(text("SELECT set_config('app.tenant_id', '', false)"))
        return
    # Other dialects rely on explicit tenant_id filters in queries for now.
    return


@asynccontextmanager
async def tenant_scope(session: AsyncSession, tenant_id: str) -> AsyncIterator[None]:
    await set_tenant_context(session, tenant_id)
    try:
        yield
    finally:
        await clear_tenant_context(session)
