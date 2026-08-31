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

from sqlalchemy import event
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
    _make_transactions_real(engine)
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        factory = async_sessionmaker(engine, expire_on_commit=False)
        async with factory() as session:
            yield session
    finally:
        await engine.dispose()


def _make_transactions_real(engine) -> None:
    """Give SQLite the transactional behaviour the production database has.

    The pysqlite/aiosqlite driver does not emit BEGIN on its own, so by default
    everything runs in autocommit and SAVEPOINT is a no-op. That silently
    disarms every test of transactional behaviour: a rollback appears to
    succeed while the rows stay committed.

    The two hooks below are SQLAlchemy's documented workaround — take the
    driver's implicit transaction handling out of the way, then emit BEGIN
    ourselves. Without them nothing in this suite can prove that a failed
    request leaves no trace.
    """

    @event.listens_for(engine.sync_engine, "connect")
    def _disable_implicit_begin(dbapi_connection, _record) -> None:  # noqa: ANN001
        dbapi_connection.isolation_level = None

    @event.listens_for(engine.sync_engine, "begin")
    def _emit_begin(conn) -> None:  # noqa: ANN001
        conn.exec_driver_sql("BEGIN")
