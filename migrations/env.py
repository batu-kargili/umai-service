from __future__ import annotations

import asyncio
import os
import sys
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool
from sqlalchemy.ext.asyncio import async_engine_from_config

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.core.env import load_env  # noqa: E402
from app.models.db import Base  # noqa: E402

load_env()

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def get_database_url() -> str:
    env_url = os.getenv("UMAI_DATABASE_URL")
    if env_url:
        return env_url
    ini_url = config.get_main_option("sqlalchemy.url")
    if ini_url:
        return ini_url
    raise RuntimeError("UMAI_DATABASE_URL is not set")


def run_migrations_offline() -> None:
    url = get_database_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def ensure_version_table_width(connection) -> None:
    """Widen ``alembic_version.version_num`` before Alembic writes to it.

    Alembic creates that column as ``VARCHAR(32)``. One revision id in this
    repo — ``0014_endpoint_sensor_download_sessions`` — is 38 characters, so
    recording it fails on any engine that enforces column length. SQLite does
    not, which is why the chain appears healthy there and breaks the first time
    it runs against PostgreSQL.

    Renaming the revision would be the smaller change, but any database that
    already recorded the long id would then look un-migrated, so the column is
    widened instead. Idempotent, and a no-op on engines that do not enforce
    the limit.
    """
    dialect = connection.dialect.name

    if dialect == "postgresql":
        connection.exec_driver_sql(
            "CREATE TABLE IF NOT EXISTS alembic_version ("
            "version_num VARCHAR(128) NOT NULL, "
            "CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num))"
        )
        connection.exec_driver_sql(
            "ALTER TABLE alembic_version ALTER COLUMN version_num TYPE VARCHAR(128)"
        )


def do_run_migrations(connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    url = get_database_url()
    connectable = async_engine_from_config(
        {"sqlalchemy.url": url},
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    # Widen the version table on its own transaction, before Alembic opens the
    # migration connection. Running DDL on the migration connection first puts
    # it in an implicit transaction, which turns Alembic's own
    # ``begin_transaction()`` into a no-op — migrations then appear to succeed
    # and silently roll back.
    async with connectable.begin() as connection:
        await connection.run_sync(ensure_version_table_width)

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
