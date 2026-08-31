"""Backfill ai_usage_sessions from existing sensor and extension events.

Replays historical events per tenant through the same sessionizer used at
ingest, and stamps session_id back onto the raw event rows.

Usage:
    python scripts/backfill_usage_sessions.py --tenant-id <uuid> [--force]

--force deletes the tenant's existing sessions (and clears event session_id)
before rebuilding; without it the script refuses to run if sessions exist.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
import uuid
from pathlib import Path
from urllib.parse import urlsplit

from sqlalchemy import delete, select, update

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.core.app_catalog import build_matcher
from app.core.db import get_sessionmaker, tenant_scope
from app.core.usage_sessions import fold_event_into_session
from app.models.db import AiUsageSession, BrowserExtensionEvent, EndpointSensorEvent

logger = logging.getLogger("umai.service.backfill_usage_sessions")

PAGE_SIZE = 5000


def _host_from_url(url: str | None) -> str | None:
    if not url:
        return None
    try:
        hostname = urlsplit(url).hostname
    except ValueError:
        return None
    return hostname or None


async def _backfill_tenant(tenant_id: uuid.UUID, force: bool) -> None:
    sessionmaker = get_sessionmaker()
    async with sessionmaker() as session:
        async with session.begin():
            async with tenant_scope(session, str(tenant_id)):
                existing = await session.execute(
                    select(AiUsageSession.id)
                    .where(AiUsageSession.tenant_id == tenant_id)
                    .limit(1)
                )
                if existing.scalars().first() is not None:
                    if not force:
                        raise SystemExit(
                            "Tenant already has usage sessions; re-run with --force to rebuild."
                        )
                    logger.info("Deleting existing sessions for tenant %s", tenant_id)
                    await session.execute(
                        delete(AiUsageSession).where(AiUsageSession.tenant_id == tenant_id)
                    )
                    await session.execute(
                        update(EndpointSensorEvent)
                        .where(EndpointSensorEvent.tenant_id == tenant_id)
                        .values(session_id=None)
                    )
                    await session.execute(
                        update(BrowserExtensionEvent)
                        .where(BrowserExtensionEvent.tenant_id == tenant_id)
                        .values(session_id=None)
                    )

        total_sensor = await _replay_sensor_events(sessionmaker, tenant_id)
        total_extension = await _replay_extension_events(sessionmaker, tenant_id)
        logger.info(
            "Backfill complete tenant=%s sensor_events=%d extension_events=%d",
            tenant_id,
            total_sensor,
            total_extension,
        )


async def _replay_sensor_events(sessionmaker, tenant_id: uuid.UUID) -> int:
    processed = 0
    offset = 0
    while True:
        async with sessionmaker() as session:
            async with session.begin():
                async with tenant_scope(session, str(tenant_id)):
                    matcher = await build_matcher(session, tenant_id)
                    memo: dict = {}
                    result = await session.execute(
                        select(EndpointSensorEvent)
                        .where(EndpointSensorEvent.tenant_id == tenant_id)
                        .order_by(
                            EndpointSensorEvent.device_id.asc(),
                            EndpointSensorEvent.captured_at.asc(),
                            EndpointSensorEvent.event_id.asc(),
                        )
                        .offset(offset)
                        .limit(PAGE_SIZE)
                    )
                    rows = result.scalars().all()
                    for row in rows:
                        row.session_id = await fold_event_into_session(
                            session,
                            tenant_id=tenant_id,
                            matcher=matcher,
                            batch_memo=memo,
                            source="sensor",
                            event_type=row.event_type,
                            host=row.destination_sni or row.destination_host,
                            port=row.destination_port,
                            process_name=row.process_name,
                            process_path=row.process_path,
                            user_email=row.user_email,
                            user_idp_subject=row.user_idp_subject,
                            device_id=row.device_id,
                            captured_at=row.captured_at,
                            dlp_hit=bool(row.dlp_tags_json and row.dlp_tags_json != "[]"),
                        )
                    processed += len(rows)
        if len(rows) < PAGE_SIZE:
            return processed
        offset += PAGE_SIZE


async def _replay_extension_events(sessionmaker, tenant_id: uuid.UUID) -> int:
    processed = 0
    offset = 0
    while True:
        async with sessionmaker() as session:
            async with session.begin():
                async with tenant_scope(session, str(tenant_id)):
                    matcher = await build_matcher(session, tenant_id)
                    memo: dict = {}
                    result = await session.execute(
                        select(BrowserExtensionEvent)
                        .where(BrowserExtensionEvent.tenant_id == tenant_id)
                        .order_by(
                            BrowserExtensionEvent.device_id.asc(),
                            BrowserExtensionEvent.captured_at.asc(),
                            BrowserExtensionEvent.event_id.asc(),
                        )
                        .offset(offset)
                        .limit(PAGE_SIZE)
                    )
                    rows = result.scalars().all()
                    for row in rows:
                        row.session_id = await fold_event_into_session(
                            session,
                            tenant_id=tenant_id,
                            matcher=matcher,
                            batch_memo=memo,
                            source="extension",
                            event_type=row.event_type,
                            host=_host_from_url(row.url) or row.site,
                            port=None,
                            process_name=None,
                            user_email=row.user_email,
                            user_idp_subject=row.user_idp_subject,
                            device_id=row.device_id,
                            captured_at=row.captured_at,
                            dlp_hit=False,
                        )
                    processed += len(rows)
        if len(rows) < PAGE_SIZE:
            return processed
        offset += PAGE_SIZE


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tenant-id", required=True, type=uuid.UUID)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    asyncio.run(_backfill_tenant(args.tenant_id, args.force))


if __name__ == "__main__":
    main()
