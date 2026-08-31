from __future__ import annotations

import datetime as dt
import unittest
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.api.applications import UNCLASSIFIED_SLUG, _collect_dashboard
from app.core.app_catalog import ensure_tenant_catalog, reset_catalog_memo
from app.models.db import AiApplication, AiUsageSession, Base

NOW = dt.datetime.now(dt.timezone.utc)


def _session_row(
    tenant_id: uuid.UUID,
    *,
    app_slug: str | None,
    started_at: dt.datetime,
    user_key: str = "user@smarttech.com",
    device_id: str = "device-1",
    session_type: str = "web",
    source: str = "sensor",
    dlp_hit_count: int = 0,
) -> AiUsageSession:
    return AiUsageSession(
        tenant_id=tenant_id,
        id=uuid.uuid4(),
        app_id=None,
        app_slug=app_slug,
        user_key=user_key,
        device_id=device_id,
        source=source,
        session_type=session_type,
        started_at=started_at,
        last_activity_at=started_at + dt.timedelta(minutes=5),
        event_count=3,
        dlp_hit_count=dlp_hit_count,
        created_at=started_at,
    )


class ApplicationsDashboardTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        reset_catalog_memo()
        self.engine = create_async_engine("sqlite+aiosqlite://")
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        self.sessionmaker = async_sessionmaker(self.engine, expire_on_commit=False)
        self.tenant_id = uuid.uuid4()

    async def asyncTearDown(self) -> None:
        await self.engine.dispose()
        reset_catalog_memo()

    async def test_dashboard_aggregates_sessions_users_and_sensitive_counts(self) -> None:
        async with self.sessionmaker() as session:
            async with session.begin():
                await ensure_tenant_catalog(session, self.tenant_id)
                session.add(
                    _session_row(
                        self.tenant_id,
                        app_slug="chatgpt",
                        started_at=NOW - dt.timedelta(days=1),
                        dlp_hit_count=2,
                    )
                )
                session.add(
                    _session_row(
                        self.tenant_id,
                        app_slug="chatgpt",
                        started_at=NOW - dt.timedelta(days=2),
                        user_key="other@smarttech.com",
                        session_type="desktop",
                    )
                )
                session.add(
                    _session_row(
                        self.tenant_id,
                        app_slug="claude",
                        started_at=NOW - dt.timedelta(days=3),
                    )
                )

        async with self.sessionmaker() as session:
            async with session.begin():
                dashboard = await _collect_dashboard(session, self.tenant_id, 30)

        self.assertEqual(dashboard.total_sessions, 3)
        by_slug = {app.slug: app for app in dashboard.apps}
        chatgpt = by_slug["chatgpt"]
        self.assertEqual(chatgpt.sessions, 2)
        self.assertEqual(chatgpt.unique_users, 2)
        self.assertEqual(chatgpt.sensitive_count, 2)
        self.assertEqual(chatgpt.types, ["Desktop", "Web"])
        self.assertEqual(chatgpt.category, "llm_chat")
        self.assertTrue(chatgpt.is_training)
        # Highest session count first.
        self.assertEqual(dashboard.apps[0].slug, "chatgpt")

    async def test_pct_change_compares_previous_window(self) -> None:
        async with self.sessionmaker() as session:
            async with session.begin():
                await ensure_tenant_catalog(session, self.tenant_id)
                for offset_days in (1, 2, 3):
                    session.add(
                        _session_row(
                            self.tenant_id,
                            app_slug="chatgpt",
                            started_at=NOW - dt.timedelta(days=offset_days),
                        )
                    )
                # Previous window (7-14 days ago): 2 sessions -> +50%.
                for offset_days in (8, 9):
                    session.add(
                        _session_row(
                            self.tenant_id,
                            app_slug="chatgpt",
                            started_at=NOW - dt.timedelta(days=offset_days),
                        )
                    )

        async with self.sessionmaker() as session:
            async with session.begin():
                dashboard = await _collect_dashboard(session, self.tenant_id, 7)

        chatgpt = next(app for app in dashboard.apps if app.slug == "chatgpt")
        self.assertEqual(chatgpt.sessions, 3)
        self.assertEqual(chatgpt.pct_change, 50.0)

    async def test_pct_change_is_none_without_previous_data(self) -> None:
        async with self.sessionmaker() as session:
            async with session.begin():
                await ensure_tenant_catalog(session, self.tenant_id)
                session.add(
                    _session_row(
                        self.tenant_id,
                        app_slug="claude",
                        started_at=NOW - dt.timedelta(days=1),
                    )
                )

        async with self.sessionmaker() as session:
            async with session.begin():
                dashboard = await _collect_dashboard(session, self.tenant_id, 7)

        claude = next(app for app in dashboard.apps if app.slug == "claude")
        self.assertIsNone(claude.pct_change)

    async def test_risk_distribution_and_category_totals_count_sessions(self) -> None:
        async with self.sessionmaker() as session:
            async with session.begin():
                await ensure_tenant_catalog(session, self.tenant_id)
                session.add(
                    _session_row(
                        self.tenant_id,
                        app_slug="chatgpt",  # llm_chat / high
                        started_at=NOW - dt.timedelta(days=1),
                    )
                )
                session.add(
                    _session_row(
                        self.tenant_id,
                        app_slug="perplexity",  # ai_search / high
                        started_at=NOW - dt.timedelta(days=1),
                    )
                )
                session.add(
                    _session_row(
                        self.tenant_id,
                        app_slug="grammarly",  # productivity / none
                        started_at=NOW - dt.timedelta(days=1),
                    )
                )

        async with self.sessionmaker() as session:
            async with session.begin():
                dashboard = await _collect_dashboard(session, self.tenant_id, 30)

        self.assertEqual(dashboard.risk_distribution["high"], 2)
        self.assertEqual(dashboard.risk_distribution["none"], 1)
        self.assertEqual(dashboard.risk_distribution["critical"], 0)
        categories = {item.category: item for item in dashboard.category_totals}
        self.assertEqual(categories["llm_chat"].sessions, 1)
        self.assertEqual(categories["ai_search"].sessions, 1)
        self.assertEqual(categories["productivity"].sessions, 1)

    async def test_trend_is_zero_filled_for_full_window(self) -> None:
        async with self.sessionmaker() as session:
            async with session.begin():
                await ensure_tenant_catalog(session, self.tenant_id)
                session.add(
                    _session_row(
                        self.tenant_id,
                        app_slug="chatgpt",
                        started_at=NOW - dt.timedelta(days=1),
                    )
                )

        async with self.sessionmaker() as session:
            async with session.begin():
                dashboard = await _collect_dashboard(session, self.tenant_id, 7)

        chatgpt = next(app for app in dashboard.apps if app.slug == "chatgpt")
        self.assertEqual(len(chatgpt.trend), 7)
        self.assertEqual(sum(point.sessions for point in chatgpt.trend), 1)

    async def test_unclassified_sessions_surface_as_unclassified_row(self) -> None:
        async with self.sessionmaker() as session:
            async with session.begin():
                await ensure_tenant_catalog(session, self.tenant_id)
                session.add(
                    _session_row(
                        self.tenant_id,
                        app_slug=None,
                        started_at=NOW - dt.timedelta(days=1),
                        source="extension",
                    )
                )

        async with self.sessionmaker() as session:
            async with session.begin():
                dashboard = await _collect_dashboard(session, self.tenant_id, 30)

        self.assertEqual(dashboard.apps[0].slug, UNCLASSIFIED_SLUG)
        self.assertEqual(dashboard.apps[0].name, "Unclassified")

    async def test_dashboard_is_tenant_isolated(self) -> None:
        other_tenant = uuid.uuid4()
        async with self.sessionmaker() as session:
            async with session.begin():
                await ensure_tenant_catalog(session, self.tenant_id)
                await ensure_tenant_catalog(session, other_tenant)
                session.add(
                    _session_row(
                        other_tenant,
                        app_slug="chatgpt",
                        started_at=NOW - dt.timedelta(days=1),
                    )
                )

        async with self.sessionmaker() as session:
            async with session.begin():
                dashboard = await _collect_dashboard(session, self.tenant_id, 30)

        self.assertEqual(dashboard.total_sessions, 0)
        self.assertEqual(dashboard.apps, [])

    async def test_builtin_seed_catalog_is_idempotent(self) -> None:
        async with self.sessionmaker() as session:
            async with session.begin():
                await ensure_tenant_catalog(session, self.tenant_id)
        reset_catalog_memo()
        async with self.sessionmaker() as session:
            async with session.begin():
                await ensure_tenant_catalog(session, self.tenant_id)
                result = await session.execute(
                    select(AiApplication.slug).where(AiApplication.tenant_id == self.tenant_id)
                )
                slugs = list(result.scalars().all())
        self.assertEqual(len(slugs), len(set(slugs)))


if __name__ == "__main__":
    unittest.main()
