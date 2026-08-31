from __future__ import annotations

import datetime as dt
import unittest
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.core.app_catalog import build_matcher, reset_catalog_memo, vendor_catalog_from_apps
from app.core.app_catalog import load_enabled_applications
from app.core.usage_sessions import fold_event_into_session
from app.models.db import AiUsageSession, Base

T0 = dt.datetime(2026, 7, 1, 9, 0, 0, tzinfo=dt.timezone.utc)


class UsageSessionTests(unittest.IsolatedAsyncioTestCase):
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

    async def _fold(self, session, memo, **overrides):
        matcher = overrides.pop("matcher")
        defaults = dict(
            tenant_id=self.tenant_id,
            matcher=matcher,
            batch_memo=memo,
            source="sensor",
            event_type="vendor_connection_observed",
            host="chatgpt.com",
            port=443,
            process_name="chrome.exe",
            user_email="user@smarttech.com",
            user_idp_subject=None,
            device_id="device-1",
            captured_at=T0,
            dlp_hit=False,
        )
        defaults.update(overrides)
        return await fold_event_into_session(session, **defaults)

    async def _all_sessions(self, session) -> list[AiUsageSession]:
        result = await session.execute(
            select(AiUsageSession).where(AiUsageSession.tenant_id == self.tenant_id)
        )
        return list(result.scalars().all())

    async def test_events_within_gap_merge_into_one_session(self) -> None:
        async with self.sessionmaker() as session:
            async with session.begin():
                matcher = await build_matcher(session, self.tenant_id)
                memo: dict = {}
                first = await self._fold(session, memo, matcher=matcher, captured_at=T0)
                second = await self._fold(
                    session,
                    memo,
                    matcher=matcher,
                    captured_at=T0 + dt.timedelta(minutes=10),
                )
                self.assertEqual(first, second)
                rows = await self._all_sessions(session)
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0].event_count, 2)
                self.assertEqual(rows[0].app_slug, "chatgpt")
                self.assertEqual(rows[0].session_type, "web")

    async def test_gap_timeout_splits_sessions(self) -> None:
        async with self.sessionmaker() as session:
            async with session.begin():
                matcher = await build_matcher(session, self.tenant_id)
                first = await self._fold(session, {}, matcher=matcher, captured_at=T0)
                second = await self._fold(
                    session,
                    {},
                    matcher=matcher,
                    captured_at=T0 + dt.timedelta(minutes=45),
                )
                self.assertNotEqual(first, second)
                rows = await self._all_sessions(session)
                self.assertEqual(len(rows), 2)

    async def test_out_of_order_event_extends_started_at(self) -> None:
        async with self.sessionmaker() as session:
            async with session.begin():
                matcher = await build_matcher(session, self.tenant_id)
                memo: dict = {}
                await self._fold(session, memo, matcher=matcher, captured_at=T0)
                await self._fold(
                    session,
                    memo,
                    matcher=matcher,
                    captured_at=T0 - dt.timedelta(minutes=5),
                )
                rows = await self._all_sessions(session)
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0].started_at, T0 - dt.timedelta(minutes=5))
                self.assertEqual(rows[0].last_activity_at, T0)

    async def test_synthetic_heartbeat_is_excluded(self) -> None:
        async with self.sessionmaker() as session:
            async with session.begin():
                matcher = await build_matcher(session, self.tenant_id)
                result = await self._fold(
                    session,
                    {},
                    matcher=matcher,
                    event_type="synthetic_heartbeat",
                    host="synthetic.umai.local",
                )
                self.assertIsNone(result)
                self.assertEqual(await self._all_sessions(session), [])

    async def test_unmatched_sensor_traffic_creates_no_session(self) -> None:
        async with self.sessionmaker() as session:
            async with session.begin():
                matcher = await build_matcher(session, self.tenant_id)
                result = await self._fold(
                    session,
                    {},
                    matcher=matcher,
                    host="totally-unrelated.example.com",
                    process_name="svchost.exe",
                )
                self.assertIsNone(result)
                self.assertEqual(await self._all_sessions(session), [])

    async def test_unmatched_extension_traffic_folds_into_unclassified(self) -> None:
        async with self.sessionmaker() as session:
            async with session.begin():
                matcher = await build_matcher(session, self.tenant_id)
                result = await self._fold(
                    session,
                    {},
                    matcher=matcher,
                    source="extension",
                    host="new-ai-tool.example.com",
                    process_name=None,
                    port=None,
                )
                self.assertIsNotNone(result)
                rows = await self._all_sessions(session)
                self.assertEqual(len(rows), 1)
                self.assertIsNone(rows[0].app_slug)
                self.assertEqual(rows[0].session_type, "web")

    async def test_desktop_process_creates_desktop_session(self) -> None:
        async with self.sessionmaker() as session:
            async with session.begin():
                matcher = await build_matcher(session, self.tenant_id)
                await self._fold(
                    session,
                    {},
                    matcher=matcher,
                    host="api.anthropic.com",
                    process_name="Claude.exe",
                )
                rows = await self._all_sessions(session)
                self.assertEqual(rows[0].app_slug, "claude")
                self.assertEqual(rows[0].session_type, "desktop")

    async def test_claude_code_cli_distinguished_from_claude_desktop_by_path(self) -> None:
        async with self.sessionmaker() as session:
            async with session.begin():
                matcher = await build_matcher(session, self.tenant_id)
                await self._fold(
                    session,
                    {},
                    matcher=matcher,
                    host="api.anthropic.com",
                    process_name="claude.exe",
                    process_path=(
                        r"C:\Users\batuk\AppData\Roaming\Claude\claude-code\2.1.197\claude.exe"
                    ),
                )
                rows = await self._all_sessions(session)
                self.assertEqual(rows[0].app_slug, "claude-code")
                self.assertEqual(rows[0].session_type, "desktop")

    async def test_claude_exe_without_path_hint_falls_back_to_desktop(self) -> None:
        async with self.sessionmaker() as session:
            async with session.begin():
                matcher = await build_matcher(session, self.tenant_id)
                await self._fold(
                    session,
                    {},
                    matcher=matcher,
                    host="api.anthropic.com",
                    process_name="Claude.exe",
                    process_path=(
                        r"C:\Program Files\WindowsApps\Claude_1.0.0_x64__abc\app\Claude.exe"
                    ),
                )
                rows = await self._all_sessions(session)
                self.assertEqual(rows[0].app_slug, "claude")

    async def test_dlp_hits_are_counted(self) -> None:
        async with self.sessionmaker() as session:
            async with session.begin():
                matcher = await build_matcher(session, self.tenant_id)
                memo: dict = {}
                await self._fold(session, memo, matcher=matcher, dlp_hit=True)
                await self._fold(
                    session,
                    memo,
                    matcher=matcher,
                    captured_at=T0 + dt.timedelta(minutes=1),
                    dlp_hit=True,
                )
                await self._fold(
                    session,
                    memo,
                    matcher=matcher,
                    captured_at=T0 + dt.timedelta(minutes=2),
                )
                rows = await self._all_sessions(session)
                self.assertEqual(rows[0].dlp_hit_count, 2)
                self.assertEqual(rows[0].event_count, 3)

    async def test_tenant_isolation_between_matchers(self) -> None:
        other_tenant = uuid.uuid4()
        async with self.sessionmaker() as session:
            async with session.begin():
                matcher = await build_matcher(session, self.tenant_id)
                await self._fold(session, {}, matcher=matcher)
                other_matcher = await build_matcher(session, other_tenant)
                await fold_event_into_session(
                    session,
                    tenant_id=other_tenant,
                    matcher=other_matcher,
                    batch_memo={},
                    source="sensor",
                    event_type="vendor_connection_observed",
                    host="chatgpt.com",
                    port=443,
                    process_name="chrome.exe",
                    user_email="user@smarttech.com",
                    user_idp_subject=None,
                    device_id="device-1",
                    captured_at=T0,
                    dlp_hit=False,
                )
                mine = await self._all_sessions(session)
                self.assertEqual(len(mine), 1)
                result = await session.execute(
                    select(AiUsageSession).where(AiUsageSession.tenant_id == other_tenant)
                )
                self.assertEqual(len(list(result.scalars().all())), 1)

    async def test_local_model_port_matches_inventory_app(self) -> None:
        async with self.sessionmaker() as session:
            async with session.begin():
                matcher = await build_matcher(session, self.tenant_id)
                await self._fold(
                    session,
                    {},
                    matcher=matcher,
                    event_type="local_model_connection",
                    host="127.0.0.1",
                    port=11434,
                    process_name="Ollama.exe",
                )
                rows = await self._all_sessions(session)
                self.assertEqual(rows[0].app_slug, "ollama")

    async def test_vendor_catalog_projection_matches_rust_shape(self) -> None:
        async with self.sessionmaker() as session:
            async with session.begin():
                matcher = await build_matcher(session, self.tenant_id)
                self.assertIsNotNone(matcher)
                rows = await load_enabled_applications(session, self.tenant_id)
        catalog = vendor_catalog_from_apps(rows)
        self.assertTrue(catalog)
        by_id = {entry["id"]: entry for entry in catalog}
        self.assertIn("chatgpt", by_id)
        self.assertEqual(by_id["chatgpt"]["match_strategy"], "sni")
        self.assertTrue(by_id["chatgpt"]["capture"])
        self.assertIn("ollama", by_id)
        self.assertEqual(by_id["ollama"]["match_strategy"], "port")
        self.assertFalse(by_id["ollama"]["capture"])
        self.assertTrue(by_id["ollama"]["inventory_only"])
        for entry in catalog:
            self.assertIsInstance(entry["id"], str)
            self.assertIsInstance(entry["display_name"], str)
            self.assertIsInstance(entry["domains"], list)


if __name__ == "__main__":
    unittest.main()
