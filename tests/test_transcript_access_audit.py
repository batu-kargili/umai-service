"""Transcript access auditing is complete, not just present (UMA-84).

`test_sessions_api.py` proves a read is audited and `test_transcript_retention.py` proves
each deletion is. This file asserts the property those tests assume: that there is no
*other* way for conversation content to leave the service, and that every audit action
the model can record is actually produced by something.

An unaudited egress path is the failure mode here — a future endpoint that returns
transcript bytes without recording who asked would pass every existing test.
"""

from __future__ import annotations

import ast
import asyncio
import datetime as dt
import uuid
from pathlib import Path

import pytest
from sqlalchemy import select

from app.api import sessions
from app.core import transcript_retention as retention
from app.core.errors import ServiceError
from app.models.db import AiSession, Tenant, TranscriptAuditEvent
from tests.conftest import db_session

SERVICE_ROOT = Path(__file__).parents[1]
TENANT = uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
SESSION_KEY = "c" * 64
NOW = dt.datetime(2026, 9, 1, 12, 0, tzinfo=dt.timezone.utc)

# The functions that hand transcript *content* back to a caller. Each one must record a
# read. Adding to this list is a deliberate act; the test below fails if a new caller of
# the transcript store appears outside it.
# Both were found by the check below rather than by reading the code: fetch_transcript
# serves transcript content to the analysis worker and was doing so unaudited.
AUDITED_CONTENT_READERS = {
    "load_transcript": ("app/api/sessions.py", "record_audit_event"),
    "fetch_transcript": ("app/api/analysis.py", "record_audit_event"),
}


# Both idioms the codebase uses to reach the blob store. Narrow on purpose: a bare
# `.get(...)` would also match `session.get(...)` and every dict lookup.
_STORE_NAMES = {"store", "transcript_store"}
_STORE_FACTORIES = {"get_transcript_store", "build_transcript_store"}


def _is_store_read(node: ast.AST) -> bool:
    if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
        return False
    if node.func.attr != "get":
        return False
    receiver = node.func.value
    if isinstance(receiver, ast.Name):
        return receiver.id in _STORE_NAMES
    # get_transcript_store().get(ref)
    if isinstance(receiver, ast.Call) and isinstance(receiver.func, ast.Name):
        return receiver.func.id in _STORE_FACTORIES
    return False


def _store_call_sites() -> dict[str, set[str]]:
    """Every function in app/ that reads bytes out of the transcript store.

    Walks the AST rather than grepping, so a renamed local or a comment mentioning
    `store.get` does not change the answer.
    """
    found: dict[str, set[str]] = {}
    for path in sorted((SERVICE_ROOT / "app").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for inner in ast.walk(node):
                if _is_store_read(inner):
                    found.setdefault(node.name, set()).add(
                        str(path.relative_to(SERVICE_ROOT))
                    )
    return found


class TestContentEgressIsAudited:
    def test_no_unaudited_function_reads_transcript_content(self) -> None:
        readers = _store_call_sites()
        unexpected = sorted(set(readers) - set(AUDITED_CONTENT_READERS))
        assert not unexpected, (
            "these functions read transcript content and must record an audit event, "
            f"then be added to AUDITED_CONTENT_READERS: {unexpected} "
            f"({ {name: sorted(readers[name]) for name in unexpected} })"
        )

    def test_every_known_reader_still_exists(self) -> None:
        """Otherwise the check above passes by finding nothing at all."""
        assert set(_store_call_sites()) == set(AUDITED_CONTENT_READERS)

    @pytest.mark.parametrize(
        ("reader", "module", "recorder"),
        [(name, *where) for name, where in sorted(AUDITED_CONTENT_READERS.items())],
    )
    def test_each_content_reader_records_a_read(
        self, reader: str, module: str, recorder: str
    ) -> None:
        tree = ast.parse((SERVICE_ROOT / module).read_text(encoding="utf-8"))
        node = next(
            candidate
            for candidate in ast.walk(tree)
            if isinstance(candidate, (ast.FunctionDef, ast.AsyncFunctionDef))
            and candidate.name == reader
        )
        called = {
            inner.func.id
            for inner in ast.walk(node)
            if isinstance(inner, ast.Call) and isinstance(inner.func, ast.Name)
        }
        assert recorder in called, f"{module}:{reader} reads content without auditing it"


class TestEveryAuditActionIsProduced:
    """Each action the schema can hold must be written by real code, not just defined."""

    @pytest.mark.parametrize(
        "action",
        [
            retention.ACTION_READ,
            retention.ACTION_DELETE_ON_DEMAND,
            retention.ACTION_DELETE_RETENTION,
        ],
    )
    def test_the_action_appears_in_a_call_site(self, action: str) -> None:
        sources = "".join(
            path.read_text(encoding="utf-8")
            for path in sorted((SERVICE_ROOT / "app").rglob("*.py"))
        )
        constant = {
            retention.ACTION_READ: "ACTION_READ",
            retention.ACTION_DELETE_ON_DEMAND: "ACTION_DELETE_ON_DEMAND",
            retention.ACTION_DELETE_RETENTION: "ACTION_DELETE_RETENTION",
        }[action]
        assert f"action={constant}" in sources

    def test_the_three_actions_are_distinct(self) -> None:
        actions = {
            retention.ACTION_READ,
            retention.ACTION_DELETE_ON_DEMAND,
            retention.ACTION_DELETE_RETENTION,
        }
        assert len(actions) == 3


class TestAuditRowAndEffectAreAtomic:
    """An audit row that survives a rolled-back operation describes something that
    never happened; one that is lost describes access nobody can see."""

    async def _seed(self, db) -> None:
        db.add_all(
            [
                Tenant(tenant_id=TENANT, name="A", collection_mode="full_session"),
                AiSession(
                    tenant_id=TENANT,
                    session_key=SESSION_KEY,
                    source="adr",
                    source_session_id="src-1",
                    observed_at=NOW,
                    ingested_at=NOW,
                    message_count=1,
                    tool_call_count=0,
                    analysis_status="complete",
                    analysis_attempts=1,
                    updated_at=NOW,
                    transcript_ref="a/b/c.json.gz",
                    transcript_sha256="e" * 64,
                    transcript_bytes=10,
                ),
            ]
        )
        await db.commit()

    def test_a_rolled_back_read_leaves_no_audit_row(self) -> None:
        async def run() -> None:
            async with db_session() as db:
                await self._seed(db)
                retention.record_audit_event(
                    db,
                    tenant_id=TENANT,
                    session_key=SESSION_KEY,
                    action=retention.ACTION_READ,
                    actor="operator@example.com",
                )
                await db.rollback()
                rows = (await db.execute(select(TranscriptAuditEvent))).scalars().all()
                assert rows == []

        asyncio.run(run())

    def test_a_committed_read_is_queryable_with_who_and_when(self) -> None:
        async def run() -> None:
            async with db_session() as db:
                await self._seed(db)
                retention.record_audit_event(
                    db,
                    tenant_id=TENANT,
                    session_key=SESSION_KEY,
                    action=retention.ACTION_READ,
                    actor="operator@example.com",
                    now=NOW,
                )
                await db.commit()
                row = (await db.execute(select(TranscriptAuditEvent))).scalars().one()
                assert row.action == retention.ACTION_READ
                assert row.actor == "operator@example.com"
                # SQLite drops tzinfo on read, so compare the instant, not the object.
                assert row.occurred_at.replace(tzinfo=dt.timezone.utc) == NOW
                assert row.tenant_id == TENANT
                assert row.session_key == SESSION_KEY

        asyncio.run(run())

    def test_a_retention_deletion_records_no_actor(self) -> None:
        """Nobody asked; the clock did. An actor here would misattribute the deletion."""

        async def run() -> None:
            async with db_session() as db:
                await self._seed(db)
                retention.record_audit_event(
                    db,
                    tenant_id=TENANT,
                    session_key=SESSION_KEY,
                    action=retention.ACTION_DELETE_RETENTION,
                    reason="retention window elapsed",
                )
                await db.commit()
                row = (await db.execute(select(TranscriptAuditEvent))).scalars().one()
                assert row.actor is None
                assert row.reason

        asyncio.run(run())

    def test_ordering_is_preserved_within_one_second(self) -> None:
        """occurred_at is stamped in Python so two events in the same second keep order."""

        async def run() -> None:
            async with db_session() as db:
                await self._seed(db)
                for offset in range(3):
                    retention.record_audit_event(
                        db,
                        tenant_id=TENANT,
                        session_key=SESSION_KEY,
                        action=retention.ACTION_READ,
                        actor=f"reader-{offset}",
                        now=NOW + dt.timedelta(microseconds=offset),
                    )
                await db.commit()
                rows = (
                    await db.execute(
                        select(TranscriptAuditEvent).order_by(
                            TranscriptAuditEvent.occurred_at
                        )
                    )
                ).scalars().all()
                assert [row.actor for row in rows] == ["reader-0", "reader-1", "reader-2"]

        asyncio.run(run())


class TestDeletionRefusalIsNotAudited:
    def test_a_cross_tenant_delete_writes_nothing(self) -> None:
        """A refused request is not access; recording it would pollute the trail."""

        async def run() -> None:
            async with db_session() as db:
                other = uuid.UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
                db.add(Tenant(tenant_id=other, name="B", collection_mode="metadata"))
                await db.commit()
                result = await sessions.remove_transcript(
                    db,
                    tenant_id=other,
                    session_key=SESSION_KEY,
                    actor="operator@example.com",
                    reason="testing",
                )
                assert result.deleted is False
                rows = (await db.execute(select(TranscriptAuditEvent))).scalars().all()
                assert rows == []

        asyncio.run(run())
