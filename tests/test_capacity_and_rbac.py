"""Retention cleanup and least-privilege roles (UMA-93).

Three things are covered, and each exists because the current behaviour was wrong in a
way that produces no error.

**Retention starvation.** The transcript sweep selected the oldest rows and then skipped
the ones inside their window. A tenant keeping content for a year fills every batch with
rows that are old but not expired, so a second tenant's seven-day content sits behind
them and is never reached. The sweep runs, deletes nothing, reports success, and the
retention promise quietly stops being kept.

**An outbox nothing pruned.** Delivered rows were kept for the life of the deployment,
each carrying the full finding payload. It is the fastest-growing table the platform owns
and the only one whose contents are pure duplication.

**Flat roles.** `require_admin_role(principal, "tenant-auditor")` demanded that exact
string, so a tenant-admin — who may create a guardrail — could not list guardrails. It is
invisible while admin auth grants every role in network-trust mode, and appears the first
time a deployment turns JWT enforcement on, as the console failing every read.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import uuid

import pytest

from app.api import admin
from app.core.admin_auth import AdminPrincipal, effective_roles, require_admin_role
from app.core.errors import ServiceError
from app.core.metrics import registry
from app.core.pipeline_metrics import (
    RETENTION_DELETED,
    RETENTION_LAST_SUCCESS_AGE,
    RETENTION_SWEEPS,
    reset_retention_state,
    sample_pipeline,
)
from app.core.siem_drain import prune_delivered
from app.core.siem_outbox import STATUS_DEAD_LETTER, STATUS_DELIVERED, STATUS_PENDING
from app.core.transcript_retention import reap_expired_transcripts
from app.models.db import SiemOutbox
from tests.conftest import db_session
from tests.test_transcript_retention import NOW, OTHER_TENANT, TENANT, _RecordingStore, _seed


class TestRetentionDoesNotStarve:
    def test_a_long_window_tenant_does_not_block_a_short_window_one(self) -> None:
        """The failure is silent: the sweep runs, deletes nothing, and reports success."""

        async def scenario():
            store = _RecordingStore()
            async with db_session() as db:
                for index in range(5):
                    await _seed(
                        db,
                        tenant_id=TENANT,
                        session_key=f"a-{index}",
                        observed_at=NOW - dt.timedelta(days=200 - index),
                        transcript_ref=f"ref-a{index}",
                        retention_days=365,
                    )
                await _seed(
                    db,
                    tenant_id=OTHER_TENANT,
                    session_key="b-0",
                    observed_at=NOW - dt.timedelta(days=30),
                    transcript_ref="ref-b0",
                    retention_days=7,
                )
                await db.commit()
                # A batch smaller than the first tenant's backlog of unexpired rows.
                result = await reap_expired_transcripts(db, store=store, now=NOW, limit=3)
                return result, store

        result, store = asyncio.run(scenario())
        assert store.deleted == ["ref-b0"]
        assert result.deleted == 1

    def test_the_sweep_only_scans_rows_it_can_delete(self) -> None:
        """Scanning unexpired rows is what wasted the batch in the first place."""

        async def scenario():
            async with db_session() as db:
                await _seed(
                    db,
                    session_key="young",
                    observed_at=NOW - dt.timedelta(days=1),
                    transcript_ref="ref-young",
                    retention_days=30,
                )
                await db.commit()
                return await reap_expired_transcripts(db, store=_RecordingStore(), now=NOW)

        result = asyncio.run(scenario())
        assert result.scanned == 0
        assert result.deleted == 0
        assert result.disputed == 0

    def test_a_session_whose_tenant_row_is_gone_still_expires(self) -> None:
        """Otherwise an orphaned session keeps its content forever."""

        async def scenario():
            store = _RecordingStore()
            async with db_session() as db:
                await _seed(
                    db,
                    session_key="orphan",
                    observed_at=NOW - dt.timedelta(days=90),
                    transcript_ref="ref-orphan",
                    with_tenant=False,
                )
                await db.commit()
                return await reap_expired_transcripts(db, store=store, now=NOW), store

        result, store = asyncio.run(scenario())
        assert result.deleted == 1
        assert store.deleted == ["ref-orphan"]


class TestRetentionIsObservable:
    def setup_method(self) -> None:
        registry.reset()
        reset_retention_state()

    def test_a_sweep_that_deletes_nothing_still_reports_that_it_ran(self) -> None:
        """A sweep with nothing due and a sweep that has stopped look identical
        in the deletion counter. Only the completion record separates them."""

        async def scenario():
            async with db_session() as db:
                await _seed(db, observed_at=NOW - dt.timedelta(days=1))
                await db.commit()
                await reap_expired_transcripts(db, store=_RecordingStore(), now=NOW)

        asyncio.run(scenario())
        assert registry.counter_value(RETENTION_SWEEPS, {"resource": "transcript", "outcome": "ok"}) == 1
        assert registry.counter_value(RETENTION_DELETED, {"resource": "transcript"}) == 0

    def test_deletions_are_counted(self) -> None:
        async def scenario():
            async with db_session() as db:
                await _seed(db, observed_at=NOW - dt.timedelta(days=90))
                await db.commit()
                await reap_expired_transcripts(db, store=_RecordingStore(), now=NOW)

        asyncio.run(scenario())
        assert registry.counter_value(RETENTION_DELETED, {"resource": "transcript"}) == 1

    def test_the_age_of_the_last_sweep_is_published(self) -> None:
        async def scenario():
            async with db_session() as db:
                await _seed(db, observed_at=NOW - dt.timedelta(days=90))
                await db.commit()
                await reap_expired_transcripts(db, store=_RecordingStore(), now=NOW)
                await sample_pipeline(db, now=NOW + dt.timedelta(seconds=300))

        asyncio.run(scenario())
        assert registry.gauge_value(
            RETENTION_LAST_SUCCESS_AGE, {"resource": "transcript"}
        ) == pytest.approx(300, abs=2)

    def test_a_sweep_that_never_ran_publishes_no_age(self) -> None:
        """A zero would read as 'just completed', which is the opposite of the truth.

        The alert keys on the series being absent, so it has to actually be absent from
        what /metrics renders — not present with a value that happens to be zero.
        """

        async def scenario():
            async with db_session() as db:
                await sample_pipeline(db, now=NOW)

        asyncio.run(scenario())
        rendered = [
            line
            for line in registry.render().splitlines()
            if line.startswith(RETENTION_LAST_SUCCESS_AGE)
        ]
        assert rendered == []


def _outbox(status: str, delivered_at: dt.datetime | None, event_id: str) -> SiemOutbox:
    return SiemOutbox(
        id=uuid.uuid4(),
        tenant_id=TENANT,
        event_id=event_id,
        event_schema="umai.finding.v1",
        payload_json="{}",
        status=status,
        attempts=1,
        delivered_at=delivered_at,
        created_at=NOW - dt.timedelta(days=60),
    )


class TestOutboxPruning:
    def setup_method(self) -> None:
        registry.reset()

    def _prune(self, rows, **kwargs) -> tuple[int, list[str]]:
        async def scenario():
            async with db_session() as db:
                for row in rows:
                    db.add(row)
                await db.commit()
                deleted = await prune_delivered(db, now=NOW, **kwargs)
                from sqlalchemy import select

                remaining = [
                    row.event_id
                    for row in (await db.execute(select(SiemOutbox))).scalars().all()
                ]
                return deleted, sorted(remaining)

        return asyncio.run(scenario())

    def test_an_old_delivered_row_is_removed(self) -> None:
        deleted, remaining = self._prune(
            [_outbox(STATUS_DELIVERED, NOW - dt.timedelta(days=30), "old")],
            retention_days=7,
        )
        assert deleted == 1
        assert remaining == []

    def test_a_recently_delivered_row_is_kept(self) -> None:
        deleted, remaining = self._prune(
            [_outbox(STATUS_DELIVERED, NOW - dt.timedelta(days=1), "fresh")],
            retention_days=7,
        )
        assert deleted == 0
        assert remaining == ["fresh"]

    def test_pending_and_dead_letter_rows_are_never_pruned(self) -> None:
        """A dead letter is a finding the SOC has never seen. Losing one to a
        cleanup job is losing a security event."""
        deleted, remaining = self._prune(
            [
                _outbox(STATUS_PENDING, None, "pending"),
                _outbox(STATUS_DEAD_LETTER, None, "dead"),
                _outbox(STATUS_DELIVERED, NOW - dt.timedelta(days=30), "old"),
            ],
            retention_days=7,
        )
        assert deleted == 1
        assert remaining == ["dead", "pending"]

    def test_pruning_is_idempotent(self) -> None:
        async def scenario():
            async with db_session() as db:
                db.add(_outbox(STATUS_DELIVERED, NOW - dt.timedelta(days=30), "old"))
                await db.commit()
                first = await prune_delivered(db, now=NOW, retention_days=7)
                second = await prune_delivered(db, now=NOW, retention_days=7)
                return first, second

        first, second = asyncio.run(scenario())
        assert (first, second) == (1, 0)

    def test_zero_retention_days_keeps_everything(self) -> None:
        """The pre-UMA-93 behaviour stays reachable rather than being removed."""
        deleted, remaining = self._prune(
            [_outbox(STATUS_DELIVERED, NOW - dt.timedelta(days=3650), "ancient")],
            retention_days=0,
        )
        assert deleted == 0
        assert remaining == ["ancient"]

    def test_the_prune_is_counted_as_a_retention_sweep(self) -> None:
        self._prune(
            [_outbox(STATUS_DELIVERED, NOW - dt.timedelta(days=30), "old")], retention_days=7
        )
        assert registry.counter_value(RETENTION_DELETED, {"resource": "siem_outbox"}) == 1
        assert (
            registry.counter_value(RETENTION_SWEEPS, {"resource": "siem_outbox", "outcome": "ok"})
            == 1
        )


class TestLeastPrivilegeRoles:
    """One case per (role, operation) pair the deployment actually issues."""

    AUDITOR = AdminPrincipal(TENANT, ["tenant-auditor"], "auditor@example.com")
    ADMIN = AdminPrincipal(TENANT, ["tenant-admin"], "admin@example.com")
    PLATFORM = AdminPrincipal(None, ["platform-admin"], "platform@example.com")
    LICENCE = AdminPrincipal(TENANT, ["license-admin"], "licence@example.com")

    def test_an_admin_can_read_what_it_is_allowed_to_write(self) -> None:
        admin._require_tenant_access(self.ADMIN, TENANT, required_role="tenant-auditor")

    def test_a_platform_admin_can_read_a_tenant(self) -> None:
        admin._require_tenant_access(self.PLATFORM, TENANT, required_role="tenant-auditor")

    def test_a_platform_admin_can_write_to_a_tenant(self) -> None:
        admin._require_tenant_access(self.PLATFORM, TENANT)

    def test_an_auditor_can_read(self) -> None:
        admin._require_tenant_access(self.AUDITOR, TENANT, required_role="tenant-auditor")

    def test_an_auditor_cannot_write(self) -> None:
        with pytest.raises(ServiceError) as caught:
            admin._require_tenant_access(self.AUDITOR, TENANT)
        assert caught.value.status_code == 403

    def test_an_auditor_is_not_a_platform_admin(self) -> None:
        with pytest.raises(ServiceError):
            require_admin_role(self.AUDITOR, "platform-admin")

    def test_a_tenant_admin_is_not_a_platform_admin(self) -> None:
        """The hierarchy goes one way. Widening reads must not widen the top role."""
        with pytest.raises(ServiceError):
            require_admin_role(self.ADMIN, "platform-admin")

    def test_a_platform_admin_does_not_inherit_licence_administration(self) -> None:
        """Applying a licence is a commercial act, not a bigger administrative one.
        Separating them is the entire reason license-admin is its own role."""
        with pytest.raises(ServiceError):
            require_admin_role(self.PLATFORM, "license-admin")

    def test_a_licence_admin_cannot_administer_a_tenant(self) -> None:
        with pytest.raises(ServiceError):
            admin._require_tenant_access(self.LICENCE, TENANT)

    def test_an_unknown_role_grants_nothing(self) -> None:
        assert effective_roles(["tenant-viewer"]) == {"tenant-viewer"}
        with pytest.raises(ServiceError):
            require_admin_role(AdminPrincipal(TENANT, ["tenant-viewer"], "x"), "tenant-auditor")

    def test_no_roles_grants_nothing(self) -> None:
        assert effective_roles([]) == set()
        with pytest.raises(ServiceError):
            require_admin_role(AdminPrincipal(TENANT, [], "x"), "tenant-auditor")

    def test_the_hierarchy_is_exactly_what_is_documented(self) -> None:
        assert effective_roles(["platform-admin"]) == {
            "platform-admin",
            "tenant-admin",
            "tenant-auditor",
        }
        assert effective_roles(["tenant-admin"]) == {"tenant-admin", "tenant-auditor"}
        assert effective_roles(["tenant-auditor"]) == {"tenant-auditor"}
        assert effective_roles(["license-admin"]) == {"license-admin"}
