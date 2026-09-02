"""Session and transcript drill-down (UMA-48).

Two things are being proved here. First, that an operator can walk from a
finding to the session behind it. Second — the part that matters more — that
the mode a tenant chose is what decides whether content comes back, and that
neither the wrong tenant nor a caller without the role can get around it.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import json
import uuid

import pytest

from app.api.sessions import (
    load_session,
    load_transcript,
    query_sessions,
    reanalyze_session_endpoint,
)
from app.core import finding_schema
from app.core.admin_auth import AdminPrincipal
from app.core.errors import ServiceError
from app.core.transcript_store import get_transcript_store, reset_transcript_store
from sqlalchemy import select

from app.models.db import AiSession, Finding, Tenant, TranscriptAuditEvent
from tests.conftest import db_session

TENANT = uuid.UUID("11111111-1111-1111-1111-111111111111")
OTHER_TENANT = uuid.UUID("22222222-2222-2222-2222-222222222222")
NOW = dt.datetime(2026, 8, 31, 12, 0, tzinfo=dt.timezone.utc)

TRANSCRIPT = {
    "messages": [
        {"role": "user", "content": "here is the customer export"},
        {"role": "assistant", "content": "summarising it now"},
    ]
}


async def _tenant(db, tenant_id: uuid.UUID, mode: str) -> None:
    db.add(
        Tenant(
            tenant_id=tenant_id,
            name=f"t-{tenant_id.hex[:4]}",
            collection_mode=mode,
        )
    )


async def _session(
    db,
    *,
    tenant_id: uuid.UUID = TENANT,
    session_key: str = "sess-1",
    source: str = "claude_code",
    actor_user: str = "batu",
    observed_at: dt.datetime | None = None,
    transcript_ref: str | None = None,
    posture: dict | None = None,
    analysis_status: str = "complete",
    verdict: str | None = "malicious",
) -> AiSession:
    row = AiSession(
        tenant_id=tenant_id,
        session_key=session_key,
        source=source,
        source_session_id=f"src-{session_key}",
        actor_user=actor_user,
        actor_device_id="dev-1",
        hostname="LAPTOP-1",
        model="claude-opus-5",
        project_path="C:/work/app",
        title="customer export",
        message_count=12,
        tool_call_count=3,
        analysis_status=analysis_status,
        verdict=verdict,
        confidence=0.91,
        threat_tactic="ADR.T1005",
        observed_at=observed_at or NOW,
        ingested_at=NOW,
        collector_name="umai-adr-collector",
        collector_version="0.4.0",
        transcript_ref=transcript_ref,
        transcript_bytes=len(json.dumps(TRANSCRIPT)) if transcript_ref else None,
        posture_json=json.dumps(posture) if posture else None,
    )
    db.add(row)
    return row


async def _store_transcript(tenant_id: uuid.UUID = TENANT) -> str:
    reset_transcript_store()
    ref, _digest, _size = await get_transcript_store().put(
        tenant_id, json.dumps(TRANSCRIPT).encode()
    )
    return ref


def _run(body):
    return asyncio.run(body())


class TestListing:
    def test_sessions_come_back_newest_first(self) -> None:
        async def body():
            async with db_session() as db:
                await _tenant(db, TENANT, finding_schema.MODE_METADATA)
                await _session(db, session_key="old", observed_at=NOW - dt.timedelta(days=2))
                await _session(db, session_key="new", observed_at=NOW)
                await _session(db, session_key="mid", observed_at=NOW - dt.timedelta(hours=3))
                await db.commit()
                return await query_sessions(db, tenant_id=TENANT)

        page = _run(body)
        assert [i.session_key for i in page.items] == ["new", "mid", "old"]
        assert page.total == 3

    def test_another_tenants_sessions_are_invisible(self) -> None:
        async def body():
            async with db_session() as db:
                await _tenant(db, TENANT, finding_schema.MODE_METADATA)
                await _tenant(db, OTHER_TENANT, finding_schema.MODE_FULL_SESSION)
                await _session(db, session_key="mine")
                await _session(db, tenant_id=OTHER_TENANT, session_key="theirs")
                await db.commit()
                return await query_sessions(db, tenant_id=TENANT)

        page = _run(body)
        assert [i.session_key for i in page.items] == ["mine"]
        assert page.total == 1

    @pytest.mark.parametrize(
        "field,value,expected",
        [
            ("source", "cursor", ["b"]),
            ("actor_user", "ada", ["b"]),
            ("verdict", "benign", ["b"]),
            ("analysis_status", "pending", ["b"]),
        ],
    )
    def test_filters_narrow_the_list(self, field: str, value: str, expected: list[str]) -> None:
        async def body():
            async with db_session() as db:
                await _tenant(db, TENANT, finding_schema.MODE_METADATA)
                await _session(db, session_key="a")
                await _session(
                    db,
                    session_key="b",
                    source="cursor",
                    actor_user="ada",
                    verdict="benign",
                    analysis_status="pending",
                )
                await db.commit()
                return await query_sessions(db, tenant_id=TENANT, **{field: value})

        assert [i.session_key for i in _run(body).items] == expected

    def test_a_time_window_excludes_its_upper_bound(self) -> None:
        async def body():
            async with db_session() as db:
                await _tenant(db, TENANT, finding_schema.MODE_METADATA)
                await _session(db, session_key="inside", observed_at=NOW - dt.timedelta(hours=1))
                await _session(db, session_key="edge", observed_at=NOW)
                await db.commit()
                return await query_sessions(
                    db,
                    tenant_id=TENANT,
                    observed_after=NOW - dt.timedelta(days=1),
                    observed_before=NOW,
                )

        assert [i.session_key for i in _run(body).items] == ["inside"]

    def test_paging_reports_the_full_total(self) -> None:
        async def body():
            async with db_session() as db:
                await _tenant(db, TENANT, finding_schema.MODE_METADATA)
                for n in range(5):
                    await _session(
                        db, session_key=f"s{n}", observed_at=NOW - dt.timedelta(hours=n)
                    )
                await db.commit()
                return await query_sessions(db, tenant_id=TENANT, limit=2, offset=2)

        page = _run(body)
        assert [i.session_key for i in page.items] == ["s2", "s3"]
        assert page.total == 5

    def test_each_row_carries_its_finding_count(self) -> None:
        async def body():
            async with db_session() as db:
                await _tenant(db, TENANT, finding_schema.MODE_METADATA)
                await _session(db, session_key="busy")
                await _session(db, session_key="quiet", observed_at=NOW - dt.timedelta(hours=1))
                for n in range(3):
                    db.add(
                        Finding(
                            tenant_id=TENANT,
                            finding_key=f"f{n}",
                            session_key="busy",
                            rule_id="detector.ADR.T1005",
                            source="adr",
                            detector="reasoning",
                            category="data_exposure",
                            severity="high",
                            status="open",
                            title="t",
                            detected_at=NOW,
                        )
                    )
                await db.commit()
                return await query_sessions(db, tenant_id=TENANT)

        by_key = {i.session_key: i.finding_count for i in _run(body).items}
        assert by_key == {"busy": 3, "quiet": 0}


class TestDetail:
    def test_posture_is_returned_even_without_content_collection(self) -> None:
        """Posture is configuration, not conversation — every mode gets it."""

        async def body():
            async with db_session() as db:
                await _tenant(db, TENANT, finding_schema.MODE_POSTURE_ONLY)
                await _session(db, posture={"bypass_permissions": True})
                await db.commit()
                return await load_session(db, tenant_id=TENANT, session_key="sess-1")

        detail = _run(body)
        assert detail.posture == {"bypass_permissions": True}
        assert detail.collection_mode == finding_schema.MODE_POSTURE_ONLY

    def test_a_stored_transcript_is_only_advertised_in_full_session_mode(self) -> None:
        async def body(mode):
            async with db_session() as db:
                await _tenant(db, TENANT, mode)
                await _session(db, transcript_ref="tenant/x/abc.json")
                await db.commit()
                return await load_session(db, tenant_id=TENANT, session_key="sess-1")

        assert asyncio.run(body(finding_schema.MODE_FULL_SESSION)).transcript_available is True
        # The blob may still be on disk from before the mode changed; the API
        # must not offer it once the tenant has stopped collecting content.
        assert asyncio.run(body(finding_schema.MODE_METADATA)).transcript_available is False

    def test_an_expired_transcript_reads_as_unavailable_not_as_an_error(self) -> None:
        async def body():
            async with db_session() as db:
                await _tenant(db, TENANT, finding_schema.MODE_FULL_SESSION)
                await _session(db, transcript_ref=None)
                await db.commit()
                return await load_session(db, tenant_id=TENANT, session_key="sess-1")

        detail = _run(body)
        assert detail.transcript_available is False
        assert detail.session_key == "sess-1"

    def test_a_missing_session_is_a_404(self) -> None:
        async def body():
            async with db_session() as db:
                await _tenant(db, TENANT, finding_schema.MODE_METADATA)
                await db.commit()
                with pytest.raises(ServiceError) as exc:
                    await load_session(db, tenant_id=TENANT, session_key="nope")
                return exc.value

        assert _run(body).status_code == 404

    def test_a_session_belonging_to_another_tenant_is_a_404(self) -> None:
        """Not a 403: existence itself is another tenant's information."""

        async def body():
            async with db_session() as db:
                await _tenant(db, TENANT, finding_schema.MODE_METADATA)
                await _tenant(db, OTHER_TENANT, finding_schema.MODE_METADATA)
                await _session(db, tenant_id=OTHER_TENANT, session_key="theirs")
                await db.commit()
                with pytest.raises(ServiceError) as exc:
                    await load_session(db, tenant_id=TENANT, session_key="theirs")
                return exc.value

        assert _run(body).status_code == 404


class TestTranscript:
    def test_full_session_mode_returns_the_content(self) -> None:
        async def body():
            ref = await _store_transcript()
            async with db_session() as db:
                await _tenant(db, TENANT, finding_schema.MODE_FULL_SESSION)
                await _session(db, transcript_ref=ref)
                await db.commit()
                return await load_transcript(
                    db, tenant_id=TENANT, session_key="sess-1", actor="ada"
                )

        response = _run(body)
        assert response.transcript == TRANSCRIPT
        assert response.collection_mode == finding_schema.MODE_FULL_SESSION

    @pytest.mark.parametrize(
        "mode", [finding_schema.MODE_POSTURE_ONLY, finding_schema.MODE_METADATA]
    )
    def test_modes_without_content_refuse_and_say_why(self, mode: str) -> None:
        async def body():
            ref = await _store_transcript()
            async with db_session() as db:
                await _tenant(db, TENANT, mode)
                # The blob exists. The mode, not the storage, is what decides.
                await _session(db, transcript_ref=ref)
                await db.commit()
                with pytest.raises(ServiceError) as exc:
                    await load_transcript(
                        db, tenant_id=TENANT, session_key="sess-1", actor="ada"
                    )
                return exc.value

        error = _run(body)
        assert error.status_code == 409
        assert error.error_type == "CONTENT_NOT_COLLECTED"
        assert mode in error.message

    def test_a_deleted_transcript_is_410_not_500(self) -> None:
        """Retention removed the blob; the session row is still meaningful."""

        async def body():
            async with db_session() as db:
                await _tenant(db, TENANT, finding_schema.MODE_FULL_SESSION)
                await _session(db, transcript_ref="tenant/x/gone.json")
                await db.commit()
                with pytest.raises(ServiceError) as exc:
                    await load_transcript(
                        db, tenant_id=TENANT, session_key="sess-1", actor="ada"
                    )
                return exc.value

        error = _run(body)
        assert error.status_code == 410
        assert error.error_type == "TRANSCRIPT_UNAVAILABLE"

    def test_a_session_with_no_transcript_ref_is_410(self) -> None:
        async def body():
            async with db_session() as db:
                await _tenant(db, TENANT, finding_schema.MODE_FULL_SESSION)
                await _session(db, transcript_ref=None)
                await db.commit()
                with pytest.raises(ServiceError) as exc:
                    await load_transcript(
                        db, tenant_id=TENANT, session_key="sess-1", actor="ada"
                    )
                return exc.value

        assert _run(body).status_code == 410

    def test_an_unknown_tenant_row_falls_back_to_the_strictest_mode(self) -> None:
        """No tenant record is not permission to hand over content."""

        async def body():
            ref = await _store_transcript()
            async with db_session() as db:
                # Deliberately no tenant row.
                await _session(db, transcript_ref=ref)
                await db.commit()
                with pytest.raises(ServiceError) as exc:
                    await load_transcript(
                        db, tenant_id=TENANT, session_key="sess-1", actor="ada"
                    )
                return exc.value

        error = _run(body)
        assert error.error_type == "CONTENT_NOT_COLLECTED"
        assert finding_schema.MODE_POSTURE_ONLY in error.message

    def test_reading_content_is_logged_with_who_read_it(self, caplog) -> None:
        async def body():
            ref = await _store_transcript()
            async with db_session() as db:
                await _tenant(db, TENANT, finding_schema.MODE_FULL_SESSION)
                await _session(db, transcript_ref=ref)
                await db.commit()
                return await load_transcript(
                    db, tenant_id=TENANT, session_key="sess-1", actor="ada@corp"
                )

        with caplog.at_level("INFO", logger="umai.service.sessions"):
            _run(body)
        rendered = [r.getMessage() for r in caplog.records]
        assert any("transcript.read" in m and "ada@corp" in m for m in rendered)

    def test_reading_content_leaves_a_queryable_audit_row(self) -> None:
        """A log line is not something anyone can query months later."""

        async def body():
            ref = await _store_transcript()
            async with db_session() as db:
                await _tenant(db, TENANT, finding_schema.MODE_FULL_SESSION)
                await _session(db, transcript_ref=ref)
                await db.commit()
                await load_transcript(
                    db, tenant_id=TENANT, session_key="sess-1", actor="ada@corp"
                )
                return list(
                    (await db.execute(select(TranscriptAuditEvent))).scalars().all()
                )

        events = _run(body)
        assert len(events) == 1
        assert (events[0].action, events[0].actor) == ("read", "ada@corp")
        assert events[0].session_key == "sess-1"

    def test_a_refused_read_leaves_no_audit_row(self) -> None:
        """Nothing was disclosed, so nothing is recorded as disclosed."""

        async def body():
            ref = await _store_transcript()
            async with db_session() as db:
                await _tenant(db, TENANT, finding_schema.MODE_METADATA)
                await _session(db, transcript_ref=ref)
                await db.commit()
                with pytest.raises(ServiceError):
                    await load_transcript(
                        db, tenant_id=TENANT, session_key="sess-1", actor="ada"
                    )
                return list(
                    (await db.execute(select(TranscriptAuditEvent))).scalars().all()
                )

        assert _run(body) == []


class TestAccessControl:
    """The role and tenant gate, exercised through the same helper the routes use."""

    def _check(self, principal: AdminPrincipal, tenant_id: uuid.UUID) -> None:
        from app.api.sessions import _require_read_access

        _require_read_access(principal, tenant_id)

    def test_an_auditor_of_this_tenant_may_read(self) -> None:
        self._check(AdminPrincipal(tenant_id=TENANT, roles=["tenant-auditor"]), TENANT)

    def test_an_admin_of_this_tenant_may_read(self) -> None:
        self._check(AdminPrincipal(tenant_id=TENANT, roles=["tenant-admin"]), TENANT)

    def test_an_auditor_of_another_tenant_may_not(self) -> None:
        principal = AdminPrincipal(tenant_id=OTHER_TENANT, roles=["tenant-auditor"])
        with pytest.raises(ServiceError) as exc:
            self._check(principal, TENANT)
        assert exc.value.status_code in (403, 404)

    def test_a_principal_with_no_role_may_not(self) -> None:
        with pytest.raises(ServiceError) as exc:
            self._check(AdminPrincipal(tenant_id=TENANT, roles=[]), TENANT)
        assert exc.value.status_code == 403


class TestRequeueAfterAFailedAnalysis:
    """`analysis_failed` is terminal by design, but not a dead end.

    A wrong key, an exhausted quota or a provider outage parks real sessions as
    unexamined. Nothing must retry them on its own — a permanently failing
    session would loop forever — but once the cause is fixed the operator needs
    a way to get them looked at that is not raw SQL against `ai_sessions`.
    """

    ADMIN = AdminPrincipal(tenant_id=TENANT, roles=["tenant-admin"])
    AUDITOR = AdminPrincipal(tenant_id=TENANT, roles=["tenant-auditor"])

    def test_a_failed_session_goes_back_to_the_queue(self) -> None:
        async def body():
            async with db_session() as db:
                await _tenant(db, TENANT, finding_schema.MODE_FULL_SESSION)
                row = await _session(
                    db, analysis_status="analysis_failed", verdict=None
                )
                row.analysis_error = "APIConnectionError: Connection error."
                row.analysis_attempts = 2
                row.claimed_by = "worker-7"
                row.claimed_at = NOW
                await db.commit()

                response = await reanalyze_session_endpoint(
                    "sess-1", db, TENANT, self.ADMIN
                )
                refreshed = await db.get(AiSession, (TENANT, "sess-1"))
                return response, refreshed

        response, refreshed = _run(body)

        assert response.analysis_status == "ingested"
        assert refreshed.analysis_status == "ingested"
        assert refreshed.analysis_error is None
        # A stale lease would keep the claim query from ever picking it up.
        assert refreshed.claimed_by is None
        assert refreshed.claimed_at is None
        # Kept, not reset: the count is the record of what this session has
        # already cost without producing a verdict.
        assert refreshed.analysis_attempts == 2
        assert response.analysis_attempts == 2

    def test_a_session_with_a_verdict_is_refused(self) -> None:
        async def body():
            async with db_session() as db:
                await _tenant(db, TENANT, finding_schema.MODE_FULL_SESSION)
                await _session(db, analysis_status="analyzed", verdict="malicious")
                await db.commit()
                with pytest.raises(ServiceError) as raised:
                    await reanalyze_session_endpoint("sess-1", db, TENANT, self.ADMIN)
                return raised.value

        error = _run(body)

        # Requeuing would discard a verdict somebody may already have acted on.
        assert error.status_code == 409

    def test_a_session_being_analysed_right_now_is_refused(self) -> None:
        async def body():
            async with db_session() as db:
                await _tenant(db, TENANT, finding_schema.MODE_FULL_SESSION)
                await _session(db, analysis_status="reasoning", verdict=None)
                await db.commit()
                with pytest.raises(ServiceError) as raised:
                    await reanalyze_session_endpoint("sess-1", db, TENANT, self.ADMIN)
                return raised.value

        assert _run(body).status_code == 409

    def test_an_auditor_cannot_requeue(self) -> None:
        async def body():
            async with db_session() as db:
                await _tenant(db, TENANT, finding_schema.MODE_FULL_SESSION)
                await _session(db, analysis_status="analysis_failed", verdict=None)
                await db.commit()
                with pytest.raises(ServiceError) as raised:
                    await reanalyze_session_endpoint("sess-1", db, TENANT, self.AUDITOR)
                return raised.value

        # Requeuing spends model budget; reading the queue does not.
        assert _run(body).status_code == 403

    def test_another_tenant_cannot_requeue(self) -> None:
        async def body():
            async with db_session() as db:
                await _tenant(db, TENANT, finding_schema.MODE_FULL_SESSION)
                await _session(db, analysis_status="analysis_failed", verdict=None)
                await db.commit()
                outsider = AdminPrincipal(tenant_id=OTHER_TENANT, roles=["tenant-admin"])
                with pytest.raises(ServiceError) as raised:
                    await reanalyze_session_endpoint("sess-1", db, TENANT, outsider)
                return raised.value

        assert _run(body).status_code in (403, 404)
