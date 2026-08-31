"""Operator API for the finding queue (UMA-45).

Exercises the handlers directly with a real session, matching the pattern in
`test_applications_api.py`.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import json
import uuid

import pytest

from app.api.findings import _require_read_access, load_finding, query_findings
from app.core import finding_schema as fs
from app.core.admin_auth import AdminPrincipal
from app.core.errors import ServiceError
from app.models.db import AiSession, Finding, FindingStatusEvent
from tests.conftest import db_session

TENANT = uuid.UUID("11111111-1111-1111-1111-111111111111")
OTHER_TENANT = uuid.UUID("22222222-2222-2222-2222-222222222222")
NOW = dt.datetime(2026, 8, 31, 12, 0, tzinfo=dt.timezone.utc)

AUDITOR = AdminPrincipal(tenant_id=TENANT, roles=["tenant-auditor"], subject="soc@example.com")
PLATFORM = AdminPrincipal(tenant_id=None, roles=["tenant-auditor"], subject="platform")
NO_ROLE = AdminPrincipal(tenant_id=TENANT, roles=["tenant-viewer"], subject="nobody")


def _finding(key: str, *, tenant: uuid.UUID = TENANT, **overrides: object) -> Finding:
    values: dict[str, object] = {
        "session_key": "s" * 64,
        "rule_id": "detector.ADR.T0007",
        "technique_id": "ADR.T0007",
        "technique_name": "Indirect prompt injection",
        "tactic": "reasoning_data_manipulation",
        "severity": fs.SEVERITY_HIGH,
        "category": fs.CATEGORY_PROMPT_INJECTION,
        "title": "Indirect prompt injection",
        "summary": "tool output steered the agent",
        "evidence_json": json.dumps({"confidence": 0.95, "severity_basis": "confidence"}),
        "source": fs.SOURCE_ADR,
        "detector": fs.DETECTOR_REASONING,
        "actor_user": "someone@example.com",
        "actor_device_id": "device-1",
        "project_path": "/repo",
        "observed_at": NOW,
        "detected_at": NOW,
        "status": fs.STATUS_OPEN,
    }
    values.update(overrides)
    return Finding(tenant_id=tenant, finding_key=key, **values)


async def _seed(db) -> None:
    db.add_all(
        [
            _finding("a" * 64, detected_at=NOW, severity=fs.SEVERITY_HIGH),
            _finding(
                "b" * 64,
                detected_at=NOW - dt.timedelta(hours=1),
                severity=fs.SEVERITY_LOW,
                status=fs.STATUS_INVESTIGATING,
                category=fs.CATEGORY_SHADOW_AI,
                detector=fs.DETECTOR_POSTURE,
                assignee="analyst@example.com",
            ),
            _finding(
                "c" * 64,
                detected_at=NOW - dt.timedelta(hours=2),
                actor_user="other@example.com",
            ),
            # Another tenant's finding. Must never appear.
            _finding("d" * 64, tenant=OTHER_TENANT),
        ]
    )
    await db.commit()


def _run(coro_factory) -> object:
    async def scenario():
        async with db_session() as db:
            await _seed(db)
            return await coro_factory(db)

    return asyncio.run(scenario())


class TestListing:
    def test_returns_only_the_callers_tenant(self) -> None:
        page = _run(lambda db: query_findings(db, tenant_id=TENANT))
        assert page.total == 3
        assert {item.finding_key for item in page.items} == {"a" * 64, "b" * 64, "c" * 64}

    def test_newest_first_with_a_stable_tiebreak(self) -> None:
        page = _run(lambda db: query_findings(db, tenant_id=TENANT))
        assert [item.finding_key for item in page.items] == ["a" * 64, "b" * 64, "c" * 64]

    def test_paging_reports_the_full_total(self) -> None:
        page = _run(
            lambda db: query_findings(db, tenant_id=TENANT, limit=2, offset=0,)
        )
        assert len(page.items) == 2
        # The count is of everything that matched, not of the page.
        assert page.total == 3

    def test_paging_does_not_repeat_or_skip(self) -> None:
        first = _run(
            lambda db: query_findings(db, tenant_id=TENANT, limit=2, offset=0,)
        )
        second = _run(
            lambda db: query_findings(db, tenant_id=TENANT, limit=2, offset=2,)
        )
        keys = [i.finding_key for i in first.items] + [i.finding_key for i in second.items]
        assert len(keys) == len(set(keys)) == 3


class TestFilters:
    @pytest.mark.parametrize(
        "kwargs,expected",
        [
            ({"status": fs.STATUS_INVESTIGATING}, 1),
            ({"severity": fs.SEVERITY_HIGH}, 2),
            ({"category": fs.CATEGORY_SHADOW_AI}, 1),
            ({"detector": fs.DETECTOR_POSTURE}, 1),
            ({"source": fs.SOURCE_ADR}, 3),
            ({"actor_user": "other@example.com"}, 1),
            ({"assignee": "analyst@example.com"}, 1),
            ({"actor_device_id": "device-1"}, 3),
        ],
    )
    def test_each_filter_narrows(self, kwargs: dict, expected: int) -> None:
        page = _run(
            lambda db: query_findings(db, tenant_id=TENANT, **kwargs)
        )
        assert page.total == expected

    def test_time_window(self) -> None:
        page = _run(
            lambda db: query_findings(db, tenant_id=TENANT, detected_after=NOW - dt.timedelta(minutes=90),)
        )
        assert page.total == 2

    def test_unknown_filter_value_is_rejected_not_silently_empty(self) -> None:
        # An empty page reads as "clean queue". A typo must not look like one.
        with pytest.raises(ServiceError) as exc:
            _run(
                lambda db: query_findings(db, tenant_id=TENANT, status="nonsense",)
            )
        assert exc.value.status_code == 422


class TestAccessControl:
    """Access is enforced before the query runs, so it is checked on its own."""

    def test_cross_tenant_read_is_refused(self) -> None:
        with pytest.raises(ServiceError) as exc:
            _require_read_access(AUDITOR, OTHER_TENANT)
        assert exc.value.status_code == 403

    def test_missing_role_is_refused(self) -> None:
        with pytest.raises(ServiceError) as exc:
            _require_read_access(NO_ROLE, TENANT)
        assert exc.value.status_code == 403

    def test_own_tenant_with_the_role_is_allowed(self) -> None:
        _require_read_access(AUDITOR, TENANT)

    def test_platform_principal_may_read_any_tenant(self) -> None:
        _require_read_access(PLATFORM, OTHER_TENANT)
        page = _run(lambda db: query_findings(db, tenant_id=OTHER_TENANT))
        assert page.total == 1

    def test_query_never_crosses_the_tenant_boundary(self) -> None:
        # Even with access granted, the query itself is scoped: another
        # tenant's row must not appear in this tenant's page.
        page = _run(lambda db: query_findings(db, tenant_id=TENANT))
        assert all(item.finding_key != "d" * 64 for item in page.items)

    def test_detail_of_another_tenants_finding_is_not_found(self) -> None:
        # Not 403: confirming the key exists elsewhere would leak that it does.
        with pytest.raises(ServiceError) as exc:
            _run(lambda db: load_finding(db, tenant_id=TENANT, finding_key="d" * 64))
        assert exc.value.status_code == 404


class TestDetail:
    def test_carries_evidence_and_technique(self) -> None:
        detail = _run(
            lambda db: load_finding(db, tenant_id=TENANT, finding_key="a" * 64)
        )
        assert detail.technique_id == "ADR.T0007"
        assert detail.tactic == "reasoning_data_manipulation"
        assert detail.evidence["severity_basis"] == "confidence"

    def test_includes_the_audit_trail_newest_first(self) -> None:
        async def scenario():
            async with db_session() as db:
                await _seed(db)
                db.add_all(
                    [
                        FindingStatusEvent(
                            id=uuid.uuid4(),
                            tenant_id=TENANT,
                            finding_key="a" * 64,
                            from_status=None,
                            to_status=fs.STATUS_OPEN,
                            actor="system",
                            occurred_at=NOW,
                        ),
                        FindingStatusEvent(
                            id=uuid.uuid4(),
                            tenant_id=TENANT,
                            finding_key="a" * 64,
                            from_status=fs.STATUS_OPEN,
                            to_status=fs.STATUS_INVESTIGATING,
                            actor="soc@example.com",
                            occurred_at=NOW + dt.timedelta(minutes=5),
                        ),
                    ]
                )
                await db.commit()
                return await load_finding(db, tenant_id=TENANT, finding_key="a" * 64)

        detail = asyncio.run(scenario())
        assert [e.to_status for e in detail.history] == [
            fs.STATUS_INVESTIGATING,
            fs.STATUS_OPEN,
        ]

    def test_includes_session_context_when_the_session_still_exists(self) -> None:
        async def scenario():
            async with db_session() as db:
                await _seed(db)
                db.add(
                    AiSession(
                        tenant_id=TENANT,
                        session_key="s" * 64,
                        source="claude",
                        source_session_id="abc",
                        observed_at=NOW,
                        message_count=12,
                        tool_call_count=3,
                        transcript_ref="ref",
                        transcript_sha256="a" * 64,
                        analysis_status="analyzed",
                        verdict="malicious",
                        confidence=0.95,
                    )
                )
                await db.commit()
                return await load_finding(db, tenant_id=TENANT, finding_key="a" * 64)

        detail = asyncio.run(scenario())
        assert detail.session is not None
        # The AI tool lives here, not on the finding's `source`.
        assert detail.session.source == "claude"
        assert detail.source == fs.SOURCE_ADR

    def test_survives_a_session_removed_by_retention(self) -> None:
        # Transcript retention deletes the session; the finding and its audit
        # trail outlive it and must still open.
        detail = _run(
            lambda db: load_finding(db, tenant_id=TENANT, finding_key="a" * 64)
        )
        assert detail.session is None
        assert detail.finding_key == "a" * 64

    def test_malformed_evidence_does_not_break_the_queue(self) -> None:
        async def scenario():
            async with db_session() as db:
                db.add(_finding("e" * 64, evidence_json="{not json"))
                await db.commit()
                return await load_finding(db, tenant_id=TENANT, finding_key="e" * 64)

        detail = asyncio.run(scenario())
        assert detail.evidence is None
