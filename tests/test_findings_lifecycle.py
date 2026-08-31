"""Finding lifecycle transitions and their audit trail (UMA-46).

Rules come from ``docs/contracts/finding-and-worker-result-schema.md`` §6.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import uuid

import pytest

from app.api.findings import _require_write_access, assign_finding, transition_finding
from app.core import finding_schema as fs
from app.core.admin_auth import AdminPrincipal
from app.core.errors import ServiceError
from app.models.db import Finding
from tests.conftest import db_session

TENANT = uuid.UUID("11111111-1111-1111-1111-111111111111")
OTHER_TENANT = uuid.UUID("22222222-2222-2222-2222-222222222222")
KEY = "a" * 64
NOW = dt.datetime(2026, 8, 31, 12, 0, tzinfo=dt.timezone.utc)
ACTOR = "soc@example.com"

ADMIN = AdminPrincipal(tenant_id=TENANT, roles=["tenant-admin"], subject=ACTOR)
AUDITOR = AdminPrincipal(tenant_id=TENANT, roles=["tenant-auditor"], subject="readonly")


def _finding(status: str = fs.STATUS_OPEN) -> Finding:
    return Finding(
        tenant_id=TENANT,
        finding_key=KEY,
        session_key="s" * 64,
        rule_id="detector.ADR.T0007",
        severity=fs.SEVERITY_HIGH,
        category=fs.CATEGORY_PROMPT_INJECTION,
        title="Indirect prompt injection",
        source=fs.SOURCE_ADR,
        detector=fs.DETECTOR_REASONING,
        observed_at=NOW,
        detected_at=NOW,
        status=status,
    )


def _run(factory, *, start: str = fs.STATUS_OPEN):
    async def scenario():
        async with db_session() as db:
            db.add(_finding(start))
            await db.commit()
            return await factory(db)

    return asyncio.run(scenario())


class TestAllowedMoves:
    @pytest.mark.parametrize(
        "start,target,note",
        [
            (fs.STATUS_OPEN, fs.STATUS_INVESTIGATING, None),
            (fs.STATUS_OPEN, fs.STATUS_FALSE_POSITIVE, "not real"),
            (fs.STATUS_OPEN, fs.STATUS_ACCEPTED_RISK, "signed off"),
            (fs.STATUS_INVESTIGATING, fs.STATUS_RESOLVED, None),
            (fs.STATUS_INVESTIGATING, fs.STATUS_FALSE_POSITIVE, "detector noise"),
            (fs.STATUS_RESOLVED, fs.STATUS_OPEN, "came back"),
        ],
    )
    def test_moves_the_contract_allows(self, start: str, target: str, note: str | None) -> None:
        detail = _run(
            lambda db: transition_finding(
                db, tenant_id=TENANT, finding_key=KEY, to_status=target, actor=ACTOR, note=note
            ),
            start=start,
        )
        assert detail.status == target

    def test_resolved_is_only_reachable_through_investigating(self) -> None:
        # Clearing a queue is not the same as working it.
        with pytest.raises(ServiceError) as exc:
            _run(
                lambda db: transition_finding(
                    db,
                    tenant_id=TENANT,
                    finding_key=KEY,
                    to_status=fs.STATUS_RESOLVED,
                    actor=ACTOR,
                ),
                start=fs.STATUS_OPEN,
            )
        assert exc.value.error_type == "INVALID_TRANSITION"

    def test_terminal_states_lead_only_back_to_open(self) -> None:
        with pytest.raises(ServiceError) as exc:
            _run(
                lambda db: transition_finding(
                    db,
                    tenant_id=TENANT,
                    finding_key=KEY,
                    to_status=fs.STATUS_RESOLVED,
                    actor=ACTOR,
                    note="n",
                ),
                start=fs.STATUS_FALSE_POSITIVE,
            )
        assert exc.value.error_type == "INVALID_TRANSITION"

    def test_moving_to_the_current_status_is_refused(self) -> None:
        with pytest.raises(ServiceError) as exc:
            _run(
                lambda db: transition_finding(
                    db,
                    tenant_id=TENANT,
                    finding_key=KEY,
                    to_status=fs.STATUS_OPEN,
                    actor=ACTOR,
                ),
            )
        assert exc.value.status_code == 409

    def test_unknown_status_is_refused(self) -> None:
        with pytest.raises(ServiceError) as exc:
            _run(
                lambda db: transition_finding(
                    db, tenant_id=TENANT, finding_key=KEY, to_status="archived", actor=ACTOR
                ),
            )
        assert exc.value.status_code == 422


class TestNoteRequirement:
    @pytest.mark.parametrize("target", [fs.STATUS_FALSE_POSITIVE, fs.STATUS_ACCEPTED_RISK])
    def test_judgements_must_be_explained(self, target: str) -> None:
        with pytest.raises(ServiceError) as exc:
            _run(
                lambda db: transition_finding(
                    db, tenant_id=TENANT, finding_key=KEY, to_status=target, actor=ACTOR
                ),
            )
        assert exc.value.error_type == "NOTE_REQUIRED"

    def test_whitespace_is_not_a_reason(self) -> None:
        with pytest.raises(ServiceError) as exc:
            _run(
                lambda db: transition_finding(
                    db,
                    tenant_id=TENANT,
                    finding_key=KEY,
                    to_status=fs.STATUS_ACCEPTED_RISK,
                    actor=ACTOR,
                    note="   ",
                ),
            )
        assert exc.value.error_type == "NOTE_REQUIRED"

    def test_reopening_a_closed_finding_must_be_explained(self) -> None:
        with pytest.raises(ServiceError) as exc:
            _run(
                lambda db: transition_finding(
                    db,
                    tenant_id=TENANT,
                    finding_key=KEY,
                    to_status=fs.STATUS_OPEN,
                    actor=ACTOR,
                ),
                start=fs.STATUS_ACCEPTED_RISK,
            )
        assert exc.value.error_type == "NOTE_REQUIRED"

    def test_starting_an_investigation_needs_no_ceremony(self) -> None:
        detail = _run(
            lambda db: transition_finding(
                db,
                tenant_id=TENANT,
                finding_key=KEY,
                to_status=fs.STATUS_INVESTIGATING,
                actor=ACTOR,
            ),
        )
        assert detail.status == fs.STATUS_INVESTIGATING


class TestAuditTrail:
    def test_every_move_is_recorded_with_who_and_why(self) -> None:
        async def scenario():
            async with db_session() as db:
                db.add(_finding())
                await db.commit()
                await transition_finding(
                    db,
                    tenant_id=TENANT,
                    finding_key=KEY,
                    to_status=fs.STATUS_INVESTIGATING,
                    actor=ACTOR,
                )
                return await transition_finding(
                    db,
                    tenant_id=TENANT,
                    finding_key=KEY,
                    to_status=fs.STATUS_FALSE_POSITIVE,
                    actor="second@example.com",
                    note="detector noise",
                )

        detail = asyncio.run(scenario())
        assert len(detail.history) == 2
        newest = detail.history[0]
        assert (newest.from_status, newest.to_status) == (
            fs.STATUS_INVESTIGATING,
            fs.STATUS_FALSE_POSITIVE,
        )
        assert newest.actor == "second@example.com"
        assert newest.note == "detector noise"

    def test_a_refused_move_leaves_no_trace(self) -> None:
        """A rejected transition must not write an audit row or change status."""

        async def scenario():
            async with db_session() as db:
                db.add(_finding())
                await db.commit()
                with pytest.raises(ServiceError):
                    await transition_finding(
                        db,
                        tenant_id=TENANT,
                        finding_key=KEY,
                        to_status=fs.STATUS_RESOLVED,
                        actor=ACTOR,
                    )
                from app.api.findings import load_finding

                return await load_finding(db, tenant_id=TENANT, finding_key=KEY)

        detail = asyncio.run(scenario())
        assert detail.status == fs.STATUS_OPEN
        assert detail.history == []


class TestAssignment:
    def test_assign_and_clear(self) -> None:
        async def scenario():
            async with db_session() as db:
                db.add(_finding())
                await db.commit()
                assigned = await assign_finding(
                    db,
                    tenant_id=TENANT,
                    finding_key=KEY,
                    assignee="analyst@example.com",
                    actor=ACTOR,
                )
                cleared = await assign_finding(
                    db, tenant_id=TENANT, finding_key=KEY, assignee=None, actor=ACTOR
                )
                return assigned, cleared

        assigned, cleared = asyncio.run(scenario())
        assert assigned.assignee == "analyst@example.com"
        assert cleared.assignee is None

    def test_assignment_is_not_a_status_change(self) -> None:
        # Who is looking is not what was decided; it does not belong in the
        # decision trail.
        detail = _run(
            lambda db: assign_finding(
                db, tenant_id=TENANT, finding_key=KEY, assignee="a@example.com", actor=ACTOR
            ),
        )
        assert detail.status == fs.STATUS_OPEN
        assert detail.history == []


class TestAccessControl:
    def test_read_only_principal_cannot_transition(self) -> None:
        with pytest.raises(ServiceError) as exc:
            _require_write_access(AUDITOR, TENANT)
        assert exc.value.status_code == 403

    def test_admin_of_another_tenant_cannot_transition(self) -> None:
        with pytest.raises(ServiceError) as exc:
            _require_write_access(ADMIN, OTHER_TENANT)
        assert exc.value.status_code == 403

    def test_tenant_admin_may_transition(self) -> None:
        _require_write_access(ADMIN, TENANT)

    def test_another_tenants_finding_is_not_found(self) -> None:
        with pytest.raises(ServiceError) as exc:
            _run(
                lambda db: transition_finding(
                    db,
                    tenant_id=OTHER_TENANT,
                    finding_key=KEY,
                    to_status=fs.STATUS_INVESTIGATING,
                    actor=ACTOR,
                ),
            )
        assert exc.value.status_code == 404
