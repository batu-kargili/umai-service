"""The publish eval gate (go-live WS5.1, decision D4).

A guardrail version reaches runtime through the explicit publish endpoint only when
its latest COMPLETED evaluation run meets the gate thresholds, or when the operator
bypasses the gate with a reason. Library deploys and the auto-published first version
are exempt unless ``publish_gate_enforce_on_library_deploy`` is on. Every outcome is
carried on the ``umai.admin.publish.v1`` SIEM event.

The endpoints are driven directly against the real schema on in-memory SQLite, with
Redis and SIEM delivery replaced by in-process fakes.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import json
import uuid

import pytest

from app.api import admin
from app.core.admin_auth import AdminPrincipal
from app.core.errors import ServiceError
from app.core.settings import settings
from app.models import admin as admin_models
from app.models.db import (
    EvaluationCase,
    EvaluationRun,
    Guardrail,
    GuardrailPublishGate,
    GuardrailVersion,
)
from tests.conftest import db_session

TENANT = uuid.UUID("5a5a5a5a-0000-0000-0000-000000000001")
ENV = "prod"
PROJECT = "chat"
GUARDRAIL = "gr-gate"
ADMIN = AdminPrincipal(TENANT, ["tenant-admin"], "alice@example.com")


class FakeRedis:
    def __init__(self) -> None:
        self.values: dict[str, str] = {}

    async def set(self, key: str, value: str) -> None:
        self.values[key] = value

    async def exists(self, key: str) -> int:
        return 1 if key in self.values else 0


@pytest.fixture
def env(monkeypatch):
    """Fake Redis, captured SIEM events and pinned gate settings."""
    redis = FakeRedis()
    events: list[dict] = []

    def _capture(event: dict):
        events.append(event)
        return asyncio.sleep(0)

    monkeypatch.setattr(admin, "get_redis", lambda: redis)
    monkeypatch.setattr(admin, "emit_event", _capture)
    for name, value in {
        "publish_gate_enforced": True,
        "publish_gate_enforce_on_library_deploy": False,
        "publish_gate_min_expected_action_accuracy": 0.7,
        "publish_gate_min_expected_allowed_accuracy": None,
        "publish_gate_min_eval_cases": 10,
        "publish_gate_max_p95_latency_ms": None,
        "publish_gate_require_bypass_reason": True,
        "snapshot_signing_key": "gate-test-key",
        "snapshot_signing_key_id": "gate-test",
    }.items():
        monkeypatch.setattr(settings, name, value)
    return {"redis": redis, "events": events}


def snapshot(version: int) -> dict:
    return {
        "guardrail_id": GUARDRAIL,
        "version": version,
        "mode": "ENFORCE",
        "phases": ["PRE_LLM"],
        "preflight": {"target": "LAST_MESSAGE", "rules": [], "max_length": 8000},
        "policies": [],
        "llm_config": {"provider": "test", "base_url": "http://llm.test", "model": "m"},
    }


async def seed_guardrail(session, *, versions=(1, 2), current: int = 1, created_by=None) -> None:
    async with session.begin():
        session.add(
            Guardrail(
                tenant_id=TENANT,
                environment_id=ENV,
                project_id=PROJECT,
                guardrail_id=GUARDRAIL,
                name="Gate test",
                mode="ENFORCE",
                current_version=current,
            )
        )
        for version in versions:
            session.add(
                GuardrailVersion(
                    tenant_id=TENANT,
                    environment_id=ENV,
                    project_id=PROJECT,
                    guardrail_id=GUARDRAIL,
                    version=version,
                    snapshot_json=json.dumps(snapshot(version)),
                    created_by=created_by,
                )
            )


async def seed_run(
    session,
    *,
    version: int = 2,
    total: int = 12,
    accuracy: float | None = 0.9,
    status: str = "COMPLETED",
    latencies: list[float] | None = None,
    completed_at: dt.datetime | None = None,
) -> uuid.UUID:
    run_id = uuid.uuid4()
    metrics = {"total": total, "expected_action_accuracy": accuracy}
    async with session.begin():
        session.add(
            EvaluationRun(
                id=run_id,
                tenant_id=TENANT,
                environment_id=ENV,
                project_id=PROJECT,
                guardrail_id=GUARDRAIL,
                guardrail_version=version,
                phase="PRE_LLM",
                status=status,
                total_cases=total,
                processed_cases=total,
                metrics_json=json.dumps(metrics),
                completed_at=completed_at or dt.datetime.now(dt.timezone.utc),
            )
        )
        for index, latency in enumerate(latencies or [], start=1):
            session.add(
                EvaluationCase(
                    run_id=run_id,
                    tenant_id=TENANT,
                    environment_id=ENV,
                    project_id=PROJECT,
                    guardrail_id=GUARDRAIL,
                    guardrail_version=version,
                    index=index,
                    prompt=f"case {index}",
                    latency_ms=latency,
                )
            )
    return run_id


def publish_request(**overrides) -> admin_models.PublishRequest:
    body = {
        "tenant_id": TENANT,
        "environment_id": ENV,
        "project_id": PROJECT,
        "publisher_id": "alice@example.com",
        "approver_id": "bob@example.com",
    }
    body.update(overrides)
    return admin_models.PublishRequest(**body)


async def publish(session, version: int = 2, **overrides):
    return await admin.publish_guardrail_version(
        GUARDRAIL, version, publish_request(**overrides), session=session, principal=ADMIN
    )


def run(coro_factory):
    async def _main():
        async with db_session() as session:
            return await coro_factory(session)

    return asyncio.run(_main())


def publish_events(events: list[dict]) -> list[dict]:
    return [event for event in events if event.get("schema") == "umai.admin.publish.v1"]


# --- rejection -------------------------------------------------------------------


def _rejected(env, seed) -> ServiceError:
    async def scenario(session):
        await seed_guardrail(session)
        await seed(session)
        with pytest.raises(ServiceError) as caught:
            await publish(session)
        current = await session.get(Guardrail, (TENANT, ENV, PROJECT, GUARDRAIL))
        assert current.current_version == 1, "a rejected publish must not move current_version"
        return caught.value

    error = run(scenario)
    assert error.error_type == "EVAL_GATE_NOT_MET"
    assert error.status_code == 409
    assert env["redis"].values == {}
    assert publish_events(env["events"]) == []
    return error


def _failed_checks(error: ServiceError) -> list[str]:
    return [item["check"] for item in error.details["failed_checks"]]


def test_no_eval_run_is_rejected(env) -> None:
    async def no_run(session):
        return None

    error = _rejected(env, no_run)
    assert _failed_checks(error) == ["eval_run"]
    assert error.details["run_id"] is None


def test_run_for_another_version_does_not_count(env) -> None:
    async def other_version(session):
        await seed_run(session, version=1)

    assert _failed_checks(_rejected(env, other_version)) == ["eval_run"]


def test_failed_or_running_runs_do_not_count(env) -> None:
    async def not_completed(session):
        await seed_run(session, status="FAILED")
        await seed_run(session, status="RUNNING")

    assert _failed_checks(_rejected(env, not_completed)) == ["eval_run"]


def test_too_few_cases_is_rejected(env) -> None:
    async def small(session):
        await seed_run(session, total=3)

    error = _rejected(env, small)
    assert error.details["failed_checks"] == [
        {"check": "min_eval_cases", "required": 10, "actual": 3}
    ]


def test_accuracy_below_threshold_is_rejected(env) -> None:
    async def inaccurate(session):
        await seed_run(session, accuracy=0.5)

    assert _failed_checks(_rejected(env, inaccurate)) == ["min_expected_action_accuracy"]


def test_unlabelled_run_cannot_satisfy_an_accuracy_threshold(env) -> None:
    async def unlabelled(session):
        await seed_run(session, accuracy=None)

    assert _failed_checks(_rejected(env, unlabelled)) == ["min_expected_action_accuracy"]


def test_latest_completed_run_decides(env) -> None:
    async def regressed(session):
        earlier = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=1)
        await seed_run(session, accuracy=0.95, completed_at=earlier)
        await seed_run(session, accuracy=0.4)

    assert _failed_checks(_rejected(env, regressed)) == ["min_expected_action_accuracy"]


def test_p95_latency_above_threshold_is_rejected(env, monkeypatch) -> None:
    monkeypatch.setattr(settings, "publish_gate_max_p95_latency_ms", 500.0)

    async def slow(session):
        await seed_run(session, latencies=[100.0] * 18 + [900.0, 950.0])

    error = _rejected(env, slow)
    assert error.details["failed_checks"] == [
        {"check": "max_p95_latency_ms", "required": 500.0, "actual": 900.0}
    ]


def test_tenant_gate_row_overrides_defaults(env) -> None:
    async def strict_row(session):
        async with session.begin():
            session.add(
                GuardrailPublishGate(
                    tenant_id=TENANT,
                    environment_id=ENV,
                    project_id=PROJECT,
                    guardrail_id=GUARDRAIL,
                    min_expected_action_accuracy=0.95,
                    min_eval_cases=50,
                )
            )
        await seed_run(session, total=12, accuracy=0.9)

    assert sorted(_failed_checks(_rejected(env, strict_row))) == [
        "min_eval_cases",
        "min_expected_action_accuracy",
    ]


# --- passing and bypass ----------------------------------------------------------


def test_passing_run_publishes(env) -> None:
    async def scenario(session):
        await seed_guardrail(session)
        run_id = await seed_run(session, latencies=[50.0] * 12)
        response = await publish(session)
        current = await session.get(Guardrail, (TENANT, ENV, PROJECT, GUARDRAIL))
        return run_id, response, current.current_version

    run_id, response, current_version = run(scenario)
    assert current_version == 2
    assert response.redis_key in env["redis"].values
    assert response.eval_gate["status"] == "passed"
    assert response.eval_gate["run_id"] == str(run_id)
    [event] = publish_events(env["events"])
    assert event["eval_gate_status"] == "passed"
    assert event["eval_gate_bypassed"] is False
    assert event["eval_gate_run_id"] == str(run_id)


def test_bypass_without_reason_is_rejected(env) -> None:
    async def scenario(session):
        await seed_guardrail(session)
        with pytest.raises(ServiceError) as caught:
            await publish(session, bypass_eval_gate=True, bypass_reason="   ")
        return caught.value

    error = run(scenario)
    assert error.error_type == "BYPASS_REASON_REQUIRED"
    assert error.status_code == 422
    assert env["redis"].values == {}


def test_bypass_without_reason_allowed_when_setting_off(env, monkeypatch) -> None:
    monkeypatch.setattr(settings, "publish_gate_require_bypass_reason", False)

    async def scenario(session):
        await seed_guardrail(session)
        return await publish(session, bypass_eval_gate=True)

    response = run(scenario)
    assert response.eval_gate["status"] == "bypassed"
    assert response.eval_gate["reason"] is None


def test_bypass_with_reason_publishes_and_is_recorded(env) -> None:
    async def scenario(session):
        await seed_guardrail(session)
        await seed_run(session, total=3)
        return await publish(
            session, bypass_eval_gate=True, bypass_reason="hotfix for INC-42"
        )

    response = run(scenario)
    assert response.redis_key in env["redis"].values
    assert response.eval_gate["status"] == "bypassed"
    assert response.eval_gate["bypass_kind"] == "bypass_eval_gate"
    assert response.eval_gate["reason"] == "hotfix for INC-42"
    [event] = publish_events(env["events"])
    assert event["eval_gate_status"] == "bypassed"
    assert event["eval_gate_bypassed"] is True
    assert event["eval_gate_bypass_kind"] == "bypass_eval_gate"
    assert event["eval_gate_reason"] == "hotfix for INC-42"
    assert event["eval_gate_failed_checks"] == "min_eval_cases"
    assert event["break_glass"] is False


def test_break_glass_counts_as_a_bypass(env) -> None:
    async def scenario(session):
        # created_by set and no approver: break-glass skips four-eyes as well.
        await seed_guardrail(session, created_by="alice@example.com")
        return await publish(
            session, approver_id=None, break_glass_reason="engine outage, SEV1"
        )

    response = run(scenario)
    assert response.eval_gate["status"] == "bypassed"
    assert response.eval_gate["bypass_kind"] == "break_glass"
    assert response.eval_gate["reason"] == "engine outage, SEV1"
    [event] = publish_events(env["events"])
    assert event["break_glass"] is True
    assert event["eval_gate_bypass_kind"] == "break_glass"
    assert event["eval_gate_reason"] == "engine outage, SEV1"
    assert event["eval_gate_failed_checks"] == "eval_run"


def test_gate_disabled_publishes_without_a_run(env, monkeypatch) -> None:
    monkeypatch.setattr(settings, "publish_gate_enforced", False)

    async def scenario(session):
        await seed_guardrail(session)
        return await publish(session)

    response = run(scenario)
    assert response.eval_gate == {
        "status": "skipped",
        "reason": "gate_disabled",
        "bypass_kind": None,
        "run_id": None,
        "failed_checks": [],
    }
    [event] = publish_events(env["events"])
    assert event["eval_gate_status"] == "skipped"
    assert event["eval_gate_reason"] == "gate_disabled"


def test_republishing_the_live_version_skips_the_gate(env) -> None:
    """The Control Center re-publishes v1 right after it was auto-published."""

    async def scenario(session):
        await seed_guardrail(session, versions=(1,), current=1)
        key = admin.build_snapshot_key(str(TENANT), ENV, PROJECT, GUARDRAIL, 1)
        env["redis"].values[key] = "{}"
        return await publish(session, version=1, approver_id=None)

    response = run(scenario)
    assert response.eval_gate["status"] == "skipped"
    assert response.eval_gate["reason"] == "already_live_version"


def test_current_version_without_a_live_snapshot_is_gated(env) -> None:
    """current_version alone is caller-controlled (POST /guardrails); it proves nothing."""

    async def scenario(session):
        await seed_guardrail(session, versions=(1,), current=1)
        with pytest.raises(ServiceError) as caught:
            await publish(session, version=1)
        return caught.value

    assert run(scenario).error_type == "EVAL_GATE_NOT_MET"


# --- exempt paths ----------------------------------------------------------------


def library_request(**overrides) -> admin_models.GuardrailLibraryDeployRequest:
    body = {
        "tenant_id": TENANT,
        "environment_id": ENV,
        "project_id": PROJECT,
        "template_id": "gr-owasp-llm-top-10-2025-baseline",
        "guardrail_id": "gr-library",
        "publish": True,
    }
    body.update(overrides)
    return admin_models.GuardrailLibraryDeployRequest(**body)


def test_library_deploy_is_exempt_by_default_and_recorded(env) -> None:
    async def scenario(session):
        return await admin.deploy_guardrail_library(
            library_request(), session=session, principal=ADMIN
        )

    response = run(scenario)
    assert response.published is True
    assert response.redis_key in env["redis"].values
    assert response.eval_gate["status"] == "skipped"
    assert response.eval_gate["reason"] == "library_deploy_exempt"
    [event] = publish_events(env["events"])
    assert event["guardrail_id"] == "gr-library"
    assert event["eval_gate_status"] == "skipped"
    assert event["eval_gate_reason"] == "library_deploy_exempt"


def test_library_deploy_without_publish_needs_no_gate(env, monkeypatch) -> None:
    monkeypatch.setattr(settings, "publish_gate_enforce_on_library_deploy", True)

    async def scenario(session):
        return await admin.deploy_guardrail_library(
            library_request(publish=False), session=session, principal=ADMIN
        )

    response = run(scenario)
    assert response.published is False
    assert response.eval_gate is None
    assert env["redis"].values == {}


def test_library_deploy_is_gated_when_setting_on(env, monkeypatch) -> None:
    monkeypatch.setattr(settings, "publish_gate_enforce_on_library_deploy", True)

    async def scenario(session):
        with pytest.raises(ServiceError) as caught:
            await admin.deploy_guardrail_library(
                library_request(), session=session, principal=ADMIN
            )
        created = await session.get(Guardrail, (TENANT, ENV, PROJECT, "gr-library"))
        return caught.value, created

    error, created = run(scenario)
    assert error.error_type == "EVAL_GATE_NOT_MET"
    assert created is None, "a rejected deploy must leave nothing behind"
    assert env["redis"].values == {}


def _create_first_version(session):
    return admin.create_guardrail_version(
        GUARDRAIL,
        admin_models.GuardrailVersionCreateRequest(
            tenant_id=TENANT,
            environment_id=ENV,
            project_id=PROJECT,
            version=1,
            snapshot_json=snapshot(1),
        ),
        session=session,
        principal=ADMIN,
    )


def test_first_version_is_auto_published_by_default_and_recorded(env) -> None:
    async def scenario(session):
        await seed_guardrail(session, versions=())
        return await _create_first_version(session)

    response = run(scenario)
    assert response.auto_published is True
    assert response.eval_gate["reason"] == "first_version_exempt"
    assert len(env["redis"].values) == 1
    [event] = publish_events(env["events"])
    assert event["guardrail_version"] == 1
    assert event["eval_gate_status"] == "skipped"
    assert event["eval_gate_reason"] == "first_version_exempt"


def test_first_version_stays_a_draft_when_setting_on(env, monkeypatch) -> None:
    monkeypatch.setattr(settings, "publish_gate_enforce_on_library_deploy", True)

    async def scenario(session):
        await seed_guardrail(session, versions=())
        created = await _create_first_version(session)
        with pytest.raises(ServiceError) as caught:
            await publish(session, version=1)
        return created, caught.value

    created, error = run(scenario)
    assert created.auto_published is False
    assert created.eval_gate["reason"] == "first_version_left_unpublished"
    assert env["redis"].values == {}
    assert publish_events(env["events"]) == []
    assert error.error_type == "EVAL_GATE_NOT_MET"
