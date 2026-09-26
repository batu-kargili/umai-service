"""Publishing from the Control Center vs the four-eyes check (go-live WS5.3).

The suspected bug: the Control Center publishes with ``approver_id == publisher_id``
(the signed-in user) and, after the agentic builder, publishes v1 with no approver at
all, while ``publish_guardrail_version`` enforces an approver and four-eyes.

What actually happens: both checks run only when the version has ``created_by``, and
nothing sets ``created_by`` from the caller. The service copies it from the create
request body, and the Control Center (release pin 9e7b0ac, ``lib/api.ts``
``createGuardrailVersion``) never sends it; its ``/api/admin`` proxy forwards the body
untouched. So every version the Control Center creates has ``created_by = NULL`` and
four-eyes never fires: UI publishes succeed, and the "approval" is self-asserted.

These tests pin that behaviour with the exact request bodies the Control Center sends,
isolated from the eval gate. The last test shows the same UI publish once the eval gate
is on: it is the eval gate, not four-eyes, that the Control Center now has to handle.
"""

from __future__ import annotations

import pytest

from app.api import admin
from app.core.errors import ServiceError
from app.core.settings import settings
from app.models import admin as admin_models
from tests.test_publish_eval_gate import (  # noqa: F401  (env is a fixture)
    ADMIN,
    ENV,
    GUARDRAIL,
    PROJECT,
    TENANT,
    env,
    publish_events,
    run,
    snapshot,
)

ACTOR = "alice@example.com"


async def create_like_control_center(session, version: int) -> admin_models.GuardrailVersionResponse:
    """POST /guardrails/{id}/versions with the body shape ``createGuardrailVersion`` sends."""
    return await admin.create_guardrail_version(
        GUARDRAIL,
        admin_models.GuardrailVersionCreateRequest(
            tenant_id=TENANT,
            environment_id=ENV,
            project_id=PROJECT,
            version=version,
            snapshot_json=snapshot(version),
        ),
        session=session,
        principal=ADMIN,
    )


async def create_guardrail(session) -> None:
    await admin.create_guardrail(
        admin_models.GuardrailCreateRequest(
            tenant_id=TENANT,
            environment_id=ENV,
            project_id=PROJECT,
            guardrail_id=GUARDRAIL,
            name="Four eyes",
            current_version=1,
        ),
        session=session,
        principal=ADMIN,
    )


async def publish(session, version: int, **body):
    return await admin.publish_guardrail_version(
        GUARDRAIL,
        version,
        admin_models.PublishRequest(
            tenant_id=TENANT, environment_id=ENV, project_id=PROJECT, **body
        ),
        session=session,
        principal=ADMIN,
    )


@pytest.fixture
def gate_off(env, monkeypatch):
    monkeypatch.setattr(settings, "publish_gate_enforced", False)
    return env


def test_control_center_versions_have_no_created_by(gate_off) -> None:
    async def scenario(session):
        await create_guardrail(session)
        return await create_like_control_center(session, 1)

    created = run(scenario)
    assert created.created_by is None
    # The auto-publish fills approved_by with the "system" placeholder.
    assert created.approved_by == "system"
    assert created.auto_published is True


def test_self_approved_publish_from_the_details_panel_succeeds(gate_off) -> None:
    """guardrails/page.tsx handlePublishSelectedVersion: approver_id == publisher_id."""

    async def scenario(session):
        await create_guardrail(session)
        await create_like_control_center(session, 1)
        await create_like_control_center(session, 2)
        return await publish(session, 2, publisher_id=ACTOR, approver_id=ACTOR)

    response = run(scenario)
    assert response.redis_key.endswith(":2")
    auto_v1, event = publish_events(gate_off["events"])
    assert auto_v1["guardrail_version"] == 1
    assert event["guardrail_version"] == 2
    assert event["approver_id"] == ACTOR
    assert event["actor_id"] == ACTOR


def test_agentic_v1_publish_without_approver_succeeds(gate_off) -> None:
    """guardrails/page.tsx agentic approve: publish v1 with no publisher/approver."""

    async def scenario(session):
        await create_guardrail(session)
        await create_like_control_center(session, 1)
        return await publish(session, 1)

    assert run(scenario).redis_key.endswith(":1")


def test_four_eyes_fires_only_when_created_by_is_sent(gate_off) -> None:
    """The counterfactual: a client that does send created_by hits both checks."""

    async def scenario(session):
        await create_guardrail(session)
        await create_like_control_center(session, 1)
        await admin.create_guardrail_version(
            GUARDRAIL,
            admin_models.GuardrailVersionCreateRequest(
                tenant_id=TENANT,
                environment_id=ENV,
                project_id=PROJECT,
                version=2,
                created_by=ACTOR,
                snapshot_json=snapshot(2),
            ),
            session=session,
            principal=ADMIN,
        )
        errors = []
        for body in ({}, {"publisher_id": ACTOR, "approver_id": ACTOR}):
            with pytest.raises(ServiceError) as caught:
                await publish(session, 2, **body)
            errors.append(caught.value)
        ok = await publish(session, 2, approver_id="bob@example.com")
        return errors, ok

    (missing, same), ok = run(scenario)
    assert (missing.error_type, missing.status_code) == ("APPROVER_REQUIRED", 422)
    assert (same.error_type, same.status_code) == ("FOUR_EYES_REQUIRED", 409)
    assert ok.redis_key.endswith(":2")


def test_control_center_publish_now_hits_the_eval_gate(env) -> None:
    """With the gate on (the default), the same UI publish of v2 is a 409 until 5.2."""

    async def scenario(session):
        await create_guardrail(session)
        await create_like_control_center(session, 1)
        await create_like_control_center(session, 2)
        with pytest.raises(ServiceError) as caught:
            await publish(session, 2, publisher_id=ACTOR, approver_id=ACTOR)
        # The agentic flow's re-publish of the auto-published v1 keeps working.
        republished = await publish(session, 1)
        return caught.value, republished

    error, republished = run(scenario)
    assert (error.error_type, error.status_code) == ("EVAL_GATE_NOT_MET", 409)
    assert republished.eval_gate["reason"] == "already_live_version"
