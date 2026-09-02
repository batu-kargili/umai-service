from __future__ import annotations

import asyncio
import datetime as dt
import json
import uuid

import pytest

from sqlalchemy import select

from app.api import adr
from app.api.fleet import (
    BootstrapTokenRequest,
    RevokeRequest,
    get_fleet_device,
    issue_bootstrap_token,
    list_fleet_devices,
    revoke_fleet_device,
)
from app.core.admin_auth import AdminPrincipal
from app.core.agent_mesh import hash_secret
from app.core.errors import ServiceError
from app.models.db import AdrBootstrapToken, AdrDevice, AdrDeviceAuditEvent, Tenant
from tests.conftest import db_session

TENANT = uuid.UUID("11111111-1111-1111-1111-111111111111")
OTHER = uuid.UUID("22222222-2222-2222-2222-222222222222")
AUDITOR = AdminPrincipal(TENANT, ["tenant-auditor"], "audit@example.com")
ADMIN = AdminPrincipal(TENANT, ["tenant-admin"], "admin@example.com")


async def _seed(db):
    now = dt.datetime.now(dt.timezone.utc)
    db.add_all(
        [
            Tenant(tenant_id=TENANT, name="Fleet", collection_mode="metadata"),
            Tenant(tenant_id=OTHER, name="Other", collection_mode="full_session"),
            AdrDevice(
                tenant_id=TENANT,
                device_id="adr-1",
                hostname="WIN-01",
                os="Windows",
                os_version="11",
                agent_version="1.0.0",
                status="active",
                last_heartbeat_at=now,
                last_successful_upload_at=now - dt.timedelta(minutes=2),
                queue_depth=3,
                metadata_json=json.dumps(
                    {
                        "collector_kind": "adr",
                        "supported_sources": ["codex", "claude"],
                        "observed_sources": ["codex"],
                        "health_status": "degraded",
                        "status_detail": "PARTIAL_INGEST",
                    }
                ),
            ),
            AdrDevice(
                tenant_id=TENANT,
                device_id="legacy-sensor",
                status="active",
                metadata_json=json.dumps({"collector_kind": "sensor"}),
            ),
            AdrDevice(
                tenant_id=OTHER,
                device_id="other-adr",
                status="active",
                metadata_json=json.dumps({"collector_kind": "adr"}),
            ),
        ]
    )
    await db.commit()


@pytest.fixture(autouse=True)
def adr_signing_secret():
    """Bootstrap tokens are signed, so the fleet API needs the ADR secret set.

    The service refuses to mint one without it (`AUTH_MISCONFIGURED`), which is
    the right production behaviour and just needs supplying here.
    """
    from app.core.settings import settings

    original = settings.adr_ingest_jwt_hs256_secret
    settings.adr_ingest_jwt_hs256_secret = "fleet-test-secret"
    try:
        yield
    finally:
        settings.adr_ingest_jwt_hs256_secret = original


def _run(callback):
    async def scenario():
        async with db_session() as db:
            await _seed(db)
            return await callback(db)

    return asyncio.run(scenario())


def test_list_is_tenant_safe_and_excludes_retiring_sensor_rows():
    page = _run(
        lambda db: list_fleet_devices(
            health=None,
            status=None,
            source=None,
            session=db,
            x_tenant_id=TENANT,
            principal=AUDITOR,
        )
    )
    assert page.total == 1
    assert page.items[0].device_id == "adr-1"
    assert page.items[0].last_ingest_at is not None
    assert page.items[0].observed_sources == ["codex"]
    assert page.items[0].collection_mode == "metadata"


def test_health_and_source_filters_are_applied():
    page = _run(
        lambda db: list_fleet_devices(
            health="degraded",
            status=None,
            source="codex",
            session=db,
            x_tenant_id=TENANT,
            principal=AUDITOR,
        )
    )
    assert page.total == 1


def test_revoke_requires_admin_and_writes_audit_event():
    async def scenario(db):
        with pytest.raises(ServiceError) as denied:
            await revoke_fleet_device(
                "adr-1", RevokeRequest(reason="lost device"), db, TENANT, AUDITOR
            )
        assert denied.value.status_code == 403
        detail = await revoke_fleet_device(
            "adr-1", RevokeRequest(reason="lost device"), db, TENANT, ADMIN
        )
        return detail

    detail = _run(scenario)
    assert detail.status == "revoked"
    event = next(item for item in detail.audit_events if item.event_type == "device_revoked")
    assert event.actor == "admin@example.com"
    assert event.detail == {"reason": "lost device"}


def test_detail_does_not_cross_tenant_boundary():
    async def scenario(db):
        with pytest.raises(ServiceError) as raised:
            await get_fleet_device("other-adr", db, TENANT, AUDITOR)
        return raised.value

    assert _run(scenario).status_code == 404


# ---------------------------------------------------------------------------
# Bootstrap token issuance
# ---------------------------------------------------------------------------


def test_issuing_a_bootstrap_token_makes_enrolment_possible():
    """Without this endpoint a collector cannot be enrolled at all.

    `POST /adr/bootstrap` only accepts a token whose hash is already a row in
    `adr_bootstrap_tokens`, and nothing else in the product writes that row —
    so enrolment was documented in the installer guide and unreachable in
    practice.
    """

    async def scenario(db):
        response = await issue_bootstrap_token(
            BootstrapTokenRequest(), db, TENANT, ADMIN
        )
        row = (
            await db.execute(
                select(AdrBootstrapToken).where(AdrBootstrapToken.id == response.token_id)
            )
        ).scalar_one()
        return response, row

    response, row = _run(scenario)

    assert response.tenant_id == TENANT
    assert response.token
    assert row.created_by == "admin@example.com"
    assert row.used_at is None
    # Stored hashed: the plaintext in the response is the only copy that ever
    # exists, which is why the response says so.
    assert response.token not in (row.token_hash or "")
    assert hash_secret(response.token) == row.token_hash


def test_the_issued_token_is_accepted_by_bootstrap_exactly_once():
    async def scenario(db):
        issued = await issue_bootstrap_token(BootstrapTokenRequest(), db, TENANT, ADMIN)
        principal = await adr._authenticate_bootstrap(
            db, f"Bearer {issued.token}", TENANT, "new-device"
        )
        with pytest.raises(ServiceError) as reused:
            await adr._authenticate_bootstrap(
                db, f"Bearer {issued.token}", TENANT, "new-device"
            )
        return principal, reused.value

    principal, error = _run(scenario)

    assert principal.tenant_id == TENANT
    assert error.error_type == "ADR_BOOTSTRAP_TOKEN_CONSUMED"
    assert error.status_code == 409


def test_a_device_bound_token_is_rejected_for_another_device():
    async def scenario(db):
        issued = await issue_bootstrap_token(
            BootstrapTokenRequest(device_id="adr-2"), db, TENANT, ADMIN
        )
        with pytest.raises(ServiceError) as wrong_device:
            await adr._authenticate_bootstrap(
                db, f"Bearer {issued.token}", TENANT, "somebody-else"
            )
        return issued, wrong_device.value

    issued, error = _run(scenario)

    assert issued.device_id == "adr-2"
    assert error.error_type == "ADR_BOOTSTRAP_TOKEN_INVALID"


def test_issuing_requires_admin_and_is_tenant_scoped():
    async def scenario(db):
        with pytest.raises(ServiceError) as denied:
            await issue_bootstrap_token(BootstrapTokenRequest(), db, TENANT, AUDITOR)
        with pytest.raises(ServiceError) as cross_tenant:
            await issue_bootstrap_token(BootstrapTokenRequest(), db, OTHER, ADMIN)
        return denied.value, cross_tenant.value

    denied, cross_tenant = _run(scenario)

    assert denied.status_code == 403
    assert cross_tenant.status_code in (403, 404)


def test_a_bound_token_shows_up_in_the_device_timeline():
    async def scenario(db):
        await issue_bootstrap_token(
            BootstrapTokenRequest(device_id="adr-1"), db, TENANT, ADMIN
        )
        return await get_fleet_device("adr-1", db, TENANT, AUDITOR)

    detail = _run(scenario)
    event = next(
        item for item in detail.audit_events if item.event_type == "bootstrap_token_issued"
    )
    assert event.actor == "admin@example.com"
