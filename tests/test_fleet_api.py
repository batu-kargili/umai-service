from __future__ import annotations

import asyncio
import datetime as dt
import json
import uuid

import pytest

from app.api.fleet import RevokeRequest, get_fleet_device, list_fleet_devices, revoke_fleet_device
from app.core.admin_auth import AdminPrincipal
from app.core.errors import ServiceError
from app.models.db import AdrDevice, AdrDeviceAuditEvent, Tenant
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
