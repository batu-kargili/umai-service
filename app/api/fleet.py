"""Tenant-safe operator API for the ADR collector fleet."""

from __future__ import annotations

import datetime as dt
import json
import uuid
from typing import Any, Literal

from fastapi import APIRouter, Depends, Header, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.adr import (
    ADR_BOOTSTRAP_TTL_SECONDS,
    _audit_device_event,
    _build_adr_bootstrap_token_row,
    _load_metadata,
)
from app.core.admin_auth import (
    AdminPrincipal,
    ensure_tenant_access,
    get_admin_principal,
    require_any_admin_role,
)
from app.core.db import get_session, tenant_scope
from app.core.errors import ServiceError
from app.core.settings import settings
from app.models.db import AdrDevice, AdrDeviceAuditEvent, Tenant

fleet_admin_router = APIRouter(
    prefix="/api/v1/admin/adr",
    tags=["adr-fleet-admin"],
    dependencies=[Depends(get_admin_principal)],
)


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class FleetDevice(_Model):
    device_id: str
    hostname: str | None = None
    user_email: str | None = None
    os: str | None = None
    os_version: str | None = None
    collector_version: str | None = None
    status: str
    health_status: str
    stale: bool
    status_detail: str | None = None
    last_seen_at: dt.datetime | None = None
    last_ingest_at: dt.datetime | None = None
    supported_sources: list[str] = Field(default_factory=list)
    observed_sources: list[str] = Field(default_factory=list)
    collection_mode: str
    queue_depth: int = 0
    enrolled_at: dt.datetime


class FleetAuditEvent(_Model):
    event_type: str
    actor: str
    detail: dict[str, Any] | None = None
    occurred_at: dt.datetime


class FleetDeviceDetail(FleetDevice):
    audit_events: list[FleetAuditEvent] = Field(default_factory=list)


class FleetPage(_Model):
    items: list[FleetDevice]
    total: int


class RevokeRequest(_Model):
    reason: str = Field(min_length=3, max_length=500)


class BootstrapTokenRequest(_Model):
    # Binding the token to a device id is the stronger form: a leaked token is
    # then useless anywhere else. It is optional because an operator enrolling
    # a machine from the console does not always know the id the collector will
    # derive for it.
    device_id: str | None = Field(default=None, min_length=1, max_length=128)
    expires_in_seconds: int = Field(
        default=ADR_BOOTSTRAP_TTL_SECONDS, ge=300, le=24 * 60 * 60
    )


class BootstrapTokenResponse(_Model):
    token: str
    token_id: uuid.UUID
    tenant_id: uuid.UUID
    device_id: str | None = None
    expires_at: dt.datetime
    # Said plainly because the value is not recoverable: it is stored hashed.
    note: str = "Single use. Shown once — it is stored hashed and cannot be retrieved again."


def _access(principal: AdminPrincipal, tenant_id: uuid.UUID, *, write: bool = False) -> None:
    ensure_tenant_access(principal, tenant_id)
    if write:
        require_any_admin_role(principal, "tenant-admin", "platform-admin")
    else:
        require_any_admin_role(principal, "tenant-auditor", "tenant-admin", "platform-admin")


def _string_list(value: Any) -> list[str]:
    return sorted({str(item) for item in value}) if isinstance(value, list) else []


def _is_adr(device: AdrDevice) -> bool:
    return _load_metadata(device).get("collector_kind") == "adr"


def _to_device(device: AdrDevice, collection_mode: str) -> FleetDevice:
    metadata = _load_metadata(device)
    now = dt.datetime.now(dt.timezone.utc)
    last_seen = device.last_heartbeat_at
    if last_seen and last_seen.tzinfo is None:
        last_seen = last_seen.replace(tzinfo=dt.timezone.utc)
    stale = last_seen is None or (now - last_seen).total_seconds() > int(
        settings.adr_heartbeat_stale_seconds
    )
    explicit_health = str(metadata.get("health_status") or "unknown")
    health = "stale" if stale and device.status == "active" else explicit_health
    if device.status != "active":
        health = device.status
    return FleetDevice(
        device_id=device.device_id,
        hostname=device.hostname,
        user_email=device.last_user_email,
        os=device.os,
        os_version=device.os_version,
        collector_version=device.agent_version,
        status=device.status,
        health_status=health,
        stale=stale,
        status_detail=str(metadata.get("status_detail")) if metadata.get("status_detail") else None,
        last_seen_at=last_seen,
        last_ingest_at=device.last_successful_upload_at,
        supported_sources=_string_list(metadata.get("supported_sources")),
        observed_sources=_string_list(metadata.get("observed_sources")),
        collection_mode=collection_mode,
        queue_depth=int(device.queue_depth or 0),
        enrolled_at=device.enrolled_at,
    )


@fleet_admin_router.get("/devices", response_model=FleetPage)
async def list_fleet_devices(
    health: str | None = Query(default=None),
    status: str | None = Query(default=None),
    source: str | None = Query(default=None),
    session: AsyncSession = Depends(get_session),
    x_tenant_id: uuid.UUID = Header(alias="X-Tenant-Id"),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> FleetPage:
    _access(principal, x_tenant_id)
    async with session.begin():
        async with tenant_scope(session, str(x_tenant_id)):
            tenant = await session.get(Tenant, x_tenant_id)
            if tenant is None:
                raise ServiceError("NOT_FOUND", "Tenant not found", 404)
            rows = (
                await session.execute(
                    select(AdrDevice)
                    .where(AdrDevice.tenant_id == x_tenant_id)
                    .order_by(AdrDevice.last_heartbeat_at.desc().nullslast())
                )
            ).scalars().all()
    items = [_to_device(row, tenant.collection_mode) for row in rows if _is_adr(row)]
    if health:
        items = [item for item in items if item.health_status == health]
    if status:
        items = [item for item in items if item.status == status]
    if source:
        items = [item for item in items if source in item.observed_sources]
    return FleetPage(items=items, total=len(items))


@fleet_admin_router.get("/devices/{device_id}", response_model=FleetDeviceDetail)
async def get_fleet_device(
    device_id: str,
    session: AsyncSession = Depends(get_session),
    x_tenant_id: uuid.UUID = Header(alias="X-Tenant-Id"),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> FleetDeviceDetail:
    _access(principal, x_tenant_id)
    async with session.begin():
        async with tenant_scope(session, str(x_tenant_id)):
            tenant = await session.get(Tenant, x_tenant_id)
            device = await session.get(AdrDevice, (x_tenant_id, device_id))
            if tenant is None or device is None or not _is_adr(device):
                raise ServiceError("NOT_FOUND", "ADR collector device not found", 404)
            events = (
                await session.execute(
                    select(AdrDeviceAuditEvent)
                    .where(
                        AdrDeviceAuditEvent.tenant_id == x_tenant_id,
                        AdrDeviceAuditEvent.device_id == device_id,
                    )
                    .order_by(AdrDeviceAuditEvent.occurred_at.desc())
                    .limit(100)
                )
            ).scalars().all()
    summary = _to_device(device, tenant.collection_mode)
    return FleetDeviceDetail(
        **summary.model_dump(),
        audit_events=[
            FleetAuditEvent(
                event_type=event.event_type,
                actor=event.actor,
                detail=json.loads(event.detail_json) if event.detail_json else None,
                occurred_at=event.occurred_at,
            )
            for event in events
        ],
    )


@fleet_admin_router.post("/bootstrap-tokens", response_model=BootstrapTokenResponse)
async def issue_bootstrap_token(
    payload: BootstrapTokenRequest,
    session: AsyncSession = Depends(get_session),
    x_tenant_id: uuid.UUID = Header(alias="X-Tenant-Id"),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> BootstrapTokenResponse:
    """Mint the single-use credential a collector needs for its first run.

    Without this there is no way to enrol a device through the product: the
    collector's whole identity chain starts at a bootstrap token, the token has
    to exist as a hashed row before `POST /adr/bootstrap` will accept it, and
    nothing but this endpoint creates that row. Enrolment was documented in the
    installer guide and impossible to perform.

    The plaintext token is returned exactly once. `adr_bootstrap_tokens` keeps
    only its hash, along with who minted it and when — that row is the issuance
    record, which is why an unbound token needs no separate device audit event.
    """
    _access(principal, x_tenant_id, write=True)
    actor = principal.subject or "admin"

    async with session.begin():
        async with tenant_scope(session, str(x_tenant_id)):
            tenant = await session.get(Tenant, x_tenant_id)
            if tenant is None:
                raise ServiceError("NOT_FOUND", "Tenant not found", 404)

            token, row = _build_adr_bootstrap_token_row(
                tenant_id=x_tenant_id,
                expires_in_seconds=payload.expires_in_seconds,
                device_id=payload.device_id,
                created_by=actor,
            )
            session.add(row)

            if payload.device_id:
                # A token bound to a known device belongs in that device's
                # timeline; an operator reading it should see the credential
                # being issued next to the enrolment it produced.
                _audit_device_event(
                    session,
                    tenant_id=x_tenant_id,
                    device_id=payload.device_id,
                    event_type="bootstrap_token_issued",
                    actor=actor,
                    detail={"token_id": str(row.id), "expires_at": row.expires_at.isoformat()},
                )

    return BootstrapTokenResponse(
        token=token,
        token_id=row.id,
        tenant_id=x_tenant_id,
        device_id=payload.device_id,
        expires_at=row.expires_at,
    )


@fleet_admin_router.post("/devices/{device_id}/revoke", response_model=FleetDeviceDetail)
async def revoke_fleet_device(
    device_id: str,
    payload: RevokeRequest,
    session: AsyncSession = Depends(get_session),
    x_tenant_id: uuid.UUID = Header(alias="X-Tenant-Id"),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> FleetDeviceDetail:
    _access(principal, x_tenant_id, write=True)
    actor = principal.subject or "admin"
    async with session.begin():
        async with tenant_scope(session, str(x_tenant_id)):
            device = await session.get(AdrDevice, (x_tenant_id, device_id))
            if device is None or not _is_adr(device):
                raise ServiceError("NOT_FOUND", "ADR collector device not found", 404)
            if device.status != "revoked":
                device.status = "revoked"
                _audit_device_event(
                    session,
                    tenant_id=x_tenant_id,
                    device_id=device_id,
                    event_type="device_revoked",
                    actor=actor,
                    detail={"reason": payload.reason},
                )
    return await get_fleet_device(device_id, session, x_tenant_id, principal)
