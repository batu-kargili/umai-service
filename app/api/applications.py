"""Admin API for the AI application registry and usage dashboard.

Backs the Control Center "Applications" page: catalog CRUD plus a
session-based usage aggregation (risk distribution, category totals,
per-app sessions/users/sensitive counts with trend).
"""

from __future__ import annotations

import csv
import datetime as dt
import io
import json
import uuid
from typing import Any

from fastapi import APIRouter, Depends, Header, Query, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import distinct, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.admin_auth import (
    AdminPrincipal,
    ensure_tenant_access,
    get_admin_principal,
    require_admin_role,
)
from app.core.app_catalog import (
    APP_TYPES,
    CATEGORIES,
    RISK_LEVELS,
    ensure_tenant_catalog,
)
from app.core.db import get_session, tenant_scope
from app.core.errors import ServiceError
from app.models.db import AiApplication, AiUsageSession

applications_admin_router = APIRouter(
    prefix="/api/v1/admin",
    tags=["applications-admin"],
    dependencies=[Depends(get_admin_principal)],
)

UNCLASSIFIED_SLUG = "__unclassified__"


class _BaseModel(BaseModel):
    model_config = ConfigDict(extra="ignore")


class ApplicationCatalogEntryResponse(_BaseModel):
    app_id: uuid.UUID
    slug: str
    name: str
    vendor: str | None = None
    category: str
    risk_level: str
    icon_key: str | None = None
    domains: list[str] = Field(default_factory=list)
    process_names: list[str] = Field(default_factory=list)
    ports: list[int] = Field(default_factory=list)
    app_type: str
    is_sanctioned: bool
    is_training: bool
    sensor_capture: bool
    inventory_only: bool
    path_hint: str | None = None
    enabled: bool
    source: str
    is_customized: bool
    created_at: dt.datetime | None = None
    updated_at: dt.datetime | None = None


class ApplicationCatalogCreateRequest(_BaseModel):
    slug: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9][a-z0-9\-]*$")
    name: str = Field(min_length=1, max_length=200)
    vendor: str | None = Field(default=None, max_length=200)
    category: str = "other"
    risk_level: str = "none"
    icon_key: str | None = Field(default=None, max_length=64)
    domains: list[str] = Field(default_factory=list)
    process_names: list[str] = Field(default_factory=list)
    ports: list[int] = Field(default_factory=list)
    app_type: str = "web"
    is_sanctioned: bool = False
    is_training: bool = False
    sensor_capture: bool = True
    inventory_only: bool = False
    path_hint: str | None = Field(default=None, max_length=128)


class ApplicationCatalogUpdateRequest(_BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    vendor: str | None = Field(default=None, max_length=200)
    category: str | None = None
    risk_level: str | None = None
    icon_key: str | None = Field(default=None, max_length=64)
    domains: list[str] | None = None
    process_names: list[str] | None = None
    ports: list[int] | None = None
    app_type: str | None = None
    is_sanctioned: bool | None = None
    is_training: bool | None = None
    sensor_capture: bool | None = None
    inventory_only: bool | None = None
    path_hint: str | None = Field(default=None, max_length=128)
    enabled: bool | None = None


class ApplicationTrendPointResponse(_BaseModel):
    day: str
    sessions: int


class ApplicationUsageResponse(_BaseModel):
    app_id: uuid.UUID | None = None
    slug: str
    name: str
    vendor: str | None = None
    icon_key: str | None = None
    category: str
    risk_level: str
    is_training: bool = False
    is_sanctioned: bool = False
    sessions: int
    unique_users: int
    sensitive_count: int
    types: list[str] = Field(default_factory=list)
    last_used_at: dt.datetime | None = None
    trend: list[ApplicationTrendPointResponse] = Field(default_factory=list)
    pct_change: float | None = None


class ApplicationCategoryTotalResponse(_BaseModel):
    category: str
    sessions: int
    apps: int


class ApplicationsDashboardResponse(_BaseModel):
    window_days: int
    generated_at: dt.datetime
    total_sessions: int
    total_apps: int
    risk_distribution: dict[str, int]
    category_totals: list[ApplicationCategoryTotalResponse]
    apps: list[ApplicationUsageResponse]


def _require_tenant_access(
    principal: AdminPrincipal,
    tenant_id: uuid.UUID,
    required_role: str = "tenant-auditor",
) -> None:
    ensure_tenant_access(principal, tenant_id)
    require_admin_role(principal, required_role)


def _json_list(value: Any) -> str:
    return json.dumps(list(value or []), separators=(",", ":"), ensure_ascii=True)


def _parse_json_list(raw: str | None) -> list[Any]:
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return []
    return parsed if isinstance(parsed, list) else []


def _validate_enums(
    category: str | None, risk_level: str | None, app_type: str | None
) -> None:
    if category is not None and category not in CATEGORIES:
        raise ServiceError("INVALID_REQUEST", f"category must be one of {CATEGORIES}", 422)
    if risk_level is not None and risk_level not in RISK_LEVELS:
        raise ServiceError("INVALID_REQUEST", f"risk_level must be one of {RISK_LEVELS}", 422)
    if app_type is not None and app_type not in APP_TYPES:
        raise ServiceError("INVALID_REQUEST", f"app_type must be one of {APP_TYPES}", 422)


def _catalog_row_to_response(row: AiApplication) -> ApplicationCatalogEntryResponse:
    return ApplicationCatalogEntryResponse(
        app_id=row.id,
        slug=row.slug,
        name=row.name,
        vendor=row.vendor,
        category=row.category,
        risk_level=row.risk_level,
        icon_key=row.icon_key,
        domains=[str(item) for item in _parse_json_list(row.domains_json)],
        process_names=[str(item) for item in _parse_json_list(row.process_names_json)],
        ports=[int(item) for item in _parse_json_list(row.ports_json)],
        app_type=row.app_type,
        is_sanctioned=row.is_sanctioned,
        is_training=row.is_training,
        sensor_capture=row.sensor_capture,
        inventory_only=row.inventory_only,
        path_hint=row.path_hint,
        enabled=row.enabled,
        source=row.source,
        is_customized=row.is_customized,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


@applications_admin_router.get(
    "/applications/catalog", response_model=list[ApplicationCatalogEntryResponse]
)
async def list_application_catalog(
    include_disabled: bool = Query(default=True),
    session: AsyncSession = Depends(get_session),
    x_tenant_id: uuid.UUID = Header(alias="X-Tenant-Id"),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> list[ApplicationCatalogEntryResponse]:
    _require_tenant_access(principal, x_tenant_id, required_role="tenant-auditor")
    async with session.begin():
        async with tenant_scope(session, str(x_tenant_id)):
            await ensure_tenant_catalog(session, x_tenant_id)
            stmt = select(AiApplication).where(AiApplication.tenant_id == x_tenant_id)
            if not include_disabled:
                stmt = stmt.where(AiApplication.enabled == True)  # noqa: E712
            stmt = stmt.order_by(AiApplication.name.asc())
            result = await session.execute(stmt)
            rows = result.scalars().all()
    return [_catalog_row_to_response(row) for row in rows]


@applications_admin_router.post(
    "/applications/catalog", response_model=ApplicationCatalogEntryResponse
)
async def create_application_catalog_entry(
    payload: ApplicationCatalogCreateRequest,
    session: AsyncSession = Depends(get_session),
    x_tenant_id: uuid.UUID = Header(alias="X-Tenant-Id"),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> ApplicationCatalogEntryResponse:
    _require_tenant_access(principal, x_tenant_id, required_role="tenant-admin")
    _validate_enums(payload.category, payload.risk_level, payload.app_type)
    now = dt.datetime.now(dt.timezone.utc)
    async with session.begin():
        async with tenant_scope(session, str(x_tenant_id)):
            await ensure_tenant_catalog(session, x_tenant_id)
            existing = await session.execute(
                select(AiApplication.id).where(
                    AiApplication.tenant_id == x_tenant_id,
                    AiApplication.slug == payload.slug,
                )
            )
            if existing.scalars().first() is not None:
                raise ServiceError("CONFLICT", f"Application slug '{payload.slug}' already exists", 409)
            row = AiApplication(
                tenant_id=x_tenant_id,
                id=uuid.uuid4(),
                slug=payload.slug,
                name=payload.name,
                vendor=payload.vendor,
                category=payload.category,
                risk_level=payload.risk_level,
                icon_key=payload.icon_key,
                domains_json=_json_list(payload.domains),
                process_names_json=_json_list(payload.process_names),
                ports_json=_json_list(payload.ports),
                app_type=payload.app_type,
                is_sanctioned=payload.is_sanctioned,
                is_training=payload.is_training,
                sensor_capture=payload.sensor_capture,
                inventory_only=payload.inventory_only,
                path_hint=payload.path_hint,
                enabled=True,
                source="custom",
                is_customized=True,
                created_at=now,
                updated_at=now,
            )
            session.add(row)
    return _catalog_row_to_response(row)


@applications_admin_router.put(
    "/applications/catalog/{app_id}", response_model=ApplicationCatalogEntryResponse
)
async def update_application_catalog_entry(
    app_id: uuid.UUID,
    payload: ApplicationCatalogUpdateRequest,
    session: AsyncSession = Depends(get_session),
    x_tenant_id: uuid.UUID = Header(alias="X-Tenant-Id"),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> ApplicationCatalogEntryResponse:
    _require_tenant_access(principal, x_tenant_id, required_role="tenant-admin")
    _validate_enums(payload.category, payload.risk_level, payload.app_type)
    async with session.begin():
        async with tenant_scope(session, str(x_tenant_id)):
            row = await session.get(AiApplication, (x_tenant_id, app_id))
            if row is None:
                raise ServiceError("NOT_FOUND", "Application not found", 404)
            if payload.name is not None:
                row.name = payload.name
            if payload.vendor is not None:
                row.vendor = payload.vendor
            if payload.category is not None:
                row.category = payload.category
            if payload.risk_level is not None:
                row.risk_level = payload.risk_level
            if payload.icon_key is not None:
                row.icon_key = payload.icon_key
            if payload.domains is not None:
                row.domains_json = _json_list(payload.domains)
            if payload.process_names is not None:
                row.process_names_json = _json_list(payload.process_names)
            if payload.ports is not None:
                row.ports_json = _json_list(payload.ports)
            if payload.app_type is not None:
                row.app_type = payload.app_type
            if payload.is_sanctioned is not None:
                row.is_sanctioned = payload.is_sanctioned
            if payload.is_training is not None:
                row.is_training = payload.is_training
            if payload.sensor_capture is not None:
                row.sensor_capture = payload.sensor_capture
            if payload.inventory_only is not None:
                row.inventory_only = payload.inventory_only
            if payload.path_hint is not None:
                row.path_hint = payload.path_hint
            if payload.enabled is not None:
                row.enabled = payload.enabled
            row.is_customized = True
            row.updated_at = dt.datetime.now(dt.timezone.utc)
    return _catalog_row_to_response(row)


@applications_admin_router.delete("/applications/catalog/{app_id}")
async def delete_application_catalog_entry(
    app_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    x_tenant_id: uuid.UUID = Header(alias="X-Tenant-Id"),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> dict[str, Any]:
    _require_tenant_access(principal, x_tenant_id, required_role="tenant-admin")
    async with session.begin():
        async with tenant_scope(session, str(x_tenant_id)):
            row = await session.get(AiApplication, (x_tenant_id, app_id))
            if row is None:
                raise ServiceError("NOT_FOUND", "Application not found", 404)
            if row.source == "builtin":
                # Builtin entries are soft-disabled so a catalog re-seed
                # doesn't resurrect them.
                row.enabled = False
                row.is_customized = True
                row.updated_at = dt.datetime.now(dt.timezone.utc)
                outcome = "disabled"
            else:
                await session.delete(row)
                outcome = "deleted"
    return {"app_id": str(app_id), "status": outcome}


async def _collect_dashboard(
    session: AsyncSession,
    tenant_id: uuid.UUID,
    days: int,
) -> ApplicationsDashboardResponse:
    now = dt.datetime.now(dt.timezone.utc)
    since = now - dt.timedelta(days=days)
    prev_since = since - dt.timedelta(days=days)

    await ensure_tenant_catalog(session, tenant_id)
    catalog_result = await session.execute(
        select(AiApplication).where(AiApplication.tenant_id == tenant_id)
    )
    catalog_by_slug = {row.slug: row for row in catalog_result.scalars().all()}

    # Query A: current-window per-app aggregates (portable GROUP BY).
    current_result = await session.execute(
        select(
            AiUsageSession.app_slug,
            func.count(AiUsageSession.id),
            func.count(distinct(AiUsageSession.user_key)),
            func.sum(AiUsageSession.dlp_hit_count),
            func.max(AiUsageSession.last_activity_at),
        )
        .where(
            AiUsageSession.tenant_id == tenant_id,
            AiUsageSession.started_at >= since,
        )
        .group_by(AiUsageSession.app_slug)
    )
    current_rows = current_result.all()

    # Query B: previous equal window session counts (for pct_change).
    previous_result = await session.execute(
        select(AiUsageSession.app_slug, func.count(AiUsageSession.id))
        .where(
            AiUsageSession.tenant_id == tenant_id,
            AiUsageSession.started_at >= prev_since,
            AiUsageSession.started_at < since,
        )
        .group_by(AiUsageSession.app_slug)
    )
    previous_counts = {slug: count for slug, count in previous_result.all()}

    # Query C: trend + types. Day-bucketing happens in Python on purpose:
    # date_trunc/TRUNC diverge across Postgres/Oracle/MSSQL and sessions are
    # low-cardinality by design.
    detail_result = await session.execute(
        select(
            AiUsageSession.app_slug,
            AiUsageSession.session_type,
            AiUsageSession.started_at,
        ).where(
            AiUsageSession.tenant_id == tenant_id,
            AiUsageSession.started_at >= since,
        )
    )
    day_keys = [
        (now - dt.timedelta(days=offset)).date().isoformat()
        for offset in range(days - 1, -1, -1)
    ]
    trend_by_slug: dict[str | None, dict[str, int]] = {}
    types_by_slug: dict[str | None, set[str]] = {}
    for app_slug, session_type, started_at in detail_result.all():
        day = started_at.astimezone(dt.timezone.utc).date().isoformat()
        buckets = trend_by_slug.setdefault(app_slug, {})
        buckets[day] = buckets.get(day, 0) + 1
        types_by_slug.setdefault(app_slug, set()).add(session_type)

    apps: list[ApplicationUsageResponse] = []
    risk_distribution: dict[str, int] = {level: 0 for level in RISK_LEVELS}
    category_sessions: dict[str, int] = {}
    category_apps: dict[str, int] = {}
    total_sessions = 0

    for app_slug, sessions_count, users_count, sensitive_sum, last_used in current_rows:
        catalog_row = catalog_by_slug.get(app_slug) if app_slug else None
        if catalog_row is not None:
            slug = catalog_row.slug
            name = catalog_row.name
            vendor = catalog_row.vendor
            icon_key = catalog_row.icon_key
            category = catalog_row.category
            risk_level = catalog_row.risk_level
            is_training = catalog_row.is_training
            is_sanctioned = catalog_row.is_sanctioned
            app_uuid = catalog_row.id
        else:
            slug = app_slug or UNCLASSIFIED_SLUG
            name = app_slug or "Unclassified"
            vendor = None
            icon_key = None
            category = "other"
            risk_level = "none"
            is_training = False
            is_sanctioned = False
            app_uuid = None

        previous = previous_counts.get(app_slug, 0)
        pct_change: float | None = None
        if previous > 0:
            pct_change = round((sessions_count - previous) / previous * 100.0, 1)

        buckets = trend_by_slug.get(app_slug, {})
        trend = [
            ApplicationTrendPointResponse(day=day, sessions=buckets.get(day, 0))
            for day in day_keys
        ]
        type_labels = sorted(
            {"Web" if value == "web" else "Desktop" for value in types_by_slug.get(app_slug, set())}
        )

        apps.append(
            ApplicationUsageResponse(
                app_id=app_uuid,
                slug=slug,
                name=name,
                vendor=vendor,
                icon_key=icon_key,
                category=category,
                risk_level=risk_level,
                is_training=is_training,
                is_sanctioned=is_sanctioned,
                sessions=int(sessions_count or 0),
                unique_users=int(users_count or 0),
                sensitive_count=int(sensitive_sum or 0),
                types=type_labels,
                last_used_at=last_used,
                trend=trend,
                pct_change=pct_change,
            )
        )
        total_sessions += int(sessions_count or 0)
        risk_distribution[risk_level] = risk_distribution.get(risk_level, 0) + int(sessions_count or 0)
        category_sessions[category] = category_sessions.get(category, 0) + int(sessions_count or 0)
        category_apps[category] = category_apps.get(category, 0) + 1

    apps.sort(key=lambda item: item.sessions, reverse=True)
    category_totals = [
        ApplicationCategoryTotalResponse(
            category=category,
            sessions=sessions,
            apps=category_apps.get(category, 0),
        )
        for category, sessions in sorted(
            category_sessions.items(), key=lambda item: item[1], reverse=True
        )
    ]

    return ApplicationsDashboardResponse(
        window_days=days,
        generated_at=now,
        total_sessions=total_sessions,
        total_apps=len(apps),
        risk_distribution=risk_distribution,
        category_totals=category_totals,
        apps=apps,
    )


@applications_admin_router.get("/applications", response_model=ApplicationsDashboardResponse)
async def get_applications_dashboard(
    days: int = Query(default=30, ge=1, le=90),
    session: AsyncSession = Depends(get_session),
    x_tenant_id: uuid.UUID = Header(alias="X-Tenant-Id"),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> ApplicationsDashboardResponse:
    _require_tenant_access(principal, x_tenant_id, required_role="tenant-auditor")
    async with session.begin():
        async with tenant_scope(session, str(x_tenant_id)):
            return await _collect_dashboard(session, x_tenant_id, days)


@applications_admin_router.get("/applications/export")
async def export_applications_csv(
    days: int = Query(default=30, ge=1, le=90),
    session: AsyncSession = Depends(get_session),
    x_tenant_id: uuid.UUID = Header(alias="X-Tenant-Id"),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> Response:
    _require_tenant_access(principal, x_tenant_id, required_role="tenant-auditor")
    async with session.begin():
        async with tenant_scope(session, str(x_tenant_id)):
            dashboard = await _collect_dashboard(session, x_tenant_id, days)

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        [
            "name",
            "vendor",
            "category",
            "risk_level",
            "sessions",
            "unique_users",
            "sensitive_count",
            "types",
            "last_used_at",
            "pct_change",
        ]
    )
    for app in dashboard.apps:
        writer.writerow(
            [
                app.name,
                app.vendor or "",
                app.category,
                app.risk_level,
                app.sessions,
                app.unique_users,
                app.sensitive_count,
                ", ".join(app.types),
                app.last_used_at.isoformat() if app.last_used_at else "",
                app.pct_change if app.pct_change is not None else "",
            ]
        )
    return Response(
        content=buffer.getvalue(),
        media_type="text/csv",
        headers={
            "Content-Disposition": f"attachment; filename=umai-applications-{days}d.csv",
        },
    )
