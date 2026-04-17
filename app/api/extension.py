from __future__ import annotations

import base64
import datetime as dt
import hashlib
import hmac
import json
import logging
import time
import uuid
from collections import Counter, defaultdict

from fastapi import APIRouter, Depends, Header, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.admin_auth import AdminPrincipal, get_admin_principal, require_admin_role
from app.core.db import get_session, tenant_scope
from app.core.errors import ServiceError
from app.core.settings import settings
from app.models.db import BrowserExtensionEvent

logger = logging.getLogger("duvarai.service.extension")

# ── Routers ─────────────────────────────────────────────────────────────────

ext_admin_router = APIRouter(
    prefix="/api/v1/admin",
    tags=["extension-admin"],
    dependencies=[Depends(get_admin_principal)],
)

ext_router = APIRouter(
    prefix="/api/v1/extension",
    tags=["extension"],
)


# ── Response models ──────────────────────────────────────────────────────────

class ExtensionEventResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    event_id: str
    event_type: str
    site: str
    url: str
    device_id: str
    user_email: str | None = None
    decision: str | None = None
    message: str | None = None
    chain_valid: bool
    captured_at: dt.datetime
    created_at: dt.datetime


class DailyStat(BaseModel):
    day: str
    count: int


class ExtensionSummary(BaseModel):
    total_events: int
    unique_devices: int
    unique_users: int
    blocked_events: int
    warned_events: int
    redacted_events: int
    last_event_at: dt.datetime | None = None
    by_site: dict = Field(default_factory=dict)
    by_event_type: dict = Field(default_factory=dict)
    by_decision: dict = Field(default_factory=dict)
    daily: list[DailyStat] = Field(default_factory=list)


class ExtensionIngestEvent(BaseModel):
    event_id: str
    event_type: str
    site: str
    url: str
    tab_id: int | None = None
    user_email: str | None = None
    user_idp_subject: str | None = None
    device_id: str
    browser_profile_id: str | None = None
    captured_at: dt.datetime
    prev_event_hash: str | None = None
    event_hash: str
    decision: str | None = None
    message: str | None = None
    status: str | None = None
    prompt_hash: str | None = None
    response_hash: str | None = None
    prompt_len: int | None = None
    response_len: int | None = None
    payload: dict = Field(default_factory=dict)


class ExtensionIngestRequest(BaseModel):
    events: list[ExtensionIngestEvent]


class ExtensionIngestResponse(BaseModel):
    accepted: int
    rejected: int


# ── JWT helpers ──────────────────────────────────────────────────────────────

def _pad_b64(value: str) -> str:
    return value + "=" * (-len(value) % 4)


def _validate_extension_jwt(token: str) -> dict:
    """Validate an HS256 extension device JWT and return its payload."""
    secret = settings.extension_ingest_jwt_hs256_secret
    if not secret:
        raise ServiceError(
            "AUTH_MISCONFIGURED",
            "Extension JWT secret is not configured on the service",
            500,
        )

    parts = token.split(".")
    if len(parts) != 3:
        raise ServiceError("TOKEN_INVALID", "Malformed JWT", 401)

    header_b64, payload_b64, sig_b64 = parts
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    key_bytes = secret.encode("utf-8")

    expected_sig = hmac.new(key_bytes, signing_input, hashlib.sha256).digest()
    try:
        actual_sig = base64.urlsafe_b64decode(_pad_b64(sig_b64))
    except Exception as exc:
        raise ServiceError("TOKEN_INVALID", "JWT signature encoding invalid", 401) from exc

    if not hmac.compare_digest(expected_sig, actual_sig):
        raise ServiceError("TOKEN_INVALID", "JWT signature mismatch", 401)

    try:
        payload_json = base64.urlsafe_b64decode(_pad_b64(payload_b64)).decode("utf-8")
        payload = json.loads(payload_json)
    except Exception as exc:
        raise ServiceError("TOKEN_INVALID", "JWT payload decode failed", 401) from exc

    exp = payload.get("exp")
    if exp is not None and time.time() > float(exp):
        raise ServiceError("TOKEN_EXPIRED", "JWT has expired", 401)

    aud = payload.get("aud")
    if aud != "umai-ext-ingest":
        raise ServiceError("TOKEN_INVALID", f"Invalid JWT audience: {aud}", 401)

    roles = payload.get("roles") or []
    if "tenant-device" not in roles:
        raise ServiceError("FORBIDDEN", "JWT does not carry tenant-device role", 403)

    return payload


def _extract_extension_jwt(request: Request) -> str:
    """Extract the bearer token from the Authorization header."""
    # First try static bearer token (simpler auth mode)
    authorization = request.headers.get("Authorization") or ""
    if authorization.lower().startswith("bearer "):
        return authorization.split(" ", 1)[1].strip()
    raise ServiceError("UNAUTHENTICATED", "Bearer token required", 401)


# ── Admin endpoints ──────────────────────────────────────────────────────────

def _event_to_response(row: BrowserExtensionEvent) -> ExtensionEventResponse:
    return ExtensionEventResponse(
        id=row.id,
        tenant_id=row.tenant_id,
        event_id=row.event_id,
        event_type=row.event_type,
        site=row.site,
        url=row.url,
        device_id=row.device_id,
        user_email=row.user_email,
        decision=row.decision,
        message=row.message,
        chain_valid=bool(row.chain_valid),
        captured_at=row.captured_at,
        created_at=row.created_at,
    )


@ext_admin_router.get("/extension/events", response_model=list[ExtensionEventResponse])
async def list_extension_events(
    site: str | None = Query(default=None),
    event_type: str | None = Query(default=None),
    decision: str | None = Query(default=None),
    device_id: str | None = Query(default=None),
    chain_valid: bool | None = Query(default=None),
    from_ts: dt.datetime | None = Query(default=None),
    to_ts: dt.datetime | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
    session: AsyncSession = Depends(get_session),
    x_tenant_id: uuid.UUID = Header(alias="X-Tenant-Id"),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> list[ExtensionEventResponse]:
    require_admin_role(principal, "tenant-auditor")
    stmt = select(BrowserExtensionEvent).where(
        BrowserExtensionEvent.tenant_id == x_tenant_id
    )
    if site:
        stmt = stmt.where(BrowserExtensionEvent.site == site)
    if event_type:
        stmt = stmt.where(BrowserExtensionEvent.event_type == event_type)
    if decision:
        stmt = stmt.where(BrowserExtensionEvent.decision == decision.upper())
    if device_id:
        stmt = stmt.where(BrowserExtensionEvent.device_id == device_id)
    if chain_valid is not None:
        stmt = stmt.where(BrowserExtensionEvent.chain_valid == chain_valid)
    if from_ts:
        stmt = stmt.where(BrowserExtensionEvent.captured_at >= from_ts)
    if to_ts:
        stmt = stmt.where(BrowserExtensionEvent.captured_at <= to_ts)
    stmt = stmt.order_by(BrowserExtensionEvent.captured_at.desc()).limit(limit)
    async with session.begin():
        async with tenant_scope(session, str(x_tenant_id)):
            result = await session.execute(stmt)
            rows = result.scalars().all()
    return [_event_to_response(row) for row in rows]


@ext_admin_router.get("/extension/summary", response_model=ExtensionSummary)
async def get_extension_summary(
    days: int = Query(default=7, ge=1, le=90),
    session: AsyncSession = Depends(get_session),
    x_tenant_id: uuid.UUID = Header(alias="X-Tenant-Id"),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> ExtensionSummary:
    require_admin_role(principal, "tenant-auditor")
    cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)
    stmt = (
        select(BrowserExtensionEvent)
        .where(
            BrowserExtensionEvent.tenant_id == x_tenant_id,
            BrowserExtensionEvent.captured_at >= cutoff,
        )
        .order_by(BrowserExtensionEvent.captured_at.desc())
        .limit(10000)
    )
    async with session.begin():
        async with tenant_scope(session, str(x_tenant_id)):
            result = await session.execute(stmt)
            rows = result.scalars().all()

    if not rows:
        return ExtensionSummary()

    devices: set[str] = set()
    users: set[str] = set()
    by_site: Counter[str] = Counter()
    by_event_type: Counter[str] = Counter()
    by_decision: Counter[str] = Counter()
    daily: Counter[str] = Counter()
    blocked = warned = redacted = 0
    last_event_at: dt.datetime | None = None

    for row in rows:
        devices.add(row.device_id)
        if row.user_email:
            users.add(row.user_email)
        elif row.user_idp_subject:
            users.add(row.user_idp_subject)
        by_site[row.site] += 1
        by_event_type[row.event_type] += 1
        if row.decision:
            by_decision[row.decision] += 1
            d = row.decision.upper()
            if d in {"BLOCK", "BLOCKED"}:
                blocked += 1
            elif d in {"WARN", "WARNED", "WARNING"}:
                warned += 1
            elif d in {"REDACT", "REDACTED"}:
                redacted += 1
        day_key = row.captured_at.strftime("%Y-%m-%d")
        daily[day_key] += 1
        if last_event_at is None or row.captured_at > last_event_at:
            last_event_at = row.captured_at

    return ExtensionSummary(
        total_events=len(rows),
        unique_devices=len(devices),
        unique_users=len(users),
        blocked_events=blocked,
        warned_events=warned,
        redacted_events=redacted,
        last_event_at=last_event_at,
        by_site=dict(by_site.most_common(20)),
        by_event_type=dict(by_event_type),
        by_decision=dict(by_decision),
        daily=[DailyStat(day=k, count=v) for k, v in sorted(daily.items())],
    )


# ── Ingest endpoint (called by browser extension) ────────────────────────────

def _validate_ingest_auth(request: Request) -> tuple[uuid.UUID, str | None]:
    """Validate the extension ingest request.  Returns ``(tenant_id, subject)``."""
    token = _extract_extension_jwt(request)

    # Static bearer token mode (simpler, no JWT)
    if settings.extension_ingest_bearer_token:
        if token == settings.extension_ingest_bearer_token:
            # Static token carries no tenant; caller must supply X-Tenant-Id
            return uuid.UUID(int=0), None  # sentinel handled below

    # JWT mode
    payload = _validate_extension_jwt(token)
    tenant_id_str = payload.get("tenant_id")
    if not tenant_id_str:
        raise ServiceError("TOKEN_INVALID", "JWT missing tenant_id claim", 401)
    try:
        return uuid.UUID(str(tenant_id_str)), payload.get("sub")
    except ValueError as exc:
        raise ServiceError("TOKEN_INVALID", "Invalid tenant_id in JWT", 401) from exc


def _compute_chain_validity(
    event: ExtensionIngestEvent,
    expected_prev_hash: str | None,
) -> tuple[bool, str | None]:
    """Validate the event's hash chain integrity."""
    if event.prev_event_hash != expected_prev_hash:
        return False, "prev_event_hash mismatch"
    return True, None


@ext_router.post("/ingest", response_model=ExtensionIngestResponse)
async def ingest_extension_events(
    payload: ExtensionIngestRequest,
    request: Request,
    session: AsyncSession = Depends(get_session),
    x_tenant_id: uuid.UUID | None = Header(default=None, alias="X-Tenant-Id"),
) -> ExtensionIngestResponse:
    """Receive browser extension events.

    Authenticated via HS256 JWT (aud=umai-ext-ingest) issued by the control
    center, or optionally via a static bearer token for testing.
    """
    tenant_id, subject = _validate_ingest_auth(request)

    # If static-token mode returned sentinel, fall back to header
    if tenant_id == uuid.UUID(int=0):
        if x_tenant_id is None:
            raise ServiceError("INVALID_REQUEST", "X-Tenant-Id header required", 400)
        tenant_id = x_tenant_id

    accepted = 0
    rejected = 0

    async with session.begin():
        async with tenant_scope(session, str(tenant_id)):
            for ext_event in payload.events:
                try:
                    row = BrowserExtensionEvent(
                        tenant_id=tenant_id,
                        event_id=ext_event.event_id,
                        event_type=ext_event.event_type,
                        site=ext_event.site,
                        url=ext_event.url,
                        tab_id=ext_event.tab_id,
                        user_email=ext_event.user_email,
                        user_idp_subject=ext_event.user_idp_subject,
                        device_id=ext_event.device_id,
                        browser_profile_id=ext_event.browser_profile_id,
                        captured_at=ext_event.captured_at,
                        prev_event_hash=ext_event.prev_event_hash,
                        event_hash=ext_event.event_hash,
                        chain_valid=True,
                        decision=ext_event.decision,
                        message=ext_event.message,
                        status=ext_event.status,
                        prompt_hash=ext_event.prompt_hash,
                        response_hash=ext_event.response_hash,
                        prompt_len=ext_event.prompt_len,
                        response_len=ext_event.response_len,
                        payload_json=json.dumps(
                            ext_event.payload, separators=(",", ":"), ensure_ascii=True
                        ),
                    )
                    session.add(row)
                    accepted += 1
                except Exception:
                    logger.exception(
                        "extension.ingest.event_error tenant_id=%s event_id=%s",
                        tenant_id,
                        ext_event.event_id,
                    )
                    rejected += 1

    logger.info(
        "extension.ingest.ok tenant_id=%s accepted=%d rejected=%d",
        tenant_id,
        accepted,
        rejected,
    )
    return ExtensionIngestResponse(accepted=accepted, rejected=rejected)
