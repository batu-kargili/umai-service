from __future__ import annotations

import base64
import datetime as dt
import hashlib
import hmac
import json
import logging
import time
import uuid
from collections import Counter
from typing import Any

from fastapi import APIRouter, Depends, Header, Query, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.admin_auth import (
    AdminPrincipal,
    ensure_tenant_access,
    get_admin_principal,
    require_admin_role,
)
from app.core.db import get_session, tenant_scope
from app.core.errors import ServiceError
from app.core.settings import settings
from app.models.db import BrowserExtensionEvent

logger = logging.getLogger("duvarai.service.extension")

DEVICE_TOKEN_AUDIENCE = "umai-ext-ingest"
DEFAULT_POLICY_PACK = {
    "version": "default-local-allow",
    "default_action": "allow",
    "rules": [],
}


ext_router = APIRouter(prefix="/api/v1/ext", tags=["extension"])
ext_admin_router = APIRouter(
    prefix="/api/v1/admin",
    tags=["extension-admin"],
    dependencies=[Depends(get_admin_principal)],
)


class _BaseModel(BaseModel):
    model_config = ConfigDict(extra="ignore")


class ExtensionUser(_BaseModel):
    user_email: str | None = None
    user_idp_subject: str | None = None


class ExtensionDevice(_BaseModel):
    device_id: str


class ExtensionApp(_BaseModel):
    site: str
    url: str
    tab_id: int | None = None


class ExtensionTimestamps(_BaseModel):
    captured_at_ms: int


class ExtensionChain(_BaseModel):
    prev_event_hash: str | None = None
    event_hash: str


class ExtensionEventEnvelope(_BaseModel):
    event_id: str
    event_type: str
    tenant_id: uuid.UUID
    user: ExtensionUser = Field(default_factory=ExtensionUser)
    device: ExtensionDevice
    app: ExtensionApp
    timestamps: ExtensionTimestamps
    chain: ExtensionChain
    payload: dict[str, Any] = Field(default_factory=dict)


class ExtensionEventBatchRequest(_BaseModel):
    tenant_id: uuid.UUID
    device_id: str | None = None
    events: list[ExtensionEventEnvelope]


class ExtensionEventIngestResponse(_BaseModel):
    accepted: int
    duplicate_count: int
    chain_invalid_count: int


class ExtensionDailyCountResponse(_BaseModel):
    day: str
    count: int


class ExtensionSummaryResponse(_BaseModel):
    total_events: int
    unique_devices: int
    unique_users: int
    blocked_events: int
    warned_events: int
    redacted_events: int
    last_event_at: dt.datetime | None = None
    by_site: dict[str, int]
    by_event_type: dict[str, int]
    by_decision: dict[str, int]
    daily: list[ExtensionDailyCountResponse]


class ExtensionEventResponse(_BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
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
    chain_valid: bool
    chain_error: str | None = None
    decision: str | None = None
    message: str | None = None
    status: str | None = None
    prompt_hash: str | None = None
    response_hash: str | None = None
    prompt_len: int | None = None
    response_len: int | None = None
    payload: dict[str, Any]
    created_at: dt.datetime


class ExtensionAuthPrincipal(_BaseModel):
    tenant_id: uuid.UUID
    subject: str | None = None


def _pad_b64(value: str) -> str:
    return value + "=" * (-len(value) % 4)


def _verify_hs256_jwt(token: str, secret: str) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 3:
        raise ServiceError("TOKEN_INVALID", "Malformed extension token", 401)

    header_b64, payload_b64, sig_b64 = parts
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    secret_bytes = secret.encode("utf-8")

    expected_sig = hmac.new(secret_bytes, signing_input, hashlib.sha256).digest()
    try:
        actual_sig = base64.urlsafe_b64decode(_pad_b64(sig_b64))
    except Exception as exc:  # pragma: no cover - defensive decoding
        raise ServiceError("TOKEN_INVALID", "Invalid extension token signature", 401) from exc

    if not hmac.compare_digest(expected_sig, actual_sig):
        raise ServiceError("TOKEN_INVALID", "Extension token signature mismatch", 401)

    try:
        payload = json.loads(base64.urlsafe_b64decode(_pad_b64(payload_b64)).decode("utf-8"))
    except Exception as exc:  # pragma: no cover - defensive decoding
        raise ServiceError("TOKEN_INVALID", "Extension token payload is invalid", 401) from exc

    try:
        header = json.loads(base64.urlsafe_b64decode(_pad_b64(header_b64)).decode("utf-8"))
    except Exception as exc:  # pragma: no cover - defensive decoding
        raise ServiceError("TOKEN_INVALID", "Extension token header is invalid", 401) from exc

    if str(header.get("alg", "")).upper() != "HS256":
        raise ServiceError("TOKEN_INVALID", "Unsupported extension token algorithm", 401)

    exp = payload.get("exp")
    if exp is not None and time.time() > float(exp):
        raise ServiceError("TOKEN_EXPIRED", "Extension token has expired", 401)

    audience = payload.get("aud")
    if audience != DEVICE_TOKEN_AUDIENCE:
        raise ServiceError("TOKEN_INVALID", "Extension token audience mismatch", 401)

    roles = payload.get("roles") or []
    if isinstance(roles, str):
        roles = [roles]
    if "tenant-device" not in roles:
        raise ServiceError("FORBIDDEN", "Extension token is missing tenant-device role", 403)

    return payload


def _authenticate_extension_request(
    authorization: str | None,
    tenant_id: uuid.UUID | None,
) -> ExtensionAuthPrincipal:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise ServiceError("UNAUTHENTICATED", "Bearer token required for extension access", 401)

    token = authorization.split(" ", 1)[1].strip()
    static_token = (settings.extension_ingest_bearer_token or "").strip()
    if static_token and hmac.compare_digest(token, static_token):
        if tenant_id is None:
            raise ServiceError("INVALID_REQUEST", "X-Tenant-Id is required", 422)
        return ExtensionAuthPrincipal(tenant_id=tenant_id, subject="static-extension-token")

    secret = (settings.extension_ingest_jwt_hs256_secret or "").strip()
    if not secret:
        raise ServiceError(
            "AUTH_MISCONFIGURED",
            "Extension ingest auth is not configured",
            500,
        )

    payload = _verify_hs256_jwt(token, secret)
    try:
        token_tenant_id = uuid.UUID(str(payload.get("tenant_id")))
    except Exception as exc:
        raise ServiceError("TOKEN_INVALID", "Extension token tenant_id is invalid", 401) from exc

    if tenant_id is not None and tenant_id != token_tenant_id:
        raise ServiceError("FORBIDDEN", "Tenant header does not match extension token", 403)

    return ExtensionAuthPrincipal(
        tenant_id=token_tenant_id,
        subject=str(payload.get("sub")) if payload.get("sub") else None,
    )


def _normalize_device_id(
    envelope: ExtensionEventEnvelope,
    batch_device_id: str | None,
    header_device_id: str | None,
) -> str:
    device_id = (envelope.device.device_id or "").strip()
    if not device_id:
        device_id = (batch_device_id or "").strip()
    if not device_id:
        device_id = (header_device_id or "").strip()
    if not device_id:
        raise ServiceError("INVALID_REQUEST", "Extension event device_id is required", 422)
    if header_device_id and header_device_id.strip() and header_device_id.strip() != device_id:
        raise ServiceError("FORBIDDEN", "X-Device-Id does not match event device_id", 403)
    return device_id


def _canonicalize(value: Any) -> Any:
    if isinstance(value, list):
        return [_canonicalize(item) for item in value]
    if isinstance(value, dict):
        return {key: _canonicalize(value[key]) for key in sorted(value)}
    return value


def _stable_json(value: Any) -> str:
    return json.dumps(_canonicalize(value), separators=(",", ":"), ensure_ascii=False)


def _hash_object_hex(value: Any) -> str:
    return hashlib.sha256(_stable_json(value).encode("utf-8")).hexdigest()


def _event_hash_payload(envelope: ExtensionEventEnvelope) -> dict[str, Any]:
    return {
        "event_id": envelope.event_id,
        "event_type": envelope.event_type,
        "tenant_id": str(envelope.tenant_id),
        "user": envelope.user.model_dump(exclude_none=True),
        "device": envelope.device.model_dump(exclude_none=True),
        "app": envelope.app.model_dump(exclude_none=True),
        "timestamps": envelope.timestamps.model_dump(exclude_none=True),
        "chain": {
            "prev_event_hash": envelope.chain.prev_event_hash,
            "event_hash": "",
        },
        "payload": envelope.payload,
    }


def _compute_event_hash(envelope: ExtensionEventEnvelope) -> str:
    return _hash_object_hex(_event_hash_payload(envelope))


def _load_policy_pack() -> dict[str, Any]:
    raw = (settings.extension_policy_json or "").strip()
    if not raw:
        return DEFAULT_POLICY_PACK
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        logger.warning("extension.policy.invalid_json")
        return DEFAULT_POLICY_PACK
    if not isinstance(parsed, dict):
        logger.warning("extension.policy.invalid_shape type=%s", type(parsed).__name__)
        return DEFAULT_POLICY_PACK
    version = parsed.get("version")
    default_action = parsed.get("default_action")
    rules = parsed.get("rules")
    if not isinstance(version, str) or not isinstance(default_action, str) or not isinstance(rules, list):
        logger.warning("extension.policy.missing_required_fields")
        return DEFAULT_POLICY_PACK
    return parsed


def _policy_etag(policy_pack: dict[str, Any]) -> str:
    return _hash_object_hex(policy_pack)


def _require_tenant_access(
    principal: AdminPrincipal,
    tenant_id: uuid.UUID,
    required_role: str = "tenant-auditor",
) -> None:
    ensure_tenant_access(principal, tenant_id)
    require_admin_role(principal, required_role)


def _parse_payload_json(raw: str) -> dict[str, Any]:
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _payload_string(payload: dict[str, Any], key: str) -> str | None:
    value = payload.get(key)
    return value if isinstance(value, str) else None


def _payload_int(payload: dict[str, Any], key: str) -> int | None:
    value = payload.get(key)
    return value if isinstance(value, int) else None


def _extension_event_to_response(row: BrowserExtensionEvent) -> ExtensionEventResponse:
    payload = _parse_payload_json(row.payload_json)
    return ExtensionEventResponse(
        id=row.id,
        tenant_id=row.tenant_id,
        event_id=row.event_id,
        event_type=row.event_type,
        site=row.site,
        url=row.url,
        tab_id=row.tab_id,
        user_email=row.user_email,
        user_idp_subject=row.user_idp_subject,
        device_id=row.device_id,
        browser_profile_id=row.browser_profile_id,
        captured_at=row.captured_at,
        prev_event_hash=row.prev_event_hash,
        event_hash=row.event_hash,
        chain_valid=bool(row.chain_valid),
        chain_error=row.chain_error,
        decision=row.decision,
        message=row.message,
        status=row.status,
        prompt_hash=row.prompt_hash,
        response_hash=row.response_hash,
        prompt_len=row.prompt_len,
        response_len=row.response_len,
        payload=payload,
        created_at=row.created_at,
    )


def _summarize_extension_rows(
    rows: list[BrowserExtensionEvent],
    days: int,
) -> ExtensionSummaryResponse:
    total_events = len(rows)
    unique_devices = len({row.device_id for row in rows if row.device_id})
    unique_users = len(
        {
            row.user_email or row.user_idp_subject
            for row in rows
            if row.user_email or row.user_idp_subject
        }
    )
    by_site = Counter(row.site for row in rows if row.site)
    by_event_type = Counter(row.event_type for row in rows if row.event_type)
    by_decision = Counter(row.decision for row in rows if row.decision)

    today = dt.datetime.now(dt.timezone.utc).date()
    earliest = today - dt.timedelta(days=max(days - 1, 0))
    daily_counts = {
        (earliest + dt.timedelta(days=offset)).isoformat(): 0
        for offset in range(days)
    }
    for row in rows:
        day = row.captured_at.astimezone(dt.timezone.utc).date().isoformat()
        if day in daily_counts:
            daily_counts[day] += 1

    last_event_at = max((row.captured_at for row in rows), default=None)

    return ExtensionSummaryResponse(
        total_events=total_events,
        unique_devices=unique_devices,
        unique_users=unique_users,
        blocked_events=sum(1 for row in rows if row.decision == "block"),
        warned_events=sum(1 for row in rows if row.decision == "warn"),
        redacted_events=sum(1 for row in rows if row.decision == "redact"),
        last_event_at=last_event_at,
        by_site=dict(sorted(by_site.items())),
        by_event_type=dict(sorted(by_event_type.items())),
        by_decision=dict(sorted(by_decision.items())),
        daily=[
            ExtensionDailyCountResponse(day=day, count=count)
            for day, count in daily_counts.items()
        ],
    )


@ext_router.get("/policy")
async def get_extension_policy(
    response: Response,
    authorization: str | None = Header(default=None, alias="Authorization"),
    x_tenant_id: uuid.UUID = Header(alias="X-Tenant-Id"),
    if_none_match: str | None = Header(default=None, alias="If-None-Match"),
):
    _authenticate_extension_request(authorization, x_tenant_id)
    policy_pack = _load_policy_pack()
    etag = _policy_etag(policy_pack)
    response.headers["Cache-Control"] = "no-store"
    response.headers["ETag"] = etag
    if if_none_match and if_none_match.strip() == etag:
        response.status_code = 304
        return Response(status_code=304, headers={"ETag": etag, "Cache-Control": "no-store"})
    return JSONResponse(
        content=policy_pack,
        headers={"ETag": etag, "Cache-Control": "no-store"},
    )


@ext_router.post("/events", response_model=ExtensionEventIngestResponse)
async def ingest_extension_events(
    payload: ExtensionEventBatchRequest,
    authorization: str | None = Header(default=None, alias="Authorization"),
    x_tenant_id: uuid.UUID | None = Header(default=None, alias="X-Tenant-Id"),
    x_device_id: str | None = Header(default=None, alias="X-Device-Id"),
    session: AsyncSession = Depends(get_session),
) -> ExtensionEventIngestResponse:
    principal = _authenticate_extension_request(authorization, x_tenant_id or payload.tenant_id)
    if payload.tenant_id != principal.tenant_id:
        raise ServiceError("FORBIDDEN", "Payload tenant_id does not match extension token", 403)

    incoming_event_ids = [event.event_id for event in payload.events]
    existing_ids: set[str] = set()
    accepted = 0
    duplicates = 0
    chain_invalid = 0

    async with session.begin():
        async with tenant_scope(session, str(principal.tenant_id)):
            if incoming_event_ids:
                existing_result = await session.execute(
                    select(BrowserExtensionEvent.event_id).where(
                        BrowserExtensionEvent.tenant_id == principal.tenant_id,
                        BrowserExtensionEvent.event_id.in_(incoming_event_ids),
                    )
                )
                existing_ids = set(existing_result.scalars().all())

            last_hash_by_device: dict[str, str | None] = {}

            for envelope in payload.events:
                if envelope.tenant_id != principal.tenant_id:
                    raise ServiceError(
                        "FORBIDDEN",
                        f"Event {envelope.event_id} tenant_id does not match extension token",
                        403,
                    )

                if envelope.event_id in existing_ids:
                    duplicates += 1
                    continue

                device_id = _normalize_device_id(envelope, payload.device_id, x_device_id)
                if device_id not in last_hash_by_device:
                    previous_row = await session.execute(
                        select(BrowserExtensionEvent.event_hash)
                        .where(
                            BrowserExtensionEvent.tenant_id == principal.tenant_id,
                            BrowserExtensionEvent.device_id == device_id,
                        )
                        .order_by(
                            BrowserExtensionEvent.captured_at.desc(),
                            BrowserExtensionEvent.created_at.desc(),
                        )
                        .limit(1)
                    )
                    last_hash_by_device[device_id] = previous_row.scalar_one_or_none()

                computed_hash = _compute_event_hash(envelope)
                chain_error_parts: list[str] = []
                if computed_hash != envelope.chain.event_hash:
                    chain_error_parts.append("event_hash_mismatch")

                expected_prev_hash = last_hash_by_device[device_id]
                if envelope.chain.prev_event_hash != expected_prev_hash:
                    chain_error_parts.append("prev_event_hash_mismatch")

                payload_body = envelope.payload
                chain_error = ",".join(chain_error_parts) if chain_error_parts else None
                chain_is_valid = chain_error is None
                if not chain_is_valid:
                    chain_invalid += 1

                captured_at = dt.datetime.fromtimestamp(
                    envelope.timestamps.captured_at_ms / 1000.0,
                    tz=dt.timezone.utc,
                )
                row = BrowserExtensionEvent(
                    tenant_id=principal.tenant_id,
                    event_id=envelope.event_id,
                    event_type=envelope.event_type,
                    site=envelope.app.site,
                    url=envelope.app.url,
                    tab_id=envelope.app.tab_id,
                    user_email=envelope.user.user_email,
                    user_idp_subject=envelope.user.user_idp_subject,
                    device_id=device_id,
                    browser_profile_id=_payload_string(payload_body, "browser_profile_id"),
                    captured_at=captured_at,
                    prev_event_hash=envelope.chain.prev_event_hash,
                    event_hash=envelope.chain.event_hash,
                    chain_valid=chain_is_valid,
                    chain_error=chain_error,
                    decision=_payload_string(payload_body, "decision"),
                    message=_payload_string(payload_body, "message"),
                    status=_payload_string(payload_body, "status"),
                    prompt_hash=_payload_string(payload_body, "prompt_hash"),
                    response_hash=_payload_string(payload_body, "response_hash"),
                    prompt_len=_payload_int(payload_body, "prompt_len"),
                    response_len=_payload_int(payload_body, "response_len"),
                    payload_json=json.dumps(payload_body, separators=(",", ":"), ensure_ascii=True),
                )
                session.add(row)
                accepted += 1
                existing_ids.add(envelope.event_id)
                last_hash_by_device[device_id] = envelope.chain.event_hash

    return ExtensionEventIngestResponse(
        accepted=accepted,
        duplicate_count=duplicates,
        chain_invalid_count=chain_invalid,
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
    limit: int = Query(default=100, ge=1, le=500),
    session: AsyncSession = Depends(get_session),
    x_tenant_id: uuid.UUID = Header(alias="X-Tenant-Id"),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> list[ExtensionEventResponse]:
    _require_tenant_access(principal, x_tenant_id, required_role="tenant-auditor")

    stmt = select(BrowserExtensionEvent).where(BrowserExtensionEvent.tenant_id == x_tenant_id)
    if site:
        stmt = stmt.where(BrowserExtensionEvent.site == site)
    if event_type:
        stmt = stmt.where(BrowserExtensionEvent.event_type == event_type)
    if decision:
        stmt = stmt.where(BrowserExtensionEvent.decision == decision)
    if device_id:
        stmt = stmt.where(BrowserExtensionEvent.device_id == device_id)
    if chain_valid is not None:
        stmt = stmt.where(BrowserExtensionEvent.chain_valid == chain_valid)
    if from_ts:
        stmt = stmt.where(BrowserExtensionEvent.captured_at >= from_ts)
    if to_ts:
        stmt = stmt.where(BrowserExtensionEvent.captured_at <= to_ts)

    stmt = stmt.order_by(
        BrowserExtensionEvent.captured_at.desc(),
        BrowserExtensionEvent.created_at.desc(),
    ).limit(limit)

    async with session.begin():
        async with tenant_scope(session, str(x_tenant_id)):
            result = await session.execute(stmt)
            rows = result.scalars().all()

    return [_extension_event_to_response(row) for row in rows]


@ext_admin_router.get("/extension/summary", response_model=ExtensionSummaryResponse)
async def get_extension_summary(
    days: int = Query(default=7, ge=1, le=90),
    session: AsyncSession = Depends(get_session),
    x_tenant_id: uuid.UUID = Header(alias="X-Tenant-Id"),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> ExtensionSummaryResponse:
    _require_tenant_access(principal, x_tenant_id, required_role="tenant-auditor")
    cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)

    stmt = (
        select(BrowserExtensionEvent)
        .where(
            BrowserExtensionEvent.tenant_id == x_tenant_id,
            BrowserExtensionEvent.captured_at >= cutoff,
        )
        .order_by(BrowserExtensionEvent.captured_at.asc(), BrowserExtensionEvent.created_at.asc())
    )

    async with session.begin():
        async with tenant_scope(session, str(x_tenant_id)):
            result = await session.execute(stmt)
            rows = result.scalars().all()

    return _summarize_extension_rows(rows, days)
