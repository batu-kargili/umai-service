"""Public API for the passive UMAI ADR Collector.

This namespace deliberately contains only collector lifecycle and session
ingest. Runtime policy and evaluate endpoints are outside the ADR contract.
"""

from __future__ import annotations

import datetime as dt
import gzip
import hashlib
import io
import json
import logging
import secrets
import time
import uuid
from dataclasses import dataclass
from typing import Any, Literal

from fastapi import APIRouter, Depends, Header, Request
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.extension import _encode_hs256_jwt, _verify_hs256_jwt
from app.core.agent_mesh import hash_secret
from app.core.db import get_session, tenant_scope
from app.core.errors import ServiceError
from app.core.finding_schema import (
    COLLECTION_MODES,
    MODE_FULL_SESSION,
    MODE_POSTURE_ONLY,
)
from app.core.session_recorder import record_agent_sessions, session_key
from app.core.settings import settings
from app.models.db import (
    AdrDeviceAuditEvent,
    AdrBootstrapToken,
    AdrDevice,
    Tenant,
)

logger = logging.getLogger("umai.service.adr")

from app.core.token_audiences import (  # noqa: E402  audiences live in one place
    ADR_BOOTSTRAP_TOKEN_AUDIENCE,
    ADR_DEVICE_TOKEN_AUDIENCE,
)
ADR_BOOTSTRAP_TTL_SECONDS = 15 * 60
ADR_BOOTSTRAP_RATE_LIMIT_WINDOW_SECONDS = 60
ADR_BOOTSTRAP_RATE_LIMIT_MAX_ATTEMPTS = 10
ADR_SESSION_BATCH_LIMIT = 100
ADR_BODY_SIZE_LIMIT = 32 * 1024 * 1024
ADR_TRANSCRIPT_SIZE_LIMIT = 8 * 1024 * 1024

_BOOTSTRAP_ATTEMPTS: dict[tuple[str, str], list[float]] = {}

adr_router = APIRouter(prefix="/api/v1/adr", tags=["adr"])


class _AdrModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


CollectionMode = Literal["posture_only", "metadata", "full_session"]
AdrStatusDetail = Literal[
    "PARTIAL_INGEST",
    "INGEST_FAILED",
    "COLLECTOR_EXCEPTION",
    "AUTH_FAILED",
    "STORAGE_ERROR",
    "PROXY_ERROR",
]


class AdrBootstrapRequest(_AdrModel):
    tenant_id: uuid.UUID | None = None
    device_id: str = Field(min_length=1, max_length=128)
    hostname: str | None = Field(default=None, max_length=255)
    os: str | None = Field(default=None, max_length=32)
    os_version: str | None = Field(default=None, max_length=64)
    collector_version: str = Field(min_length=1, max_length=32)
    supported_sources: list[str] = Field(min_length=1)


class AdrAccessResponse(_AdrModel):
    tenant_id: uuid.UUID
    device_id: str
    device_token: str
    token_type: Literal["bearer"] = "bearer"
    expires_at: int
    audience: str = ADR_DEVICE_TOKEN_AUDIENCE
    collection_mode: CollectionMode
    config_etag: str


class AdrHeartbeatRequest(_AdrModel):
    device_id: str = Field(min_length=1, max_length=128)
    collector_version: str = Field(min_length=1, max_length=32)
    hostname: str | None = Field(default=None, max_length=255)
    os: str | None = Field(default=None, max_length=32)
    os_version: str | None = Field(default=None, max_length=64)
    config_etag: str | None = Field(default=None, max_length=128)
    supported_sources: list[str]
    observed_sources: list[str]
    last_successful_ingest_at: dt.datetime | None = None
    pending_sessions: int | None = Field(default=None, ge=0)
    status: Literal["healthy", "degraded", "error"]
    status_detail: AdrStatusDetail | None = None


class AdrHeartbeatResponse(_AdrModel):
    collection_mode: CollectionMode
    config_etag: str
    next_heartbeat_after_s: int
    directives: list[str] = Field(default_factory=list)


class AdrSessionBatch(_AdrModel):
    sessions: list[dict[str, Any]]
    collector: dict[str, Any] = Field(default_factory=dict)


class AdrSessionIngestResponse(_AdrModel):
    accepted: int
    created: int
    updated: int
    unchanged: int
    findings: int
    rejected: list[str] = Field(default_factory=list)


@dataclass(frozen=True)
class AdrPrincipal:
    tenant_id: uuid.UUID
    subject: str | None
    device_id: str | None
    bootstrap_token_id: uuid.UUID | None = None


def _adr_jwt_secret() -> str:
    secret = (settings.adr_ingest_jwt_hs256_secret or "").strip()
    if not secret:
        raise ServiceError("AUTH_MISCONFIGURED", "ADR collector auth is not configured", 500)
    return secret


def _issue_adr_device_token(
    *, tenant_id: uuid.UUID, device_id: str, subject: str
) -> tuple[str, int]:
    now = int(time.time())
    expires_at = now + max(int(settings.adr_device_token_ttl_seconds), 60)
    token = _encode_hs256_jwt(
        {
            "sub": subject,
            "tenant_id": str(tenant_id),
            "device_id": device_id,
            "aud": ADR_DEVICE_TOKEN_AUDIENCE,
            "iat": now,
            "exp": expires_at,
            "roles": ["tenant-device"],
        },
        _adr_jwt_secret(),
    )
    return token, expires_at


def _build_adr_bootstrap_token_row(
    *,
    tenant_id: uuid.UUID,
    expires_in_seconds: int = ADR_BOOTSTRAP_TTL_SECONDS,
    device_id: str | None = None,
    created_by: str | None = None,
) -> tuple[str, AdrBootstrapToken]:
    """Build the hashed bootstrap credential used by the fleet API."""
    token_id = uuid.uuid4()
    now = dt.datetime.now(dt.timezone.utc)
    expires_at = now + dt.timedelta(seconds=expires_in_seconds)
    subject = f"adr-bootstrap:{device_id or secrets.token_urlsafe(10)}"
    payload: dict[str, Any] = {
        "sub": subject,
        "jti": str(token_id),
        "tenant_id": str(tenant_id),
        "aud": ADR_BOOTSTRAP_TOKEN_AUDIENCE,
        "iat": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
        "roles": ["tenant-bootstrap"],
    }
    if device_id:
        payload["device_id"] = device_id
    token = _encode_hs256_jwt(payload, _adr_jwt_secret())
    return token, AdrBootstrapToken(
        id=token_id,
        tenant_id=tenant_id,
        token_hash=hash_secret(token),
        device_id=device_id,
        subject=subject,
        expires_at=expires_at,
        created_by=created_by,
        created_at=now,
    )


def _check_bootstrap_rate_limit(tenant_id: uuid.UUID, source_ip: str) -> None:
    now = time.time()
    key = (str(tenant_id), source_ip)
    cutoff = now - ADR_BOOTSTRAP_RATE_LIMIT_WINDOW_SECONDS
    attempts = [value for value in _BOOTSTRAP_ATTEMPTS.get(key, []) if value >= cutoff]
    if len(attempts) >= ADR_BOOTSTRAP_RATE_LIMIT_MAX_ATTEMPTS:
        raise ServiceError("RATE_LIMITED", "Too many ADR bootstrap attempts", 429)
    attempts.append(now)
    _BOOTSTRAP_ATTEMPTS[key] = attempts


def _verified_payload(
    authorization: str | None, *, audience: str, role: str, expired_code: str
) -> dict[str, Any]:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise ServiceError("UNAUTHENTICATED", "Bearer token required for ADR access", 401)
    try:
        return _verify_hs256_jwt(
            authorization.split(" ", 1)[1].strip(),
            _adr_jwt_secret(),
            audience=audience,
            required_role=role,
        )
    except ServiceError as exc:
        if exc.error_type == "TOKEN_EXPIRED":
            raise ServiceError(expired_code, "ADR token has expired", 401) from exc
        raise


def _token_tenant(payload: dict[str, Any]) -> uuid.UUID:
    try:
        return uuid.UUID(str(payload.get("tenant_id")))
    except (TypeError, ValueError, AttributeError) as exc:
        raise ServiceError("UNAUTHENTICATED", "ADR token tenant is invalid", 401) from exc


async def _authenticate_bootstrap(
    db: AsyncSession,
    authorization: str | None,
    tenant_id: uuid.UUID | None,
    device_id: str,
) -> AdrPrincipal:
    try:
        payload = _verified_payload(
            authorization,
            audience=ADR_BOOTSTRAP_TOKEN_AUDIENCE,
            role="tenant-bootstrap",
            expired_code="ADR_BOOTSTRAP_TOKEN_INVALID",
        )
    except ServiceError as exc:
        if exc.error_type in {"UNAUTHENTICATED", "TOKEN_INVALID"}:
            raise ServiceError(
                "ADR_BOOTSTRAP_TOKEN_INVALID", "ADR bootstrap token is invalid", 401
            ) from exc
        raise
    token_tenant_id = _token_tenant(payload)
    if tenant_id is not None and tenant_id != token_tenant_id:
        raise ServiceError("ADR_TENANT_MISMATCH", "Tenant does not match token", 403)
    expected_device = str(payload.get("device_id") or "").strip()
    if expected_device and expected_device != device_id:
        raise ServiceError(
            "ADR_BOOTSTRAP_TOKEN_INVALID", "Bootstrap token is for another device", 401
        )

    raw_token = authorization.split(" ", 1)[1].strip() if authorization else ""
    async with tenant_scope(db, str(token_tenant_id)):
        token_row = (
            await db.execute(
                select(AdrBootstrapToken).where(
                    AdrBootstrapToken.tenant_id == token_tenant_id,
                    AdrBootstrapToken.token_hash == hash_secret(raw_token),
                )
            )
        ).scalar_one_or_none()
        if token_row is None:
            raise ServiceError(
                "ADR_BOOTSTRAP_TOKEN_INVALID", "ADR bootstrap token is not registered", 401
            )
        if token_row.used_at is not None:
            raise ServiceError(
                "ADR_BOOTSTRAP_TOKEN_CONSUMED",
                "ADR bootstrap token has already been consumed",
                409,
            )
        expires_at = token_row.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=dt.timezone.utc)
        if expires_at <= dt.datetime.now(dt.timezone.utc):
            raise ServiceError(
                "ADR_BOOTSTRAP_TOKEN_INVALID", "ADR bootstrap token has expired", 401
            )
        token_row.used_at = dt.datetime.now(dt.timezone.utc)

    return AdrPrincipal(
        tenant_id=token_tenant_id,
        subject=str(payload.get("sub") or "") or None,
        device_id=device_id,
        bootstrap_token_id=token_row.id,
    )


def _authenticate_device(
    authorization: str | None, tenant_id: uuid.UUID | None
) -> AdrPrincipal:
    payload = _verified_payload(
        authorization,
        audience=ADR_DEVICE_TOKEN_AUDIENCE,
        role="tenant-device",
        expired_code="ADR_TOKEN_EXPIRED",
    )
    token_tenant_id = _token_tenant(payload)
    if tenant_id is not None and tenant_id != token_tenant_id:
        raise ServiceError("ADR_TENANT_MISMATCH", "Tenant does not match token", 403)
    return AdrPrincipal(
        tenant_id=token_tenant_id,
        subject=str(payload.get("sub") or "") or None,
        device_id=str(payload.get("device_id") or "") or None,
    )


def _config_etag(mode: str, retention_days: int) -> str:
    raw = json.dumps(
        {"collection_mode": mode, "transcript_retention_days": retention_days},
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return f'"adr-{hashlib.sha256(raw).hexdigest()[:24]}"'


async def _tenant_config(db: AsyncSession, tenant_id: uuid.UUID) -> tuple[str, str]:
    tenant = await db.get(Tenant, tenant_id)
    if tenant is None:
        raise ServiceError("ADR_TENANT_MISMATCH", "Tenant does not exist", 403)
    mode = tenant.collection_mode if tenant.collection_mode in COLLECTION_MODES else MODE_POSTURE_ONLY
    return mode, _config_etag(mode, int(tenant.transcript_retention_days))


async def _require_active_device(
    db: AsyncSession, principal: AdrPrincipal, device_id: str | None
) -> AdrDevice:
    resolved_device_id = (device_id or principal.device_id or "").strip()
    if not resolved_device_id or (
        principal.device_id and principal.device_id != resolved_device_id
    ):
        raise ServiceError("ADR_DEVICE_UNKNOWN", "Device identity is missing or mismatched", 404)
    device = await db.get(AdrDevice, (principal.tenant_id, resolved_device_id))
    if device is None:
        raise ServiceError("ADR_DEVICE_UNKNOWN", "ADR collector device is not enrolled", 404)
    if (device.status or "").lower() != "active":
        raise ServiceError("ADR_DEVICE_REVOKED", "ADR collector device is revoked", 403)
    return device


def _load_metadata(device: AdrDevice) -> dict[str, Any]:
    try:
        loaded = json.loads(device.metadata_json or "{}")
    except json.JSONDecodeError:
        return {}
    return loaded if isinstance(loaded, dict) else {}


def _audit_device_event(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    device_id: str,
    event_type: str,
    actor: str,
    detail: dict[str, Any] | None = None,
) -> None:
    db.add(
        AdrDeviceAuditEvent(
            tenant_id=tenant_id,
            device_id=device_id,
            event_type=event_type,
            actor=actor,
            detail_json=json.dumps(detail, separators=(",", ":"), sort_keys=True)
            if detail
            else None,
        )
    )


def _contains_session_content(payload: dict[str, Any]) -> bool:
    for message in payload.get("chat_history") or []:
        if not isinstance(message, dict):
            continue
        if message.get("content") not in (None, "", [], {}):
            return True
        for tool in message.get("tools") or []:
            if not isinstance(tool, dict):
                continue
            if any(tool.get(field) not in (None, "", [], {}) for field in ("arguments", "result", "error")):
                return True
    return False


def _rejected_session_key(payload: dict[str, Any], index: int) -> str:
    source = str(payload.get("source") or "").strip()
    source_id = str(payload.get("session_id") or "").strip()
    if source and source_id:
        return session_key(source, source_id, payload.get("raw_log_path"))
    return f"sessions[{index}]"


def _decode_batch(raw: bytes, content_encoding: str | None) -> AdrSessionBatch:
    if len(raw) > ADR_BODY_SIZE_LIMIT:
        raise ServiceError("ADR_BODY_TOO_LARGE", "ADR request body exceeds 32 MB", 413)
    if (content_encoding or "").lower() == "gzip":
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(raw)) as stream:
                raw = stream.read(ADR_BODY_SIZE_LIMIT + 1)
        except (OSError, EOFError) as exc:
            raise ServiceError("INVALID_REQUEST", "Body is not valid gzip", 400) from exc
        if len(raw) > ADR_BODY_SIZE_LIMIT:
            raise ServiceError("ADR_BODY_TOO_LARGE", "ADR request body exceeds 32 MB", 413)
    try:
        value = json.loads(raw.decode("utf-8"))
        return AdrSessionBatch.model_validate(value)
    except (UnicodeDecodeError, json.JSONDecodeError, ValidationError) as exc:
        raise ServiceError("INVALID_REQUEST", "ADR session batch is invalid", 422) from exc


@adr_router.post("/bootstrap", response_model=AdrAccessResponse)
async def bootstrap_adr_collector(
    payload: AdrBootstrapRequest,
    request: Request,
    authorization: str | None = Header(default=None, alias="Authorization"),
    x_tenant_id: uuid.UUID | None = Header(default=None, alias="X-Tenant-Id"),
    db: AsyncSession = Depends(get_session),
) -> AdrAccessResponse:
    requested_tenant_id = x_tenant_id or payload.tenant_id
    if requested_tenant_id is not None:
        _check_bootstrap_rate_limit(
            requested_tenant_id,
            request.client.host if request.client else "unknown",
        )
    try:
        async with db.begin():
            principal = await _authenticate_bootstrap(
                db, authorization, requested_tenant_id, payload.device_id
            )
    except ServiceError as exc:
        if requested_tenant_id is not None:
            async with db.begin():
                async with tenant_scope(db, str(requested_tenant_id)):
                    _audit_device_event(
                        db,
                        tenant_id=requested_tenant_id,
                        device_id=payload.device_id,
                        event_type="bootstrap_denied",
                        actor=f"collector:{payload.device_id}",
                        detail={"error_type": exc.error_type},
                    )
        raise

    now = dt.datetime.now(dt.timezone.utc)
    async with db.begin():
        async with tenant_scope(db, str(principal.tenant_id)):
            mode, config_etag = await _tenant_config(db, principal.tenant_id)
            device = await db.get(
                AdrDevice, (principal.tenant_id, payload.device_id)
            )
            if device is None:
                device = AdrDevice(
                    tenant_id=principal.tenant_id,
                    device_id=payload.device_id,
                    enrolled_at=now,
                    status="active",
                )
                db.add(device)
            device.hostname = payload.hostname
            device.os = payload.os
            device.os_version = payload.os_version
            device.agent_version = payload.collector_version
            device.status = "active"
            metadata = _load_metadata(device)
            metadata.update(
                {
                    "collector_kind": "adr",
                    "supported_sources": sorted(set(payload.supported_sources)),
                    "config_etag": config_etag,
                }
            )
            device.metadata_json = json.dumps(metadata, separators=(",", ":"), sort_keys=True)
            _audit_device_event(
                db,
                tenant_id=principal.tenant_id,
                device_id=payload.device_id,
                event_type="bootstrap_succeeded",
                actor=principal.subject or f"collector:{payload.device_id}",
                detail={"collector_version": payload.collector_version},
            )

    token, expires_at = _issue_adr_device_token(
        tenant_id=principal.tenant_id,
        device_id=payload.device_id,
        subject=principal.subject or f"adr:{payload.device_id}",
    )
    return AdrAccessResponse(
        tenant_id=principal.tenant_id,
        device_id=payload.device_id,
        device_token=token,
        expires_at=expires_at,
        collection_mode=mode,
        config_etag=config_etag,
    )


@adr_router.post("/renew", response_model=AdrAccessResponse)
async def renew_adr_device_token(
    authorization: str | None = Header(default=None, alias="Authorization"),
    x_tenant_id: uuid.UUID | None = Header(default=None, alias="X-Tenant-Id"),
    db: AsyncSession = Depends(get_session),
) -> AdrAccessResponse:
    principal = _authenticate_device(authorization, x_tenant_id)
    try:
        async with db.begin():
            async with tenant_scope(db, str(principal.tenant_id)):
                device = await _require_active_device(db, principal, principal.device_id)
                mode, config_etag = await _tenant_config(db, principal.tenant_id)
                _audit_device_event(
                    db,
                    tenant_id=principal.tenant_id,
                    device_id=device.device_id,
                    event_type="token_renewed",
                    actor=principal.subject or f"collector:{device.device_id}",
                )
    except ServiceError as exc:
        if exc.error_type == "ADR_DEVICE_REVOKED" and principal.device_id:
            async with db.begin():
                async with tenant_scope(db, str(principal.tenant_id)):
                    _audit_device_event(
                        db,
                        tenant_id=principal.tenant_id,
                        device_id=principal.device_id,
                        event_type="renewal_denied",
                        actor=principal.subject or f"collector:{principal.device_id}",
                        detail={"error_type": exc.error_type},
                    )
        raise
    token, expires_at = _issue_adr_device_token(
        tenant_id=principal.tenant_id,
        device_id=device.device_id,
        subject=principal.subject or f"adr:{device.device_id}",
    )
    return AdrAccessResponse(
        tenant_id=principal.tenant_id,
        device_id=device.device_id,
        device_token=token,
        expires_at=expires_at,
        collection_mode=mode,
        config_etag=config_etag,
    )


@adr_router.post("/heartbeat", response_model=AdrHeartbeatResponse)
async def adr_heartbeat(
    payload: AdrHeartbeatRequest,
    authorization: str | None = Header(default=None, alias="Authorization"),
    x_tenant_id: uuid.UUID | None = Header(default=None, alias="X-Tenant-Id"),
    x_device_id: str | None = Header(default=None, alias="X-Device-Id"),
    db: AsyncSession = Depends(get_session),
) -> AdrHeartbeatResponse:
    if payload.status in {"degraded", "error"} and not payload.status_detail:
        raise ServiceError(
            "INVALID_REQUEST", "status_detail is required for degraded or error", 422
        )
    if x_device_id is not None and x_device_id != payload.device_id:
        raise ServiceError("ADR_DEVICE_UNKNOWN", "X-Device-Id does not match payload", 404)
    principal = _authenticate_device(authorization, x_tenant_id)
    now = dt.datetime.now(dt.timezone.utc)
    async with db.begin():
        async with tenant_scope(db, str(principal.tenant_id)):
            device = await _require_active_device(db, principal, payload.device_id)
            mode, config_etag = await _tenant_config(db, principal.tenant_id)
            device.hostname = payload.hostname
            device.os = payload.os
            device.os_version = payload.os_version
            device.agent_version = payload.collector_version
            device.last_heartbeat_at = now
            device.last_policy_etag = payload.config_etag
            device.queue_depth = payload.pending_sessions
            device.last_successful_upload_at = payload.last_successful_ingest_at
            metadata = _load_metadata(device)
            metadata.update(
                {
                    "collector_kind": "adr",
                    "supported_sources": sorted(set(payload.supported_sources)),
                    "observed_sources": sorted(set(payload.observed_sources)),
                    "health_status": payload.status,
                    "status_detail": payload.status_detail,
                    "config_etag": payload.config_etag,
                }
            )
            device.metadata_json = json.dumps(metadata, separators=(",", ":"), sort_keys=True)
    return AdrHeartbeatResponse(
        collection_mode=mode,
        config_etag=config_etag,
        next_heartbeat_after_s=max(30, int(settings.adr_heartbeat_stale_seconds) // 3),
    )


@adr_router.post("/sessions", response_model=AdrSessionIngestResponse)
async def ingest_adr_sessions(
    request: Request,
    authorization: str | None = Header(default=None, alias="Authorization"),
    x_tenant_id: uuid.UUID | None = Header(default=None, alias="X-Tenant-Id"),
    x_device_id: str | None = Header(default=None, alias="X-Device-Id"),
    db: AsyncSession = Depends(get_session),
) -> AdrSessionIngestResponse:
    principal = _authenticate_device(authorization, x_tenant_id)
    batch = _decode_batch(await request.body(), request.headers.get("Content-Encoding"))
    if len(batch.sessions) > ADR_SESSION_BATCH_LIMIT:
        raise ServiceError("ADR_BATCH_TOO_LARGE", "ADR batch exceeds 100 sessions", 413)

    rejected: list[str] = []
    accepted_payloads: list[dict[str, Any]] = []
    try:
        async with db.begin():
            async with tenant_scope(db, str(principal.tenant_id)):
                device = await _require_active_device(db, principal, x_device_id)
                mode, _ = await _tenant_config(db, principal.tenant_id)
                if mode != MODE_FULL_SESSION and any(
                    _contains_session_content(payload) for payload in batch.sessions
                ):
                    raise ServiceError(
                        "ADR_MODE_FORBIDS_CONTENT",
                        f"Tenant collection mode {mode} forbids session content",
                        422,
                    )
                for index, payload in enumerate(batch.sessions):
                    encoded = json.dumps(
                        payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True
                    ).encode("utf-8")
                    if len(encoded) > ADR_TRANSCRIPT_SIZE_LIMIT:
                        rejected.append(_rejected_session_key(payload, index))
                    else:
                        accepted_payloads.append(payload)
                result = await record_agent_sessions(
                    db,
                    tenant_id=principal.tenant_id,
                    device_id=device.device_id,
                    collector=batch.collector,
                    sessions=accepted_payloads,
                )
    except ServiceError as exc:
        denied_device = x_device_id or principal.device_id
        if exc.error_type == "ADR_DEVICE_REVOKED" and denied_device:
            async with db.begin():
                async with tenant_scope(db, str(principal.tenant_id)):
                    _audit_device_event(
                        db,
                        tenant_id=principal.tenant_id,
                        device_id=denied_device,
                        event_type="session_ingest_denied",
                        actor=principal.subject or f"collector:{denied_device}",
                        detail={"error_type": exc.error_type},
                    )
        raise

    logger.info(
        "adr.sessions.ingested tenant=%s device=%s created=%s updated=%s unchanged=%s rejected=%s",
        principal.tenant_id,
        device.device_id,
        result.created,
        result.updated,
        result.unchanged,
        len(rejected) + len(result.rejected),
    )
    return AdrSessionIngestResponse(
        accepted=result.accepted,
        created=result.created,
        updated=result.updated,
        unchanged=result.unchanged,
        findings=result.findings,
        rejected=[*rejected, *result.rejected],
    )
