from __future__ import annotations

import asyncio
import datetime as dt
import hmac
import json
import logging
import secrets
import time
import uuid
from collections import Counter
from copy import deepcopy
from typing import Any

import httpx
from fastapi import APIRouter, Depends, Header, Query, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.extension import (
    _encode_hs256_jwt,
    _extension_action_from_engine,
    _extension_rules_from_engine,
    _hash_object_hex,
    _payload_first_string,
    _payload_int,
    _payload_string,
    _policy_etag,
    _resolve_extension_policy_pack,
    _utc_iso,
    _verify_hs256_jwt,
)
from app.core.admin_auth import (
    AdminPrincipal,
    ensure_tenant_access,
    get_admin_principal,
    require_admin_role,
)
from app.core.agent_mesh import hash_secret
from app.core.session_recorder import record_agent_sessions
from app.core.siem import emit_event
from app.core.app_catalog import (
    build_matcher,
    ensure_tenant_catalog,
    load_enabled_applications,
    vendor_catalog_from_apps,
)
from app.core.usage_sessions import fold_event_into_session
from app.core.db import get_session, tenant_scope
from app.core.engine_client import evaluate_engine
from app.core.errors import ServiceError
from app.core.events import record_audit_event
from app.core.license import license_allows_llm_calls, require_active_license
from app.core.resolver import resolve_guardrail
from app.core.settings import settings
from app.models.db import (
    EndpointSensorBootstrapToken,
    EndpointSensorDevice,
    EndpointSensorDownloadSession,
    EndpointSensorEvent,
    GuardrailVersion,
)
from app.models.engine import EngineFlags, EngineRequest, EngineResponse
from app.models.public import ChatMessage, InputArtifact, InputPayload, PublicGuardRequest

logger = logging.getLogger("umai.service.sensor")

SENSOR_DEVICE_TOKEN_AUDIENCE = "umai-sensor-ingest"
SENSOR_BOOTSTRAP_TOKEN_AUDIENCE = "umai-sensor-bootstrap"
DEFAULT_SENSOR_BOOTSTRAP_TTL_SECONDS = 15 * 60
SENSOR_BOOTSTRAP_RATE_LIMIT_WINDOW_SECONDS = 60
SENSOR_BOOTSTRAP_RATE_LIMIT_MAX_ATTEMPTS = 10
SENSOR_BOOTSTRAP_ATTEMPTS: dict[tuple[str, str], list[float]] = {}
DOWNLOAD_SESSION_STATUS_ORDER = {
    "requested": 0,
    "generating": 1,
    "ready": 2,
    "downloaded": 3,
    "enrolled": 4,
    "heartbeat_seen": 5,
    "event_seen": 6,
}
CAPTURE_MODE_ORDER = {
    "metadata_only": 0,
    "full_content": 1,
}
DEFAULT_SENSOR_POLICY_PACK = {
    "version": "sensor-default-local-allow",
    "default_action": "allow",
    "capture_mode_default": "metadata_only",
    "capture_mode_max": "metadata_only",
    "fail_mode": "allow",
    "rules": [],
    "default_sensor_guardrail": None,
    "vendor_catalog": [
        {
            "id": "openai",
            "display_name": "OpenAI",
            "domains": ["api.openai.com", "chatgpt.com", "chat.openai.com"],
            "match_strategy": "sni",
            "capture": True,
        },
        {
            "id": "anthropic",
            "display_name": "Anthropic",
            "domains": ["api.anthropic.com", "claude.ai"],
            "match_strategy": "sni",
            "capture": True,
        },
        {
            "id": "google-gemini",
            "display_name": "Google Gemini",
            "domains": ["generativelanguage.googleapis.com", "gemini.google.com"],
            "match_strategy": "sni",
            "capture": True,
        },
        {
            "id": "microsoft-copilot",
            "display_name": "Microsoft Copilot",
            "domains": ["copilot.microsoft.com", "www.bing.com"],
            "match_strategy": "sni",
            "capture": True,
        },
        {
            "id": "ollama-local",
            "display_name": "Ollama local model API",
            "domains": ["localhost", "127.0.0.1"],
            "ports": [11434],
            "match_strategy": "port",
            "capture": False,
            "inventory_only": True,
        },
    ],
    "pinned_apps": [
        {"process_name": "1Password.exe", "reason": "Credential manager TLS pinning"},
        {"process_name": "Signal.exe", "reason": "Pinned private messaging client"},
        {"process_name": "msedgewebview2.exe", "reason": "Embedded auth surfaces"},
    ],
    "privacy": {
        "employee_activity_visible": True,
        "store_prompt_text_by_default": False,
        "content_inspection_requires_managed_policy": True,
    },
    # Noise controls for the passive capture plane. The device heartbeat
    # endpoint carries liveness, so synthetic events default off; dedupe
    # windows are per capture-signal kind, in seconds.
    "capture_settings": {
        "synthetic_events_enabled": False,
        "dedupe_windows_seconds": {
            "network_connection": 21600,
            "dns_lookup": 21600,
            "local_model_port": 21600,
            "local_model_filesystem": 900,
            "ai_application": 43200,
            "default": 3600,
        },
    },
}

sensor_router = APIRouter(prefix="/api/v1/sensor", tags=["sensor"])
sensor_admin_router = APIRouter(
    prefix="/api/v1/admin",
    tags=["sensor-admin"],
    dependencies=[Depends(get_admin_principal)],
)


class _BaseModel(BaseModel):
    model_config = ConfigDict(extra="ignore")


class SensorAuthPrincipal(_BaseModel):
    tenant_id: uuid.UUID
    subject: str | None = None
    device_id: str | None = None
    bootstrap_token_id: uuid.UUID | None = None


class SensorUser(_BaseModel):
    user_email: str | None = None
    user_idp_subject: str | None = None
    identity_status: str | None = None


class SensorDevice(_BaseModel):
    device_id: str
    hostname: str | None = None
    os: str | None = None
    os_version: str | None = None


class SensorProcess(_BaseModel):
    pid: int | None = None
    name: str | None = None
    path: str | None = None
    parent: str | None = None
    signer: str | None = None


class SensorDestination(_BaseModel):
    host: str
    sni: str | None = None
    ip: str | None = None
    port: int | None = None
    protocol: str = "https"


class SensorDlp(_BaseModel):
    tags: list[str] = Field(default_factory=list)
    # Accept both shapes because the browser extension uses camelCase while
    # Python/Rust clients naturally produce snake_case.
    riskScore: float | None = None
    risk_score: float | None = None


class SensorFileContextEntry(_BaseModel):
    path: str = Field(min_length=1, max_length=4096)
    opened_at_ms: int = Field(ge=0)
    sha256: str | None = Field(default=None, pattern=r"^[a-fA-F0-9]{64}$")
    bytes_read: int | None = Field(default=None, ge=0)


class SensorEvaluateRequest(_BaseModel):
    tenant_id: uuid.UUID | None = None
    prompt_text: str = Field(min_length=1)
    capture_mode: str = "metadata_only"
    user: SensorUser = Field(default_factory=SensorUser)
    device: SensorDevice
    process: SensorProcess = Field(default_factory=SensorProcess)
    destination: SensorDestination
    dlp: SensorDlp = Field(default_factory=SensorDlp)
    file_context: list[SensorFileContextEntry] = Field(default_factory=list)
    timeout_ms: int | None = 1500
    allow_llm_calls: bool = True


class SensorEvaluateDecision(_BaseModel):
    type: str
    message: str | None = None
    rulesFired: list[str] = Field(default_factory=list)
    dlpTags: list[str] = Field(default_factory=list)
    redactions: list[dict[str, Any]] = Field(default_factory=list)
    redactedText: str | None = None
    requireJustification: bool = False
    minJustificationChars: int | None = None


class SensorEvaluateGuardrail(_BaseModel):
    environment_id: str
    project_id: str
    guardrail_id: str
    guardrail_version: int
    mode: str


class SensorEvaluateResponse(_BaseModel):
    ok: bool = True
    configured: bool = True
    request_id: str
    decision: SensorEvaluateDecision
    guardrail: SensorEvaluateGuardrail
    triggering_policy: dict[str, Any] | None = None
    output_modifications: dict[str, Any] | None = None
    latency_ms: float
    errors: list[dict[str, Any]] = Field(default_factory=list)


class SensorBootstrapRequest(_BaseModel):
    tenant_id: uuid.UUID | None = None
    device_id: str
    hostname: str | None = None
    os: str | None = None
    os_version: str | None = None
    agent_version: str | None = None


class SensorBootstrapResponse(_BaseModel):
    tenant_id: uuid.UUID
    device_id: str
    device_token: str
    token_type: str = "bearer"
    expires_at: int
    audience: str = SENSOR_DEVICE_TOKEN_AUDIENCE


class SensorPolicyResponse(_BaseModel):
    policy: dict[str, Any]


class SensorTimestamps(_BaseModel):
    captured_at_ms: int


class SensorChain(_BaseModel):
    prev_event_hash: str | None = None
    event_hash: str


class SensorEventEnvelope(_BaseModel):
    event_id: str
    event_type: str
    tenant_id: uuid.UUID
    user: SensorUser = Field(default_factory=SensorUser)
    device: SensorDevice
    process: SensorProcess = Field(default_factory=SensorProcess)
    destination: SensorDestination
    timestamps: SensorTimestamps
    chain: SensorChain
    payload: dict[str, Any] = Field(default_factory=dict)


class SensorEventBatchRequest(_BaseModel):
    tenant_id: uuid.UUID
    device_id: str | None = None
    events: list[SensorEventEnvelope]


class SensorEventIngestResponse(_BaseModel):
    accepted: int
    duplicate_count: int
    chain_invalid_count: int
    accepted_event_ids: list[str] = Field(default_factory=list)
    duplicate_event_ids: list[str] = Field(default_factory=list)
    chain_invalid_event_ids: list[str] = Field(default_factory=list)


class SensorHeartbeatRequest(_BaseModel):
    tenant_id: uuid.UUID | None = None
    device_id: str
    hostname: str | None = None
    os: str | None = None
    os_version: str | None = None
    agent_version: str | None = None
    policy_etag: str | None = None
    queue_depth: int | None = Field(default=None, ge=0)
    last_successful_upload_at: dt.datetime | None = None
    identity_status: str | None = None
    last_user_email: str | None = None
    status: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class SensorHeartbeatResponse(_BaseModel):
    accepted: bool = True
    tenant_id: uuid.UUID
    device_id: str
    server_time: dt.datetime
    status: str
    stale_after_seconds: int


class SensorDeviceResponse(_BaseModel):
    tenant_id: uuid.UUID
    device_id: str
    hostname: str | None = None
    os: str | None = None
    os_version: str | None = None
    agent_version: str | None = None
    last_heartbeat_at: dt.datetime | None = None
    last_policy_etag: str | None = None
    last_user_email: str | None = None
    identity_status: str | None = None
    queue_depth: int | None = None
    last_successful_upload_at: dt.datetime | None = None
    enrolled_at: dt.datetime
    status: str
    metadata: dict[str, Any] | None = None


class SensorEventResponse(_BaseModel):
    tenant_id: uuid.UUID
    event_id: str
    event_type: str
    process_name: str | None = None
    process_path: str | None = None
    parent_process: str | None = None
    destination_host: str | None = None
    destination_sni: str | None = None
    destination_port: int | None = None
    user_email: str | None = None
    user_idp_subject: str | None = None
    device_id: str
    captured_at: dt.datetime
    prev_event_hash: str | None = None
    event_hash: str
    chain_valid: bool
    chain_error: str | None = None
    decision: str | None = None
    message: str | None = None
    prompt_hash: str | None = None
    prompt_len: int | None = None
    dlp_tags: list[str]
    file_context: list[SensorFileContextEntry]
    payload: dict[str, Any]
    created_at: dt.datetime


class SensorDailyCountResponse(_BaseModel):
    day: str
    count: int


class SensorSummaryResponse(_BaseModel):
    total_events: int
    unique_devices: int
    unique_users: int
    blocked_events: int
    warned_events: int
    redacted_events: int
    last_event_at: dt.datetime | None = None
    by_destination: dict[str, int]
    by_process: dict[str, int]
    by_event_type: dict[str, int]
    by_decision: dict[str, int]
    daily: list[SensorDailyCountResponse]


class SensorBootstrapTokenCreateRequest(_BaseModel):
    tenant_id: uuid.UUID
    device_id: str | None = None
    expires_in_seconds: int = Field(default=DEFAULT_SENSOR_BOOTSTRAP_TTL_SECONDS, ge=60, le=86_400)
    created_by: str | None = None


class SensorBootstrapTokenResponse(_BaseModel):
    token_id: uuid.UUID
    tenant_id: uuid.UUID
    device_id: str | None = None
    bootstrap_token: str
    expires_at: dt.datetime


class SensorDownloadSessionCreateRequest(_BaseModel):
    tenant_id: uuid.UUID
    employee_idp_subject: str = Field(min_length=1, max_length=256)
    employee_upn: str | None = Field(default=None, max_length=320)
    employee_display_name: str | None = Field(default=None, max_length=200)
    installer_version: str | None = Field(default=None, max_length=64)
    created_ip: str | None = Field(default=None, max_length=64)


class SensorDownloadSessionResponse(_BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    employee_idp_subject: str
    employee_upn: str | None = None
    employee_display_name: str | None = None
    created_ip: str | None = None
    created_at: dt.datetime
    updated_at: dt.datetime | None = None
    expires_at: dt.datetime | None = None
    installer_version: str | None = None
    bootstrap_token_id: uuid.UUID | None = None
    bootstrap_token_expires_at: dt.datetime | None = None
    artifact_id: str | None = None
    artifact_sha256: str | None = None
    artifact_filename: str | None = None
    artifact_expires_at: dt.datetime | None = None
    downloaded_at: dt.datetime | None = None
    device_id: str | None = None
    first_heartbeat_at: dt.datetime | None = None
    last_heartbeat_at: dt.datetime | None = None
    first_event_at: dt.datetime | None = None
    identity_status: str | None = None
    failure_reason: str | None = None
    status: str
    installer_download_url: str | None = None


class SensorOnboardingDeviceResponse(SensorDownloadSessionResponse):
    hostname: str | None = None
    os: str | None = None
    os_version: str | None = None
    agent_version: str | None = None
    device_status: str | None = None
    queue_depth: int | None = None
    last_policy_etag: str | None = None


def _sensor_jwt_secret() -> str:
    secret = (settings.sensor_ingest_jwt_hs256_secret or "").strip()
    if not secret:
        raise ServiceError("AUTH_MISCONFIGURED", "Sensor ingest auth is not configured", 500)
    return secret


def _authenticate_sensor_request(
    authorization: str | None,
    tenant_id: uuid.UUID | None,
) -> SensorAuthPrincipal:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise ServiceError("UNAUTHENTICATED", "Bearer token required for sensor access", 401)

    token = authorization.split(" ", 1)[1].strip()
    payload = _verify_hs256_jwt(
        token,
        _sensor_jwt_secret(),
        audience=SENSOR_DEVICE_TOKEN_AUDIENCE,
        required_role="tenant-device",
    )
    try:
        token_tenant_id = uuid.UUID(str(payload.get("tenant_id")))
    except Exception as exc:
        raise ServiceError("TOKEN_INVALID", "Sensor token tenant_id is invalid", 401) from exc

    if tenant_id is not None and tenant_id != token_tenant_id:
        raise ServiceError("FORBIDDEN", "Tenant header does not match sensor token", 403)

    return SensorAuthPrincipal(
        tenant_id=token_tenant_id,
        subject=str(payload.get("sub")) if payload.get("sub") else None,
        device_id=str(payload.get("device_id")) if payload.get("device_id") else None,
    )


async def _authenticate_sensor_bootstrap_request(
    session: AsyncSession,
    authorization: str | None,
    tenant_id: uuid.UUID | None,
    device_id: str,
) -> SensorAuthPrincipal:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise ServiceError("UNAUTHENTICATED", "Bearer token required for sensor bootstrap", 401)
    if tenant_id is None:
        raise ServiceError("INVALID_REQUEST", "X-Tenant-Id or tenant_id is required", 422)

    token = authorization.split(" ", 1)[1].strip()
    payload = _verify_hs256_jwt(
        token,
        _sensor_jwt_secret(),
        audience=SENSOR_BOOTSTRAP_TOKEN_AUDIENCE,
        required_role="tenant-bootstrap",
    )
    try:
        token_tenant_id = uuid.UUID(str(payload.get("tenant_id")))
    except Exception as exc:
        raise ServiceError("TOKEN_INVALID", "Sensor bootstrap tenant_id is invalid", 401) from exc
    if tenant_id != token_tenant_id:
        raise ServiceError("FORBIDDEN", "Tenant header does not match bootstrap token", 403)

    expected_device_id = str(payload.get("device_id") or "").strip()
    if expected_device_id and expected_device_id != device_id:
        raise ServiceError("FORBIDDEN", "Bootstrap token is not valid for this device", 403)

    token_hash = hash_secret(token)
    async with tenant_scope(session, str(token_tenant_id)):
        result = await session.execute(
            select(EndpointSensorBootstrapToken).where(
                EndpointSensorBootstrapToken.tenant_id == token_tenant_id,
                EndpointSensorBootstrapToken.token_hash == token_hash,
            )
        )
        token_row = result.scalar_one_or_none()
        if token_row is None:
            raise ServiceError("TOKEN_INVALID", "Sensor bootstrap token is not registered", 401)
        now = dt.datetime.now(dt.timezone.utc)
        if token_row.used_at is not None:
            await _mark_download_session_failed_for_token(
                session,
                token_tenant_id,
                token_row.id,
                "bootstrap_token_used",
            )
            raise ServiceError("TOKEN_USED", "Sensor bootstrap token has already been used", 401)
        expires_at = _as_utc(token_row.expires_at)
        if expires_at <= now:
            await _mark_download_session_failed_for_token(
                session,
                token_tenant_id,
                token_row.id,
                "bootstrap_token_expired",
            )
            raise ServiceError("TOKEN_EXPIRED", "Sensor bootstrap token has expired", 401)
        if token_row.device_id and token_row.device_id != device_id:
            await _mark_download_session_failed_for_token(
                session,
                token_tenant_id,
                token_row.id,
                "bootstrap_device_mismatch",
            )
            raise ServiceError("FORBIDDEN", "Bootstrap token is not valid for this device", 403)
        token_row.used_at = now

    return SensorAuthPrincipal(
        tenant_id=token_tenant_id,
        subject=str(payload.get("sub")) if payload.get("sub") else None,
        device_id=device_id,
        bootstrap_token_id=token_row.id,
    )


def _issue_sensor_device_token(
    *,
    tenant_id: uuid.UUID,
    device_id: str,
    subject: str,
) -> tuple[str, int]:
    now = int(time.time())
    ttl = max(int(settings.sensor_device_token_ttl_seconds), 60)
    expires_at = now + ttl
    token = _encode_hs256_jwt(
        {
            "sub": subject,
            "tenant_id": str(tenant_id),
            "device_id": device_id,
            "aud": SENSOR_DEVICE_TOKEN_AUDIENCE,
            "iat": now,
            "exp": expires_at,
            "roles": ["tenant-device"],
        },
        _sensor_jwt_secret(),
    )
    return token, expires_at


def _issue_sensor_bootstrap_token(
    *,
    tenant_id: uuid.UUID,
    token_id: uuid.UUID,
    expires_at: dt.datetime,
    device_id: str | None,
    subject: str,
) -> str:
    now = int(time.time())
    payload: dict[str, Any] = {
        "sub": subject,
        "jti": str(token_id),
        "tenant_id": str(tenant_id),
        "aud": SENSOR_BOOTSTRAP_TOKEN_AUDIENCE,
        "iat": now,
        "exp": int(expires_at.timestamp()),
        "roles": ["tenant-bootstrap"],
    }
    if device_id:
        payload["device_id"] = device_id
    return _encode_hs256_jwt(payload, _sensor_jwt_secret())


def _build_sensor_bootstrap_token_row(
    *,
    tenant_id: uuid.UUID,
    expires_in_seconds: int,
    created_by: str | None,
    device_id: str | None = None,
    subject: str | None = None,
) -> tuple[str, EndpointSensorBootstrapToken]:
    token_id = uuid.uuid4()
    now = dt.datetime.now(dt.timezone.utc)
    expires_at = now + dt.timedelta(seconds=expires_in_seconds)
    subject_value = subject or f"sensor-bootstrap:{device_id or secrets.token_urlsafe(10)}"
    token = _issue_sensor_bootstrap_token(
        tenant_id=tenant_id,
        token_id=token_id,
        expires_at=expires_at,
        device_id=device_id,
        subject=subject_value,
    )
    row = EndpointSensorBootstrapToken(
        id=token_id,
        tenant_id=tenant_id,
        token_hash=hash_secret(token),
        device_id=device_id,
        subject=subject_value,
        expires_at=expires_at,
        created_by=created_by,
        created_at=now,
    )
    return token, row


def _download_session_status(row: EndpointSensorDownloadSession) -> str:
    now = dt.datetime.now(dt.timezone.utc)
    if row.status not in {"failed", "expired"}:
        if row.artifact_expires_at and _as_utc(row.artifact_expires_at) <= now:
            return "expired"
        if row.bootstrap_token_expires_at and _as_utc(row.bootstrap_token_expires_at) <= now:
            if row.status in {"requested", "generating", "ready", "downloaded"}:
                return "expired"
    return row.status


def _set_download_session_status(
    row: EndpointSensorDownloadSession,
    status: str,
    now: dt.datetime | None = None,
) -> None:
    now = now or dt.datetime.now(dt.timezone.utc)
    current = row.status or "requested"
    if status in {"failed", "expired"}:
        row.status = status
        row.updated_at = now
        return
    if current in {"failed", "expired"}:
        return
    if DOWNLOAD_SESSION_STATUS_ORDER.get(status, 0) >= DOWNLOAD_SESSION_STATUS_ORDER.get(current, 0):
        row.status = status
        row.updated_at = now


def _download_session_to_response(
    row: EndpointSensorDownloadSession,
) -> SensorDownloadSessionResponse:
    status = _download_session_status(row)
    return SensorDownloadSessionResponse(
        id=row.id,
        tenant_id=row.tenant_id,
        employee_idp_subject=row.employee_idp_subject,
        employee_upn=row.employee_upn,
        employee_display_name=row.employee_display_name,
        created_ip=row.created_ip,
        created_at=row.created_at,
        updated_at=row.updated_at,
        expires_at=row.artifact_expires_at or row.bootstrap_token_expires_at,
        installer_version=row.installer_version,
        bootstrap_token_id=row.bootstrap_token_id,
        bootstrap_token_expires_at=row.bootstrap_token_expires_at,
        artifact_id=row.artifact_id,
        artifact_sha256=row.artifact_sha256,
        artifact_filename=row.artifact_filename,
        artifact_expires_at=row.artifact_expires_at,
        downloaded_at=row.downloaded_at,
        device_id=row.device_id,
        first_heartbeat_at=row.first_heartbeat_at,
        last_heartbeat_at=row.last_heartbeat_at,
        first_event_at=row.first_event_at,
        identity_status=row.identity_status,
        failure_reason=row.failure_reason,
        status=status,
        installer_download_url=f"/api/v1/admin/sensor/download-sessions/{row.id}/installer"
        if row.artifact_id
        else None,
    )


def _onboarding_session_to_response(
    row: EndpointSensorDownloadSession,
    device: EndpointSensorDevice | None,
) -> SensorOnboardingDeviceResponse:
    base = _download_session_to_response(row).model_dump()
    return SensorOnboardingDeviceResponse(
        **base,
        hostname=device.hostname if device else None,
        os=device.os if device else None,
        os_version=device.os_version if device else None,
        agent_version=device.agent_version if device else None,
        device_status=device.status if device else None,
        queue_depth=device.queue_depth if device else None,
        last_policy_etag=device.last_policy_etag if device else None,
    )


async def _download_session_by_bootstrap_token(
    session: AsyncSession,
    tenant_id: uuid.UUID,
    bootstrap_token_id: uuid.UUID | None,
) -> EndpointSensorDownloadSession | None:
    if bootstrap_token_id is None:
        return None
    result = await session.execute(
        select(EndpointSensorDownloadSession)
        .where(
            EndpointSensorDownloadSession.tenant_id == tenant_id,
            EndpointSensorDownloadSession.bootstrap_token_id == bootstrap_token_id,
        )
        .limit(1)
    )
    return result.scalar_one_or_none()


async def _mark_download_session_failed_for_token(
    session: AsyncSession,
    tenant_id: uuid.UUID,
    bootstrap_token_id: uuid.UUID | None,
    reason: str,
) -> None:
    row = await _download_session_by_bootstrap_token(session, tenant_id, bootstrap_token_id)
    if row is None:
        return
    row.failure_reason = reason
    _set_download_session_status(row, "failed")


async def _mark_download_session_enrolled(
    session: AsyncSession,
    tenant_id: uuid.UUID,
    bootstrap_token_id: uuid.UUID | None,
    device_id: str,
) -> None:
    row = await _download_session_by_bootstrap_token(session, tenant_id, bootstrap_token_id)
    if row is None:
        return
    row.device_id = device_id
    row.failure_reason = None
    _set_download_session_status(row, "enrolled")


async def _mark_download_session_heartbeat(
    session: AsyncSession,
    tenant_id: uuid.UUID,
    device_id: str,
    heartbeat_at: dt.datetime,
    identity_status: str | None,
) -> None:
    result = await session.execute(
        select(EndpointSensorDownloadSession)
        .where(
            EndpointSensorDownloadSession.tenant_id == tenant_id,
            EndpointSensorDownloadSession.device_id == device_id,
        )
        .order_by(EndpointSensorDownloadSession.created_at.desc())
        .limit(1)
    )
    row = result.scalar_one_or_none()
    if row is None:
        return
    if row.first_heartbeat_at is None:
        row.first_heartbeat_at = heartbeat_at
    row.last_heartbeat_at = heartbeat_at
    row.identity_status = identity_status
    _set_download_session_status(row, "heartbeat_seen", heartbeat_at)


async def _mark_download_session_event_seen(
    session: AsyncSession,
    tenant_id: uuid.UUID,
    device_id: str,
    event_seen_at: dt.datetime,
) -> None:
    result = await session.execute(
        select(EndpointSensorDownloadSession)
        .where(
            EndpointSensorDownloadSession.tenant_id == tenant_id,
            EndpointSensorDownloadSession.device_id == device_id,
        )
        .order_by(EndpointSensorDownloadSession.created_at.desc())
        .limit(1)
    )
    row = result.scalar_one_or_none()
    if row is None:
        return
    if row.first_event_at is None:
        row.first_event_at = event_seen_at
    _set_download_session_status(row, "event_seen", event_seen_at)


def _parse_packager_datetime(value: Any) -> dt.datetime | None:
    if not isinstance(value, str) or not value:
        return None
    normalized = value.replace("Z", "+00:00")
    try:
        return dt.datetime.fromisoformat(normalized)
    except ValueError:
        return None


async def _request_installer_artifact(
    *,
    session_id: uuid.UUID,
    tenant_id: uuid.UUID,
    employee_upn: str | None,
    installer_version: str,
    bootstrap_token: str,
) -> dict[str, Any]:
    base_url = (settings.sensor_installer_packager_url or "").strip().rstrip("/")
    if not base_url:
        raise ServiceError("PACKAGER_NOT_CONFIGURED", "Sensor installer packager is not configured", 503)
    payload = {
        "session_id": str(session_id),
        "tenant_id": str(tenant_id),
        "employee_upn": employee_upn,
        "service_url": settings.sensor_installer_service_url,
        "control_center_url": settings.sensor_installer_control_center_url,
        "enrollment_token": bootstrap_token,
        "customer": settings.sensor_installer_customer,
        "installer_version": installer_version,
        "artifact_ttl_seconds": int(settings.sensor_installer_artifact_ttl_seconds),
        "self_sign": bool(settings.sensor_installer_self_sign),
    }
    async with httpx.AsyncClient(timeout=settings.sensor_installer_packager_timeout_seconds) as client:
        response = await client.post(
            f"{base_url}/api/v1/sensor/installers/windows",
            json=payload,
        )
    if response.status_code >= 400:
        raise ServiceError(
            "PACKAGER_FAILED",
            f"Sensor installer packager returned {response.status_code}",
            502,
        )
    try:
        artifact = response.json()
    except ValueError as exc:
        raise ServiceError("PACKAGER_INVALID_RESPONSE", "Sensor installer packager response is invalid", 502) from exc
    if not isinstance(artifact, dict) or not artifact.get("artifact_id"):
        raise ServiceError("PACKAGER_INVALID_RESPONSE", "Sensor installer artifact_id is missing", 502)
    return artifact


async def _download_installer_artifact(artifact_id: str) -> tuple[bytes, str | None]:
    base_url = (settings.sensor_installer_packager_url or "").strip().rstrip("/")
    if not base_url:
        raise ServiceError("PACKAGER_NOT_CONFIGURED", "Sensor installer packager is not configured", 503)
    async with httpx.AsyncClient(timeout=settings.sensor_installer_packager_timeout_seconds) as client:
        response = await client.get(f"{base_url}/api/v1/sensor/installers/windows/{artifact_id}")
    if response.status_code == 404:
        raise ServiceError("INSTALLER_NOT_FOUND", "Sensor installer artifact was not found", 404)
    if response.status_code == 410:
        raise ServiceError("INSTALLER_EXPIRED", "Sensor installer artifact has expired", 410)
    if response.status_code >= 400:
        raise ServiceError(
            "PACKAGER_FAILED",
            f"Sensor installer packager returned {response.status_code}",
            502,
        )
    return response.content, response.headers.get("content-type")


async def _record_sensor_bootstrap_failure(
    session: AsyncSession,
    authorization: str | None,
    requested_tenant_id: uuid.UUID | None,
    reason: str,
) -> None:
    if not authorization or not authorization.lower().startswith("bearer "):
        return
    if requested_tenant_id is None:
        return
    token = authorization.split(" ", 1)[1].strip()
    try:
        payload = _verify_hs256_jwt(
            token,
            _sensor_jwt_secret(),
            audience=SENSOR_BOOTSTRAP_TOKEN_AUDIENCE,
            required_role="tenant-bootstrap",
        )
        token_tenant_id = uuid.UUID(str(payload.get("tenant_id")))
    except Exception:
        return
    if token_tenant_id != requested_tenant_id:
        return
    token_hash = hash_secret(token)
    async with session.begin():
        async with tenant_scope(session, str(token_tenant_id)):
            result = await session.execute(
                select(EndpointSensorBootstrapToken).where(
                    EndpointSensorBootstrapToken.tenant_id == token_tenant_id,
                    EndpointSensorBootstrapToken.token_hash == token_hash,
                )
            )
            token_row = result.scalar_one_or_none()
            if token_row is None:
                return
            await _mark_download_session_failed_for_token(
                session,
                token_tenant_id,
                token_row.id,
                reason,
            )


def _as_utc(value: dt.datetime) -> dt.datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=dt.timezone.utc)
    return value.astimezone(dt.timezone.utc)


def _parse_json_object(raw: str | None) -> dict[str, Any]:
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _parse_json_list(raw: str | None) -> list[Any]:
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return []
    return parsed if isinstance(parsed, list) else []


def _parse_dlp_tags_json(raw: str | None) -> list[str]:
    return [item for item in _parse_json_list(raw) if isinstance(item, str) and item]


def _file_context_to_payload(entries: list[SensorFileContextEntry]) -> list[dict[str, Any]]:
    return [entry.model_dump(exclude_none=True) for entry in entries]


def _parse_file_context_entries(value: Any) -> list[SensorFileContextEntry]:
    if not isinstance(value, list):
        return []
    entries: list[SensorFileContextEntry] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        try:
            entries.append(SensorFileContextEntry.model_validate(item))
        except Exception:
            logger.warning("sensor.file_context.invalid_entry")
    return entries


def _parse_file_context_json(raw: str | None) -> list[SensorFileContextEntry]:
    return _parse_file_context_entries(_parse_json_list(raw))


def _payload_dlp_tags(payload: dict[str, Any]) -> list[str]:
    tags = payload.get("dlp_tags")
    if not isinstance(tags, list):
        return []
    return [tag for tag in tags if isinstance(tag, str) and tag]


def _canonicalize(value: Any) -> Any:
    if isinstance(value, list):
        return [_canonicalize(item) for item in value]
    if isinstance(value, dict):
        return {key: _canonicalize(value[key]) for key in sorted(value)}
    return value


def _stable_json(value: Any) -> str:
    return json.dumps(_canonicalize(value), separators=(",", ":"), ensure_ascii=False)


def _load_sensor_policy_json() -> dict[str, Any] | None:
    raw = (settings.sensor_policy_json or "").strip()
    if not raw:
        return None
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        logger.warning("sensor.policy.invalid_json")
        return None
    if not isinstance(parsed, dict):
        logger.warning("sensor.policy.invalid_shape type=%s", type(parsed).__name__)
        return None
    return parsed


def _with_sensor_policy_defaults(policy_pack: dict[str, Any]) -> dict[str, Any]:
    merged = deepcopy(DEFAULT_SENSOR_POLICY_PACK)
    merged.update(policy_pack)
    merged.setdefault("capture_mode_default", settings.sensor_default_capture_mode)
    merged.setdefault("capture_mode_max", merged.get("capture_mode_default", "metadata_only"))
    merged.setdefault("fail_mode", "allow")
    merged.setdefault("vendor_catalog", DEFAULT_SENSOR_POLICY_PACK["vendor_catalog"])
    merged.setdefault("pinned_apps", DEFAULT_SENSOR_POLICY_PACK["pinned_apps"])
    merged.setdefault("privacy", DEFAULT_SENSOR_POLICY_PACK["privacy"])
    merged.setdefault("capture_settings", DEFAULT_SENSOR_POLICY_PACK["capture_settings"])
    merged["schema"] = "umai.sensor.policy.v1"
    return merged


async def _tenant_vendor_catalog(
    session: AsyncSession, tenant_id: uuid.UUID
) -> list[dict[str, Any]]:
    async def _load() -> list[dict[str, Any]]:
        async with tenant_scope(session, str(tenant_id)):
            await ensure_tenant_catalog(session, tenant_id)
            rows = await load_enabled_applications(session, tenant_id)
            return vendor_catalog_from_apps(rows)

    if session.in_transaction():
        return await _load()
    async with session.begin():
        return await _load()


async def _resolve_sensor_policy_pack(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    environment_id: str | None,
    project_id: str | None,
    guardrail_id: str | None,
    version: int | None,
    template_id: str | None,
) -> dict[str, Any]:
    configured = _load_sensor_policy_json()
    has_guardrail_selector = any(
        value is not None for value in (environment_id, project_id, guardrail_id, version, template_id)
    )
    if configured is not None and not has_guardrail_selector:
        pack = _with_sensor_policy_defaults(configured)
    else:
        extension_pack = await _resolve_extension_policy_pack(
            session,
            tenant_id=tenant_id,
            environment_id=environment_id,
            project_id=project_id,
            guardrail_id=guardrail_id,
            version=version,
            template_id=template_id,
        )
        sensor_pack = dict(extension_pack)
        if configured is not None:
            sensor_pack.update(configured)
        sensor_pack["version"] = f"sensor:{extension_pack.get('version', 'default')}"
        pack = _with_sensor_policy_defaults(sensor_pack)

    # The tenant application registry is the source of truth for the vendor
    # catalog; an explicit vendor_catalog in UMAI_SENSOR_POLICY_JSON wins.
    if not (configured is not None and "vendor_catalog" in configured):
        tenant_catalog = await _tenant_vendor_catalog(session, tenant_id)
        if tenant_catalog:
            pack["vendor_catalog"] = tenant_catalog
    return pack


def _normalize_capture_mode(value: object) -> str:
    mode = str(value or "").strip().lower()
    return mode if mode in CAPTURE_MODE_ORDER else "metadata_only"


def _effective_capture_mode(client_capture_mode: str, policy_pack: dict[str, Any]) -> str:
    client_mode = _normalize_capture_mode(client_capture_mode)
    policy_mode = _normalize_capture_mode(
        policy_pack.get("capture_mode_max") or policy_pack.get("capture_mode_default")
    )
    privacy = policy_pack.get("privacy") if isinstance(policy_pack.get("privacy"), dict) else {}
    if privacy.get("content_inspection_requires_managed_policy") and policy_mode != "full_content":
        policy_mode = "metadata_only"
    return (
        client_mode
        if CAPTURE_MODE_ORDER[client_mode] <= CAPTURE_MODE_ORDER[policy_mode]
        else policy_mode
    )


def _resolve_sensor_guardrail_selector(
    policy_pack: dict[str, Any],
    *,
    environment_id: str | None,
    project_id: str | None,
    guardrail_id: str | None,
    version: int | None,
) -> tuple[str, str, str, int | None]:
    supplied = [environment_id, project_id, guardrail_id]
    if any(value is not None for value in supplied):
        if not all(supplied):
            raise ServiceError(
                "INVALID_REQUEST",
                "environment_id, project_id, and guardrail_id are required together",
                422,
            )
        return environment_id or "", project_id or "", guardrail_id or "", version

    default_ref = policy_pack.get("default_sensor_guardrail")
    if not isinstance(default_ref, dict):
        raise ServiceError(
            "SENSOR_GUARDRAIL_NOT_CONFIGURED",
            "Sensor evaluate requires query guardrail params or policy.default_sensor_guardrail",
            422,
        )
    resolved_environment_id = default_ref.get("environment_id")
    resolved_project_id = default_ref.get("project_id")
    resolved_guardrail_id = default_ref.get("guardrail_id")
    if not all(
        isinstance(value, str) and value.strip()
        for value in (resolved_environment_id, resolved_project_id, resolved_guardrail_id)
    ):
        raise ServiceError(
            "SENSOR_GUARDRAIL_NOT_CONFIGURED",
            "policy.default_sensor_guardrail must include environment_id, project_id, and guardrail_id",
            422,
        )
    resolved_version = default_ref.get("version", version)
    if resolved_version is not None:
        try:
            resolved_version = int(resolved_version)
        except (TypeError, ValueError) as exc:
            raise ServiceError(
                "SENSOR_GUARDRAIL_NOT_CONFIGURED",
                "policy.default_sensor_guardrail.version must be an integer",
                422,
            ) from exc
    return resolved_environment_id, resolved_project_id, resolved_guardrail_id, resolved_version


def _dlp_tags_from_sensor_payload(dlp: SensorDlp) -> list[str]:
    return [tag for tag in dlp.tags if isinstance(tag, str) and tag]


def _risk_score_from_sensor_payload(dlp: SensorDlp) -> float | None:
    value = dlp.riskScore if dlp.riskScore is not None else dlp.risk_score
    if isinstance(value, (int, float)):
        return float(value)
    return None


def _check_sensor_bootstrap_rate_limit(tenant_id: uuid.UUID, source_ip: str) -> None:
    now = time.time()
    key = (str(tenant_id), source_ip)
    cutoff = now - SENSOR_BOOTSTRAP_RATE_LIMIT_WINDOW_SECONDS
    attempts = [
        timestamp
        for timestamp in SENSOR_BOOTSTRAP_ATTEMPTS.get(key, [])
        if timestamp >= cutoff
    ]
    if len(attempts) >= SENSOR_BOOTSTRAP_RATE_LIMIT_MAX_ATTEMPTS:
        raise ServiceError(
            "RATE_LIMITED",
            "Too many sensor bootstrap attempts for this tenant and source",
            429,
        )
    attempts.append(now)
    SENSOR_BOOTSTRAP_ATTEMPTS[key] = attempts


def _sensor_decision_from_engine(
    engine_response: EngineResponse,
    *,
    dlp_tags: list[str],
) -> SensorEvaluateDecision:
    decision_type = _extension_action_from_engine(engine_response)
    output_modifications = engine_response.output_modifications or {}
    redacted_text = output_modifications.get("modified_text")
    if not isinstance(redacted_text, str):
        redacted_text = None
    return SensorEvaluateDecision(
        type=decision_type,
        message=engine_response.decision.reason,
        rulesFired=_extension_rules_from_engine(engine_response),
        dlpTags=dlp_tags,
        redactions=[],
        redactedText=redacted_text,
        requireJustification=decision_type == "justify",
        minJustificationChars=12 if decision_type == "justify" else None,
    )


def _sensor_public_guard_request(payload: SensorEvaluateRequest) -> PublicGuardRequest:
    dlp_tags = _dlp_tags_from_sensor_payload(payload.dlp)
    risk_score = _risk_score_from_sensor_payload(payload.dlp)
    metadata: dict[str, Any] = {
        "source": "endpoint_sensor",
        "process_name": payload.process.name,
        "process_pid": payload.process.pid,
        "process_path": payload.process.path,
        "parent_process": payload.process.parent,
        "process_signer": payload.process.signer,
        "destination_host": payload.destination.host,
        "destination_sni": payload.destination.sni,
        "destination_ip": payload.destination.ip,
        "destination_port": payload.destination.port,
        "destination_protocol": payload.destination.protocol,
        "user_email": payload.user.user_email,
        "user_idp_subject": payload.user.user_idp_subject,
        "identity_status": payload.user.identity_status,
        "device_id": payload.device.device_id,
        "hostname": payload.device.hostname,
        "os": payload.device.os,
        "os_version": payload.device.os_version,
        "dlp_tags": dlp_tags,
        "risk_score": risk_score,
        "file_context": _file_context_to_payload(payload.file_context),
    }
    metadata = {key: value for key, value in metadata.items() if value is not None}
    return PublicGuardRequest(
        phase="PRE_LLM",
        input=InputPayload(
            messages=[ChatMessage(role="user", content=payload.prompt_text)],
            phase_focus="LAST_USER_MESSAGE",
            content_type="text",
            artifacts=[
                InputArtifact(
                    artifact_type="CUSTOM",
                    name="endpoint_prompt",
                    payload_summary=f"Endpoint AI prompt to {payload.destination.host}",
                    metadata=metadata,
                )
            ],
        ),
        timeout_ms=payload.timeout_ms or int(settings.sensor_evaluate_timeout_ms),
    )


def _sanitize_sensor_request_payload_for_audit(
    payload: PublicGuardRequest,
    capture_mode: str,
) -> PublicGuardRequest:
    if capture_mode == "full_content":
        return payload
    sanitized = payload.model_copy(deep=True)
    for message in sanitized.input.messages:
        message.content = f"[metadata_only:{len(message.content)} chars]"
    for artifact in sanitized.input.artifacts:
        artifact.content = None
    return sanitized


def _normalize_device_id(
    envelope: SensorEventEnvelope,
    batch_device_id: str | None,
    header_device_id: str | None,
    token_device_id: str | None,
) -> str:
    device_id = (envelope.device.device_id or "").strip()
    if not device_id:
        device_id = (batch_device_id or "").strip()
    if not device_id:
        device_id = (header_device_id or "").strip()
    if not device_id:
        device_id = (token_device_id or "").strip()
    if not device_id:
        raise ServiceError("INVALID_REQUEST", "Sensor event device_id is required", 422)
    if header_device_id and header_device_id.strip() and header_device_id.strip() != device_id:
        raise ServiceError("FORBIDDEN", "X-Device-Id does not match event device_id", 403)
    if token_device_id and token_device_id.strip() and token_device_id.strip() != device_id:
        raise ServiceError("FORBIDDEN", "Sensor token does not match event device_id", 403)
    return device_id


def _event_hash_payload(envelope: SensorEventEnvelope) -> dict[str, Any]:
    return {
        "event_id": envelope.event_id,
        "event_type": envelope.event_type,
        "tenant_id": str(envelope.tenant_id),
        "user": envelope.user.model_dump(exclude_none=True),
        "device": envelope.device.model_dump(exclude_none=True),
        "process": envelope.process.model_dump(exclude_none=True),
        "destination": envelope.destination.model_dump(exclude_none=True),
        "timestamps": envelope.timestamps.model_dump(exclude_none=True),
        "chain": {
            "prev_event_hash": envelope.chain.prev_event_hash,
            "event_hash": "",
        },
        "payload": envelope.payload,
    }


def _compute_event_hash(envelope: SensorEventEnvelope) -> str:
    return _hash_object_hex(_event_hash_payload(envelope))


def _json_dumps(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True)


def _sensor_event_to_response(row: EndpointSensorEvent) -> SensorEventResponse:
    return SensorEventResponse(
        tenant_id=row.tenant_id,
        event_id=row.event_id,
        event_type=row.event_type,
        process_name=row.process_name,
        process_path=row.process_path,
        parent_process=row.parent_process,
        destination_host=row.destination_host,
        destination_sni=row.destination_sni,
        destination_port=row.destination_port,
        user_email=row.user_email,
        user_idp_subject=row.user_idp_subject,
        device_id=row.device_id,
        captured_at=row.captured_at,
        prev_event_hash=row.prev_event_hash,
        event_hash=row.event_hash,
        chain_valid=bool(row.chain_valid),
        chain_error=row.chain_error,
        decision=row.decision,
        message=row.message,
        prompt_hash=row.prompt_hash,
        prompt_len=row.prompt_len,
        dlp_tags=_parse_dlp_tags_json(row.dlp_tags_json),
        file_context=_parse_file_context_json(row.file_context_json),
        payload=_parse_json_object(row.payload_json),
        created_at=row.created_at,
    )


def _sensor_device_to_response(row: EndpointSensorDevice) -> SensorDeviceResponse:
    status = row.status
    if row.last_heartbeat_at is not None:
        stale_after = dt.timedelta(seconds=int(settings.sensor_heartbeat_stale_seconds))
        if _as_utc(row.last_heartbeat_at) + stale_after < dt.datetime.now(dt.timezone.utc):
            status = "stale"
    return SensorDeviceResponse(
        tenant_id=row.tenant_id,
        device_id=row.device_id,
        hostname=row.hostname,
        os=row.os,
        os_version=row.os_version,
        agent_version=row.agent_version,
        last_heartbeat_at=row.last_heartbeat_at,
        last_policy_etag=row.last_policy_etag,
        last_user_email=row.last_user_email,
        identity_status=row.identity_status,
        queue_depth=row.queue_depth,
        last_successful_upload_at=row.last_successful_upload_at,
        enrolled_at=row.enrolled_at,
        status=status,
        metadata=_parse_json_object(row.metadata_json),
    )


def _summarize_sensor_rows(rows: list[EndpointSensorEvent], days: int) -> SensorSummaryResponse:
    by_destination = Counter(row.destination_host for row in rows if row.destination_host)
    by_process = Counter(row.process_name for row in rows if row.process_name)
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

    return SensorSummaryResponse(
        total_events=len(rows),
        unique_devices=len({row.device_id for row in rows if row.device_id}),
        unique_users=len(
            {
                row.user_email or row.user_idp_subject
                for row in rows
                if row.user_email or row.user_idp_subject
            }
        ),
        blocked_events=sum(1 for row in rows if row.decision == "block"),
        warned_events=sum(1 for row in rows if row.decision == "warn"),
        redacted_events=sum(1 for row in rows if row.decision == "redact"),
        last_event_at=max((row.captured_at for row in rows), default=None),
        by_destination=dict(sorted(by_destination.items())),
        by_process=dict(sorted(by_process.items())),
        by_event_type=dict(sorted(by_event_type.items())),
        by_decision=dict(sorted(by_decision.items())),
        daily=[
            SensorDailyCountResponse(day=day, count=count)
            for day, count in daily_counts.items()
        ],
    )


def _require_tenant_access(
    principal: AdminPrincipal,
    tenant_id: uuid.UUID,
    required_role: str = "tenant-auditor",
) -> None:
    ensure_tenant_access(principal, tenant_id)
    require_admin_role(principal, required_role)


@sensor_router.post("/bootstrap", response_model=SensorBootstrapResponse)
async def bootstrap_sensor_device(
    payload: SensorBootstrapRequest,
    request: Request,
    authorization: str | None = Header(default=None, alias="Authorization"),
    x_tenant_id: uuid.UUID | None = Header(default=None, alias="X-Tenant-Id"),
    session: AsyncSession = Depends(get_session),
) -> SensorBootstrapResponse:
    requested_tenant_id = x_tenant_id or payload.tenant_id
    device_id = payload.device_id.strip()
    if not device_id:
        raise ServiceError("INVALID_REQUEST", "device_id is required", 422)
    if requested_tenant_id is not None:
        _check_sensor_bootstrap_rate_limit(
            requested_tenant_id,
            request.client.host if request.client else "unknown",
        )

    try:
        async with session.begin():
            principal = await _authenticate_sensor_bootstrap_request(
                session,
                authorization,
                requested_tenant_id,
                device_id,
            )
    except ServiceError as exc:
        await _record_sensor_bootstrap_failure(
            session,
            authorization,
            requested_tenant_id,
            exc.error_type.lower(),
        )
        raise

    if payload.tenant_id is not None and payload.tenant_id != principal.tenant_id:
        await _record_sensor_bootstrap_failure(
            session,
            authorization,
            requested_tenant_id,
            "payload_tenant_mismatch",
        )
        raise ServiceError("FORBIDDEN", "Payload tenant_id does not match bootstrap token", 403)

    now = dt.datetime.now(dt.timezone.utc)
    async with session.begin():
        async with tenant_scope(session, str(principal.tenant_id)):
            row = await session.get(EndpointSensorDevice, (principal.tenant_id, device_id))
            if row is None:
                row = EndpointSensorDevice(
                    tenant_id=principal.tenant_id,
                    device_id=device_id,
                    enrolled_at=now,
                    status="active",
                )
                session.add(row)
            row.hostname = payload.hostname
            row.os = payload.os
            row.os_version = payload.os_version
            row.agent_version = payload.agent_version
            row.status = "active"
            await _mark_download_session_enrolled(
                session,
                principal.tenant_id,
                principal.bootstrap_token_id,
                device_id,
            )

    subject = principal.subject or f"sensor:{device_id}"
    device_token, expires_at = _issue_sensor_device_token(
        tenant_id=principal.tenant_id,
        device_id=device_id,
        subject=subject,
    )
    return SensorBootstrapResponse(
        tenant_id=principal.tenant_id,
        device_id=device_id,
        device_token=device_token,
        expires_at=expires_at,
    )


@sensor_router.get("/policy")
async def get_sensor_policy(
    response: Response,
    authorization: str | None = Header(default=None, alias="Authorization"),
    x_tenant_id: uuid.UUID = Header(alias="X-Tenant-Id"),
    if_none_match: str | None = Header(default=None, alias="If-None-Match"),
    environment_id: str | None = Query(default=None),
    project_id: str | None = Query(default=None),
    guardrail_id: str | None = Query(default=None),
    version: int | None = Query(default=None),
    template_id: str | None = Query(default=None),
    session: AsyncSession = Depends(get_session),
):
    _authenticate_sensor_request(authorization, x_tenant_id)
    policy_pack = await _resolve_sensor_policy_pack(
        session,
        tenant_id=x_tenant_id,
        environment_id=environment_id,
        project_id=project_id,
        guardrail_id=guardrail_id,
        version=version,
        template_id=template_id,
    )
    etag = _policy_etag(policy_pack)
    response.headers["Cache-Control"] = "no-store"
    response.headers["ETag"] = etag
    if if_none_match and hmac.compare_digest(if_none_match.strip(), etag):
        return Response(status_code=304, headers={"ETag": etag, "Cache-Control": "no-store"})
    return JSONResponse(
        content=policy_pack,
        headers={"ETag": etag, "Cache-Control": "no-store"},
    )


@sensor_router.post("/evaluate", response_model=SensorEvaluateResponse)
async def evaluate_sensor_prompt(
    payload: SensorEvaluateRequest,
    authorization: str | None = Header(default=None, alias="Authorization"),
    x_tenant_id: uuid.UUID = Header(alias="X-Tenant-Id"),
    x_device_id: str | None = Header(default=None, alias="X-Device-Id"),
    environment_id: str | None = Query(default=None),
    project_id: str | None = Query(default=None),
    guardrail_id: str | None = Query(default=None),
    version: int | None = Query(default=None),
    session: AsyncSession = Depends(get_session),
) -> SensorEvaluateResponse:
    principal = _authenticate_sensor_request(authorization, x_tenant_id)
    if payload.tenant_id is not None and payload.tenant_id != principal.tenant_id:
        raise ServiceError("FORBIDDEN", "Payload tenant_id does not match sensor token", 403)
    if x_device_id and payload.device.device_id != x_device_id:
        raise ServiceError("FORBIDDEN", "X-Device-Id does not match payload device_id", 403)
    if principal.device_id and payload.device.device_id != principal.device_id:
        raise ServiceError("FORBIDDEN", "Sensor token does not match payload device_id", 403)

    policy_pack = await _resolve_sensor_policy_pack(
        session,
        tenant_id=principal.tenant_id,
        environment_id=environment_id,
        project_id=project_id,
        guardrail_id=guardrail_id,
        version=version,
        template_id=None,
    )
    environment_id, project_id, guardrail_id, version = _resolve_sensor_guardrail_selector(
        policy_pack,
        environment_id=environment_id,
        project_id=project_id,
        guardrail_id=guardrail_id,
        version=version,
    )
    effective_capture_mode = _effective_capture_mode(payload.capture_mode, policy_pack)

    allow_llm_calls = payload.allow_llm_calls
    async with session.begin():
        async with tenant_scope(session, str(principal.tenant_id)):
            license_row = await require_active_license(session, principal.tenant_id)
            allow_llm_calls = allow_llm_calls and license_allows_llm_calls(license_row)
            guardrail = await resolve_guardrail(
                session,
                principal.tenant_id,
                environment_id,
                project_id,
                guardrail_id,
            )
            resolved_version = version or guardrail.current_version
            version_row = await session.get(
                GuardrailVersion,
                (
                    principal.tenant_id,
                    environment_id,
                    project_id,
                    guardrail_id,
                    resolved_version,
                ),
            )
            if version_row is None:
                raise ServiceError("GUARDRAIL_VERSION_NOT_FOUND", "Guardrail version not found", 404)
            guardrail_mode = guardrail.mode

    request_id = str(uuid.uuid4())
    public_payload = _sensor_public_guard_request(payload)
    engine_request = EngineRequest(
        request_id=request_id,
        timestamp=_utc_iso(),
        tenant_id=str(principal.tenant_id),
        environment_id=environment_id,
        project_id=project_id,
        guardrail_id=guardrail_id,
        guardrail_version=resolved_version,
        phase=public_payload.phase,
        input=public_payload.input,
        timeout_ms=public_payload.timeout_ms,
        flags=EngineFlags(allow_llm_calls=allow_llm_calls),
    )
    engine_response = await evaluate_engine(engine_request)

    async with session.begin():
        async with tenant_scope(session, str(principal.tenant_id)):
            await record_audit_event(
                session,
                tenant_id=principal.tenant_id,
                environment_id=environment_id,
                project_id=project_id,
                guardrail_id=guardrail_id,
                guardrail_version=resolved_version,
                engine_response=engine_response,
                request_payload=_sanitize_sensor_request_payload_for_audit(
                    public_payload,
                    effective_capture_mode,
                ),
                action_resource={
                    "source": "endpoint_sensor",
                    "process_name": payload.process.name,
                    "process_pid": payload.process.pid,
                    "destination_host": payload.destination.host,
                    "destination_sni": payload.destination.sni,
                    "device_id": payload.device.device_id,
                    "client_capture_mode": payload.capture_mode,
                    "effective_capture_mode": effective_capture_mode,
                },
            )

    return SensorEvaluateResponse(
        request_id=engine_response.request_id,
        decision=_sensor_decision_from_engine(
            engine_response,
            dlp_tags=_dlp_tags_from_sensor_payload(payload.dlp),
        ),
        guardrail=SensorEvaluateGuardrail(
            environment_id=environment_id,
            project_id=project_id,
            guardrail_id=guardrail_id,
            guardrail_version=resolved_version,
            mode=guardrail_mode,
        ),
        triggering_policy=engine_response.triggering_policy.model_dump()
        if engine_response.triggering_policy
        else None,
        output_modifications=engine_response.output_modifications,
        latency_ms=engine_response.latency_ms.total,
        errors=[error.model_dump() for error in engine_response.errors],
    )


@sensor_router.post("/events", response_model=SensorEventIngestResponse)
async def ingest_sensor_events(
    payload: SensorEventBatchRequest,
    authorization: str | None = Header(default=None, alias="Authorization"),
    x_tenant_id: uuid.UUID | None = Header(default=None, alias="X-Tenant-Id"),
    x_device_id: str | None = Header(default=None, alias="X-Device-Id"),
    session: AsyncSession = Depends(get_session),
) -> SensorEventIngestResponse:
    principal = _authenticate_sensor_request(authorization, x_tenant_id or payload.tenant_id)
    if payload.tenant_id != principal.tenant_id:
        raise ServiceError("FORBIDDEN", "Payload tenant_id does not match sensor token", 403)

    incoming_event_ids = [event.event_id for event in payload.events]
    accepted = 0
    duplicates = 0
    chain_invalid = 0
    accepted_event_ids: list[str] = []
    duplicate_event_ids: list[str] = []
    chain_invalid_event_ids: list[str] = []
    accepted_device_ids: set[str] = set()

    async with session.begin():
        async with tenant_scope(session, str(principal.tenant_id)):
            existing_ids: set[str] = set()
            if incoming_event_ids:
                existing_result = await session.execute(
                    select(EndpointSensorEvent.event_id).where(
                        EndpointSensorEvent.tenant_id == principal.tenant_id,
                        EndpointSensorEvent.event_id.in_(incoming_event_ids),
                    )
                )
                existing_ids = set(existing_result.scalars().all())

            matcher = await build_matcher(session, principal.tenant_id)
            session_memo: dict[tuple[str, str | None, str, str], Any] = {}
            last_hash_by_device: dict[str, str | None] = {}

            for envelope in payload.events:
                if envelope.tenant_id != principal.tenant_id:
                    raise ServiceError(
                        "FORBIDDEN",
                        f"Event {envelope.event_id} tenant_id does not match sensor token",
                        403,
                )
                if envelope.event_id in existing_ids:
                    duplicates += 1
                    duplicate_event_ids.append(envelope.event_id)
                    continue

                device_id = _normalize_device_id(
                    envelope,
                    payload.device_id,
                    x_device_id,
                    principal.device_id,
                )
                if device_id not in last_hash_by_device:
                    previous_row = await session.execute(
                        select(EndpointSensorEvent.event_hash)
                        .where(
                            EndpointSensorEvent.tenant_id == principal.tenant_id,
                            EndpointSensorEvent.device_id == device_id,
                        )
                        .order_by(
                            EndpointSensorEvent.captured_at.desc(),
                            EndpointSensorEvent.created_at.desc(),
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
                chain_error = ",".join(chain_error_parts) if chain_error_parts else None
                chain_is_valid = chain_error is None
                if not chain_is_valid:
                    chain_invalid += 1
                    chain_invalid_event_ids.append(envelope.event_id)

                payload_body = envelope.payload
                dlp_tags = _payload_dlp_tags(payload_body)
                file_context = _parse_file_context_entries(payload_body.get("file_context"))
                stored_payload = dict(payload_body)
                stored_payload["dlp_tags"] = dlp_tags
                stored_payload["file_context"] = _file_context_to_payload(file_context)
                captured_at = dt.datetime.fromtimestamp(
                    envelope.timestamps.captured_at_ms / 1000.0,
                    tz=dt.timezone.utc,
                )
                row = EndpointSensorEvent(
                    tenant_id=principal.tenant_id,
                    event_id=envelope.event_id,
                    event_type=envelope.event_type,
                    process_name=envelope.process.name,
                    process_path=envelope.process.path,
                    parent_process=envelope.process.parent,
                    destination_host=envelope.destination.host,
                    destination_sni=envelope.destination.sni,
                    destination_port=envelope.destination.port,
                    user_email=envelope.user.user_email,
                    user_idp_subject=envelope.user.user_idp_subject,
                    device_id=device_id,
                    captured_at=captured_at,
                    prev_event_hash=envelope.chain.prev_event_hash,
                    event_hash=envelope.chain.event_hash,
                    chain_valid=chain_is_valid,
                    chain_error=chain_error,
                    decision=_payload_string(payload_body, "decision"),
                    message=_payload_string(payload_body, "message"),
                    prompt_hash=_payload_first_string(
                        payload_body,
                        "prompt_hash",
                        "prompt_text_hash",
                    ),
                    prompt_len=_payload_int(payload_body, "prompt_len"),
                    dlp_tags_json=_json_dumps(dlp_tags),
                    file_context_json=_json_dumps(stored_payload["file_context"]),
                    payload_json=_json_dumps(stored_payload),
                )
                row.session_id = await fold_event_into_session(
                    session,
                    tenant_id=principal.tenant_id,
                    matcher=matcher,
                    batch_memo=session_memo,
                    source="sensor",
                    event_type=envelope.event_type,
                    host=envelope.destination.sni or envelope.destination.host,
                    port=envelope.destination.port,
                    process_name=envelope.process.name,
                    process_path=envelope.process.path,
                    user_email=envelope.user.user_email,
                    user_idp_subject=envelope.user.user_idp_subject,
                    device_id=device_id,
                    captured_at=captured_at,
                    dlp_hit=bool(dlp_tags),
                )
                session.add(row)
                accepted += 1
                accepted_event_ids.append(envelope.event_id)
                accepted_device_ids.add(device_id)
                existing_ids.add(envelope.event_id)
                last_hash_by_device[device_id] = envelope.chain.event_hash

            event_seen_at = dt.datetime.now(dt.timezone.utc)
            for device_id in accepted_device_ids:
                await _mark_download_session_event_seen(
                    session,
                    principal.tenant_id,
                    device_id,
                    event_seen_at,
                )

    return SensorEventIngestResponse(
        accepted=accepted,
        duplicate_count=duplicates,
        chain_invalid_count=chain_invalid,
        accepted_event_ids=accepted_event_ids,
        duplicate_event_ids=duplicate_event_ids,
        chain_invalid_event_ids=chain_invalid_event_ids,
    )


@sensor_router.post("/heartbeat", response_model=SensorHeartbeatResponse)
async def sensor_heartbeat(
    payload: SensorHeartbeatRequest,
    authorization: str | None = Header(default=None, alias="Authorization"),
    x_tenant_id: uuid.UUID | None = Header(default=None, alias="X-Tenant-Id"),
    x_device_id: str | None = Header(default=None, alias="X-Device-Id"),
    session: AsyncSession = Depends(get_session),
) -> SensorHeartbeatResponse:
    principal = _authenticate_sensor_request(authorization, x_tenant_id or payload.tenant_id)
    if payload.tenant_id is not None and payload.tenant_id != principal.tenant_id:
        raise ServiceError("FORBIDDEN", "Payload tenant_id does not match sensor token", 403)
    if x_device_id and x_device_id != payload.device_id:
        raise ServiceError("FORBIDDEN", "X-Device-Id does not match payload device_id", 403)
    if principal.device_id and principal.device_id != payload.device_id:
        raise ServiceError("FORBIDDEN", "Sensor token does not match payload device_id", 403)

    now = dt.datetime.now(dt.timezone.utc)
    status = payload.status or "active"
    async with session.begin():
        async with tenant_scope(session, str(principal.tenant_id)):
            row = await session.get(EndpointSensorDevice, (principal.tenant_id, payload.device_id))
            if row is None:
                logger.warning(
                    "sensor.heartbeat.missing_device tenant_id=%s device_id=%s",
                    principal.tenant_id,
                    payload.device_id,
                )
                row = EndpointSensorDevice(
                    tenant_id=principal.tenant_id,
                    device_id=payload.device_id,
                    enrolled_at=now,
                )
                session.add(row)
            row.hostname = payload.hostname
            row.os = payload.os
            row.os_version = payload.os_version
            row.agent_version = payload.agent_version
            row.last_heartbeat_at = now
            row.last_policy_etag = payload.policy_etag
            row.last_user_email = payload.last_user_email
            row.identity_status = payload.identity_status
            row.queue_depth = payload.queue_depth
            row.last_successful_upload_at = payload.last_successful_upload_at
            row.metadata_json = _json_dumps(payload.metadata)
            row.status = status
            await _mark_download_session_heartbeat(
                session,
                principal.tenant_id,
                payload.device_id,
                now,
                payload.identity_status,
            )

    return SensorHeartbeatResponse(
        tenant_id=principal.tenant_id,
        device_id=payload.device_id,
        server_time=now,
        status=status,
        stale_after_seconds=int(settings.sensor_heartbeat_stale_seconds),
    )


@sensor_admin_router.post("/sensor/bootstrap-tokens", response_model=SensorBootstrapTokenResponse)
async def create_sensor_bootstrap_token(
    payload: SensorBootstrapTokenCreateRequest,
    session: AsyncSession = Depends(get_session),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> SensorBootstrapTokenResponse:
    _require_tenant_access(principal, payload.tenant_id, required_role="tenant-admin")
    token, row = _build_sensor_bootstrap_token_row(
        tenant_id=payload.tenant_id,
        expires_in_seconds=payload.expires_in_seconds,
        device_id=payload.device_id,
        created_by=payload.created_by or principal.subject,
    )
    async with session.begin():
        async with tenant_scope(session, str(payload.tenant_id)):
            session.add(row)
    return SensorBootstrapTokenResponse(
        token_id=row.id,
        tenant_id=payload.tenant_id,
        device_id=payload.device_id,
        bootstrap_token=token,
        expires_at=row.expires_at,
    )


@sensor_admin_router.post(
    "/sensor/download-sessions",
    response_model=SensorDownloadSessionResponse,
)
async def create_sensor_download_session(
    payload: SensorDownloadSessionCreateRequest,
    request: Request,
    session: AsyncSession = Depends(get_session),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> SensorDownloadSessionResponse:
    _require_tenant_access(principal, payload.tenant_id, required_role="tenant-admin")
    now = dt.datetime.now(dt.timezone.utc)
    token_ttl = max(int(settings.sensor_download_token_ttl_seconds), 60)
    installer_version = payload.installer_version or settings.sensor_installer_version
    download_session_id = uuid.uuid4()
    created_ip = payload.created_ip or (request.client.host if request.client else None)
    subject = f"sensor-download:{download_session_id}:{payload.employee_idp_subject}"
    bootstrap_token, token_row = _build_sensor_bootstrap_token_row(
        tenant_id=payload.tenant_id,
        expires_in_seconds=token_ttl,
        created_by=payload.employee_upn or payload.employee_idp_subject,
        subject=subject,
    )
    download_row = EndpointSensorDownloadSession(
        id=download_session_id,
        tenant_id=payload.tenant_id,
        employee_idp_subject=payload.employee_idp_subject,
        employee_upn=payload.employee_upn,
        employee_display_name=payload.employee_display_name,
        created_ip=created_ip,
        installer_version=installer_version,
        bootstrap_token_id=token_row.id,
        bootstrap_token_expires_at=token_row.expires_at,
        status="generating",
        created_at=now,
        updated_at=now,
    )

    async with session.begin():
        async with tenant_scope(session, str(payload.tenant_id)):
            session.add(token_row)
            session.add(download_row)

    try:
        artifact = await _request_installer_artifact(
            session_id=download_session_id,
            tenant_id=payload.tenant_id,
            employee_upn=payload.employee_upn,
            installer_version=installer_version,
            bootstrap_token=bootstrap_token,
        )
    except ServiceError as exc:
        failed_at = dt.datetime.now(dt.timezone.utc)
        async with session.begin():
            async with tenant_scope(session, str(payload.tenant_id)):
                row = await session.get(EndpointSensorDownloadSession, download_session_id)
                if row is not None:
                    row.failure_reason = exc.error_type.lower()
                    _set_download_session_status(row, "failed", failed_at)
        raise

    artifact_expires_at = _parse_packager_datetime(artifact.get("expires_at"))
    if artifact_expires_at is None:
        artifact_expires_at = dt.datetime.now(dt.timezone.utc) + dt.timedelta(
            seconds=max(int(settings.sensor_installer_artifact_ttl_seconds), 60)
        )
    async with session.begin():
        async with tenant_scope(session, str(payload.tenant_id)):
            row = await session.get(EndpointSensorDownloadSession, download_session_id)
            if row is None:
                raise ServiceError("DOWNLOAD_SESSION_NOT_FOUND", "Download session not found", 404)
            row.artifact_id = str(artifact["artifact_id"])
            row.artifact_sha256 = str(artifact.get("sha256") or "") or None
            row.artifact_filename = str(artifact.get("filename") or "") or None
            row.artifact_expires_at = artifact_expires_at
            _set_download_session_status(row, "ready")
            response_row = row
    return _download_session_to_response(response_row)


@sensor_admin_router.get(
    "/sensor/download-sessions",
    response_model=list[SensorDownloadSessionResponse],
)
async def list_sensor_download_sessions(
    status: str | None = Query(default=None),
    employee: str | None = Query(default=None),
    installer_version: str | None = Query(default=None),
    from_ts: dt.datetime | None = Query(default=None),
    to_ts: dt.datetime | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    session: AsyncSession = Depends(get_session),
    x_tenant_id: uuid.UUID = Header(alias="X-Tenant-Id"),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> list[SensorDownloadSessionResponse]:
    _require_tenant_access(principal, x_tenant_id, required_role="tenant-auditor")
    stmt = select(EndpointSensorDownloadSession).where(
        EndpointSensorDownloadSession.tenant_id == x_tenant_id
    )
    if status and status not in {"expired", "all"}:
        stmt = stmt.where(EndpointSensorDownloadSession.status == status)
    if employee:
        like = f"%{employee.strip()}%"
        stmt = stmt.where(EndpointSensorDownloadSession.employee_upn.like(like))
    if installer_version:
        stmt = stmt.where(EndpointSensorDownloadSession.installer_version == installer_version)
    if from_ts:
        stmt = stmt.where(EndpointSensorDownloadSession.created_at >= from_ts)
    if to_ts:
        stmt = stmt.where(EndpointSensorDownloadSession.created_at <= to_ts)
    stmt = stmt.order_by(EndpointSensorDownloadSession.created_at.desc()).limit(limit)

    async with session.begin():
        async with tenant_scope(session, str(x_tenant_id)):
            result = await session.execute(stmt)
            rows = result.scalars().all()
    responses = [_download_session_to_response(row) for row in rows]
    if status == "expired":
        responses = [row for row in responses if row.status == "expired"]
    return responses


@sensor_admin_router.get(
    "/sensor/download-sessions/{session_id}",
    response_model=SensorDownloadSessionResponse,
)
async def get_sensor_download_session(
    session_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    x_tenant_id: uuid.UUID = Header(alias="X-Tenant-Id"),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> SensorDownloadSessionResponse:
    _require_tenant_access(principal, x_tenant_id, required_role="tenant-auditor")
    async with session.begin():
        async with tenant_scope(session, str(x_tenant_id)):
            row = await session.get(EndpointSensorDownloadSession, session_id)
            if row is None or row.tenant_id != x_tenant_id:
                raise ServiceError("DOWNLOAD_SESSION_NOT_FOUND", "Download session not found", 404)
    return _download_session_to_response(row)


@sensor_admin_router.get("/sensor/download-sessions/{session_id}/installer")
async def download_sensor_installer(
    session_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    x_tenant_id: uuid.UUID = Header(alias="X-Tenant-Id"),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> Response:
    _require_tenant_access(principal, x_tenant_id, required_role="tenant-auditor")
    now = dt.datetime.now(dt.timezone.utc)
    async with session.begin():
        async with tenant_scope(session, str(x_tenant_id)):
            row = await session.get(EndpointSensorDownloadSession, session_id)
            if row is None or row.tenant_id != x_tenant_id:
                raise ServiceError("DOWNLOAD_SESSION_NOT_FOUND", "Download session not found", 404)
            if row.artifact_id is None:
                raise ServiceError("INSTALLER_NOT_READY", "Sensor installer is not ready", 409)
            if row.artifact_expires_at and _as_utc(row.artifact_expires_at) <= now:
                _set_download_session_status(row, "expired", now)
                raise ServiceError("INSTALLER_EXPIRED", "Sensor installer artifact has expired", 410)
            artifact_id = row.artifact_id
            filename = row.artifact_filename or f"UmaiSensor-{row.id}.msi"

    content, content_type = await _download_installer_artifact(artifact_id)

    async with session.begin():
        async with tenant_scope(session, str(x_tenant_id)):
            row = await session.get(EndpointSensorDownloadSession, session_id)
            if row is not None:
                if row.downloaded_at is None:
                    row.downloaded_at = now
                _set_download_session_status(row, "downloaded", now)

    return Response(
        content=content,
        media_type=content_type or "application/octet-stream",
        headers={
            "Cache-Control": "no-store",
            "Content-Disposition": f'attachment; filename="{filename}"',
        },
    )


@sensor_admin_router.get(
    "/sensor/onboarding/devices",
    response_model=list[SensorOnboardingDeviceResponse],
)
async def list_sensor_onboarding_devices(
    status: str | None = Query(default=None),
    employee: str | None = Query(default=None),
    installer_version: str | None = Query(default=None),
    from_ts: dt.datetime | None = Query(default=None),
    to_ts: dt.datetime | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    session: AsyncSession = Depends(get_session),
    x_tenant_id: uuid.UUID = Header(alias="X-Tenant-Id"),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> list[SensorOnboardingDeviceResponse]:
    _require_tenant_access(principal, x_tenant_id, required_role="tenant-auditor")
    stmt = select(EndpointSensorDownloadSession).where(
        EndpointSensorDownloadSession.tenant_id == x_tenant_id
    )
    if status and status not in {"expired", "all"}:
        stmt = stmt.where(EndpointSensorDownloadSession.status == status)
    if employee:
        like = f"%{employee.strip()}%"
        stmt = stmt.where(EndpointSensorDownloadSession.employee_upn.like(like))
    if installer_version:
        stmt = stmt.where(EndpointSensorDownloadSession.installer_version == installer_version)
    if from_ts:
        stmt = stmt.where(EndpointSensorDownloadSession.created_at >= from_ts)
    if to_ts:
        stmt = stmt.where(EndpointSensorDownloadSession.created_at <= to_ts)
    stmt = stmt.order_by(EndpointSensorDownloadSession.created_at.desc()).limit(limit)

    async with session.begin():
        async with tenant_scope(session, str(x_tenant_id)):
            result = await session.execute(stmt)
            rows = result.scalars().all()
            device_ids = [row.device_id for row in rows if row.device_id]
            devices: dict[str, EndpointSensorDevice] = {}
            if device_ids:
                device_result = await session.execute(
                    select(EndpointSensorDevice).where(
                        EndpointSensorDevice.tenant_id == x_tenant_id,
                        EndpointSensorDevice.device_id.in_(device_ids),
                    )
                )
                devices = {device.device_id: device for device in device_result.scalars().all()}
    responses = [
        _onboarding_session_to_response(row, devices.get(row.device_id or ""))
        for row in rows
    ]
    if status == "expired":
        responses = [row for row in responses if row.status == "expired"]
    return responses


@sensor_admin_router.get("/sensor/devices", response_model=list[SensorDeviceResponse])
async def list_sensor_devices(
    status: str | None = Query(default=None),
    device_id: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    session: AsyncSession = Depends(get_session),
    x_tenant_id: uuid.UUID = Header(alias="X-Tenant-Id"),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> list[SensorDeviceResponse]:
    _require_tenant_access(principal, x_tenant_id, required_role="tenant-auditor")
    stmt = select(EndpointSensorDevice).where(EndpointSensorDevice.tenant_id == x_tenant_id)
    if device_id:
        stmt = stmt.where(EndpointSensorDevice.device_id == device_id)
    if status and status != "stale":
        stmt = stmt.where(EndpointSensorDevice.status == status)
    stmt = stmt.order_by(EndpointSensorDevice.last_heartbeat_at.desc().nullslast()).limit(limit)

    async with session.begin():
        async with tenant_scope(session, str(x_tenant_id)):
            result = await session.execute(stmt)
            rows = result.scalars().all()
    responses = [_sensor_device_to_response(row) for row in rows]
    if status == "stale":
        responses = [row for row in responses if row.status == "stale"]
    return responses


@sensor_admin_router.get("/sensor/events", response_model=list[SensorEventResponse])
async def list_sensor_events(
    event_type: str | None = Query(default=None),
    decision: str | None = Query(default=None),
    device_id: str | None = Query(default=None),
    destination_host: str | None = Query(default=None),
    process_name: str | None = Query(default=None),
    chain_valid: bool | None = Query(default=None),
    from_ts: dt.datetime | None = Query(default=None),
    to_ts: dt.datetime | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    session: AsyncSession = Depends(get_session),
    x_tenant_id: uuid.UUID = Header(alias="X-Tenant-Id"),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> list[SensorEventResponse]:
    _require_tenant_access(principal, x_tenant_id, required_role="tenant-auditor")
    stmt = select(EndpointSensorEvent).where(EndpointSensorEvent.tenant_id == x_tenant_id)
    if event_type:
        stmt = stmt.where(EndpointSensorEvent.event_type == event_type)
    if decision:
        stmt = stmt.where(EndpointSensorEvent.decision == decision)
    if device_id:
        stmt = stmt.where(EndpointSensorEvent.device_id == device_id)
    if destination_host:
        stmt = stmt.where(EndpointSensorEvent.destination_host == destination_host)
    if process_name:
        stmt = stmt.where(EndpointSensorEvent.process_name == process_name)
    if chain_valid is not None:
        stmt = stmt.where(EndpointSensorEvent.chain_valid == chain_valid)
    if from_ts:
        stmt = stmt.where(EndpointSensorEvent.captured_at >= from_ts)
    if to_ts:
        stmt = stmt.where(EndpointSensorEvent.captured_at <= to_ts)
    stmt = stmt.order_by(
        EndpointSensorEvent.captured_at.desc(),
        EndpointSensorEvent.created_at.desc(),
    ).limit(limit)

    async with session.begin():
        async with tenant_scope(session, str(x_tenant_id)):
            result = await session.execute(stmt)
            rows = result.scalars().all()
    return [_sensor_event_to_response(row) for row in rows]


@sensor_admin_router.get("/sensor/summary", response_model=SensorSummaryResponse)
async def get_sensor_summary(
    days: int = Query(default=7, ge=1, le=90),
    session: AsyncSession = Depends(get_session),
    x_tenant_id: uuid.UUID = Header(alias="X-Tenant-Id"),
    principal: AdminPrincipal = Depends(get_admin_principal),
) -> SensorSummaryResponse:
    _require_tenant_access(principal, x_tenant_id, required_role="tenant-auditor")
    cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)
    stmt = (
        select(EndpointSensorEvent)
        .where(
            EndpointSensorEvent.tenant_id == x_tenant_id,
            EndpointSensorEvent.captured_at >= cutoff,
        )
        .order_by(EndpointSensorEvent.captured_at.asc(), EndpointSensorEvent.created_at.asc())
    )

    async with session.begin():
        async with tenant_scope(session, str(x_tenant_id)):
            result = await session.execute(stmt)
            rows = result.scalars().all()
    return _summarize_sensor_rows(rows, days)


# ---------------------------------------------------------------------------
# UMAI: agent session ingest
# ---------------------------------------------------------------------------


class SensorSessionIngestResponse(_BaseModel):
    accepted: int
    created: int
    updated: int
    unchanged: int
    findings: int
    rejected: list[str] = Field(default_factory=list)


MAX_SESSION_BATCH_BYTES = 64 * 1024 * 1024


async def _read_session_batch(request: Request) -> dict[str, Any]:
    """Read the request body, decompressing when the collector gzipped it.

    Transcripts compress roughly 10:1, so the collector always gzips. FastAPI
    does not decompress request bodies, so it is handled here.
    """
    raw = await request.body()
    if len(raw) > MAX_SESSION_BATCH_BYTES:
        raise ServiceError("PAYLOAD_TOO_LARGE", "Session batch exceeds the size limit", 413)

    if (request.headers.get("Content-Encoding") or "").lower() == "gzip":
        import gzip

        try:
            raw = gzip.decompress(raw)
        except (OSError, EOFError) as exc:
            raise ServiceError("INVALID_REQUEST", "Body is not valid gzip", 400) from exc

    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ServiceError("INVALID_REQUEST", "Body is not valid JSON", 400) from exc

    if not isinstance(payload, dict):
        raise ServiceError("INVALID_REQUEST", "Body must be a JSON object", 422)
    return payload


@sensor_router.post("/sessions", response_model=SensorSessionIngestResponse)
async def ingest_agent_sessions(
    request: Request,
    authorization: str | None = Header(default=None, alias="Authorization"),
    x_tenant_id: uuid.UUID | None = Header(default=None, alias="X-Tenant-Id"),
    session: AsyncSession = Depends(get_session),
) -> SensorSessionIngestResponse:
    """Accept a batch of agent session transcripts from a managed endpoint."""
    principal = _authenticate_sensor_request(authorization, x_tenant_id)

    body = await _read_session_batch(request)
    sessions = body.get("sessions")
    if not isinstance(sessions, list):
        raise ServiceError("INVALID_REQUEST", "sessions must be an array", 422)

    collector = body.get("collector") if isinstance(body.get("collector"), dict) else {}

    async with session.begin():
        async with tenant_scope(session, str(principal.tenant_id)):
            result = await record_agent_sessions(
                session,
                tenant_id=principal.tenant_id,
                device_id=principal.device_id,
                collector=collector,
                sessions=sessions,
            )

    # Fire-and-forget after the DB transaction commits so the SIEM never sees a
    # finding the database rolled back. Same posture as the extension path: a
    # delivery failure is logged and dropped; a durable outbox is the hardening.
    for finding_event in result.siem_events:
        asyncio.create_task(emit_event(finding_event))

    logger.info(
        "sensor.sessions.ingested tenant=%s device=%s created=%s updated=%s unchanged=%s findings=%s rejected=%s",
        principal.tenant_id,
        principal.device_id,
        result.created,
        result.updated,
        result.unchanged,
        result.findings,
        len(result.rejected),
    )

    return SensorSessionIngestResponse(
        accepted=result.accepted,
        created=result.created,
        updated=result.updated,
        unchanged=result.unchanged,
        findings=result.findings,
        rejected=result.rejected,
    )


# ---------------------------------------------------------------------------
# UMAI: device token renewal
# ---------------------------------------------------------------------------


class SensorRenewResponse(_BaseModel):
    tenant_id: uuid.UUID
    device_id: str
    device_token: str
    token_type: str = "bearer"
    expires_at: int
    audience: str = SENSOR_DEVICE_TOKEN_AUDIENCE


@sensor_router.post("/renew", response_model=SensorRenewResponse)
async def renew_sensor_device_token(
    authorization: str | None = Header(default=None, alias="Authorization"),
    x_tenant_id: uuid.UUID | None = Header(default=None, alias="X-Tenant-Id"),
    session: AsyncSession = Depends(get_session),
) -> SensorRenewResponse:
    """Exchange a device token for a fresh one.

    Bootstrap tokens are single-use and device tokens are short-lived, so
    without this a deployed sensor stops reporting a day after enrolment and
    needs re-enrolling by hand.

    The current token is the renewal credential, accepted within a grace window
    past expiry. Renewal is refused when the device row is missing or not
    active, which makes deactivating a device in the console an effective kill
    switch: the sensor keeps its token until it expires, then cannot renew.
    """
    if not authorization or not authorization.lower().startswith("bearer "):
        raise ServiceError("UNAUTHENTICATED", "Bearer token required for sensor renewal", 401)

    payload = _verify_hs256_jwt(
        authorization.split(" ", 1)[1].strip(),
        _sensor_jwt_secret(),
        audience=SENSOR_DEVICE_TOKEN_AUDIENCE,
        required_role="tenant-device",
        expiry_leeway_seconds=max(int(settings.sensor_device_token_renew_grace_seconds), 0),
    )

    try:
        tenant_id = uuid.UUID(str(payload.get("tenant_id")))
    except Exception as exc:
        raise ServiceError("TOKEN_INVALID", "Sensor token tenant_id is invalid", 401) from exc

    if x_tenant_id is not None and x_tenant_id != tenant_id:
        raise ServiceError("FORBIDDEN", "Tenant header does not match sensor token", 403)

    device_id = str(payload.get("device_id") or "").strip()
    if not device_id:
        raise ServiceError("TOKEN_INVALID", "Sensor token has no device_id", 401)

    async with session.begin():
        async with tenant_scope(session, str(tenant_id)):
            device = await session.get(EndpointSensorDevice, (tenant_id, device_id))
            if device is None:
                raise ServiceError("FORBIDDEN", "Device is not enrolled", 403)
            if (device.status or "").lower() != "active":
                raise ServiceError("FORBIDDEN", "Device is not active", 403)

    device_token, expires_at = _issue_sensor_device_token(
        tenant_id=tenant_id,
        device_id=device_id,
        subject=str(payload.get("sub") or f"sensor:{device_id}"),
    )

    logger.info("sensor.token.renewed tenant=%s device=%s", tenant_id, device_id)

    return SensorRenewResponse(
        tenant_id=tenant_id,
        device_id=device_id,
        device_token=device_token,
        expires_at=expires_at,
    )
