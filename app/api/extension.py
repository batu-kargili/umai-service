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
from app.core.engine_client import evaluate_engine
from app.core.errors import ServiceError
from app.core.events import record_audit_event
from app.core.file_inspection import extract_attachment_text
from app.core.library import get_guardrail_template
from app.core.license import license_allows_llm_calls, require_active_license
from app.core.resolver import resolve_guardrail
from app.core.settings import settings
from app.models.engine import EngineFlags, EngineRequest, EngineResponse
from app.models.db import BrowserExtensionEvent, Guardrail, GuardrailVersion
from app.models.public import ChatMessage, InputArtifact, InputPayload, PublicGuardRequest

logger = logging.getLogger("umai.service.extension")

DEVICE_TOKEN_AUDIENCE = "umai-ext-ingest"
BOOTSTRAP_TOKEN_AUDIENCE = "umai-ext-bootstrap"
DEFAULT_POLICY_PACK = {
    "version": "default-local-allow",
    "default_action": "allow",
    "rules": [],
}
EXTENSION_DLP_SECRET_TAGS = [
    "SECRET_BEARER_TOKEN",
    "SECRET_PRIVATE_KEY",
    "SECRET_TOKEN",
]
EXTENSION_DLP_CONTACT_TAGS = [
    "PII_EMAIL",
    "PII_PHONE",
]
EXTENSION_DLP_FINANCIAL_TAGS = [
    "PII_CREDITCARD",
    "PII_IBAN",
    "PII_IBAN_TR",
]
EXTENSION_MAX_FILE_BYTES = 26_214_400
EXTENSION_MAX_EXTRACTED_CHARS = 250_000


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


class ExtensionBootstrapRequest(_BaseModel):
    tenant_id: uuid.UUID | None = None
    device_id: str | None = None
    extension_id: str | None = None
    browser_profile_id: str | None = None


class ExtensionBootstrapResponse(_BaseModel):
    tenant_id: uuid.UUID
    device_id: str
    device_token: str
    token_type: str = "bearer"
    expires_at: int
    audience: str = DEVICE_TOKEN_AUDIENCE


class ExtensionAttachment(_BaseModel):
    filename: str
    mime: str | None = None
    extension: str | None = None
    size_bytes: int = 0
    sha256: str | None = None
    inspection_status: str = "pending"
    extracted_chars: int = 0
    truncated: bool = False
    extracted_text: str | None = None
    content_b64: str | None = None
    error: str | None = None


class ExtensionEvaluateRequest(_BaseModel):
    tenant_id: uuid.UUID | None = None
    site: str
    url: str
    prompt_text: str = Field(min_length=1)
    capture_mode: str = "metadata_only"
    tab_id: int | None = None
    user: ExtensionUser = Field(default_factory=ExtensionUser)
    device: ExtensionDevice | None = None
    attachments: list[ExtensionAttachment] = Field(default_factory=list)
    dlp: dict[str, Any] = Field(default_factory=dict)
    timeout_ms: int | None = 1500
    allow_llm_calls: bool = True


class ExtensionEvaluateDecision(_BaseModel):
    type: str
    message: str | None = None
    rulesFired: list[str] = Field(default_factory=list)
    dlpTags: list[str] = Field(default_factory=list)
    redactions: list[dict[str, Any]] = Field(default_factory=list)
    redactedText: str | None = None
    requireJustification: bool = False
    minJustificationChars: int | None = None


class ExtensionEvaluateGuardrail(_BaseModel):
    environment_id: str
    project_id: str
    guardrail_id: str
    guardrail_version: int
    mode: str


class ExtensionEvaluateResponse(_BaseModel):
    ok: bool = True
    configured: bool = True
    request_id: str
    decision: ExtensionEvaluateDecision
    guardrail: ExtensionEvaluateGuardrail
    triggering_policy: dict[str, Any] | None = None
    output_modifications: dict[str, Any] | None = None
    latency_ms: float
    errors: list[dict[str, Any]] = Field(default_factory=list)


def _pad_b64(value: str) -> str:
    return value + "=" * (-len(value) % 4)


def _b64url_json(value: dict[str, Any]) -> str:
    raw = json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _encode_hs256_jwt(payload: dict[str, Any], secret: str) -> str:
    header_b64 = _b64url_json({"alg": "HS256", "typ": "JWT"})
    payload_b64 = _b64url_json(payload)
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    signature = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    signature_b64 = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    return f"{header_b64}.{payload_b64}.{signature_b64}"


def _verify_hs256_jwt(
    token: str,
    secret: str,
    *,
    audience: str,
    required_role: str,
) -> dict[str, Any]:
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

    token_audience = payload.get("aud")
    if token_audience != audience:
        raise ServiceError("TOKEN_INVALID", "Extension token audience mismatch", 401)

    roles = payload.get("roles") or []
    if isinstance(roles, str):
        roles = [roles]
    if required_role not in roles:
        raise ServiceError("FORBIDDEN", f"Extension token is missing {required_role} role", 403)

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

    payload = _verify_hs256_jwt(
        token,
        secret,
        audience=DEVICE_TOKEN_AUDIENCE,
        required_role="tenant-device",
    )
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


def _authenticate_extension_bootstrap_request(
    authorization: str | None,
    tenant_id: uuid.UUID | None,
) -> ExtensionAuthPrincipal:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise ServiceError("UNAUTHENTICATED", "Bearer token required for extension bootstrap", 401)
    if tenant_id is None:
        raise ServiceError("INVALID_REQUEST", "X-Tenant-Id or tenant_id is required", 422)

    secret = (settings.extension_ingest_jwt_hs256_secret or "").strip()
    if not secret:
        raise ServiceError(
            "AUTH_MISCONFIGURED",
            "Extension bootstrap auth is not configured",
            500,
        )

    token = authorization.split(" ", 1)[1].strip()
    payload = _verify_hs256_jwt(
        token,
        secret,
        audience=BOOTSTRAP_TOKEN_AUDIENCE,
        required_role="tenant-bootstrap",
    )
    try:
        token_tenant_id = uuid.UUID(str(payload.get("tenant_id")))
    except Exception as exc:
        raise ServiceError("TOKEN_INVALID", "Extension bootstrap tenant_id is invalid", 401) from exc

    if tenant_id != token_tenant_id:
        raise ServiceError("FORBIDDEN", "Tenant header does not match bootstrap token", 403)

    return ExtensionAuthPrincipal(
        tenant_id=token_tenant_id,
        subject=str(payload.get("sub")) if payload.get("sub") else None,
    )


def _issue_extension_device_token(
    *,
    tenant_id: uuid.UUID,
    device_id: str,
    subject: str,
) -> tuple[str, int]:
    secret = (settings.extension_ingest_jwt_hs256_secret or "").strip()
    if not secret:
        raise ServiceError(
            "AUTH_MISCONFIGURED",
            "Extension ingest auth is not configured",
            500,
        )

    now = int(time.time())
    expires_at = now + max(int(settings.extension_device_token_ttl_seconds), 60)
    token = _encode_hs256_jwt(
        {
            "sub": subject,
            "tenant_id": str(tenant_id),
            "device_id": device_id,
            "aud": DEVICE_TOKEN_AUDIENCE,
            "iat": now,
            "exp": expires_at,
            "roles": ["tenant-device"],
        },
        secret,
    )
    return token, expires_at


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


def _append_extension_rule(
    rules: list[dict[str, Any]],
    seen_ids: set[str],
    *,
    rule_id: str,
    tags: list[str],
    action_type: str,
    message: str,
    strategy: str | None = None,
    min_chars: int | None = None,
) -> None:
    if rule_id in seen_ids:
        return
    rule: dict[str, Any] = {
        "id": rule_id,
        "enabled": True,
        "match": {"dlp_tags_any": tags},
        "action": {"type": action_type},
        "message": message,
    }
    if strategy is not None:
        rule["action"]["strategy"] = strategy
    if min_chars is not None:
        rule["action"]["min_chars"] = min_chars
    rules.append(rule)
    seen_ids.add(rule_id)


def _build_extension_policy_pack_from_snapshot(snapshot: dict[str, Any]) -> dict[str, Any]:
    policies = snapshot.get("policies")
    if not isinstance(policies, list):
        return DEFAULT_POLICY_PACK

    policy_ids: set[str] = set()
    for policy in policies:
        if not isinstance(policy, dict):
            continue
        policy_id = policy.get("id")
        if isinstance(policy_id, str) and policy_id:
            policy_ids.add(policy_id)

    rules: list[dict[str, Any]] = []
    seen_ids: set[str] = set()

    if "pol-owasp-sensitive-disclosure" in policy_ids:
        _append_extension_rule(
            rules,
            seen_ids,
            rule_id="guardrail_block_secrets",
            tags=EXTENSION_DLP_SECRET_TAGS,
            action_type="block",
            message="Sensitive secret detected by the active UMAI guardrail.",
        )
        _append_extension_rule(
            rules,
            seen_ids,
            rule_id="guardrail_redact_financial",
            tags=EXTENSION_DLP_FINANCIAL_TAGS,
            action_type="redact",
            strategy="mask",
            message="Financial identifier detected by the active UMAI guardrail and will be redacted.",
        )

    if (
        "pol-telecom-subscriber-secrecy" in policy_ids
        or "pol-kvkk-gdpr-privacy-compliance" in policy_ids
    ):
        _append_extension_rule(
            rules,
            seen_ids,
            rule_id="guardrail_justify_contact_pii",
            tags=EXTENSION_DLP_CONTACT_TAGS,
            action_type="justify",
            min_chars=12,
            message="Possible regulated subscriber or personal data detected. Provide justification to continue.",
        )
        _append_extension_rule(
            rules,
            seen_ids,
            rule_id="guardrail_redact_regulated_financial",
            tags=EXTENSION_DLP_FINANCIAL_TAGS,
            action_type="redact",
            strategy="mask",
            message="Regulated financial identifier detected and will be redacted before submission.",
        )

    version = snapshot.get("version")
    guardrail_id = snapshot.get("guardrail_id")
    resolved_version = str(version) if version is not None else "snapshot"
    resolved_guardrail_id = guardrail_id if isinstance(guardrail_id, str) and guardrail_id else "guardrail"

    return {
        "version": f"{resolved_guardrail_id}:{resolved_version}",
        "default_action": "allow",
        "rules": rules,
    }


async def _load_guardrail_snapshot_for_extension_policy(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    environment_id: str,
    project_id: str,
    guardrail_id: str,
    version: int | None,
) -> dict[str, Any]:
    async with session.begin():
        async with tenant_scope(session, str(tenant_id)):
            guardrail = await session.get(
                Guardrail,
                (tenant_id, environment_id, project_id, guardrail_id),
            )
            if guardrail is None:
                raise ServiceError("GUARDRAIL_NOT_FOUND", "Guardrail not found", 404)
            resolved_version = version or guardrail.current_version
            version_row = await session.get(
                GuardrailVersion,
                (tenant_id, environment_id, project_id, guardrail_id, resolved_version),
            )
            if version_row is None:
                raise ServiceError("GUARDRAIL_VERSION_NOT_FOUND", "Guardrail version not found", 404)
    return json.loads(version_row.snapshot_json)


async def _resolve_extension_policy_pack(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    environment_id: str | None,
    project_id: str | None,
    guardrail_id: str | None,
    version: int | None,
    template_id: str | None,
) -> dict[str, Any]:
    if template_id:
        template = get_guardrail_template(template_id)
        if template is None:
            raise ServiceError("GUARDRAIL_TEMPLATE_NOT_FOUND", "Guardrail template not found", 404)
        snapshot = {
            "guardrail_id": template.get("default_guardrail_id") or template_id,
            "version": template.get("version"),
            "policies": template.get("policies", []),
        }
        return _build_extension_policy_pack_from_snapshot(snapshot)

    has_guardrail_selector = any(
        value is not None for value in (environment_id, project_id, guardrail_id, version)
    )
    if not has_guardrail_selector:
        return _load_policy_pack()
    if not environment_id or not project_id or not guardrail_id:
        raise ServiceError(
            "INVALID_REQUEST",
            "environment_id, project_id, and guardrail_id are required together",
            422,
        )

    snapshot = await _load_guardrail_snapshot_for_extension_policy(
        session,
        tenant_id=tenant_id,
        environment_id=environment_id,
        project_id=project_id,
        guardrail_id=guardrail_id,
        version=version,
    )
    return _build_extension_policy_pack_from_snapshot(snapshot)


def _utc_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _dlp_tags_from_extension_payload(dlp: dict[str, Any]) -> list[str]:
    tags = dlp.get("tags") if isinstance(dlp, dict) else None
    if not isinstance(tags, list):
        return []
    return [tag for tag in tags if isinstance(tag, str) and tag]


def _risk_score_from_extension_payload(dlp: dict[str, Any]) -> float | None:
    value = dlp.get("riskScore") if isinstance(dlp, dict) else None
    if value is None:
        value = dlp.get("risk_score") if isinstance(dlp, dict) else None
    if isinstance(value, (int, float)):
        return float(value)
    return None


def _extension_action_from_engine(engine_response: EngineResponse) -> str:
    action = (engine_response.decision.action or "").upper()
    if action == "STEP_UP_APPROVAL":
        return "justify"
    if action == "BLOCK" or not engine_response.decision.allowed:
        return "block"
    if action == "ALLOW_WITH_MODIFICATIONS":
        return "redact"
    if action in {"ALLOW_WITH_WARNINGS", "FLAG"}:
        return "warn"
    return "allow"


def _extension_rules_from_engine(engine_response: EngineResponse) -> list[str]:
    rules: list[str] = []
    triggering_policy = engine_response.triggering_policy
    if not triggering_policy:
        return rules

    if triggering_policy.policy_id:
        rules.append(triggering_policy.policy_id)
    details = triggering_policy.details if isinstance(triggering_policy.details, dict) else {}
    matched_rule_id = details.get("matched_rule_id")
    if isinstance(matched_rule_id, str) and matched_rule_id and matched_rule_id not in rules:
        rules.append(matched_rule_id)
    return rules


def _extension_decision_from_engine(
    engine_response: EngineResponse,
    *,
    dlp_tags: list[str],
) -> ExtensionEvaluateDecision:
    decision_type = _extension_action_from_engine(engine_response)
    output_modifications = engine_response.output_modifications or {}
    redacted_text = output_modifications.get("modified_text")
    if not isinstance(redacted_text, str):
        redacted_text = None
    return ExtensionEvaluateDecision(
        type=decision_type,
        message=engine_response.decision.reason,
        rulesFired=_extension_rules_from_engine(engine_response),
        dlpTags=dlp_tags,
        redactions=[],
        redactedText=redacted_text,
        requireJustification=decision_type == "justify",
        minJustificationChars=12 if decision_type == "justify" else None,
    )


def _attachment_extension(attachment: ExtensionAttachment) -> str:
    if attachment.extension:
        return attachment.extension.lower().lstrip(".")
    if "." in attachment.filename:
        return attachment.filename.rsplit(".", 1)[1].lower()
    return ""


def _attachment_metadata(attachment: ExtensionAttachment, status: str, extracted_chars: int, truncated: bool) -> dict[str, Any]:
    return {
        "filename": attachment.filename,
        "mime": attachment.mime,
        "extension": _attachment_extension(attachment),
        "size_bytes": attachment.size_bytes,
        "sha256": attachment.sha256,
        "inspection_status": status,
        "extracted_chars": extracted_chars,
        "truncated": truncated,
        "error": attachment.error,
    }


def _attachment_artifacts(payload: ExtensionEvaluateRequest) -> tuple[list[InputArtifact], list[dict[str, Any]]]:
    artifacts: list[InputArtifact] = []
    incomplete: list[dict[str, Any]] = []
    for attachment in payload.attachments:
        extension = _attachment_extension(attachment)
        status = attachment.inspection_status
        text = attachment.extracted_text or ""
        truncated = bool(attachment.truncated)
        error = attachment.error

        if attachment.size_bytes > EXTENSION_MAX_FILE_BYTES:
            status = "too_large"
            text = ""
            truncated = False
        elif status in {"server_required", "pending"} or attachment.content_b64:
            extracted = extract_attachment_text(
                filename=attachment.filename,
                extension=extension,
                content_b64=attachment.content_b64,
                fallback_text=attachment.extracted_text,
                max_chars=EXTENSION_MAX_EXTRACTED_CHARS,
            )
            status = extracted.status
            text = extracted.text
            truncated = extracted.truncated
            error = extracted.error
        elif text and len(text) > EXTENSION_MAX_EXTRACTED_CHARS:
            text = text[:EXTENSION_MAX_EXTRACTED_CHARS]
            status = "truncated"
            truncated = True

        extracted_chars = len(text)
        metadata = _attachment_metadata(attachment, status, extracted_chars, truncated)
        if error:
            metadata["error"] = error
        artifacts.append(
            InputArtifact(
                artifact_type="CUSTOM",
                name=attachment.filename,
                payload_summary=f"Attachment {attachment.filename} ({attachment.size_bytes} bytes)",
                content=text or None,
                content_type="text",
                metadata=metadata,
            )
        )
        if status != "extracted":
            incomplete.append(metadata)
    return artifacts, incomplete


def _sanitize_request_payload_for_audit(payload: PublicGuardRequest, capture_mode: str) -> PublicGuardRequest:
    if capture_mode == "full_content":
        return payload
    sanitized = payload.model_copy(deep=True)
    for artifact in sanitized.input.artifacts:
        artifact.content = None
    return sanitized


def _incomplete_extension_response(
    *,
    request_id: str,
    guardrail: ExtensionEvaluateGuardrail,
    incomplete: list[dict[str, Any]],
) -> ExtensionEvaluateResponse:
    first = incomplete[0]
    status = str(first.get("inspection_status") or "incomplete")
    filename = str(first.get("filename") or "attachment")
    if status == "too_large":
        decision_type = "block"
        message = f"File {filename} exceeds the organization file inspection size limit."
    else:
        decision_type = "warn" if guardrail.mode == "MONITOR" else "justify"
        message = f"File {filename} could not be fully inspected before AI submission."
    return ExtensionEvaluateResponse(
        request_id=request_id,
        decision=ExtensionEvaluateDecision(
            type=decision_type,
            message=message,
            rulesFired=[f"attachment_{status}"],
            dlpTags=[],
            redactions=[],
            requireJustification=decision_type == "justify",
            minJustificationChars=12 if decision_type == "justify" else None,
        ),
        guardrail=guardrail,
        triggering_policy={
            "policy_id": f"attachment_{status}",
            "type": "FILE_INSPECTION",
            "status": "BLOCK" if decision_type == "block" else "ALLOW_WITH_WARNINGS" if decision_type == "warn" else "STEP_UP_APPROVAL",
            "details": first,
        },
        latency_ms=0,
        errors=[],
    )


def _extension_public_guard_request(payload: ExtensionEvaluateRequest) -> PublicGuardRequest:
    dlp_tags = _dlp_tags_from_extension_payload(payload.dlp)
    risk_score = _risk_score_from_extension_payload(payload.dlp)
    attachment_artifacts, _ = _attachment_artifacts(payload)
    metadata: dict[str, Any] = {
        "source": "browser_extension",
        "site": payload.site,
        "url": payload.url,
        "tab_id": payload.tab_id,
        "user_email": payload.user.user_email,
        "user_idp_subject": payload.user.user_idp_subject,
        "device_id": payload.device.device_id if payload.device else None,
        "dlp_tags": dlp_tags,
        "risk_score": risk_score,
        "attachment_count": len(payload.attachments),
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
                    name="browser_prompt",
                    payload_summary=f"Browser prompt on {payload.site}",
                    metadata=metadata,
                )
            ]
            + attachment_artifacts,
        ),
        timeout_ms=payload.timeout_ms or 1500,
    )


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


def _payload_first_string(payload: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = _payload_string(payload, key)
        if value:
            return value
    return None


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


@ext_router.post("/bootstrap", response_model=ExtensionBootstrapResponse)
async def bootstrap_extension_device(
    payload: ExtensionBootstrapRequest,
    authorization: str | None = Header(default=None, alias="Authorization"),
    x_tenant_id: uuid.UUID | None = Header(default=None, alias="X-Tenant-Id"),
) -> ExtensionBootstrapResponse:
    requested_tenant_id = x_tenant_id or payload.tenant_id
    principal = _authenticate_extension_bootstrap_request(authorization, requested_tenant_id)

    if payload.tenant_id is not None and payload.tenant_id != principal.tenant_id:
        raise ServiceError("FORBIDDEN", "Payload tenant_id does not match bootstrap token", 403)

    device_id = (payload.device_id or "").strip()
    if not device_id:
        raise ServiceError("INVALID_REQUEST", "device_id is required", 422)

    extension_id = (payload.extension_id or "").strip()
    subject = (
        f"extension:{extension_id}:{device_id}"
        if extension_id
        else (principal.subject or f"extension:{device_id}")
    )
    device_token, expires_at = _issue_extension_device_token(
        tenant_id=principal.tenant_id,
        device_id=device_id,
        subject=subject,
    )
    return ExtensionBootstrapResponse(
        tenant_id=principal.tenant_id,
        device_id=device_id,
        device_token=device_token,
        expires_at=expires_at,
    )


@ext_router.post("/evaluate", response_model=ExtensionEvaluateResponse)
async def evaluate_extension_prompt(
    payload: ExtensionEvaluateRequest,
    authorization: str | None = Header(default=None, alias="Authorization"),
    x_tenant_id: uuid.UUID = Header(alias="X-Tenant-Id"),
    x_device_id: str | None = Header(default=None, alias="X-Device-Id"),
    environment_id: str = Query(...),
    project_id: str = Query(...),
    guardrail_id: str = Query(...),
    version: int | None = Query(default=None),
    session: AsyncSession = Depends(get_session),
) -> ExtensionEvaluateResponse:
    principal = _authenticate_extension_request(authorization, x_tenant_id)
    if payload.tenant_id is not None and payload.tenant_id != principal.tenant_id:
        raise ServiceError("FORBIDDEN", "Payload tenant_id does not match extension token", 403)
    if x_device_id and payload.device and payload.device.device_id != x_device_id:
        raise ServiceError("FORBIDDEN", "X-Device-Id does not match payload device_id", 403)

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
                raise ServiceError(
                    "GUARDRAIL_VERSION_NOT_FOUND",
                    "Guardrail version not found",
                    404,
                )
            guardrail_mode = guardrail.mode

    request_id = str(uuid.uuid4())
    public_payload = _extension_public_guard_request(payload)
    incomplete_attachments = [
        artifact.metadata
        for artifact in public_payload.input.artifacts
        if artifact.name != "browser_prompt" and artifact.metadata.get("inspection_status") != "extracted"
    ]
    response_guardrail = ExtensionEvaluateGuardrail(
        environment_id=environment_id,
        project_id=project_id,
        guardrail_id=guardrail_id,
        guardrail_version=resolved_version,
        mode=guardrail_mode,
    )
    if incomplete_attachments:
        return _incomplete_extension_response(
            request_id=request_id,
            guardrail=response_guardrail,
            incomplete=incomplete_attachments,
        )
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
                request_payload=_sanitize_request_payload_for_audit(public_payload, payload.capture_mode),
                action_resource={
                    "source": "browser_extension",
                    "site": payload.site,
                    "url": payload.url,
                    "tab_id": payload.tab_id,
                    "device_id": payload.device.device_id if payload.device else x_device_id,
                },
            )

    return ExtensionEvaluateResponse(
        request_id=engine_response.request_id,
        decision=_extension_decision_from_engine(
            engine_response,
            dlp_tags=_dlp_tags_from_extension_payload(payload.dlp),
        ),
        guardrail=ExtensionEvaluateGuardrail(
            environment_id=response_guardrail.environment_id,
            project_id=response_guardrail.project_id,
            guardrail_id=response_guardrail.guardrail_id,
            guardrail_version=response_guardrail.guardrail_version,
            mode=response_guardrail.mode,
        ),
        triggering_policy=engine_response.triggering_policy.model_dump()
        if engine_response.triggering_policy
        else None,
        output_modifications=engine_response.output_modifications,
        latency_ms=engine_response.latency_ms.total,
        errors=[error.model_dump() for error in engine_response.errors],
    )


@ext_router.get("/policy")
async def get_extension_policy(
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
    _authenticate_extension_request(authorization, x_tenant_id)
    policy_pack = await _resolve_extension_policy_pack(
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
                    prompt_hash=_payload_first_string(
                        payload_body,
                        "prompt_hash",
                        "prompt_text_hash",
                    ),
                    response_hash=_payload_first_string(
                        payload_body,
                        "response_hash",
                        "response_text_hash",
                    ),
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
