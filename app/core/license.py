from __future__ import annotations

import base64
import datetime as dt
import json
import logging
import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_sessionmaker, tenant_scope
from app.core.errors import ServiceError
from app.models.db import License, Tenant
from app.models.license import LicensePayload, LicenseToken


def _as_utc(value: dt.datetime | None) -> dt.datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=dt.timezone.utc)
    return value.astimezone(dt.timezone.utc)


async def require_active_license(session: AsyncSession, tenant_id) -> License:
    stmt = select(License).where(License.tenant_id == tenant_id)
    result = await session.execute(stmt)
    license_row = result.scalar_one_or_none()
    if not license_row:
        raise ServiceError("LICENSE_EXPIRED", "License not found", 403)
    if license_row.status.lower() != "active":
        raise ServiceError("LICENSE_SUSPENDED", "License is suspended", 403)
    now = dt.datetime.now(dt.timezone.utc)
    expires_at = _as_utc(license_row.expires_at)
    if expires_at and expires_at < now:
        raise ServiceError("LICENSE_EXPIRED", "License expired", 403)
    license_row.expires_at = expires_at
    return license_row


def extract_license_features(license_row: License) -> dict:
    if not license_row.features_json:
        return {}
    try:
        payload = json.loads(license_row.features_json)
    except json.JSONDecodeError:
        return {}
    if isinstance(payload, dict):
        features = payload.get("features")
        if isinstance(features, dict):
            return features
        return payload
    return {}


def license_allows_llm_calls(license_row: License, default: bool = True) -> bool:
    features = extract_license_features(license_row)
    value = features.get("allow_llm_calls")
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return default


LICENSE_ENV_VAR = "UMAI_LICENSE_TOKEN"
LICENSE_FILE_ENV_VAR = "UMAI_LICENSE_FILE"
LICENSE_PUBLIC_KEY_ENV_VAR = "UMAI_LICENSE_PUBLIC_KEY"
LICENSE_PUBLIC_KEYS_ENV_VAR = "UMAI_LICENSE_PUBLIC_KEYS"
LICENSE_STRICT_ENV_VAR = "UMAI_LICENSE_STRICT"
LICENSE_DEFAULT_PATH = "/etc/umai/license.json"

logger = logging.getLogger("umai.service.license")


def load_license_token() -> str | None:
    token = os.getenv(LICENSE_ENV_VAR)
    if token:
        return token.strip()
    file_path = os.getenv(LICENSE_FILE_ENV_VAR, LICENSE_DEFAULT_PATH)
    if not file_path:
        return None
    if not os.path.isfile(file_path):
        return None
    return open(file_path, "r", encoding="utf-8").read().strip()


def verify_license_token(raw_token: str) -> tuple[LicensePayload, str | None]:
    token = _parse_license_token(raw_token)
    key_id = token.key_id or "default"
    public_keys = _load_public_keys()
    public_key = public_keys.get(key_id)
    if public_key is None:
        raise ServiceError(
            "LICENSE_PUBLIC_KEY_MISSING",
            f"License public key not found for key_id {key_id}",
            500,
        )
    payload_bytes = _canonical_payload(token.payload)
    signature = _decode_signature(token.signature)
    try:
        public_key.verify(signature, payload_bytes)
    except InvalidSignature as exc:
        raise ServiceError("LICENSE_SIGNATURE_INVALID", "License signature invalid", 403) from exc
    _normalize_payload_dates(token.payload)
    _validate_payload(token.payload)
    return token.payload, token.key_id


async def apply_license_payload(
    session: AsyncSession, payload: LicensePayload, key_id: str | None
) -> License:
    tenant = await session.get(Tenant, payload.tenant_id)
    if tenant is None:
        tenant = Tenant(
            tenant_id=payload.tenant_id,
            name=payload.tenant_name or "Licensed Tenant",
            status="active",
        )
        session.add(tenant)
    license_row = await session.get(License, payload.tenant_id)
    payload_dict = payload.model_dump(mode="json", exclude_none=True)
    if key_id:
        payload_dict["key_id"] = key_id
    features_json = json.dumps(payload_dict, separators=(",", ":"), ensure_ascii=True)
    if license_row is None:
        license_row = License(
            tenant_id=payload.tenant_id,
            status=payload.status,
            expires_at=payload.expires_at,
            features_json=features_json,
        )
        session.add(license_row)
    else:
        license_row.status = payload.status
        license_row.expires_at = payload.expires_at
        license_row.features_json = features_json
    return license_row


async def bootstrap_license() -> None:
    raw_token = load_license_token()
    if not raw_token:
        logger.warning("license.bootstrap.skip reason=token_not_configured")
        return
    strict = _env_truthy(os.getenv(LICENSE_STRICT_ENV_VAR))
    try:
        payload, key_id = verify_license_token(raw_token)
    except ServiceError as exc:
        if strict:
            logger.error(
                "license.bootstrap.failed strict=true error=%s message=%s",
                exc.error_type,
                exc.message,
            )
            raise
        logger.warning(
            "license.bootstrap.failed strict=false error=%s message=%s",
            exc.error_type,
            exc.message,
        )
        return
    session_maker = get_sessionmaker()
    async with session_maker() as session:
        async with session.begin():
            async with tenant_scope(session, str(payload.tenant_id)):
                await apply_license_payload(session, payload, key_id)
    logger.info(
        "license.bootstrap.ok tenant_id=%s expires_at=%s",
        payload.tenant_id,
        payload.expires_at.isoformat(),
    )


def _parse_license_token(raw_token: str) -> LicenseToken:
    token_str = raw_token.strip()
    if not token_str:
        raise ServiceError("LICENSE_INVALID", "License token is empty", 422)
    data = _decode_json(token_str)
    try:
        return LicenseToken.model_validate(data)
    except ValidationError as exc:
        raise ServiceError("LICENSE_INVALID", f"License token invalid: {exc}", 422) from exc


def _decode_json(raw: str) -> dict:
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        try:
            decoded = base64.urlsafe_b64decode(_pad_base64(raw)).decode("utf-8")
            return json.loads(decoded)
        except Exception as exc:
            raise ServiceError("LICENSE_INVALID", "License token must be valid JSON", 422) from exc


def _canonical_payload(payload: LicensePayload) -> bytes:
    payload_dict = payload.model_dump(mode="json", exclude_none=True)
    return json.dumps(payload_dict, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _decode_signature(signature: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(_pad_base64(signature))
    except Exception as exc:
        raise ServiceError(
            "LICENSE_INVALID",
            "License signature must be base64url encoded",
            422,
        ) from exc


def _pad_base64(value: str) -> str:
    return value + "=" * (-len(value) % 4)


def _load_public_keys() -> dict[str, Ed25519PublicKey]:
    keys: dict[str, Ed25519PublicKey] = {}
    raw_keys = os.getenv(LICENSE_PUBLIC_KEYS_ENV_VAR)
    if raw_keys:
        try:
            parsed = json.loads(raw_keys)
        except json.JSONDecodeError as exc:
            raise ServiceError(
                "LICENSE_PUBLIC_KEY_INVALID",
                "UMAI_LICENSE_PUBLIC_KEYS must be JSON",
                500,
            ) from exc
        if isinstance(parsed, dict):
            for key_id, key_value in parsed.items():
                keys[str(key_id)] = _parse_public_key(str(key_value))
    raw_key = os.getenv(LICENSE_PUBLIC_KEY_ENV_VAR)
    if raw_key:
        keys.setdefault("default", _parse_public_key(raw_key))
    if not keys:
        raise ServiceError(
            "LICENSE_PUBLIC_KEY_MISSING",
            "License public key is not configured",
            500,
        )
    return keys


def _parse_public_key(raw_key: str) -> Ed25519PublicKey:
    key = raw_key.strip()
    if "BEGIN PUBLIC KEY" in key:
        return serialization.load_pem_public_key(key.encode("utf-8"))
    try:
        decoded = base64.urlsafe_b64decode(_pad_base64(key))
        return Ed25519PublicKey.from_public_bytes(decoded)
    except Exception as exc:
        raise ServiceError(
            "LICENSE_PUBLIC_KEY_INVALID",
            "Invalid public key format",
            500,
        ) from exc


def _normalize_payload_dates(payload: LicensePayload) -> None:
    if payload.issued_at.tzinfo is None:
        payload.issued_at = payload.issued_at.replace(tzinfo=dt.timezone.utc)
    if payload.expires_at.tzinfo is None:
        payload.expires_at = payload.expires_at.replace(tzinfo=dt.timezone.utc)


def _validate_payload(payload: LicensePayload) -> None:
    if payload.expires_at <= payload.issued_at:
        raise ServiceError(
            "LICENSE_INVALID",
            "License expires_at must be after issued_at",
            422,
        )


def _env_truthy(value: str | None) -> bool:
    if value is None:
        return False
    return value.strip().lower() in {"1", "true", "yes", "on"}
