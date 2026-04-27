from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import time
import uuid
from dataclasses import dataclass, field

from fastapi import Request

from app.core.errors import ServiceError
from app.core.settings import settings

logger = logging.getLogger("umai.service.admin_auth")

_ALL_ROLES = [
    "platform-admin",
    "license-admin",
    "tenant-admin",
    "tenant-auditor",
]


def _use_jwt_admin_auth() -> bool:
    mode = (settings.admin_auth_mode or "").strip().lower()
    if mode == "jwt":
        return True
    if mode in {"development", "network-trust"}:
        return False
    return settings.enforce_admin_jwt


@dataclass
class AdminPrincipal:
    """Represents an authenticated admin caller."""

    tenant_id: uuid.UUID | None = None  # None = platform-level (all tenants)
    roles: list[str] = field(default_factory=lambda: list(_ALL_ROLES))
    subject: str | None = None


def _pad_b64(value: str) -> str:
    return value + "=" * (-len(value) % 4)


def _verify_hs256_jwt(token: str, secret: str) -> dict:
    """Validate an HS256 JWT using stdlib. Returns the decoded payload dict."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ServiceError("TOKEN_INVALID", "Malformed JWT: expected 3 parts", 401)

    header_b64, payload_b64, sig_b64 = parts
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    secret_bytes = secret.encode("utf-8")

    expected_sig = hmac.new(secret_bytes, signing_input, hashlib.sha256).digest()
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
        raise ServiceError("TOKEN_INVALID", "JWT payload could not be decoded", 401) from exc

    exp = payload.get("exp")
    if exp is not None and time.time() > float(exp):
        raise ServiceError("TOKEN_EXPIRED", "JWT has expired", 401)

    # Verify header algorithm
    try:
        header_json = base64.urlsafe_b64decode(_pad_b64(header_b64)).decode("utf-8")
        header = json.loads(header_json)
    except Exception as exc:
        raise ServiceError("TOKEN_INVALID", "JWT header could not be decoded", 401) from exc

    alg = header.get("alg", "")
    if alg.upper() != "HS256":
        raise ServiceError("TOKEN_INVALID", f"Unsupported JWT algorithm: {alg}", 401)

    return payload


def _decode_jwt_principal(token: str) -> AdminPrincipal:
    secret = settings.admin_jwt_hs256_secret
    if not secret:
        raise ServiceError("AUTH_MISCONFIGURED", "Admin JWT secret not configured", 500)

    payload = _verify_hs256_jwt(token, secret)

    tenant_id_str = payload.get("tenant_id")
    tenant_id: uuid.UUID | None = None
    if tenant_id_str:
        try:
            tenant_id = uuid.UUID(str(tenant_id_str))
        except ValueError as exc:
            raise ServiceError("TOKEN_INVALID", "Invalid tenant_id in JWT", 401) from exc

    roles = payload.get("roles") or []
    if isinstance(roles, str):
        roles = [roles]

    return AdminPrincipal(
        tenant_id=tenant_id,
        roles=list(roles),
        subject=payload.get("sub"),
    )


async def get_admin_principal(request: Request) -> AdminPrincipal:
    """FastAPI dependency: resolve the admin principal for this request.

    When ``enforce_admin_jwt`` is False (default), the service operates in
    network-trust mode — callers on the ``umai-public`` Docker network are
    treated as platform-level admins with all roles. Set
    ``UMAI_ENFORCE_ADMIN_JWT=true`` and supply
    ``UMAI_ADMIN_JWT_HS256_SECRET`` to require explicit JWT auth.
    """
    if not _use_jwt_admin_auth():
        return AdminPrincipal(
            tenant_id=None,
            roles=list(_ALL_ROLES),
            subject="network-trust",
        )

    authorization = request.headers.get("Authorization") or ""
    if not authorization.lower().startswith("bearer "):
        raise ServiceError("UNAUTHENTICATED", "Bearer token required for admin access", 401)

    token = authorization.split(" ", 1)[1].strip()
    return _decode_jwt_principal(token)


def ensure_tenant_access(principal: AdminPrincipal, tenant_id: uuid.UUID) -> None:
    """Raise 403 if the principal cannot access the given tenant."""
    if principal.tenant_id is None:
        return  # platform-admin: unrestricted
    if principal.tenant_id != tenant_id:
        raise ServiceError(
            "FORBIDDEN",
            "You are not authorized to access this tenant",
            403,
        )


def require_admin_role(principal: AdminPrincipal, required_role: str = "tenant-admin") -> None:
    """Raise 403 if the principal does not hold the required role."""
    if required_role not in principal.roles:
        raise ServiceError(
            "FORBIDDEN",
            f"Role '{required_role}' is required for this operation",
            403,
        )
