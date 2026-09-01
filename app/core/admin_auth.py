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
from app.core.secret_rotation import accepted
from app.core.settings import settings
from app.core.token_audiences import NON_ADMIN_AUDIENCES

logger = logging.getLogger("umai.service.admin_auth")

_ALL_ROLES = [
    "platform-admin",
    "license-admin",
    "tenant-admin",
    "tenant-auditor",
]

# What holding one role means you can also do.
#
# Without this, roles are flat strings and "requires tenant-auditor" excludes a
# tenant-admin — an operator who may create a guardrail cannot list guardrails. That is
# not a policy anyone chose, and it stays invisible while admin_auth grants every role
# in network-trust mode: it appears the first time a deployment turns JWT enforcement on,
# as the console failing every read.
#
# `license-admin` is deliberately outside the hierarchy. Applying a licence is a
# commercial act, not a bigger version of an administrative one, so a platform-admin does
# not inherit it — separating them is the entire reason it is its own role.
_ROLE_IMPLIES = {
    "platform-admin": frozenset({"platform-admin", "tenant-admin", "tenant-auditor"}),
    "tenant-admin": frozenset({"tenant-admin", "tenant-auditor"}),
    "tenant-auditor": frozenset({"tenant-auditor"}),
    "license-admin": frozenset({"license-admin"}),
}


def effective_roles(roles) -> set[str]:
    """Every role these roles grant, directly or by implication."""
    granted: set[str] = set()
    for role in roles or ():
        granted |= _ROLE_IMPLIES.get(role, frozenset({role}))
    return granted


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

    # An admin token must expire. Treating a missing `exp` as "no expiry" turns a
    # mis-minted token into a permanent credential, which is worse than rejecting it.
    exp = payload.get("exp")
    if exp is None:
        raise ServiceError("TOKEN_INVALID", "Admin JWT must carry an exp claim", 401)
    try:
        expires_at = float(exp)
    except (TypeError, ValueError) as exc:
        raise ServiceError("TOKEN_INVALID", "Admin JWT exp claim is not numeric", 401) from exc
    if time.time() > expires_at:
        raise ServiceError("TOKEN_EXPIRED", "JWT has expired", 401)

    # Admin tokens come from the customer's identity provider, so the service cannot
    # demand a specific audience without breaking existing issuers. It can, however,
    # refuse a token that was plainly minted for another surface: a collector or device
    # token is a structurally valid admin token whenever a deployment reuses one HS256
    # secret across surfaces, and role naming should not be the only thing standing in
    # the way. An operator who does control their issuer can set
    # UMAI_ADMIN_JWT_AUDIENCE to require an exact match instead.
    audience = payload.get("aud")
    expected_audience = (settings.admin_jwt_audience or "").strip()
    if expected_audience:
        if audience != expected_audience:
            raise ServiceError("TOKEN_INVALID", "Admin JWT audience mismatch", 401)
    elif isinstance(audience, str) and audience in NON_ADMIN_AUDIENCES:
        raise ServiceError(
            "TOKEN_INVALID",
            f"Token audience {audience!r} is not valid for admin access",
            401,
        )

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
    secrets = accepted(
        settings.admin_jwt_hs256_secret, settings.admin_jwt_hs256_secret_previous
    )
    if not secrets:
        raise ServiceError("AUTH_MISCONFIGURED", "Admin JWT secret not configured", 500)

    # During a rotation both secrets verify. Only a signature failure falls through to
    # the next candidate: an expired token or a foreign audience is a decision, not a
    # reason to retry with another key.
    last_error: ServiceError | None = None
    payload = None
    for secret in secrets:
        try:
            payload = _verify_hs256_jwt(token, secret)
            break
        except ServiceError as exc:
            if "signature" not in exc.message.lower():
                raise
            last_error = exc
    if payload is None:
        raise last_error or ServiceError("TOKEN_INVALID", "JWT signature mismatch", 401)

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


def require_any_admin_role(principal: AdminPrincipal, *roles: str) -> None:
    """Raise 403 unless the principal holds at least one of ``roles``.

    Read endpoints take `tenant-auditor` or `tenant-admin`. Requiring an exact
    match made an admin who may change a finding's status unable to look at
    it, which is not a policy anyone chose.
    """
    held = effective_roles(principal.roles)
    if not any(role in held for role in roles):
        raise ServiceError(
            "FORBIDDEN",
            "One of roles " + ", ".join(sorted(roles)) + " is required for this operation",
            403,
        )


def require_admin_role(principal: AdminPrincipal, required_role: str = "tenant-admin") -> None:
    """Raise 403 if the principal does not hold the required role, or one above it."""
    if required_role not in effective_roles(principal.roles):
        raise ServiceError(
            "FORBIDDEN",
            f"Role '{required_role}' is required for this operation",
            403,
        )
