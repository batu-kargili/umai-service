from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import uuid
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import ServiceError
from app.models.db import (
    AgentIdentityCredential,
    AgentIdentityNonce,
    AgentRegistryEntry,
)
from app.models.public import AgentSignedContext

SIGNATURE_SKEW_SECONDS = 300


@dataclass(frozen=True)
class VerifiedAgent:
    agent_id: str
    agent_did: str
    public_key_fingerprint: str
    capabilities: list[str]
    trust_score: float
    trust_tier: str
    kill_switch_enabled: bool


def canonical_json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def object_hash(data: Any) -> str:
    return hashlib.sha256(canonical_json(data).encode("utf-8")).hexdigest()


def hash_secret(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _decode_b64(value: str) -> bytes:
    text = value.strip()
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode((text + padding).encode("ascii"))


def _encode_b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def public_key_fingerprint(public_key_b64: str) -> str:
    key_bytes = _decode_b64(public_key_b64)
    return "sha256:" + _encode_b64(hashlib.sha256(key_bytes).digest())


def build_agent_did(
    tenant_id: uuid.UUID,
    environment_id: str,
    project_id: str,
    agent_id: str,
    fingerprint: str,
) -> str:
    tenant_part = str(tenant_id).split("-", 1)[0]
    fp_part = fingerprint.split(":", 1)[-1][:16]
    return f"did:umai:{tenant_part}:{environment_id}:{project_id}:{agent_id}:{fp_part}"


def trust_tier_for_score(score: float) -> str:
    if score >= 0.95:
        return "PRIVILEGED"
    if score >= 0.60:
        return "STANDARD"
    return "SANDBOX"


def signed_at_to_utc(value: dt.datetime) -> dt.datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=dt.timezone.utc)
    return value.astimezone(dt.timezone.utc)


def signature_payload(
    *,
    tenant_id: uuid.UUID,
    environment_id: str,
    project_id: str,
    context: AgentSignedContext,
    event: str,
    body_hash: str,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    signed_at = signed_at_to_utc(context.signed_at).isoformat().replace("+00:00", "Z")
    payload = {
        "event": event,
        "tenant_id": str(tenant_id),
        "environment_id": environment_id,
        "project_id": project_id,
        "agent_id": context.agent_id,
        "agent_did": context.agent_did,
        "run_id": context.run_id,
        "step_id": context.step_id,
        "parent_step_id": context.parent_step_id,
        "nonce": context.nonce,
        "signed_at": signed_at,
        "body_hash": body_hash,
    }
    if extra:
        payload.update(extra)
    return payload


def verify_signature(public_key_b64: str, signature_b64: str, payload: dict[str, Any]) -> None:
    try:
        public_key = Ed25519PublicKey.from_public_bytes(_decode_b64(public_key_b64))
        signature = _decode_b64(signature_b64)
        public_key.verify(signature, canonical_json(payload).encode("utf-8"))
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise ServiceError("AGENT_SIGNATURE_INVALID", "Agent signature verification failed", 401) from exc


def load_capabilities(row: AgentRegistryEntry) -> list[str]:
    if not row.capabilities_json:
        return []
    try:
        data = json.loads(row.capabilities_json)
    except json.JSONDecodeError:
        return []
    return [str(item) for item in data] if isinstance(data, list) else []


async def verify_agent_context(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    environment_id: str,
    project_id: str,
    context: AgentSignedContext,
    event: str,
    body_hash: str,
    extra: dict[str, Any] | None = None,
    record_nonce: bool = True,
) -> VerifiedAgent:
    now = dt.datetime.now(dt.timezone.utc)
    signed_at = signed_at_to_utc(context.signed_at)
    if abs((now - signed_at).total_seconds()) > SIGNATURE_SKEW_SECONDS:
        raise ServiceError("AGENT_SIGNATURE_EXPIRED", "Agent signature timestamp is outside the allowed window", 401)

    registry = await session.get(
        AgentRegistryEntry,
        (tenant_id, environment_id, project_id, context.agent_id),
    )
    if registry is None:
        raise ServiceError("AGENT_UNKNOWN", "Agent is not registered for this project", 403)
    if registry.status != "ACTIVE":
        raise ServiceError("AGENT_DISABLED", "Agent is not active", 403)
    if registry.kill_switch_enabled:
        raise ServiceError("AGENT_KILL_SWITCH", "Agent kill switch is enabled", 403)
    if registry.agent_did and registry.agent_did != context.agent_did:
        raise ServiceError("AGENT_IDENTITY_MISMATCH", "Agent DID does not match registry", 403)

    stmt = (
        select(AgentIdentityCredential)
        .where(
            AgentIdentityCredential.tenant_id == tenant_id,
            AgentIdentityCredential.environment_id == environment_id,
            AgentIdentityCredential.project_id == project_id,
            AgentIdentityCredential.agent_id == context.agent_id,
            AgentIdentityCredential.agent_did == context.agent_did,
            AgentIdentityCredential.status == "ACTIVE",
        )
        .order_by(AgentIdentityCredential.created_at.desc())
        .limit(1)
    )
    result = await session.execute(stmt)
    credential = result.scalar_one_or_none()
    if credential is None:
        raise ServiceError("AGENT_CREDENTIAL_NOT_FOUND", "Active agent credential not found", 403)
    if (
        context.public_key_fingerprint
        and credential.public_key_fingerprint != context.public_key_fingerprint
    ):
        raise ServiceError("AGENT_CREDENTIAL_MISMATCH", "Agent public key fingerprint does not match", 403)

    if record_nonce:
        nonce_stmt = select(AgentIdentityNonce).where(
            AgentIdentityNonce.tenant_id == tenant_id,
            AgentIdentityNonce.environment_id == environment_id,
            AgentIdentityNonce.project_id == project_id,
            AgentIdentityNonce.agent_id == context.agent_id,
            AgentIdentityNonce.nonce == context.nonce,
        )
        existing_nonce = (await session.execute(nonce_stmt)).scalar_one_or_none()
        if existing_nonce is not None:
            raise ServiceError("AGENT_SIGNATURE_REPLAY", "Agent signature nonce was already used", 401)
        session.add(
            AgentIdentityNonce(
                tenant_id=tenant_id,
                environment_id=environment_id,
                project_id=project_id,
                agent_id=context.agent_id,
                nonce=context.nonce,
                signed_at=signed_at,
            )
        )

    payload = signature_payload(
        tenant_id=tenant_id,
        environment_id=environment_id,
        project_id=project_id,
        context=context,
        event=event,
        body_hash=body_hash,
        extra=extra,
    )
    verify_signature(credential.public_key_b64, context.signature, payload)

    registry.last_seen_at = now
    registry.public_key_fingerprint = credential.public_key_fingerprint
    registry.agent_did = context.agent_did
    registry.identity_status = "ACTIVE"
    registry.updated_at = now

    return VerifiedAgent(
        agent_id=context.agent_id,
        agent_did=context.agent_did,
        public_key_fingerprint=credential.public_key_fingerprint,
        capabilities=load_capabilities(registry),
        trust_score=float(registry.trust_score or 0.0),
        trust_tier=registry.trust_tier or trust_tier_for_score(float(registry.trust_score or 0.0)),
        kill_switch_enabled=bool(registry.kill_switch_enabled),
    )
