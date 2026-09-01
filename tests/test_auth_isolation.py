"""Negative tests for identity and tenant boundaries (UMA-82).

Every other suite proves a surface works for the caller it was built for. This one
proves it does *not* work for anyone else: no reading across tenants, no reaching a
neighbour's record by guessing its key, and no using a credential minted for one
surface on another.

The token-confusion tests deliberately configure **one shared HS256 secret** for the
admin, ADR, and extension surfaces. That is the realistic misconfiguration — an operator
generating "the JWT secret" once — and it is the only configuration in which these tests
mean anything: with different secrets, a signature check rejects everything and the real
question (does the service distinguish a device token from an admin token?) is never
asked.
"""

from __future__ import annotations

import asyncio
import base64
import datetime as dt
import hashlib
import hmac
import json
import time
import uuid

import pytest

from app.api import adr, extension, findings, fleet, sessions
from app.core import finding_schema as fs
from app.core.admin_auth import (
    AdminPrincipal,
    _decode_jwt_principal,
    ensure_tenant_access,
)
from app.core.errors import ServiceError
from app.core.settings import settings
from app.core.token_audiences import (
    ADR_BOOTSTRAP_TOKEN_AUDIENCE,
    ADR_DEVICE_TOKEN_AUDIENCE,
    EXTENSION_BOOTSTRAP_TOKEN_AUDIENCE,
    EXTENSION_DEVICE_TOKEN_AUDIENCE,
)
from app.models.db import AdrDevice, AiSession, Finding, Tenant
from tests.conftest import db_session

TENANT_A = uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
TENANT_B = uuid.UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
NOW = dt.datetime(2026, 9, 1, 12, 0, tzinfo=dt.timezone.utc)
SHARED_SECRET = "one-secret-reused-across-surfaces"

A_FINDING = "a" * 64
B_FINDING = "b" * 64
A_SESSION = "c" * 64
B_SESSION = "d" * 64

AUDITOR_A = AdminPrincipal(TENANT_A, ["tenant-auditor"], "a@example.com")
ADMIN_A = AdminPrincipal(TENANT_A, ["tenant-admin"], "admin-a@example.com")
AUDITOR_B = AdminPrincipal(TENANT_B, ["tenant-auditor"], "b@example.com")
PLATFORM = AdminPrincipal(None, ["platform-admin", "tenant-admin"], "platform")


# --------------------------------------------------------------------------- seeding


def _session_row(key: str, tenant: uuid.UUID) -> AiSession:
    return AiSession(
        tenant_id=tenant,
        session_key=key,
        source=fs.SOURCE_ADR,
        source_session_id=f"src-{key[:8]}",
        actor_user="someone@example.com",
        actor_device_id="device-1",
        observed_at=NOW,
        ingested_at=NOW,
        message_count=2,
        tool_call_count=1,
        analysis_status="complete",
        analysis_attempts=1,
        updated_at=NOW,
    )


def _finding_row(key: str, tenant: uuid.UUID, session_key: str) -> Finding:
    return Finding(
        tenant_id=tenant,
        finding_key=key,
        session_key=session_key,
        rule_id="detector.ADR.T0007",
        technique_id="ADR.T0007",
        technique_name="Indirect prompt injection",
        tactic="reasoning_data_manipulation",
        severity=fs.SEVERITY_HIGH,
        category=fs.CATEGORY_PROMPT_INJECTION,
        title="Indirect prompt injection",
        summary="tool output steered the agent",
        evidence_json=json.dumps({"confidence": 0.9, "severity_basis": "confidence"}),
        source=fs.SOURCE_ADR,
        detector=fs.DETECTOR_REASONING,
        actor_user="someone@example.com",
        actor_device_id="device-1",
        observed_at=NOW,
        detected_at=NOW,
        status=fs.STATUS_OPEN,
    )


async def _seed(db) -> None:
    db.add_all(
        [
            Tenant(tenant_id=TENANT_A, name="A", collection_mode="full_session"),
            Tenant(tenant_id=TENANT_B, name="B", collection_mode="full_session"),
            _session_row(A_SESSION, TENANT_A),
            _session_row(B_SESSION, TENANT_B),
            _finding_row(A_FINDING, TENANT_A, A_SESSION),
            _finding_row(B_FINDING, TENANT_B, B_SESSION),
            AdrDevice(
                tenant_id=TENANT_A,
                device_id="device-a",
                status="active",
                metadata_json=json.dumps({"collector_kind": "adr"}),
            ),
            AdrDevice(
                tenant_id=TENANT_B,
                device_id="device-b",
                status="active",
                metadata_json=json.dumps({"collector_kind": "adr"}),
            ),
        ]
    )
    await db.commit()


# ------------------------------------------------------------------- token minting


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def mint(
    payload: dict,
    *,
    secret: str = SHARED_SECRET,
    alg: str = "HS256",
    sign_with: str | None = None,
) -> str:
    """Mint a token the way each surface's issuer does, so confusion can be tested."""
    header = _b64(json.dumps({"alg": alg, "typ": "JWT"}).encode())
    body = _b64(json.dumps(payload).encode())
    signing_input = f"{header}.{body}".encode("ascii")
    signature = hmac.new((sign_with or secret).encode(), signing_input, hashlib.sha256).digest()
    return f"{header}.{body}.{_b64(signature)}"


def admin_token(tenant: uuid.UUID | None, roles: list[str], **extra) -> str:
    payload = {
        "sub": "operator@example.com",
        "roles": roles,
        "exp": int(time.time()) + 600,
        **extra,
    }
    if tenant is not None:
        payload["tenant_id"] = str(tenant)
    return mint(payload)


def surface_token(audience: str, role: str, tenant: uuid.UUID = TENANT_A, **extra) -> str:
    return mint(
        {
            "sub": f"{audience}:device-a",
            "tenant_id": str(tenant),
            "device_id": "device-a",
            "aud": audience,
            "roles": [role],
            "iat": int(time.time()),
            "exp": int(time.time()) + 600,
            **extra,
        }
    )


@pytest.fixture
def shared_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    """One HS256 secret across every surface — the misconfiguration worth testing."""
    monkeypatch.setattr(settings, "admin_jwt_hs256_secret", SHARED_SECRET)
    monkeypatch.setattr(settings, "admin_jwt_audience", None)
    monkeypatch.setattr(settings, "adr_ingest_jwt_hs256_secret", SHARED_SECRET)
    monkeypatch.setattr(settings, "extension_ingest_jwt_hs256_secret", SHARED_SECRET)
    monkeypatch.setattr(settings, "extension_ingest_bearer_token", None)


# ------------------------------------------------------------- cross-tenant access


class TestCrossTenantAccess:
    """A tenant principal must not reach another tenant's data, by any route."""

    def test_read_across_tenants_is_refused(self) -> None:
        with pytest.raises(ServiceError) as caught:
            ensure_tenant_access(AUDITOR_A, TENANT_B)
        assert caught.value.status_code == 403

    def test_write_across_tenants_is_refused(self) -> None:
        with pytest.raises(ServiceError) as caught:
            fleet._access(ADMIN_A, TENANT_B, write=True)
        assert caught.value.status_code == 403

    @pytest.mark.parametrize(
        "check",
        [findings._require_read_access, sessions._require_read_access, ensure_tenant_access],
    )
    def test_every_read_gate_refuses_a_foreign_tenant(self, check) -> None:
        with pytest.raises(ServiceError) as caught:
            check(AUDITOR_A, TENANT_B)
        assert caught.value.status_code == 403

    def test_a_findings_query_never_returns_another_tenant_rows(self) -> None:
        async def run() -> None:
            async with db_session() as db:
                await _seed(db)
                page = await findings.query_findings(db, tenant_id=TENANT_A)
                keys = {item.finding_key for item in page.items}
                assert keys == {A_FINDING}
                assert B_FINDING not in keys

        asyncio.run(run())

    def test_a_sessions_query_never_returns_another_tenant_rows(self) -> None:
        async def run() -> None:
            async with db_session() as db:
                await _seed(db)
                page = await sessions.query_sessions(db, tenant_id=TENANT_A)
                assert {item.session_key for item in page.items} == {A_SESSION}

        asyncio.run(run())

    def test_platform_admin_is_deliberately_unrestricted(self) -> None:
        # Documents the intended asymmetry, so narrowing it later is a visible change.
        ensure_tenant_access(PLATFORM, TENANT_A)
        ensure_tenant_access(PLATFORM, TENANT_B)


class TestInsecureDirectObjectReference:
    """Knowing another tenant's key must not be enough to read or change its record."""

    def test_a_foreign_finding_key_is_not_found(self) -> None:
        async def run() -> None:
            async with db_session() as db:
                await _seed(db)
                with pytest.raises(ServiceError) as caught:
                    await findings.load_finding(db, tenant_id=TENANT_A, finding_key=B_FINDING)
                assert caught.value.status_code == 404

        asyncio.run(run())

    def test_a_foreign_session_key_is_not_found(self) -> None:
        async def run() -> None:
            async with db_session() as db:
                await _seed(db)
                with pytest.raises(ServiceError) as caught:
                    await sessions.load_session(db, tenant_id=TENANT_A, session_key=B_SESSION)
                assert caught.value.status_code == 404

        asyncio.run(run())

    def test_a_foreign_transcript_is_not_readable(self) -> None:
        async def run() -> None:
            async with db_session() as db:
                await _seed(db)
                with pytest.raises(ServiceError) as caught:
                    await sessions.load_transcript(
                        db, tenant_id=TENANT_A, session_key=B_SESSION, actor="a@example.com"
                    )
                assert caught.value.status_code == 404

        asyncio.run(run())

    def test_a_foreign_finding_cannot_be_transitioned(self) -> None:
        """A write must not succeed, and must not leave the other tenant's row altered."""

        async def run() -> None:
            async with db_session() as db:
                await _seed(db)
                with pytest.raises(ServiceError) as caught:
                    await findings.transition_finding(
                        db,
                        tenant_id=TENANT_A,
                        finding_key=B_FINDING,
                        to_status=fs.STATUS_RESOLVED,
                        actor="a@example.com",
                    )
                assert caught.value.status_code == 404
                await db.rollback()
                untouched = await findings.load_finding(
                    db, tenant_id=TENANT_B, finding_key=B_FINDING
                )
                assert untouched.status == fs.STATUS_OPEN

        asyncio.run(run())

    def test_a_foreign_finding_cannot_be_assigned(self) -> None:
        async def run() -> None:
            async with db_session() as db:
                await _seed(db)
                with pytest.raises(ServiceError) as caught:
                    await findings.assign_finding(
                        db,
                        tenant_id=TENANT_A,
                        finding_key=B_FINDING,
                        assignee="a@example.com",
                        actor="a@example.com",
                    )
                assert caught.value.status_code == 404

        asyncio.run(run())

    def test_a_foreign_transcript_cannot_be_deleted(self) -> None:
        """The delete is deliberately idempotent, so it must be a no-op, not a deletion.

        Tenant A naming tenant B's session key gets ``deleted=False`` rather than a 404 —
        that is the documented contract for a retried data-subject request. What matters
        is that B's transcript is still there afterwards.
        """

        async def run() -> None:
            async with db_session() as db:
                await _seed(db)
                target = await db.get(AiSession, (TENANT_B, B_SESSION))
                target.transcript_ref = "tenant-b/transcript.jsonl"
                target.transcript_sha256 = "e" * 64
                target.transcript_bytes = 4096
                await db.commit()

                result = await sessions.remove_transcript(
                    db,
                    tenant_id=TENANT_A,
                    session_key=B_SESSION,
                    actor="a@example.com",
                    reason="testing",
                )
                assert result.deleted is False

                db.expire_all()
                survivor = await db.get(AiSession, (TENANT_B, B_SESSION))
                assert survivor.transcript_ref == "tenant-b/transcript.jsonl"
                assert survivor.transcript_sha256 == "e" * 64
                assert survivor.transcript_bytes == 4096

        asyncio.run(run())


# ---------------------------------------------------------- credential type confusion


@pytest.mark.usefixtures("shared_secret")
class TestTokenTypeConfusion:
    """A credential minted for one surface must be refused on every other surface."""

    @pytest.mark.parametrize(
        ("audience", "role"),
        [
            (ADR_DEVICE_TOKEN_AUDIENCE, "tenant-device"),
            (ADR_BOOTSTRAP_TOKEN_AUDIENCE, "tenant-bootstrap"),
            (EXTENSION_DEVICE_TOKEN_AUDIENCE, "tenant-device"),
            (EXTENSION_BOOTSTRAP_TOKEN_AUDIENCE, "tenant-bootstrap"),
        ],
    )
    def test_a_device_or_collector_token_is_not_an_admin_token(
        self, audience: str, role: str
    ) -> None:
        with pytest.raises(ServiceError) as caught:
            _decode_jwt_principal(surface_token(audience, role))
        assert caught.value.status_code == 401
        assert "not valid for admin access" in caught.value.message

    def test_an_admin_token_is_not_an_adr_device_token(self) -> None:
        token = admin_token(TENANT_A, ["tenant-admin"])
        with pytest.raises(ServiceError) as caught:
            adr._authenticate_device(f"Bearer {token}", TENANT_A)
        assert caught.value.status_code == 401

    def test_an_adr_device_token_is_refused_on_the_extension_surface(self) -> None:
        token = surface_token(ADR_DEVICE_TOKEN_AUDIENCE, "tenant-device")
        with pytest.raises(ServiceError) as caught:
            extension._authenticate_extension_request(f"Bearer {token}", TENANT_A)
        assert caught.value.status_code == 401

    def test_an_extension_device_token_is_refused_on_the_adr_surface(self) -> None:
        token = surface_token(EXTENSION_DEVICE_TOKEN_AUDIENCE, "tenant-device")
        with pytest.raises(ServiceError) as caught:
            adr._authenticate_device(f"Bearer {token}", TENANT_A)
        assert caught.value.status_code == 401

    def test_an_adr_bootstrap_token_is_not_a_device_token(self) -> None:
        token = surface_token(ADR_BOOTSTRAP_TOKEN_AUDIENCE, "tenant-bootstrap")
        with pytest.raises(ServiceError) as caught:
            adr._authenticate_device(f"Bearer {token}", TENANT_A)
        assert caught.value.status_code == 401

    def test_a_device_token_is_not_a_bootstrap_token(self) -> None:
        token = surface_token(ADR_DEVICE_TOKEN_AUDIENCE, "tenant-device")
        with pytest.raises(ServiceError) as caught:
            adr._verified_payload(
                f"Bearer {token}",
                audience=ADR_BOOTSTRAP_TOKEN_AUDIENCE,
                role="tenant-bootstrap",
                expired_code="ADR_BOOTSTRAP_TOKEN_INVALID",
            )
        assert caught.value.status_code == 401

    def test_the_right_audience_with_the_wrong_role_is_refused(self) -> None:
        token = surface_token(ADR_DEVICE_TOKEN_AUDIENCE, "tenant-auditor")
        with pytest.raises(ServiceError) as caught:
            adr._authenticate_device(f"Bearer {token}", TENANT_A)
        assert caught.value.status_code == 403

    def test_a_worker_token_is_not_accepted_as_an_admin_token(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The worker credential is an opaque shared secret, not a JWT.
        monkeypatch.setattr(settings, "analysis_worker_token", "worker-shared-secret")
        with pytest.raises(ServiceError) as caught:
            _decode_jwt_principal("worker-shared-secret")
        assert caught.value.status_code == 401

    def test_an_admin_token_is_not_accepted_as_a_worker_token(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from app.api import analysis

        monkeypatch.setattr(settings, "analysis_worker_token", "worker-shared-secret")
        token = admin_token(TENANT_A, ["tenant-admin"])
        with pytest.raises(ServiceError) as caught:
            analysis._authenticate_worker(f"Bearer {token}")
        assert caught.value.status_code == 401

    def test_a_device_token_is_not_accepted_as_a_worker_token(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from app.api import analysis

        monkeypatch.setattr(settings, "analysis_worker_token", "worker-shared-secret")
        token = surface_token(ADR_DEVICE_TOKEN_AUDIENCE, "tenant-device")
        with pytest.raises(ServiceError) as caught:
            analysis._authenticate_worker(f"Bearer {token}")
        assert caught.value.status_code == 401

    def test_a_configured_admin_audience_refuses_everything_else(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(settings, "admin_jwt_audience", "umai-admin")
        accepted = _decode_jwt_principal(admin_token(TENANT_A, ["tenant-admin"], aud="umai-admin"))
        assert accepted.tenant_id == TENANT_A
        with pytest.raises(ServiceError) as caught:
            _decode_jwt_principal(admin_token(TENANT_A, ["tenant-admin"]))
        assert "audience mismatch" in caught.value.message


@pytest.mark.usefixtures("shared_secret")
class TestTokenForgery:
    """The usual JWT attacks, on every surface that accepts one."""

    def test_a_token_signed_with_another_secret_is_refused(self) -> None:
        token = mint(
            {"sub": "x", "roles": ["tenant-admin"], "exp": int(time.time()) + 600},
            sign_with="a-different-secret",
        )
        with pytest.raises(ServiceError) as caught:
            _decode_jwt_principal(token)
        assert caught.value.status_code == 401

    @pytest.mark.parametrize("alg", ["none", "None", "HS512", "RS256"])
    def test_an_unexpected_algorithm_is_refused(self, alg: str) -> None:
        token = mint({"sub": "x", "roles": ["tenant-admin"], "exp": int(time.time()) + 600}, alg=alg)
        with pytest.raises(ServiceError) as caught:
            _decode_jwt_principal(token)
        assert caught.value.status_code == 401

    def test_an_expired_admin_token_is_refused(self) -> None:
        token = mint({"sub": "x", "roles": ["tenant-admin"], "exp": int(time.time()) - 1})
        with pytest.raises(ServiceError) as caught:
            _decode_jwt_principal(token)
        assert caught.value.error_type == "TOKEN_EXPIRED"

    def test_an_admin_token_without_an_expiry_is_refused(self) -> None:
        """A missing exp must not read as "never expires"."""
        token = mint({"sub": "x", "roles": ["tenant-admin"]})
        with pytest.raises(ServiceError) as caught:
            _decode_jwt_principal(token)
        assert "must carry an exp claim" in caught.value.message

    def test_a_non_numeric_expiry_is_refused(self) -> None:
        token = mint({"sub": "x", "roles": ["tenant-admin"], "exp": "whenever"})
        with pytest.raises(ServiceError) as caught:
            _decode_jwt_principal(token)
        assert caught.value.status_code == 401

    def test_an_expired_device_token_is_refused(self) -> None:
        token = surface_token(ADR_DEVICE_TOKEN_AUDIENCE, "tenant-device", exp=int(time.time()) - 1)
        with pytest.raises(ServiceError) as caught:
            adr._authenticate_device(f"Bearer {token}", TENANT_A)
        assert caught.value.error_type == "ADR_TOKEN_EXPIRED"

    def test_a_malformed_token_is_refused(self) -> None:
        for value in ("", "not-a-jwt", "a.b", "a.b.c.d"):
            with pytest.raises(ServiceError):
                _decode_jwt_principal(value)

    @pytest.mark.parametrize("header", ["", "Basic abc", "Token abc", "bearer"])
    def test_a_non_bearer_authorization_header_is_refused(self, header: str) -> None:
        with pytest.raises(ServiceError) as caught:
            adr._authenticate_device(header or None, TENANT_A)
        assert caught.value.status_code == 401

    def test_a_device_token_cannot_claim_another_tenant(self) -> None:
        token = surface_token(ADR_DEVICE_TOKEN_AUDIENCE, "tenant-device", tenant=TENANT_B)
        with pytest.raises(ServiceError) as caught:
            adr._authenticate_device(f"Bearer {token}", TENANT_A)
        assert caught.value.status_code == 403
        assert caught.value.error_type == "ADR_TENANT_MISMATCH"

    def test_a_device_token_with_an_unparseable_tenant_is_refused(self) -> None:
        token = mint(
            {
                "sub": "x",
                "tenant_id": "not-a-uuid",
                "aud": ADR_DEVICE_TOKEN_AUDIENCE,
                "roles": ["tenant-device"],
                "exp": int(time.time()) + 600,
            }
        )
        with pytest.raises(ServiceError) as caught:
            adr._authenticate_device(f"Bearer {token}", TENANT_A)
        assert caught.value.status_code == 401


@pytest.mark.usefixtures("shared_secret")
class TestDeviceScoping:
    """A collector's token must only speak for its own, still-enrolled device."""

    def test_a_token_cannot_act_for_another_device(self) -> None:
        async def run() -> None:
            async with db_session() as db:
                await _seed(db)
                principal = adr._authenticate_device(
                    f"Bearer {surface_token(ADR_DEVICE_TOKEN_AUDIENCE, 'tenant-device')}",
                    TENANT_A,
                )
                with pytest.raises(ServiceError) as caught:
                    await adr._require_active_device(db, principal, "device-b")
                assert caught.value.status_code == 404

        asyncio.run(run())

    def test_a_token_cannot_reach_a_device_in_another_tenant(self) -> None:
        async def run() -> None:
            async with db_session() as db:
                await _seed(db)
                # A token for tenant B's device, presented without a tenant header.
                principal = adr._authenticate_device(
                    f"Bearer {surface_token(ADR_DEVICE_TOKEN_AUDIENCE, 'tenant-device', tenant=TENANT_B)}",
                    None,
                )
                assert principal.tenant_id == TENANT_B
                # device-a belongs to tenant A, so it must not resolve for this principal.
                with pytest.raises(ServiceError) as caught:
                    await adr._require_active_device(db, principal, "device-a")
                assert caught.value.status_code == 404

        asyncio.run(run())

    def test_a_revoked_device_is_refused(self) -> None:
        async def run() -> None:
            async with db_session() as db:
                await _seed(db)
                device = await db.get(AdrDevice, (TENANT_A, "device-a"))
                device.status = "revoked"
                await db.commit()
                principal = adr._authenticate_device(
                    f"Bearer {surface_token(ADR_DEVICE_TOKEN_AUDIENCE, 'tenant-device')}",
                    TENANT_A,
                )
                with pytest.raises(ServiceError) as caught:
                    await adr._require_active_device(db, principal, "device-a")
                assert caught.value.error_type == "ADR_DEVICE_REVOKED"
                assert caught.value.status_code == 403

        asyncio.run(run())


class TestRoleSeparation:
    """Read-only roles must not be able to write."""

    def test_an_auditor_cannot_write_to_the_fleet(self) -> None:
        with pytest.raises(ServiceError) as caught:
            fleet._access(AUDITOR_A, TENANT_A, write=True)
        assert caught.value.status_code == 403

    def test_an_auditor_can_still_read(self) -> None:
        fleet._access(AUDITOR_A, TENANT_A)

    def test_an_unknown_role_cannot_read(self) -> None:
        nobody = AdminPrincipal(TENANT_A, ["tenant-viewer"], "nobody@example.com")
        with pytest.raises(ServiceError) as caught:
            findings._require_read_access(nobody, TENANT_A)
        assert caught.value.status_code == 403

    def test_an_empty_role_list_cannot_read(self) -> None:
        nobody = AdminPrincipal(TENANT_A, [], "nobody@example.com")
        with pytest.raises(ServiceError) as caught:
            findings._require_read_access(nobody, TENANT_A)
        assert caught.value.status_code == 403
