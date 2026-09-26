"""Browser-extension enrollment tokens (WS2.3, decision D3-A).

An enrollment token sits in a fleet's managed browser policy and mints a 30-day
device token for every browser that presents it. Before this ledger it had no
issuer, `exp` was optional and nothing counted or revoked it: a token without
`exp` enrolled devices forever. These tests pin the replacement — minted only by
the admin API, bounded in time and uses, and revocable.
"""

from __future__ import annotations

import asyncio
import base64
import datetime as dt
import json
import time
import uuid

import pytest
from sqlalchemy import select

from app.api import extension
from app.api.extension import (
    ExtensionBootstrapRequest,
    ExtensionBootstrapTokenRequest,
    ExtensionBootstrapTokenRevokeRequest,
    bootstrap_extension_device,
    issue_extension_bootstrap_token,
    list_extension_bootstrap_tokens,
    revoke_extension_bootstrap_token,
)
from app.core.admin_auth import AdminPrincipal
from app.core.errors import ServiceError
from app.core.settings import settings
from app.core.token_audiences import (
    ADR_BOOTSTRAP_TOKEN_AUDIENCE,
    EXTENSION_BOOTSTRAP_TOKEN_AUDIENCE,
    EXTENSION_DEVICE_TOKEN_AUDIENCE,
)
from app.models.db import ExtensionBootstrapToken, Tenant
from tests.conftest import db_session

TENANT = uuid.UUID("11111111-1111-1111-1111-111111111111")
OTHER = uuid.UUID("22222222-2222-2222-2222-222222222222")
ADMIN = AdminPrincipal(TENANT, ["tenant-admin"], "admin@example.com")
AUDITOR = AdminPrincipal(TENANT, ["tenant-auditor"], "audit@example.com")
OTHER_ADMIN = AdminPrincipal(OTHER, ["tenant-admin"], "admin@other.example.com")
SECRET = "extension-bootstrap-test-secret"
PREVIOUS_SECRET = "extension-bootstrap-previous-secret"


@pytest.fixture(autouse=True)
def extension_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "extension_ingest_jwt_hs256_secret", SECRET)
    monkeypatch.setattr(settings, "extension_ingest_jwt_hs256_secret_previous", None)
    monkeypatch.setattr(settings, "extension_ingest_bearer_token", None)
    monkeypatch.setattr(settings, "extension_bootstrap_token_max_ttl_seconds", 7 * 24 * 3600)


def _run(callback):
    async def scenario():
        async with db_session() as db:
            db.add_all(
                [
                    Tenant(tenant_id=TENANT, name="Fleet"),
                    Tenant(tenant_id=OTHER, name="Other"),
                ]
            )
            await db.commit()
            return await callback(db)

    return asyncio.run(scenario())


def _claims(token: str) -> dict:
    payload_b64 = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4)))


async def _issue(db, principal=ADMIN, tenant=TENANT, **fields):
    return await issue_extension_bootstrap_token(
        ExtensionBootstrapTokenRequest(**fields),
        session=db,
        x_tenant_id=tenant,
        principal=principal,
    )


async def _enroll(db, token: str, *, tenant=TENANT, device_id="browser-1", body_tenant=None):
    return await bootstrap_extension_device(
        ExtensionBootstrapRequest(tenant_id=body_tenant, device_id=device_id),
        authorization=f"Bearer {token}",
        x_tenant_id=tenant,
        session=db,
    )


async def _row(db, token_id) -> ExtensionBootstrapToken:
    db.expire_all()
    row = (
        await db.execute(select(ExtensionBootstrapToken).where(ExtensionBootstrapToken.id == token_id))
    ).scalar_one()
    # End the read's implicit transaction: the endpoints open their own.
    await db.commit()
    return row


def _hand_minted(**overrides) -> str:
    now = int(time.time())
    claims = {
        "sub": "hand-minted",
        "tenant_id": str(TENANT),
        "aud": EXTENSION_BOOTSTRAP_TOKEN_AUDIENCE,
        "roles": ["tenant-bootstrap"],
        "iat": now,
        "exp": now + 3600,
        "jti": str(uuid.uuid4()),
    }
    claims.update(overrides)
    for key in [key for key, value in claims.items() if value is None]:
        claims.pop(key)
    return extension._encode_hs256_jwt(claims, SECRET)


# ------------------------------------------------------------------ issuance


def test_issue_returns_a_bounded_token_once_and_records_it():
    async def scenario(db):
        issued = await _issue(db, max_uses=25, label="Smarttech pilot", ttl_seconds=3600)
        row = await _row(db, issued.token_id)
        return issued, row

    issued, row = _run(scenario)
    claims = _claims(issued.token)
    assert claims["aud"] == EXTENSION_BOOTSTRAP_TOKEN_AUDIENCE
    assert claims["roles"] == ["tenant-bootstrap"]
    assert claims["tenant_id"] == str(TENANT)
    assert claims["jti"] == issued.jti == row.jti
    assert claims["exp"] - claims["iat"] == 3600
    assert issued.max_uses == row.max_uses == 25
    assert issued.status == "active"
    assert row.use_count == 0
    assert row.created_by == "admin@example.com"
    assert row.label == "Smarttech pilot"
    assert issued.bootstrap_path == "/api/v1/ext/bootstrap"
    assert issued.managed_config == {"tenantId": str(TENANT), "bootstrapToken": issued.token}
    # The row never holds the token itself.
    assert issued.token not in json.dumps({c.name: str(getattr(row, c.name)) for c in row.__table__.columns})


def test_issue_defaults_to_the_configured_ceiling():
    issued = _run(lambda db: _issue(db))
    claims = _claims(issued.token)
    assert claims["exp"] - claims["iat"] == 7 * 24 * 3600
    assert issued.max_uses == extension.EXTENSION_BOOTSTRAP_DEFAULT_MAX_USES


def test_issue_refuses_a_lifetime_over_the_ceiling():
    with pytest.raises(ServiceError) as caught:
        _run(lambda db: _issue(db, ttl_seconds=7 * 24 * 3600 + 1))
    assert caught.value.status_code == 422


def test_issue_bounds_max_uses():
    with pytest.raises(ValueError):
        ExtensionBootstrapTokenRequest(max_uses=0)
    with pytest.raises(ValueError):
        ExtensionBootstrapTokenRequest(max_uses=extension.EXTENSION_BOOTSTRAP_MAX_USES_LIMIT + 1)


def test_an_auditor_cannot_issue_or_revoke():
    with pytest.raises(ServiceError) as caught:
        _run(lambda db: _issue(db, principal=AUDITOR))
    assert caught.value.status_code == 403

    async def scenario(db):
        issued = await _issue(db)
        await revoke_extension_bootstrap_token(
            issued.token_id,
            ExtensionBootstrapTokenRevokeRequest(reason="not mine"),
            session=db,
            x_tenant_id=TENANT,
            principal=AUDITOR,
        )

    with pytest.raises(ServiceError) as caught:
        _run(scenario)
    assert caught.value.status_code == 403


# ------------------------------------------------------------------ list / revoke


def test_list_never_returns_the_token():
    async def scenario(db):
        issued = await _issue(db, label="fleet")
        listed = await list_extension_bootstrap_tokens(
            limit=100, session=db, x_tenant_id=TENANT, principal=AUDITOR
        )
        return issued, listed

    issued, listed = _run(scenario)
    assert [item.token_id for item in listed] == [issued.token_id]
    dumped = json.dumps([item.model_dump(mode="json") for item in listed])
    assert "token" not in listed[0].model_dump()
    assert issued.token not in dumped
    assert listed[0].status == "active"


def test_revoke_stops_further_enrollment_and_is_idempotent():
    async def scenario(db):
        issued = await _issue(db)
        await _enroll(db, issued.token, device_id="before-revoke")
        revoked = await revoke_extension_bootstrap_token(
            issued.token_id,
            ExtensionBootstrapTokenRevokeRequest(reason="policy leaked"),
            session=db,
            x_tenant_id=TENANT,
            principal=ADMIN,
        )
        again = await revoke_extension_bootstrap_token(
            issued.token_id,
            ExtensionBootstrapTokenRevokeRequest(reason="second time"),
            session=db,
            x_tenant_id=TENANT,
            principal=ADMIN,
        )
        try:
            await _enroll(db, issued.token, device_id="after-revoke")
        except ServiceError as exc:
            return revoked, again, exc, await _row(db, issued.token_id)
        raise AssertionError("a revoked token enrolled a device")

    revoked, again, error, row = _run(scenario)
    assert revoked.status == "revoked"
    assert revoked.revoked_by == "admin@example.com"
    assert again.revoke_reason == "policy leaked"
    assert error.error_type == "EXTENSION_BOOTSTRAP_TOKEN_REVOKED"
    assert error.status_code == 401
    assert row.use_count == 1


def test_revoke_cannot_reach_another_tenants_token():
    async def scenario(db):
        issued = await _issue(db)
        try:
            await revoke_extension_bootstrap_token(
                issued.token_id,
                ExtensionBootstrapTokenRevokeRequest(reason="cross tenant"),
                session=db,
                x_tenant_id=OTHER,
                principal=OTHER_ADMIN,
            )
        except ServiceError as exc:
            return exc, await _row(db, issued.token_id)
        raise AssertionError("revoked another tenant's token")

    error, row = _run(scenario)
    assert error.status_code == 404
    assert row.revoked_at is None


# ------------------------------------------------------------------ enrollment


def test_replay_is_allowed_up_to_max_uses_then_refused():
    async def scenario(db):
        issued = await _issue(db, max_uses=3)
        responses = [
            await _enroll(db, issued.token, device_id=f"browser-{index}") for index in range(3)
        ]
        try:
            await _enroll(db, issued.token, device_id="browser-4")
        except ServiceError as exc:
            return issued, responses, exc, await _row(db, issued.token_id)
        raise AssertionError("an exhausted token enrolled a device")

    issued, responses, error, row = _run(scenario)
    assert [r.device_id for r in responses] == ["browser-0", "browser-1", "browser-2"]
    device_claims = _claims(responses[0].device_token)
    assert device_claims["aud"] == EXTENSION_DEVICE_TOKEN_AUDIENCE
    assert device_claims["tenant_id"] == str(TENANT)
    assert error.error_type == "EXTENSION_BOOTSTRAP_TOKEN_EXHAUSTED"
    assert error.status_code == 403
    assert row.use_count == 3
    assert row.last_used_at is not None


def test_a_token_whose_jwt_has_expired_is_refused():
    async def scenario(db):
        issued = await _issue(db, ttl_seconds=3600)
        row = await _row(db, issued.token_id)
        past = int(time.time()) - 60
        token = _hand_minted(jti=row.jti, iat=past - 3600, exp=past)
        return await _enroll(db, token)

    with pytest.raises(ServiceError) as caught:
        _run(scenario)
    assert caught.value.error_type == "EXTENSION_BOOTSTRAP_TOKEN_EXPIRED"
    assert caught.value.status_code == 401


def test_a_token_whose_row_has_expired_is_refused():
    """The row is authoritative: shortening it ends the token even if `exp` has not."""

    async def scenario(db):
        issued = await _issue(db, ttl_seconds=3600)
        row = await _row(db, issued.token_id)
        row.expires_at = dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=1)
        await db.commit()
        try:
            await _enroll(db, issued.token)
        except ServiceError as exc:
            return exc, await _row(db, issued.token_id)
        raise AssertionError("an expired token enrolled a device")

    error, row = _run(scenario)
    assert error.error_type == "EXTENSION_BOOTSTRAP_TOKEN_EXPIRED"
    assert row.use_count == 0


@pytest.mark.parametrize("missing", ["exp", "jti", "iat"])
def test_a_token_missing_a_bounding_claim_is_refused(missing: str):
    async def scenario(db):
        issued = await _issue(db)
        row = await _row(db, issued.token_id)
        token = _hand_minted(**{"jti": row.jti, missing: None})
        try:
            await _enroll(db, token)
        except ServiceError as exc:
            return exc, await _row(db, issued.token_id)
        raise AssertionError(f"a token without {missing} enrolled a device")

    error, row = _run(scenario)
    assert error.error_type == "EXTENSION_BOOTSTRAP_TOKEN_INVALID"
    assert error.status_code == 401
    assert f"must carry {missing}" in error.message
    assert row.use_count == 0


def test_a_correctly_signed_token_with_an_unknown_jti_is_refused():
    """Signing it by hand with the shared secret no longer makes a working token."""
    with pytest.raises(ServiceError) as caught:
        _run(lambda db: _enroll(db, _hand_minted()))
    assert caught.value.error_type == "EXTENSION_BOOTSTRAP_TOKEN_INVALID"
    assert "not registered" in caught.value.message


def test_a_token_with_an_over_long_lifetime_is_refused():
    async def scenario(db):
        issued = await _issue(db)
        row = await _row(db, issued.token_id)
        now = int(time.time())
        return await _enroll(db, _hand_minted(jti=row.jti, iat=now, exp=now + 7 * 24 * 3600 + 1))

    with pytest.raises(ServiceError) as caught:
        _run(scenario)
    assert caught.value.error_type == "EXTENSION_BOOTSTRAP_TOKEN_INVALID"
    assert "lifetime exceeds" in caught.value.message


def test_a_non_numeric_exp_is_a_401_not_a_500():
    with pytest.raises(ServiceError) as caught:
        _run(lambda db: _enroll(db, _hand_minted(exp="whenever")))
    assert caught.value.status_code == 401


def test_another_surfaces_token_is_refused():
    token = _hand_minted(aud=ADR_BOOTSTRAP_TOKEN_AUDIENCE)
    with pytest.raises(ServiceError) as caught:
        _run(lambda db: _enroll(db, token))
    assert caught.value.status_code == 401


def test_a_token_signed_with_the_previous_secret_still_enrolls(monkeypatch):
    async def scenario(db):
        monkeypatch.setattr(settings, "extension_ingest_jwt_hs256_secret", PREVIOUS_SECRET)
        issued = await _issue(db)
        # Rotation: the secret the token was signed with is now the previous one.
        monkeypatch.setattr(settings, "extension_ingest_jwt_hs256_secret", SECRET)
        monkeypatch.setattr(settings, "extension_ingest_jwt_hs256_secret_previous", PREVIOUS_SECRET)
        return await _enroll(db, issued.token)

    response = _run(scenario)
    assert response.tenant_id == TENANT


# ------------------------------------------------------------------ tenant isolation


def test_a_token_presented_for_another_tenant_is_refused_without_spending_a_use():
    async def scenario(db):
        issued = await _issue(db, max_uses=1)
        errors = []
        for kwargs in ({"tenant": OTHER}, {"tenant": TENANT, "body_tenant": OTHER}):
            try:
                await _enroll(db, issued.token, **kwargs)
            except ServiceError as exc:
                errors.append(exc)
        row = await _row(db, issued.token_id)
        # The one use is still there for the tenant it belongs to.
        await _enroll(db, issued.token)
        return errors, row

    errors, row = _run(scenario)
    assert [e.status_code for e in errors] == [403, 403]
    assert row.use_count == 0


def test_a_jti_cannot_be_borrowed_by_a_token_claiming_another_tenant():
    """The row lookup is keyed on the token's tenant, not just its jti."""

    async def scenario(db):
        issued = await _issue(db)
        row = await _row(db, issued.token_id)
        forged = _hand_minted(jti=row.jti, tenant_id=str(OTHER))
        return await _enroll(db, forged, tenant=OTHER)

    with pytest.raises(ServiceError) as caught:
        _run(scenario)
    assert caught.value.error_type == "EXTENSION_BOOTSTRAP_TOKEN_INVALID"
    assert "not registered" in caught.value.message


def test_list_is_tenant_scoped():
    async def scenario(db):
        await _issue(db)
        await _issue(db, principal=OTHER_ADMIN, tenant=OTHER)
        return await list_extension_bootstrap_tokens(
            limit=100, session=db, x_tenant_id=OTHER, principal=OTHER_ADMIN
        )

    listed = _run(scenario)
    assert [item.tenant_id for item in listed] == [OTHER]

    with pytest.raises(ServiceError) as caught:
        _run(
            lambda db: list_extension_bootstrap_tokens(
                limit=100, session=db, x_tenant_id=OTHER, principal=AUDITOR
            )
        )
    assert caught.value.status_code == 403
