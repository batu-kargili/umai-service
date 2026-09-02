from __future__ import annotations

import asyncio
import gzip
import json
import tempfile
import uuid
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Iterator

import pytest
from pydantic import ValidationError
from sqlalchemy import select

from app.api import adr
from app.core.errors import ServiceError
from app.core.settings import settings
from app.core.transcript_store import reset_transcript_store
from app.models.db import AdrDevice, AdrDeviceAuditEvent, AiSession, Tenant
from tests.conftest import db_session


@contextmanager
def patched_settings(**overrides: object) -> Iterator[None]:
    original = {name: getattr(settings, name) for name in overrides}
    try:
        for name, value in overrides.items():
            setattr(settings, name, value)
        yield
    finally:
        for name, value in original.items():
            setattr(settings, name, value)


class BodyRequest:
    def __init__(self, payload: dict, *, gzip_body: bool = False) -> None:
        raw = json.dumps(payload).encode("utf-8")
        self._raw = gzip.compress(raw) if gzip_body else raw
        self.headers = {"Content-Encoding": "gzip"} if gzip_body else {}

    async def body(self) -> bytes:
        return self._raw


def fixture(name: str = "claude_benign") -> dict:
    path = Path(__file__).parent / "fixtures" / "adr" / f"{name}.json"
    return json.loads(path.read_text(encoding="utf-8"))


async def enrolled_tenant(db, *, mode: str = "full_session"):
    tenant_id = uuid.uuid4()
    device_id = "collector-01"
    db.add(Tenant(tenant_id=tenant_id, name="ADR Test", collection_mode=mode))
    db.add(
        AdrDevice(
            tenant_id=tenant_id,
            device_id=device_id,
            status="active",
        )
    )
    await db.commit()
    token, _ = adr._issue_adr_device_token(
        tenant_id=tenant_id,
        device_id=device_id,
        subject=f"adr:{device_id}",
    )
    return tenant_id, device_id, token


def test_router_exposes_only_the_four_frozen_adr_endpoints() -> None:
    paths = {
        route.path
        for route in adr.adr_router.routes
        if "POST" in getattr(route, "methods", set())
    }
    assert paths == {
        "/api/v1/adr/bootstrap",
        "/api/v1/adr/renew",
        "/api/v1/adr/heartbeat",
        "/api/v1/adr/sessions",
    }


def test_bootstrap_contract_is_strict() -> None:
    with pytest.raises(ValidationError):
        adr.AdrBootstrapRequest.model_validate(
            {
                "device_id": "collector-01",
                "collector_version": "1.0.0",
                "supported_sources": ["claude"],
                "agent_version": "legacy-name-is-forbidden",
            }
        )
    with pytest.raises(ValidationError):
        adr.AdrHeartbeatRequest.model_validate(
            {
                "device_id": "collector-01",
                "collector_version": "1.0.0",
                "supported_sources": ["codex"],
                "observed_sources": ["codex"],
                "status": "degraded",
                "status_detail": "free-form text is not a stable code",
            }
        )


def test_bootstrap_consumes_token_and_returns_tenant_configuration() -> None:
    async def scenario():
        async with db_session() as db:
            tenant_id = uuid.uuid4()
            db.add(
                Tenant(
                    tenant_id=tenant_id,
                    name="Bootstrap Test",
                    collection_mode="metadata",
                )
            )
            token, token_row = adr._build_adr_bootstrap_token_row(
                tenant_id=tenant_id,
                device_id="collector-01",
            )
            db.add(token_row)
            await db.commit()

            payload = adr.AdrBootstrapRequest(
                device_id="collector-01",
                hostname="laptop-01",
                os="windows",
                collector_version="1.2.3",
                supported_sources=["claude", "codex"],
            )
            request = SimpleNamespace(client=SimpleNamespace(host="127.0.0.1"))
            response = await adr.bootstrap_adr_collector(
                payload,
                request,
                authorization=f"Bearer {token}",
                x_tenant_id=tenant_id,
                db=db,
            )
            with pytest.raises(ServiceError) as consumed:
                await adr.bootstrap_adr_collector(
                    payload,
                    request,
                    authorization=f"Bearer {token}",
                    x_tenant_id=tenant_id,
                    db=db,
                )
            audit_types = {
                row.event_type
                for row in (
                    await db.execute(select(AdrDeviceAuditEvent))
                ).scalars().all()
            }
            return response, consumed.value, audit_types

    with patched_settings(adr_ingest_jwt_hs256_secret="adr-secret"):
        adr._BOOTSTRAP_ATTEMPTS.clear()
        response, consumed, audit_types = asyncio.run(scenario())

    assert response.collection_mode == "metadata"
    assert response.audience == adr.ADR_DEVICE_TOKEN_AUDIENCE
    assert response.config_etag.startswith('"adr-')
    assert consumed.error_type == "ADR_BOOTSTRAP_TOKEN_CONSUMED"
    assert consumed.status_code == 409
    assert audit_types == {"bootstrap_succeeded", "bootstrap_denied"}


def test_renew_and_heartbeat_use_active_device_and_return_current_mode() -> None:
    async def scenario():
        async with db_session() as db:
            tenant_id, device_id, token = await enrolled_tenant(db, mode="posture_only")
            renewed = await adr.renew_adr_device_token(
                authorization=f"Bearer {token}",
                x_tenant_id=tenant_id,
                db=db,
            )
            heartbeat = await adr.adr_heartbeat(
                adr.AdrHeartbeatRequest(
                    device_id=device_id,
                    collector_version="2.0.0",
                    supported_sources=["claude", "cursor"],
                    observed_sources=["claude"],
                    pending_sessions=2,
                    status="healthy",
                ),
                authorization=f"Bearer {renewed.device_token}",
                x_tenant_id=tenant_id,
                x_device_id=device_id,
                db=db,
            )
            return renewed, heartbeat

    with patched_settings(adr_ingest_jwt_hs256_secret="adr-secret"):
        renewed, heartbeat = asyncio.run(scenario())

    assert renewed.collection_mode == "posture_only"
    assert heartbeat.collection_mode == "posture_only"
    assert heartbeat.directives == []
    assert heartbeat.next_heartbeat_after_s > 0


def test_revoked_device_cannot_renew() -> None:
    async def scenario():
        async with db_session() as db:
            tenant_id, device_id, token = await enrolled_tenant(db)
            device = await db.get(AdrDevice, (tenant_id, device_id))
            device.status = "revoked"
            await db.commit()
            with pytest.raises(ServiceError) as raised:
                await adr.renew_adr_device_token(
                    authorization=f"Bearer {token}",
                    x_tenant_id=tenant_id,
                    db=db,
                )
            with pytest.raises(ServiceError) as ingest_raised:
                await adr.ingest_adr_sessions(
                    BodyRequest({"sessions": []}),
                    authorization=f"Bearer {token}",
                    x_tenant_id=tenant_id,
                    x_device_id=device_id,
                    db=db,
                )
            audit_types = {
                row.event_type
                for row in (
                    await db.execute(select(AdrDeviceAuditEvent))
                ).scalars().all()
            }
            return raised.value, ingest_raised.value, audit_types

    with patched_settings(adr_ingest_jwt_hs256_secret="adr-secret"):
        error, ingest_error, audit_types = asyncio.run(scenario())
    assert error.error_type == "ADR_DEVICE_REVOKED"
    assert error.status_code == 403
    assert ingest_error.error_type == "ADR_DEVICE_REVOKED"
    assert audit_types == {"renewal_denied", "session_ingest_denied"}


def test_expired_device_token_has_the_frozen_error_code() -> None:
    tenant_id = uuid.uuid4()
    payload = {
        "sub": "adr:collector-01",
        "tenant_id": str(tenant_id),
        "device_id": "collector-01",
        "aud": adr.ADR_DEVICE_TOKEN_AUDIENCE,
        "iat": 1,
        "exp": 2,
        "roles": ["tenant-device"],
    }
    with patched_settings(adr_ingest_jwt_hs256_secret="adr-secret"):
        token = adr._encode_hs256_jwt(payload, "adr-secret")
        with pytest.raises(ServiceError) as raised:
            adr._authenticate_device(f"Bearer {token}", tenant_id)
    assert raised.value.error_type == "ADR_TOKEN_EXPIRED"
    assert raised.value.status_code == 401


def test_session_ingest_is_idempotent_and_accepts_gzip() -> None:
    async def scenario():
        async with db_session() as db:
            tenant_id, device_id, token = await enrolled_tenant(db)
            request = BodyRequest(
                {
                    "collector": {"name": "umai-adr", "version": "1.0.0"},
                    "sessions": [fixture()],
                },
                gzip_body=True,
            )
            first = await adr.ingest_adr_sessions(
                request,
                authorization=f"Bearer {token}",
                x_tenant_id=tenant_id,
                x_device_id=device_id,
                db=db,
            )
            second = await adr.ingest_adr_sessions(
                request,
                authorization=f"Bearer {token}",
                x_tenant_id=tenant_id,
                x_device_id=device_id,
                db=db,
            )
            rows = (await db.execute(select(AiSession))).scalars().all()
            return first, second, rows

    with tempfile.TemporaryDirectory() as transcript_path:
        with patched_settings(
            adr_ingest_jwt_hs256_secret="adr-secret",
            transcript_store_path=transcript_path,
        ):
            reset_transcript_store()
            first, second, rows = asyncio.run(scenario())
            reset_transcript_store()

    assert (first.created, first.updated, first.unchanged) == (1, 0, 0)
    assert (second.created, second.updated, second.unchanged) == (0, 0, 1)
    assert len(rows) == 1


def test_session_limits_and_mode_are_enforced() -> None:
    oversized_batch = {"sessions": [{"source": "x", "session_id": str(i)} for i in range(101)]}
    parsed = adr._decode_batch(json.dumps(oversized_batch).encode(), None)
    assert len(parsed.sessions) == 101

    async def scenario():
        async with db_session() as db:
            tenant_id, device_id, token = await enrolled_tenant(db, mode="metadata")
            with pytest.raises(ServiceError) as mode_error:
                await adr.ingest_adr_sessions(
                    BodyRequest({"sessions": [fixture()]}),
                    authorization=f"Bearer {token}",
                    x_tenant_id=tenant_id,
                    x_device_id=device_id,
                    db=db,
                )
            with pytest.raises(ServiceError) as batch_error:
                await adr.ingest_adr_sessions(
                    BodyRequest(oversized_batch),
                    authorization=f"Bearer {token}",
                    x_tenant_id=tenant_id,
                    x_device_id=device_id,
                    db=db,
                )
            return mode_error.value, batch_error.value

    with patched_settings(adr_ingest_jwt_hs256_secret="adr-secret"):
        mode_error, batch_error = asyncio.run(scenario())

    assert mode_error.error_type == "ADR_MODE_FORBIDS_CONTENT"
    assert batch_error.error_type == "ADR_BATCH_TOO_LARGE"
    assert batch_error.status_code == 413


def test_body_limit_and_bootstrap_rate_limit_are_explicit() -> None:
    with pytest.raises(ServiceError) as body_error:
        adr._decode_batch(b"x" * (adr.ADR_BODY_SIZE_LIMIT + 1), None)
    assert body_error.value.error_type == "ADR_BODY_TOO_LARGE"

    tenant_id = uuid.uuid4()
    adr._BOOTSTRAP_ATTEMPTS.clear()
    for _ in range(adr.ADR_BOOTSTRAP_RATE_LIMIT_MAX_ATTEMPTS):
        adr._check_bootstrap_rate_limit(tenant_id, "127.0.0.1")
    with pytest.raises(ServiceError) as rate_error:
        adr._check_bootstrap_rate_limit(tenant_id, "127.0.0.1")
    assert rate_error.value.status_code == 429


# The repetition interval registered by the shipped Windows installer,
# `UMAI-ADR/Sensor/packaging/windows/Install-ScheduledTask.ps1`. The collector
# heartbeats once per run, so every freshness number here is a multiple of it.
COLLECTOR_TASK_INTERVAL_SECONDS = 15 * 60


def test_freshness_thresholds_match_the_shipped_collector_schedule() -> None:
    """A healthy fleet must not read as stale.

    The default was 180s while the installed collector runs every 15 minutes,
    so a correctly deployed device showed `stale` for twelve minutes out of
    every fifteen and the fleet screen was red by default. The two numbers are
    coupled — the heartbeat interval the server asks for is derived from the
    staleness window — so they are asserted together.
    """
    default = type(settings)().adr_heartbeat_stale_seconds

    assert default >= 3 * COLLECTOR_TASK_INTERVAL_SECONDS
    assert default % COLLECTOR_TASK_INTERVAL_SECONDS == 0


def test_heartbeat_asks_for_the_interval_the_collector_actually_runs_at() -> None:
    async def scenario():
        async with db_session() as db:
            tenant_id, device_id, token = await enrolled_tenant(db)
            return await adr.adr_heartbeat(
                adr.AdrHeartbeatRequest(
                    device_id=device_id,
                    collector_version="1.0.0",
                    supported_sources=["claude"],
                    observed_sources=["claude"],
                    status="healthy",
                ),
                authorization=f"Bearer {token}",
                x_tenant_id=tenant_id,
                x_device_id=device_id,
                db=db,
            )

    with patched_settings(
        adr_ingest_jwt_hs256_secret="adr-secret",
        adr_heartbeat_stale_seconds=type(settings)().adr_heartbeat_stale_seconds,
    ):
        heartbeat = asyncio.run(scenario())

    # Asking for a cadence the deployed collector cannot keep is the same bug
    # from the other side: it would report healthy devices as late.
    assert heartbeat.next_heartbeat_after_s == COLLECTOR_TASK_INTERVAL_SECONDS
