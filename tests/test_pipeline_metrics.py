"""Asynchronous-pipeline and freshness metrics (UMA-88).

Everything measured here fails quietly, so the tests care about the states that look
healthy but are not: a collector enrolled but silent, an outbox holding events nobody
delivered, a licence about to lapse, a snapshot nobody republished.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import uuid

import pytest

from app.core.metrics import registry
from app.core.pipeline_metrics import (
    COLLECTOR_DEVICES,
    COLLECTOR_FLEET_QUEUE_DEPTH,
    COLLECTOR_OLDEST_HEARTBEAT_AGE,
    INGEST_REQUESTS,
    INGEST_SESSIONS,
    LICENSE_EXPIRES_IN,
    POLICY_SNAPSHOT_AGE,
    SIEM_DELIVERY,
    SIEM_OUTBOX_DEPTH,
    SIEM_OUTBOX_OLDEST_PENDING_AGE,
    TRANSCRIPT_ERRORS,
    TRANSCRIPT_STORED_BYTES,
    TRANSCRIPT_STORED_SESSIONS,
    record_ingest_request,
    record_ingest_sessions,
    record_siem_delivery,
    record_transcript_error,
    sample_pipeline,
)
from app.models.db import AdrDevice, AiSession, GuardrailVersion, License, SiemOutbox, Tenant
from tests.conftest import db_session

TENANT = uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
NOW = dt.datetime(2026, 9, 1, 12, 0, tzinfo=dt.timezone.utc)
STALE_AFTER = 180


@pytest.fixture(autouse=True)
def clean_metrics() -> None:
    registry.reset()


def device(device_id: str, *, status: str = "active", heartbeat: dt.datetime | None = NOW,
           queue_depth: int = 0) -> AdrDevice:
    return AdrDevice(
        tenant_id=TENANT,
        device_id=device_id,
        status=status,
        last_heartbeat_at=heartbeat,
        queue_depth=queue_depth,
    )


def session_row(key: str, *, ref: str | None = None, size: int | None = None) -> AiSession:
    return AiSession(
        tenant_id=TENANT,
        session_key=key,
        source="adr",
        source_session_id=f"src-{key[:6]}",
        observed_at=NOW,
        ingested_at=NOW,
        message_count=1,
        tool_call_count=0,
        analysis_status="analyzed",
        analysis_attempts=1,
        updated_at=NOW,
        transcript_ref=ref,
        transcript_bytes=size,
    )


def outbox_row(event_id: str, status: str, created_at: dt.datetime) -> SiemOutbox:
    return SiemOutbox(
        tenant_id=TENANT,
        event_id=event_id,
        event_schema="finding.v1",
        payload_json="{}",
        status=status,
        attempts=0,
        created_at=created_at,
    )


class TestCounters:
    def test_ingest_outcomes_are_counted(self) -> None:
        record_ingest_request("accepted")
        record_ingest_request("denied")
        assert registry.counter_value(INGEST_REQUESTS, {"outcome": "accepted"}) == 1
        assert registry.counter_value(INGEST_REQUESTS, {"outcome": "denied"}) == 1

    def test_session_level_results_are_counted(self) -> None:
        record_ingest_sessions(created=3, updated=1, unchanged=5, rejected=2)
        for result, expected in (("created", 3), ("updated", 1), ("unchanged", 5), ("rejected", 2)):
            assert registry.counter_value(INGEST_SESSIONS, {"result": result}) == expected

    def test_zero_counts_create_no_series(self) -> None:
        record_ingest_sessions(created=0)
        assert registry.counter_value(INGEST_SESSIONS, {"result": "created"}) == 0

    def test_a_decryption_failure_is_counted_apart_from_absence(self) -> None:
        """A key misconfiguration must not be buried among ordinary missing transcripts."""
        record_transcript_error("get", "decrypt")
        record_transcript_error("get", "unavailable")
        assert registry.counter_value(
            TRANSCRIPT_ERRORS, {"operation": "get", "reason": "decrypt"}
        ) == 1
        assert registry.counter_value(
            TRANSCRIPT_ERRORS, {"operation": "get", "reason": "unavailable"}
        ) == 1

    def test_siem_outcomes_are_counted(self) -> None:
        record_siem_delivery("delivered", 5)
        record_siem_delivery("retry", 2)
        record_siem_delivery("dead_letter", 1)
        assert registry.counter_value(SIEM_DELIVERY, {"outcome": "delivered"}) == 5
        assert registry.counter_value(SIEM_DELIVERY, {"outcome": "retry"}) == 2
        assert registry.counter_value(SIEM_DELIVERY, {"outcome": "dead_letter"}) == 1

    def test_a_zero_delivery_batch_records_nothing(self) -> None:
        record_siem_delivery("delivered", 0)
        assert registry.counter_value(SIEM_DELIVERY, {"outcome": "delivered"}) == 0


async def _sample(rows: list) -> None:
    async with db_session() as db:
        db.add(Tenant(tenant_id=TENANT, name="A", collection_mode="full_session"))
        db.add_all(rows)
        await db.commit()
        await sample_pipeline(db, now=NOW, heartbeat_stale_seconds=STALE_AFTER)


class TestCollectorFreshness:
    def test_devices_are_counted_by_state(self) -> None:
        asyncio.run(_sample([
            device("d1"),
            device("d2"),
            device("d3", status="revoked"),
        ]))
        assert registry.gauge_value(COLLECTOR_DEVICES, {"state": "active"}) == 2
        assert registry.gauge_value(COLLECTOR_DEVICES, {"state": "revoked"}) == 1

    def test_an_active_device_that_stopped_heartbeating_is_stale(self) -> None:
        """It still looks enrolled. Nothing errors; findings just stop arriving."""
        asyncio.run(_sample([
            device("fresh", heartbeat=NOW - dt.timedelta(seconds=30)),
            device("silent", heartbeat=NOW - dt.timedelta(hours=6)),
        ]))
        assert registry.gauge_value(COLLECTOR_DEVICES, {"state": "stale"}) == 1
        assert registry.gauge_value(COLLECTOR_DEVICES, {"state": "active"}) == 2

    def test_a_device_that_never_heartbeated_is_stale_not_ignored(self) -> None:
        asyncio.run(_sample([device("never", heartbeat=None)]))
        assert registry.gauge_value(COLLECTOR_DEVICES, {"state": "stale"}) == 1

    def test_the_oldest_heartbeat_is_reported_not_the_average(self) -> None:
        """An aggregate that hid one stuck device would defeat the purpose."""
        asyncio.run(_sample([
            device("a", heartbeat=NOW - dt.timedelta(seconds=10)),
            device("b", heartbeat=NOW - dt.timedelta(seconds=10)),
            device("c", heartbeat=NOW - dt.timedelta(hours=3)),
        ]))
        assert registry.gauge_value(COLLECTOR_OLDEST_HEARTBEAT_AGE) == pytest.approx(3 * 3600)

    def test_a_revoked_device_does_not_drag_the_heartbeat_age(self) -> None:
        asyncio.run(_sample([
            device("live", heartbeat=NOW - dt.timedelta(seconds=5)),
            device("old", status="revoked", heartbeat=NOW - dt.timedelta(days=30)),
        ]))
        assert registry.gauge_value(COLLECTOR_OLDEST_HEARTBEAT_AGE) == pytest.approx(5)

    def test_the_fleet_backlog_is_summed_across_devices(self) -> None:
        asyncio.run(_sample([
            device("a", queue_depth=4),
            device("b", queue_depth=11),
            device("c", status="revoked", queue_depth=99),
        ]))
        assert registry.gauge_value(COLLECTOR_FLEET_QUEUE_DEPTH) == 15

    def test_no_devices_reports_zeroes_rather_than_nothing(self) -> None:
        asyncio.run(_sample([]))
        assert registry.gauge_value(COLLECTOR_DEVICES, {"state": "active"}) == 0
        assert registry.gauge_value(COLLECTOR_OLDEST_HEARTBEAT_AGE) == 0

    def test_per_device_series_are_not_created(self) -> None:
        """A per-device label would put the size of a customer's estate into the
        metric's cardinality."""
        asyncio.run(_sample([device(f"d{i}") for i in range(50)]))
        rendered = registry.render()
        assert "device_id" not in rendered


class TestTranscriptCapacity:
    def test_retained_bytes_and_sessions_are_reported(self) -> None:
        asyncio.run(_sample([
            session_row("a" * 64, ref="x/y/a.gz", size=1000),
            session_row("b" * 64, ref="x/y/b.gz", size=2500),
            session_row("c" * 64, ref=None, size=None),
        ]))
        assert registry.gauge_value(TRANSCRIPT_STORED_BYTES) == 3500
        assert registry.gauge_value(TRANSCRIPT_STORED_SESSIONS) == 2

    def test_a_store_with_nothing_in_it_reports_zero(self) -> None:
        asyncio.run(_sample([session_row("a" * 64, ref=None)]))
        assert registry.gauge_value(TRANSCRIPT_STORED_BYTES) == 0
        assert registry.gauge_value(TRANSCRIPT_STORED_SESSIONS) == 0


class TestOutboxDepth:
    def test_rows_are_counted_by_status(self) -> None:
        asyncio.run(_sample([
            outbox_row("e1", "pending", NOW),
            outbox_row("e2", "pending", NOW),
            outbox_row("e3", "delivered", NOW),
            outbox_row("e4", "dead_letter", NOW),
        ]))
        assert registry.gauge_value(SIEM_OUTBOX_DEPTH, {"status": "pending"}) == 2
        assert registry.gauge_value(SIEM_OUTBOX_DEPTH, {"status": "delivered"}) == 1
        assert registry.gauge_value(SIEM_OUTBOX_DEPTH, {"status": "dead_letter"}) == 1

    def test_the_oldest_undelivered_event_age_is_reported(self) -> None:
        """The outbox loses nothing, so depth alone does not say the SOC went blind."""
        asyncio.run(_sample([
            outbox_row("old", "pending", NOW - dt.timedelta(hours=2)),
            outbox_row("new", "pending", NOW - dt.timedelta(seconds=5)),
        ]))
        assert registry.gauge_value(SIEM_OUTBOX_OLDEST_PENDING_AGE) == pytest.approx(2 * 3600)

    def test_a_delivered_event_does_not_count_as_pending_age(self) -> None:
        asyncio.run(_sample([
            outbox_row("delivered-long-ago", "delivered", NOW - dt.timedelta(days=7)),
        ]))
        assert registry.gauge_value(SIEM_OUTBOX_OLDEST_PENDING_AGE) == 0

    def test_a_dead_letter_is_not_counted_as_pending(self) -> None:
        asyncio.run(_sample([
            outbox_row("dead", "dead_letter", NOW - dt.timedelta(days=1)),
        ]))
        assert registry.gauge_value(SIEM_OUTBOX_OLDEST_PENDING_AGE) == 0
        assert registry.gauge_value(SIEM_OUTBOX_DEPTH, {"status": "pending"}) == 0


class TestFreshness:
    def test_time_remaining_on_the_licence_is_reported(self) -> None:
        asyncio.run(_sample([
            License(tenant_id=TENANT, status="active", expires_at=NOW + dt.timedelta(days=30)),
        ]))
        assert registry.gauge_value(LICENSE_EXPIRES_IN) == pytest.approx(30 * 86400)

    def test_an_expired_licence_reports_a_negative_value(self) -> None:
        """One threshold then covers 'expiring soon' and 'already expired'."""
        asyncio.run(_sample([
            License(tenant_id=TENANT, status="active", expires_at=NOW - dt.timedelta(days=2)),
        ]))
        assert registry.gauge_value(LICENSE_EXPIRES_IN) == pytest.approx(-2 * 86400)

    def test_the_soonest_expiry_across_tenants_is_reported(self) -> None:
        other = uuid.UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")

        async def run() -> None:
            async with db_session() as db:
                db.add_all([
                    Tenant(tenant_id=TENANT, name="A", collection_mode="metadata"),
                    Tenant(tenant_id=other, name="B", collection_mode="metadata"),
                    License(tenant_id=TENANT, status="active", expires_at=NOW + dt.timedelta(days=90)),
                    License(tenant_id=other, status="active", expires_at=NOW + dt.timedelta(days=3)),
                ])
                await db.commit()
                await sample_pipeline(db, now=NOW, heartbeat_stale_seconds=STALE_AFTER)

        asyncio.run(run())
        assert registry.gauge_value(LICENSE_EXPIRES_IN) == pytest.approx(3 * 86400)

    def test_the_policy_snapshot_age_is_reported(self) -> None:
        asyncio.run(_sample([
            GuardrailVersion(
                tenant_id=TENANT, environment_id="env", project_id="proj",
                guardrail_id="gr-1", version=1, snapshot_json="{}",
                created_at=NOW - dt.timedelta(days=5),
            ),
        ]))
        assert registry.gauge_value(POLICY_SNAPSHOT_AGE) == pytest.approx(5 * 86400)

    def test_the_newest_snapshot_defines_freshness(self) -> None:
        asyncio.run(_sample([
            GuardrailVersion(
                tenant_id=TENANT, environment_id="env", project_id="proj",
                guardrail_id="gr-1", version=1, snapshot_json="{}",
                created_at=NOW - dt.timedelta(days=100),
            ),
            GuardrailVersion(
                tenant_id=TENANT, environment_id="env", project_id="proj",
                guardrail_id="gr-1", version=2, snapshot_json="{}",
                created_at=NOW - dt.timedelta(hours=1),
            ),
        ]))
        assert registry.gauge_value(POLICY_SNAPSHOT_AGE) == pytest.approx(3600)

    def test_no_licence_and_no_snapshot_report_zero(self) -> None:
        asyncio.run(_sample([]))
        assert registry.gauge_value(LICENSE_EXPIRES_IN) == 0
        assert registry.gauge_value(POLICY_SNAPSHOT_AGE) == 0


class TestSamplingProperties:
    def test_sampling_twice_does_not_double_a_gauge(self) -> None:
        async def run() -> None:
            async with db_session() as db:
                db.add(Tenant(tenant_id=TENANT, name="A", collection_mode="metadata"))
                db.add(device("d1", queue_depth=7))
                await db.commit()
                await sample_pipeline(db, now=NOW, heartbeat_stale_seconds=STALE_AFTER)
                await sample_pipeline(db, now=NOW, heartbeat_stale_seconds=STALE_AFTER)

        asyncio.run(run())
        assert registry.gauge_value(COLLECTOR_FLEET_QUEUE_DEPTH) == 7

    def test_every_declared_gauge_appears_after_one_sample(self) -> None:
        """A missing series reads as a broken exporter, so an empty system still reports."""
        asyncio.run(_sample([]))
        rendered = registry.render()
        for name in (
            COLLECTOR_DEVICES,
            COLLECTOR_OLDEST_HEARTBEAT_AGE,
            COLLECTOR_FLEET_QUEUE_DEPTH,
            TRANSCRIPT_STORED_BYTES,
            TRANSCRIPT_STORED_SESSIONS,
            SIEM_OUTBOX_DEPTH,
            SIEM_OUTBOX_OLDEST_PENDING_AGE,
            LICENSE_EXPIRES_IN,
            POLICY_SNAPSHOT_AGE,
        ):
            assert name in rendered, name
