"""Asynchronous-pipeline and freshness metrics (UMA-88).

The synchronous decision path fails loudly — a caller gets an error. Everything on this
page fails *quietly*, which is why it needs its own observation layer:

* **A collector that stopped uploading** still looks enrolled. Nothing errors; findings
  simply stop arriving for those machines, and a fleet dashboard showing "12 devices
  active" is telling the truth about enrolment and nothing about data.
* **A SIEM outbox that is not draining** loses nobody's data — that is the point of the
  outbox — but the SOC stops seeing findings while the platform looks healthy.
* **A transcript store that is failing to read** turns evidence into 500s one finding at
  a time, and a decryption failure is a configuration problem that must not be reported
  as ordinary absence.
* **A licence about to expire, or a policy snapshot nobody republished**, are the two
  ways the platform stops enforcing what an operator believes it enforces.

Fleet-wide values are aggregates, never per device. A per-device series would put the
size of a customer's estate into the cardinality of the metric, so what is reported is
the count by state plus the *worst* case — the oldest heartbeat, the oldest pending
event. An aggregate that hides a single stuck item is not much use, and the worst case
is what an alert should fire on.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import logging

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.metrics import registry
from app.models.db import AdrDevice, AiSession, GuardrailVersion, License, SiemOutbox

logger = logging.getLogger("umai.service.pipeline_metrics")

# Collector fleet
COLLECTOR_DEVICES = "umai_collector_devices"
COLLECTOR_OLDEST_HEARTBEAT_AGE = "umai_collector_oldest_heartbeat_age_seconds"
COLLECTOR_FLEET_QUEUE_DEPTH = "umai_collector_fleet_queue_depth"
INGEST_REQUESTS = "umai_adr_ingest_requests_total"
INGEST_SESSIONS = "umai_adr_ingest_sessions_total"

# Transcript store
TRANSCRIPT_ERRORS = "umai_transcript_store_errors_total"
TRANSCRIPT_STORED_BYTES = "umai_transcript_stored_bytes"
TRANSCRIPT_STORED_SESSIONS = "umai_transcript_stored_sessions"

# SIEM outbox
SIEM_OUTBOX_DEPTH = "umai_siem_outbox_depth"
SIEM_OUTBOX_OLDEST_PENDING_AGE = "umai_siem_outbox_oldest_pending_age_seconds"
SIEM_DELIVERY = "umai_siem_delivery_total"

# Freshness
LICENSE_EXPIRES_IN = "umai_license_expires_in_seconds"
POLICY_SNAPSHOT_AGE = "umai_policy_snapshot_age_seconds"

registry.describe(
    COLLECTOR_DEVICES,
    "Collector devices by state. 'stale' means enrolled and active but not heartbeating.",
)
registry.describe(
    COLLECTOR_OLDEST_HEARTBEAT_AGE,
    "Age of the oldest heartbeat among active collectors. An aggregate that hid one "
    "stuck device would defeat the purpose, so this reports the worst case.",
)
registry.describe(
    COLLECTOR_FLEET_QUEUE_DEPTH,
    "Sessions the fleet reports as still pending upload, summed across devices.",
)
registry.describe(INGEST_REQUESTS, "Collector ingest requests by outcome.")
registry.describe(INGEST_SESSIONS, "Sessions inside ingest batches, by what happened to each.")
registry.describe(
    TRANSCRIPT_ERRORS,
    "Transcript store failures by operation and reason. 'decrypt' is a configuration "
    "problem, not a missing transcript.",
)
registry.describe(TRANSCRIPT_STORED_BYTES, "Bytes of transcript content currently retained.")
registry.describe(TRANSCRIPT_STORED_SESSIONS, "Sessions that currently hold transcript content.")
registry.describe(SIEM_OUTBOX_DEPTH, "SIEM outbox rows by status.")
registry.describe(
    SIEM_OUTBOX_OLDEST_PENDING_AGE,
    "Age of the oldest undelivered SIEM event. The outbox loses nothing, but a SOC that "
    "stops receiving findings while the platform looks healthy is the failure here.",
)
registry.describe(SIEM_DELIVERY, "SIEM delivery attempts by outcome.")
registry.describe(
    LICENSE_EXPIRES_IN,
    "Seconds until the licence expires. Negative once expired, so one alert covers both "
    "'expiring soon' and 'already expired'.",
)
registry.describe(
    POLICY_SNAPSHOT_AGE,
    "Age of the most recently published policy snapshot. A snapshot nobody republished "
    "means the platform is enforcing something older than the operator believes.",
)


def record_ingest_request(outcome: str) -> None:
    registry.increment(INGEST_REQUESTS, {"outcome": outcome})


def record_ingest_sessions(
    created: int = 0, updated: int = 0, unchanged: int = 0, rejected: int = 0
) -> None:
    for result, count in (
        ("created", created),
        ("updated", updated),
        ("unchanged", unchanged),
        ("rejected", rejected),
    ):
        if count:
            registry.increment(INGEST_SESSIONS, {"result": result}, count)


def record_transcript_error(operation: str, reason: str) -> None:
    registry.increment(TRANSCRIPT_ERRORS, {"operation": operation, "reason": reason})


def record_siem_delivery(outcome: str, count: int = 1) -> None:
    if count:
        registry.increment(SIEM_DELIVERY, {"outcome": outcome}, count)


def _age_seconds(moment: dt.datetime, value: dt.datetime | None) -> float | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=dt.timezone.utc)
    return max(0.0, (moment - value).total_seconds())


async def sample_pipeline(
    session: AsyncSession,
    now: dt.datetime | None = None,
    heartbeat_stale_seconds: int | None = None,
) -> None:
    """Refresh every sampled gauge from one pass over the relevant tables."""
    moment = now or dt.datetime.now(dt.timezone.utc)
    if heartbeat_stale_seconds is None:
        from app.core.settings import settings

        heartbeat_stale_seconds = int(settings.adr_heartbeat_stale_seconds)

    await _sample_collectors(session, moment, heartbeat_stale_seconds)
    await _sample_transcripts(session)
    await _sample_outbox(session, moment)
    await _sample_freshness(session, moment)


async def _sample_collectors(
    session: AsyncSession, moment: dt.datetime, stale_after: int
) -> None:
    devices = list((await session.execute(select(AdrDevice))).scalars().all())

    active = revoked = stale = 0
    oldest_age = 0.0
    fleet_queue = 0
    for device in devices:
        status = (device.status or "").lower()
        if status != "active":
            revoked += 1
            continue
        active += 1
        fleet_queue += int(device.queue_depth or 0)
        age = _age_seconds(moment, device.last_heartbeat_at)
        # A device that has never heartbeated is stale, not unknown: it enrolled and
        # then said nothing, which is exactly the state worth alerting on.
        if age is None or age > stale_after:
            stale += 1
        if age is not None:
            oldest_age = max(oldest_age, age)

    registry.set_gauge(COLLECTOR_DEVICES, active, {"state": "active"})
    registry.set_gauge(COLLECTOR_DEVICES, revoked, {"state": "revoked"})
    registry.set_gauge(COLLECTOR_DEVICES, stale, {"state": "stale"})
    registry.set_gauge(COLLECTOR_OLDEST_HEARTBEAT_AGE, oldest_age)
    registry.set_gauge(COLLECTOR_FLEET_QUEUE_DEPTH, fleet_queue)


async def _sample_transcripts(session: AsyncSession) -> None:
    total_bytes, held = (
        await session.execute(
            select(func.coalesce(func.sum(AiSession.transcript_bytes), 0), func.count())
            .where(AiSession.transcript_ref.isnot(None))
        )
    ).one()
    registry.set_gauge(TRANSCRIPT_STORED_BYTES, int(total_bytes or 0))
    registry.set_gauge(TRANSCRIPT_STORED_SESSIONS, int(held or 0))


async def _sample_outbox(session: AsyncSession, moment: dt.datetime) -> None:
    counts = dict(
        (
            await session.execute(
                select(SiemOutbox.status, func.count()).group_by(SiemOutbox.status)
            )
        ).all()
    )
    for status in ("pending", "delivered", "dead_letter"):
        registry.set_gauge(SIEM_OUTBOX_DEPTH, counts.get(status, 0), {"status": status})

    oldest = (
        await session.execute(
            select(func.min(SiemOutbox.created_at)).where(SiemOutbox.status == "pending")
        )
    ).scalar_one_or_none()
    registry.set_gauge(SIEM_OUTBOX_OLDEST_PENDING_AGE, _age_seconds(moment, oldest) or 0.0)


async def _sample_freshness(session: AsyncSession, moment: dt.datetime) -> None:
    # Licence. Reported as seconds remaining rather than a boolean so one alert
    # threshold covers "expiring soon" and "already expired" — the latter is just a
    # negative value, which is far easier to graph than a flag that flips once.
    soonest = (
        await session.execute(select(func.min(License.expires_at)))
    ).scalar_one_or_none()
    if soonest is None:
        registry.set_gauge(LICENSE_EXPIRES_IN, 0)
    else:
        if soonest.tzinfo is None:
            soonest = soonest.replace(tzinfo=dt.timezone.utc)
        registry.set_gauge(LICENSE_EXPIRES_IN, (soonest - moment).total_seconds())

    newest = (
        await session.execute(select(func.max(GuardrailVersion.created_at)))
    ).scalar_one_or_none()
    registry.set_gauge(POLICY_SNAPSHOT_AGE, _age_seconds(moment, newest) or 0.0)


async def run_pipeline_sampler(sessionmaker, interval_s: float, stop: asyncio.Event) -> None:
    """Sample the pipeline gauges periodically, surviving transient failures."""
    while not stop.is_set():
        try:
            async with sessionmaker() as session:
                await sample_pipeline(session)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.warning("pipeline_metrics.sample_failed", exc_info=True)
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval_s)
        except asyncio.TimeoutError:
            continue
