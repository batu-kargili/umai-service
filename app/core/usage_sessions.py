"""Ingest-time sessionization of collector and extension events.

Folds raw AI-usage events into ``ai_usage_sessions`` rows so dashboards read
low-cardinality sessions instead of the raw event stream. Runs inside the
caller's ingest transaction — atomic with the raw event insert.
"""

from __future__ import annotations

import datetime as dt
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.app_catalog import AppMatcher
from app.models.db import AiUsageSession

def _as_aware_utc(value: dt.datetime) -> dt.datetime:
    """Coerce a datetime to timezone-aware UTC.

    Oracle returns TIMESTAMP columns as offset-naive datetimes, while values we
    compute in-process (e.g. ``captured_at``) are offset-aware. Comparing the
    two raises ``TypeError``, so normalize both sides through this helper before
    any comparison. Naive values are assumed to already be UTC.
    """
    if value.tzinfo is None:
        return value.replace(tzinfo=dt.timezone.utc)
    return value.astimezone(dt.timezone.utc)


SESSION_GAP_SECONDS = 30 * 60
SESSION_EXCLUDED_EVENT_TYPES = {"synthetic_heartbeat", "capture_failure"}
BROWSER_PROCESSES = {
    "chrome.exe",
    "msedge.exe",
    "firefox.exe",
    "brave.exe",
    "opera.exe",
    "arc.exe",
    "vivaldi.exe",
}


def resolve_user_key(
    user_email: str | None,
    user_idp_subject: str | None,
    device_id: str,
) -> str:
    if user_email:
        return user_email.strip().lower()
    if user_idp_subject:
        return user_idp_subject.strip()
    return f"device:{device_id}"


def session_type_for(source: str, process_name: str | None) -> str:
    if source == "extension":
        return "web"
    if process_name and process_name.strip().lower() in BROWSER_PROCESSES:
        return "web"
    return "desktop"


async def fold_event_into_session(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    matcher: AppMatcher,
    batch_memo: dict[tuple[str, str | None, str, str], AiUsageSession],
    source: str,
    event_type: str,
    host: str | None,
    port: int | None,
    process_name: str | None,
    user_email: str | None,
    user_idp_subject: str | None,
    device_id: str,
    captured_at: dt.datetime,
    process_path: str | None = None,
    dlp_hit: bool = False,
) -> str | None:
    """Attach one event to an open usage session, creating one if needed.

    Returns the session id to stamp on the raw event row, or None when the
    event carries no usage signal (excluded types, unmatched collector traffic).
    """
    if event_type in SESSION_EXCLUDED_EVENT_TYPES:
        return None

    app = matcher.match(host, port, process_name, process_path)
    if app is None and source != "extension":
        # Unmatched collector traffic is noise — no session, event stays raw-only.
        return None

    # Oracle hands back naive datetimes; normalize so every comparison below is
    # aware-vs-aware.
    captured_at = _as_aware_utc(captured_at)
    app_slug = app.slug if app is not None else None
    session_type = session_type_for(source, process_name)
    user_key = resolve_user_key(user_email, user_idp_subject, device_id)
    memo_key = (device_id, app_slug, session_type, user_key)
    gap = dt.timedelta(seconds=SESSION_GAP_SECONDS)

    open_session = batch_memo.get(memo_key)
    if open_session is None:
        result = await session.execute(
            select(AiUsageSession)
            .where(
                AiUsageSession.tenant_id == tenant_id,
                AiUsageSession.device_id == device_id,
                AiUsageSession.app_slug == app_slug,
                AiUsageSession.session_type == session_type,
                AiUsageSession.user_key == user_key,
                AiUsageSession.last_activity_at >= captured_at - gap,
            )
            .order_by(AiUsageSession.last_activity_at.desc())
            .limit(1)
        )
        open_session = result.scalars().first()

    if open_session is not None and _as_aware_utc(open_session.last_activity_at) >= captured_at - gap:
        # Out-of-order safe: extend both bounds.
        if captured_at > _as_aware_utc(open_session.last_activity_at):
            open_session.last_activity_at = captured_at
        if captured_at < _as_aware_utc(open_session.started_at):
            open_session.started_at = captured_at
        open_session.event_count = (open_session.event_count or 0) + 1
        if dlp_hit:
            open_session.dlp_hit_count = (open_session.dlp_hit_count or 0) + 1
        batch_memo[memo_key] = open_session
        return str(open_session.id)

    new_session = AiUsageSession(
        tenant_id=tenant_id,
        id=uuid.uuid4(),
        app_id=app.id if app is not None else None,
        app_slug=app_slug,
        user_key=user_key,
        device_id=device_id,
        source=source,
        session_type=session_type,
        started_at=captured_at,
        last_activity_at=captured_at,
        event_count=1,
        dlp_hit_count=1 if dlp_hit else 0,
        created_at=dt.datetime.now(dt.timezone.utc),
    )
    session.add(new_session)
    batch_memo[memo_key] = new_session
    return str(new_session.id)
