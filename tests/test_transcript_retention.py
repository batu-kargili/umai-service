"""Transcript encryption, retention and on-demand deletion (UMA-50).

The claims being tested: content at rest is encrypted when a key is set,
transcripts age out on the tenant's schedule while their sessions and findings
survive, a person can delete one on request, and every one of those touches
leaves a row someone can read months later.
"""

from __future__ import annotations

import asyncio
import base64
import datetime as dt
import gzip
import json
import os
import uuid
from pathlib import Path

import pytest
from sqlalchemy import select

from app.core import transcript_store as store_module
from app.core.settings import settings
from app.core.transcript_retention import (
    ACTION_DELETE_ON_DEMAND,
    ACTION_DELETE_RETENTION,
    delete_transcript,
    reap_expired_transcripts,
)
from app.core.transcript_store import (
    FilesystemTranscriptStore,
    TranscriptDecryptionError,
    seal,
    transcript_sha256,
    unseal,
)
from app.models.db import AiSession, Finding, Tenant, TranscriptAuditEvent
from tests.conftest import db_session

TENANT = uuid.UUID("11111111-1111-1111-1111-111111111111")
OTHER_TENANT = uuid.UUID("22222222-2222-2222-2222-222222222222")
NOW = dt.datetime(2026, 8, 31, 12, 0, tzinfo=dt.timezone.utc)
PAYLOAD = json.dumps({"messages": [{"role": "user", "content": "secret export"}]}).encode()


@pytest.fixture
def key(monkeypatch):
    """A configured encryption key, for the duration of one test."""
    value = base64.b64encode(os.urandom(32)).decode()
    monkeypatch.setattr(settings, "transcript_encryption_key", value, raising=False)
    return value


@pytest.fixture
def no_key(monkeypatch):
    monkeypatch.setattr(settings, "transcript_encryption_key", None, raising=False)


@pytest.fixture
def fs_store(tmp_path: Path) -> FilesystemTranscriptStore:
    return FilesystemTranscriptStore(root=tmp_path)


class TestEncryptionEnvelope:
    def test_without_a_key_bytes_pass_through_untouched(self, no_key) -> None:
        assert seal(PAYLOAD) == PAYLOAD
        assert unseal(PAYLOAD) == PAYLOAD

    def test_with_a_key_the_plaintext_is_not_on_disk(self, key, fs_store) -> None:
        async def scenario():
            ref, _sha, _size = await fs_store.put(TENANT, PAYLOAD)
            raw = (fs_store.root / ref).read_bytes()
            return ref, raw

        ref, raw = asyncio.run(scenario())
        assert b"secret export" not in raw
        # Not merely compressed — gzip of the payload would still be there.
        assert gzip.compress(PAYLOAD) not in raw
        assert raw.startswith(store_module._ENVELOPE_MAGIC)

    def test_a_round_trip_returns_the_original(self, key, fs_store) -> None:
        async def scenario():
            ref, _sha, _size = await fs_store.put(TENANT, PAYLOAD)
            return await fs_store.get(ref)

        assert asyncio.run(scenario()) == PAYLOAD

    def test_encrypting_twice_produces_different_ciphertext(self, key) -> None:
        """A fresh nonce each time — identical blobs must not be linkable."""
        assert seal(PAYLOAD) != seal(PAYLOAD)

    def test_a_blob_written_before_encryption_stays_readable(
        self, monkeypatch, fs_store
    ) -> None:
        """Turning encryption on must not orphan the existing store."""

        async def scenario():
            monkeypatch.setattr(settings, "transcript_encryption_key", None, raising=False)
            ref, _sha, _size = await fs_store.put(TENANT, PAYLOAD)
            monkeypatch.setattr(
                settings,
                "transcript_encryption_key",
                base64.b64encode(os.urandom(32)).decode(),
                raising=False,
            )
            return await fs_store.get(ref)

        assert asyncio.run(scenario()) == PAYLOAD

    def test_losing_the_key_is_an_error_not_silence(self, monkeypatch, fs_store) -> None:
        async def scenario():
            monkeypatch.setattr(
                settings,
                "transcript_encryption_key",
                base64.b64encode(os.urandom(32)).decode(),
                raising=False,
            )
            ref, _sha, _size = await fs_store.put(TENANT, PAYLOAD)
            monkeypatch.setattr(settings, "transcript_encryption_key", None, raising=False)
            with pytest.raises(TranscriptDecryptionError):
                await fs_store.get(ref)

        asyncio.run(scenario())

    def test_the_wrong_key_is_rejected_rather_than_returning_garbage(
        self, monkeypatch, fs_store
    ) -> None:
        async def scenario():
            monkeypatch.setattr(
                settings,
                "transcript_encryption_key",
                base64.b64encode(os.urandom(32)).decode(),
                raising=False,
            )
            ref, _sha, _size = await fs_store.put(TENANT, PAYLOAD)
            monkeypatch.setattr(
                settings,
                "transcript_encryption_key",
                base64.b64encode(os.urandom(32)).decode(),
                raising=False,
            )
            with pytest.raises(TranscriptDecryptionError):
                await fs_store.get(ref)

        asyncio.run(scenario())

    @pytest.mark.parametrize("bad", ["not-base64!!", base64.b64encode(b"tooshort").decode()])
    def test_a_malformed_key_fails_loudly_at_first_use(self, monkeypatch, bad: str) -> None:
        monkeypatch.setattr(settings, "transcript_encryption_key", bad, raising=False)
        with pytest.raises(RuntimeError):
            seal(PAYLOAD)

    def test_the_reference_is_still_the_plaintext_digest(self, key, fs_store) -> None:
        """Dedup and idempotent re-ingest must survive encryption."""

        async def scenario():
            ref, sha, _size = await fs_store.put(TENANT, PAYLOAD)
            again, sha2, _ = await fs_store.put(TENANT, PAYLOAD)
            return ref, sha, again, sha2

        ref, sha, again, sha2 = asyncio.run(scenario())
        assert sha == sha2 == transcript_sha256(PAYLOAD)
        assert ref == again


class TestStoreDelete:
    def test_deleting_removes_the_file(self, no_key, fs_store) -> None:
        async def scenario():
            ref, _sha, _size = await fs_store.put(TENANT, PAYLOAD)
            removed = await fs_store.delete(ref)
            return removed, (fs_store.root / ref).exists()

        removed, still_there = asyncio.run(scenario())
        assert removed is True
        assert still_there is False

    def test_deleting_twice_is_safe(self, no_key, fs_store) -> None:
        """Retention has to be re-runnable after a crash."""

        async def scenario():
            ref, _sha, _size = await fs_store.put(TENANT, PAYLOAD)
            await fs_store.delete(ref)
            return await fs_store.delete(ref)

        assert asyncio.run(scenario()) is False

    def test_a_reference_escaping_the_root_is_refused(self, no_key, fs_store) -> None:
        async def scenario():
            with pytest.raises(ValueError):
                await fs_store.delete("../../etc/passwd")

        asyncio.run(scenario())


# --- database-backed lifecycle ----------------------------------------------


async def _seed(
    db,
    *,
    tenant_id: uuid.UUID = TENANT,
    session_key: str = "sess-1",
    observed_at: dt.datetime | None = None,
    transcript_ref: str | None = "ref-a",
    retention_days: int = 30,
    with_tenant: bool = True,
) -> None:
    if with_tenant:
        existing = await db.get(Tenant, tenant_id)
        if existing is None:
            db.add(
                Tenant(
                    tenant_id=tenant_id,
                    name="acme",
                    collection_mode="full_session",
                    transcript_retention_days=retention_days,
                )
            )
    db.add(
        AiSession(
            tenant_id=tenant_id,
            session_key=session_key,
            source="claude_code",
            source_session_id=f"src-{session_key}",
            message_count=1,
            tool_call_count=0,
            analysis_status="complete",
            observed_at=observed_at or NOW,
            transcript_ref=transcript_ref,
            transcript_sha256="deadbeef" if transcript_ref else None,
            transcript_bytes=1234 if transcript_ref else None,
        )
    )


class _RecordingStore:
    """Counts deletions instead of touching a filesystem."""

    def __init__(self) -> None:
        self.deleted: list[str] = []

    async def put(self, tenant_id, payload):  # pragma: no cover - unused here
        raise NotImplementedError

    async def get(self, ref):  # pragma: no cover - unused here
        raise NotImplementedError

    async def delete(self, ref: str) -> bool:
        self.deleted.append(ref)
        return True


async def _rows(db, model):
    return list((await db.execute(select(model))).scalars().all())


class TestRetentionSweep:
    def test_a_transcript_past_the_window_is_deleted(self) -> None:
        async def scenario():
            store = _RecordingStore()
            async with db_session() as db:
                await _seed(db, observed_at=NOW - dt.timedelta(days=45))
                await db.commit()
                result = await reap_expired_transcripts(db, store=store, now=NOW)
                return result, (await _rows(db, AiSession))[0], store

        result, row, store = asyncio.run(scenario())
        assert result.deleted == 1
        assert store.deleted == ["ref-a"]
        assert row.transcript_ref is None
        assert row.transcript_sha256 is None
        assert row.transcript_bytes is None

    def test_a_transcript_inside_the_window_is_left_alone(self) -> None:
        async def scenario():
            store = _RecordingStore()
            async with db_session() as db:
                await _seed(db, observed_at=NOW - dt.timedelta(days=10))
                await db.commit()
                result = await reap_expired_transcripts(db, store=store, now=NOW)
                return result, (await _rows(db, AiSession))[0], store

        result, row, store = asyncio.run(scenario())
        assert result.deleted == 0
        assert store.deleted == []
        assert row.transcript_ref == "ref-a"

    def test_the_session_and_its_findings_outlive_the_transcript(self) -> None:
        """13 months of findings, 30 days of content — the whole point."""

        async def scenario():
            async with db_session() as db:
                await _seed(db, observed_at=NOW - dt.timedelta(days=200))
                db.add(
                    Finding(
                        tenant_id=TENANT,
                        finding_key="f1",
                        session_key="sess-1",
                        rule_id="detector.ADR.T1005",
                        source="adr",
                        detector="reasoning",
                        category="data_exposure",
                        severity="high",
                        status="open",
                        title="exfiltration",
                        detected_at=NOW,
                    )
                )
                await db.commit()
                await reap_expired_transcripts(db, store=_RecordingStore(), now=NOW)
                return await _rows(db, AiSession), await _rows(db, Finding)

        sessions, findings = asyncio.run(scenario())
        assert len(sessions) == 1 and sessions[0].transcript_ref is None
        assert len(findings) == 1 and findings[0].status == "open"

    def test_each_tenant_keeps_its_own_window(self) -> None:
        async def scenario():
            store = _RecordingStore()
            async with db_session() as db:
                await _seed(
                    db,
                    tenant_id=TENANT,
                    session_key="short",
                    observed_at=NOW - dt.timedelta(days=45),
                    retention_days=30,
                )
                await _seed(
                    db,
                    tenant_id=OTHER_TENANT,
                    session_key="long",
                    observed_at=NOW - dt.timedelta(days=45),
                    transcript_ref="ref-b",
                    retention_days=90,
                )
                await db.commit()
                await reap_expired_transcripts(db, store=store, now=NOW)
                rows = {r.session_key: r.transcript_ref for r in await _rows(db, AiSession)}
                return rows, store

        rows, store = asyncio.run(scenario())
        assert rows == {"short": None, "long": "ref-b"}
        assert store.deleted == ["ref-a"]

    def test_a_shared_blob_is_kept_while_another_session_needs_it(self) -> None:
        """Content-addressed storage means one file can back two sessions."""

        async def scenario():
            store = _RecordingStore()
            async with db_session() as db:
                await _seed(
                    db, session_key="old", observed_at=NOW - dt.timedelta(days=45)
                )
                await _seed(
                    db,
                    session_key="recent",
                    observed_at=NOW - dt.timedelta(days=2),
                    transcript_ref="ref-a",
                )
                await db.commit()
                result = await reap_expired_transcripts(db, store=store, now=NOW)
                rows = {r.session_key: r.transcript_ref for r in await _rows(db, AiSession)}
                return result, rows, store

        result, rows, store = asyncio.run(scenario())
        assert result.deleted == 1
        assert result.blobs_shared == 1
        # The pointer is dropped; the file the other session still needs is not.
        assert store.deleted == []
        assert rows == {"old": None, "recent": "ref-a"}

    def test_age_is_measured_from_when_the_conversation_happened(self) -> None:
        """A backlog upload must not restart the clock on old content."""

        async def scenario():
            async with db_session() as db:
                await _seed(db, observed_at=NOW - dt.timedelta(days=60))
                await db.commit()
                # Ingested today, observed two months ago.
                row = (await _rows(db, AiSession))[0]
                row.ingested_at = NOW
                await db.commit()
                return await reap_expired_transcripts(db, store=_RecordingStore(), now=NOW)

        assert asyncio.run(scenario()).deleted == 1

    def test_the_schema_guarantees_every_session_has_an_observation_time(self) -> None:
        """Retention is computed from `observed_at`, so it must always be set.

        `reap_expired_transcripts` still guards against None — cheap insurance
        if this column is ever relaxed — but the guarantee lives here.
        """
        assert AiSession.__table__.c.observed_at.nullable is False

    def test_a_tenant_with_no_row_falls_back_to_the_default_window(self) -> None:
        async def scenario():
            async with db_session() as db:
                await _seed(
                    db, observed_at=NOW - dt.timedelta(days=45), with_tenant=False
                )
                await db.commit()
                return await reap_expired_transcripts(db, store=_RecordingStore(), now=NOW)

        assert asyncio.run(scenario()).deleted == 1

    def test_one_unremovable_blob_does_not_stall_the_sweep(self) -> None:
        class Flaky(_RecordingStore):
            async def delete(self, ref: str) -> bool:
                if ref == "bad":
                    raise OSError("storage is unhappy")
                return await super().delete(ref)

        async def scenario():
            async with db_session() as db:
                await _seed(
                    db,
                    session_key="bad-one",
                    observed_at=NOW - dt.timedelta(days=45),
                    transcript_ref="bad",
                )
                await _seed(
                    db,
                    session_key="good-one",
                    observed_at=NOW - dt.timedelta(days=46),
                    transcript_ref="good",
                )
                await db.commit()
                result = await reap_expired_transcripts(db, store=Flaky(), now=NOW)
                rows = {r.session_key: r.transcript_ref for r in await _rows(db, AiSession)}
                return result, rows

        result, rows = asyncio.run(scenario())
        assert (result.deleted, result.failed) == (1, 1)
        assert rows == {"bad-one": "bad", "good-one": None}

    def test_the_sweep_is_bounded(self) -> None:
        """A mis-computed cut-off takes out one batch, not the whole store."""

        async def scenario():
            async with db_session() as db:
                for n in range(5):
                    await _seed(
                        db,
                        session_key=f"s{n}",
                        observed_at=NOW - dt.timedelta(days=100 + n),
                        transcript_ref=f"ref-{n}",
                    )
                await db.commit()
                return await reap_expired_transcripts(
                    db, store=_RecordingStore(), now=NOW, limit=2
                )

        assert asyncio.run(scenario()).deleted == 2

    def test_re_running_the_sweep_deletes_nothing_twice(self) -> None:
        async def scenario():
            store = _RecordingStore()
            async with db_session() as db:
                await _seed(db, observed_at=NOW - dt.timedelta(days=45))
                await db.commit()
                await reap_expired_transcripts(db, store=store, now=NOW)
                second = await reap_expired_transcripts(db, store=store, now=NOW)
                return second, store

        second, store = asyncio.run(scenario())
        assert second.deleted == 0
        assert len(store.deleted) == 1


class TestOnDemandDeletion:
    def test_deleting_removes_the_blob_and_the_pointer(self) -> None:
        async def scenario():
            store = _RecordingStore()
            async with db_session() as db:
                await _seed(db)
                await db.commit()
                deleted = await delete_transcript(
                    db,
                    tenant_id=TENANT,
                    session_key="sess-1",
                    actor="ada@corp",
                    reason="subject access request 4471",
                    store=store,
                    now=NOW,
                )
                return deleted, (await _rows(db, AiSession))[0], store

        deleted, row, store = asyncio.run(scenario())
        assert deleted is True
        assert store.deleted == ["ref-a"]
        assert row.transcript_ref is None

    def test_deleting_an_already_deleted_transcript_is_not_an_error(self) -> None:
        async def scenario():
            store = _RecordingStore()
            async with db_session() as db:
                await _seed(db, transcript_ref=None)
                await db.commit()
                return (
                    await delete_transcript(
                        db,
                        tenant_id=TENANT,
                        session_key="sess-1",
                        actor="ada",
                        reason="repeat request",
                        store=store,
                        now=NOW,
                    ),
                    store,
                )

        deleted, store = asyncio.run(scenario())
        assert deleted is False
        assert store.deleted == []

    def test_deleting_a_session_of_another_tenant_does_nothing(self) -> None:
        async def scenario():
            store = _RecordingStore()
            async with db_session() as db:
                await _seed(db)
                await db.commit()
                return (
                    await delete_transcript(
                        db,
                        tenant_id=OTHER_TENANT,
                        session_key="sess-1",
                        actor="mallory",
                        reason="curiosity",
                        store=store,
                        now=NOW,
                    ),
                    store,
                )

        deleted, store = asyncio.run(scenario())
        assert deleted is False
        assert store.deleted == []

    def test_a_shared_blob_survives_an_on_demand_deletion(self) -> None:
        async def scenario():
            store = _RecordingStore()
            async with db_session() as db:
                await _seed(db, session_key="a")
                await _seed(db, session_key="b", transcript_ref="ref-a")
                await db.commit()
                await delete_transcript(
                    db,
                    tenant_id=TENANT,
                    session_key="a",
                    actor="ada",
                    reason="request",
                    store=store,
                    now=NOW,
                )
                rows = {r.session_key: r.transcript_ref for r in await _rows(db, AiSession)}
                return rows, store

        rows, store = asyncio.run(scenario())
        assert rows == {"a": None, "b": "ref-a"}
        assert store.deleted == []


class TestAuditTrail:
    def test_an_on_demand_deletion_records_who_and_why(self) -> None:
        async def scenario():
            async with db_session() as db:
                await _seed(db)
                await db.commit()
                await delete_transcript(
                    db,
                    tenant_id=TENANT,
                    session_key="sess-1",
                    actor="ada@corp",
                    reason="subject access request 4471",
                    store=_RecordingStore(),
                    now=NOW,
                )
                return await _rows(db, TranscriptAuditEvent)

        events = asyncio.run(scenario())
        assert len(events) == 1
        assert events[0].action == ACTION_DELETE_ON_DEMAND
        assert events[0].actor == "ada@corp"
        assert events[0].reason == "subject access request 4471"
        # Recorded before the pointer was cleared, so it survives as evidence.
        assert events[0].transcript_bytes == 1234

    def test_a_retention_deletion_records_the_policy_not_a_person(self) -> None:
        async def scenario():
            async with db_session() as db:
                await _seed(db, observed_at=NOW - dt.timedelta(days=45))
                await db.commit()
                await reap_expired_transcripts(db, store=_RecordingStore(), now=NOW)
                return await _rows(db, TranscriptAuditEvent)

        events = asyncio.run(scenario())
        assert len(events) == 1
        assert events[0].action == ACTION_DELETE_RETENTION
        # Nobody asked; the clock did.
        assert events[0].actor is None
        assert "30 days" in events[0].reason

    def test_no_audit_row_is_written_for_a_deletion_that_did_not_happen(self) -> None:
        async def scenario():
            async with db_session() as db:
                await _seed(db, transcript_ref=None)
                await db.commit()
                await delete_transcript(
                    db,
                    tenant_id=TENANT,
                    session_key="sess-1",
                    actor="ada",
                    reason="repeat",
                    store=_RecordingStore(),
                    now=NOW,
                )
                return await _rows(db, TranscriptAuditEvent)

        assert asyncio.run(scenario()) == []

    def test_the_audit_row_and_the_deletion_land_together(self) -> None:
        """A store failure must not leave an audit entry claiming success."""

        class Exploding(_RecordingStore):
            async def delete(self, ref: str) -> bool:
                raise OSError("storage is unhappy")

        async def scenario():
            async with db_session() as db:
                await _seed(db)
                await db.commit()
                try:
                    await delete_transcript(
                        db,
                        tenant_id=TENANT,
                        session_key="sess-1",
                        actor="ada",
                        reason="request",
                        store=Exploding(),
                        now=NOW,
                    )
                except OSError:
                    pass
                return await _rows(db, TranscriptAuditEvent), (await _rows(db, AiSession))[0]

        events, row = asyncio.run(scenario())
        assert events == []
        assert row.transcript_ref == "ref-a"
