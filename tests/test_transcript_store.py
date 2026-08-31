"""Transcript storage backends (UMA-49)."""

from __future__ import annotations

import asyncio
import gzip
import json
import tempfile
import uuid
from pathlib import Path

import pytest

from app.core.transcript_store import (
    FilesystemTranscriptStore,
    S3TranscriptStore,
    build_transcript_store,
    transcript_sha256,
)

TENANT = uuid.UUID("11111111-1111-1111-1111-111111111111")
PAYLOAD = json.dumps({"chat_history": [{"role": "user", "content": "hi"}]}).encode()


class _FakeS3:
    """Enough of the boto3 S3 client to exercise the backend."""

    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}
        self.put_kwargs: list[dict] = []

    def put_object(self, **kwargs) -> dict:
        self.put_kwargs.append(kwargs)
        self.objects[kwargs["Key"]] = kwargs["Body"]
        return {}

    def get_object(self, *, Bucket: str, Key: str) -> dict:  # noqa: N803
        if Key not in self.objects:
            raise KeyError(Key)

        class _Body:
            def __init__(self, data: bytes) -> None:
                self._data = data

            def read(self) -> bytes:
                return self._data

        return {"Body": _Body(self.objects[Key])}


class TestFilesystem:
    def test_round_trip(self) -> None:
        async def scenario():
            with tempfile.TemporaryDirectory() as tmp:
                store = FilesystemTranscriptStore(root=tmp)
                ref, sha, size = await store.put(TENANT, PAYLOAD)
                return ref, sha, size, await store.get(ref)

        ref, sha, size, got = asyncio.run(scenario())
        assert got == PAYLOAD
        assert sha == transcript_sha256(PAYLOAD)
        assert size < len(PAYLOAD) or size > 0

    def test_is_content_addressed(self) -> None:
        # The same transcript stored twice is one blob, not two.
        async def scenario():
            with tempfile.TemporaryDirectory() as tmp:
                store = FilesystemTranscriptStore(root=tmp)
                first, _, _ = await store.put(TENANT, PAYLOAD)
                second, _, _ = await store.put(TENANT, PAYLOAD)
                blobs = list(Path(tmp).rglob("*.json.gz"))
                return first, second, blobs

        first, second, blobs = asyncio.run(scenario())
        assert first == second
        assert len(blobs) == 1

    def test_refuses_a_reference_that_escapes_the_root(self) -> None:
        async def scenario():
            with tempfile.TemporaryDirectory() as tmp:
                store = FilesystemTranscriptStore(root=tmp)
                await store.get("../../etc/passwd")

        with pytest.raises(ValueError):
            asyncio.run(scenario())

    def test_a_missing_transcript_raises(self) -> None:
        # Retention deletes transcripts; callers must see that, not empty bytes.
        async def scenario():
            with tempfile.TemporaryDirectory() as tmp:
                store = FilesystemTranscriptStore(root=tmp)
                await store.get(f"{TENANT}/aa/{'a' * 64}.json.gz")

        with pytest.raises(OSError):
            asyncio.run(scenario())


class TestS3:
    def test_round_trip(self) -> None:
        fake = _FakeS3()
        store = S3TranscriptStore(bucket="b", prefix="transcripts", client=fake)

        async def scenario():
            ref, sha, _ = await store.put(TENANT, PAYLOAD)
            return ref, sha, await store.get(ref)

        ref, sha, got = asyncio.run(scenario())
        assert got == PAYLOAD
        assert sha == transcript_sha256(PAYLOAD)

    def test_server_side_encryption_is_requested(self) -> None:
        # Contract: full_session transcripts must be encrypted at rest.
        fake = _FakeS3()
        store = S3TranscriptStore(bucket="b", client=fake, sse="AES256")
        asyncio.run(store.put(TENANT, PAYLOAD))
        assert fake.put_kwargs[0]["ServerSideEncryption"] == "AES256"

    def test_reference_layout_matches_the_filesystem_backend(self) -> None:
        # A ref must mean the same thing on both, so switching backends is a
        # copy rather than a rewrite of every ai_sessions row.
        fake = _FakeS3()
        s3 = S3TranscriptStore(bucket="b", prefix="p", client=fake)

        async def scenario():
            with tempfile.TemporaryDirectory() as tmp:
                fs_ref, _, _ = await FilesystemTranscriptStore(root=tmp).put(TENANT, PAYLOAD)
            s3_ref, _, _ = await s3.put(TENANT, PAYLOAD)
            return fs_ref, s3_ref

        fs_ref, s3_ref = asyncio.run(scenario())
        assert fs_ref.replace("\\", "/") == s3_ref

    def test_stores_compressed(self) -> None:
        fake = _FakeS3()
        store = S3TranscriptStore(bucket="b", client=fake)
        asyncio.run(store.put(TENANT, PAYLOAD))
        stored = next(iter(fake.objects.values()))
        assert gzip.decompress(stored) == PAYLOAD

    def test_a_bucketless_configuration_fails_immediately(self) -> None:
        with pytest.raises(RuntimeError, match="transcript_s3_bucket"):
            S3TranscriptStore(bucket=None, client=_FakeS3())

    def test_refuses_a_reference_that_escapes_the_prefix(self) -> None:
        store = S3TranscriptStore(bucket="b", client=_FakeS3())
        with pytest.raises(ValueError):
            asyncio.run(store.get("../secrets"))


class TestFactory:
    def test_builds_the_filesystem_backend_by_default(self) -> None:
        assert isinstance(build_transcript_store("filesystem"), FilesystemTranscriptStore)

    def test_an_unknown_backend_fails_loudly(self) -> None:
        # Silently falling back would put transcripts somewhere nobody expects.
        with pytest.raises(RuntimeError, match="Unknown transcript_store_backend"):
            build_transcript_store("nfs")
