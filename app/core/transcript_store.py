"""Storage for agent session transcripts.

Transcripts are too large for the database — a single Claude Code session on a
developer machine measured 1.3 MB, and a 300-seat fleet produces tens of
gigabytes. They live in a blob store; the database keeps metadata plus a
reference.

The filesystem backend is the v1 implementation. On-premise customers differ on
whether they want MinIO, their own S3-compatible endpoint, or a plain mount, so
the interface exists from the start and swapping the backend is one class.

Content is addressed by SHA-256, which makes writes idempotent: re-sending an
unchanged transcript resolves to the same reference and rewrites nothing.
"""

from __future__ import annotations

import asyncio
import gzip
import hashlib
import os
import tempfile
import uuid
from pathlib import Path
from typing import Any, Protocol

from app.core.settings import settings


def transcript_sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


class TranscriptStore(Protocol):
    """Blob storage for session transcripts."""

    async def put(self, tenant_id: uuid.UUID, payload: bytes) -> tuple[str, str, int]:
        """Store a transcript. Returns (ref, sha256, stored_bytes)."""

    async def get(self, ref: str) -> bytes:
        """Retrieve a transcript by reference."""


class FilesystemTranscriptStore:
    """Gzip-compressed, content-addressed transcripts on a local path or mount.

    Layout: ``{root}/{tenant_id}/{sha[:2]}/{sha}.json.gz``. The two-character
    fan-out keeps directory sizes manageable on filesystems that degrade with
    very wide directories.
    """

    def __init__(self, root: Path | str | None = None):
        configured = root or settings.transcript_store_path
        self.root = Path(configured).expanduser()

    def _path_for(self, tenant_id: uuid.UUID, sha: str) -> Path:
        return self.root / str(tenant_id) / sha[:2] / f"{sha}.json.gz"

    def _ref_for(self, tenant_id: uuid.UUID, sha: str) -> str:
        return f"{tenant_id}/{sha[:2]}/{sha}.json.gz"

    async def put(self, tenant_id: uuid.UUID, payload: bytes) -> tuple[str, str, int]:
        sha = transcript_sha256(payload)
        target = self._path_for(tenant_id, sha)
        ref = self._ref_for(tenant_id, sha)

        if target.exists():
            # Content-addressed: identical bytes are already stored.
            return ref, sha, target.stat().st_size

        target.parent.mkdir(parents=True, exist_ok=True)
        compressed = gzip.compress(payload)

        # Write to a temporary name and rename, so a crash mid-write cannot
        # leave a truncated blob behind a valid-looking reference.
        #
        # The temporary name is deliberately short and unrelated to the target:
        # derived names such as `<sha>.json.<pid>.tmp` are longer than the final
        # file, and on Windows that difference is enough to push a path that
        # otherwise fits past the 260-character MAX_PATH limit.
        handle, tmp_name = tempfile.mkstemp(prefix=".t", dir=target.parent)
        tmp = Path(tmp_name)
        try:
            with os.fdopen(handle, "wb") as f:
                f.write(compressed)
            os.replace(tmp, target)
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise

        return ref, sha, len(compressed)

    async def get(self, ref: str) -> bytes:
        path = self.root / ref
        # Reject references that escape the configured root.
        resolved = path.resolve()
        if not resolved.is_relative_to(self.root.resolve()):
            raise ValueError(f"Transcript reference escapes the store root: {ref}")
        return gzip.decompress(resolved.read_bytes())


class S3TranscriptStore:
    """Content-addressed transcripts in an S3-compatible bucket.

    Same layout as the filesystem backend — `{prefix}/{tenant}/{sha[:2]}/{sha}.json.gz`
    — so a reference means the same thing whichever backend produced it and a
    migration between them is a copy, not a rewrite.

    boto3 is imported lazily and is an optional dependency: most deployments
    run the filesystem backend on a mounted volume, and a 50 MB AWS SDK should
    not be mandatory for them. Configuring `s3` without it fails immediately
    and says what to install, rather than at the first transcript.
    """

    def __init__(
        self,
        *,
        bucket: str | None = None,
        prefix: str | None = None,
        endpoint_url: str | None = None,
        region: str | None = None,
        sse: str | None = None,
        client: Any | None = None,
    ) -> None:
        self.bucket = bucket or settings.transcript_s3_bucket
        if not self.bucket:
            raise RuntimeError(
                "transcript_store_backend=s3 requires transcript_s3_bucket"
            )
        self.prefix = (prefix if prefix is not None else settings.transcript_s3_prefix).strip("/")
        self.sse = sse if sse is not None else settings.transcript_s3_sse
        self._client = client
        self._endpoint_url = endpoint_url or settings.transcript_s3_endpoint_url
        self._region = region or settings.transcript_s3_region

    def _get_client(self) -> Any:
        if self._client is None:
            try:
                import boto3  # noqa: PLC0415 - optional dependency
            except ImportError as exc:  # pragma: no cover - depends on install
                raise RuntimeError(
                    "transcript_store_backend=s3 requires boto3. "
                    "Install it with: pip install boto3"
                ) from exc
            self._client = boto3.client(
                "s3", endpoint_url=self._endpoint_url, region_name=self._region
            )
        return self._client

    def _key_for(self, tenant_id: uuid.UUID, sha: str) -> str:
        parts = [p for p in (self.prefix, str(tenant_id), sha[:2], f"{sha}.json.gz") if p]
        return "/".join(parts)

    def _ref_for(self, tenant_id: uuid.UUID, sha: str) -> str:
        return f"{tenant_id}/{sha[:2]}/{sha}.json.gz"

    async def put(self, tenant_id: uuid.UUID, payload: bytes) -> tuple[str, str, int]:
        sha = transcript_sha256(payload)
        compressed = gzip.compress(payload)
        key = self._key_for(tenant_id, sha)
        client = self._get_client()

        extra: dict[str, Any] = {}
        if self.sse:
            extra["ServerSideEncryption"] = self.sse

        # Content-addressed: an object with this key already holds these bytes.
        await asyncio.to_thread(
            client.put_object, Bucket=self.bucket, Key=key, Body=compressed, **extra
        )
        return self._ref_for(tenant_id, sha), sha, len(compressed)

    async def get(self, ref: str) -> bytes:
        if ".." in ref or ref.startswith("/"):
            raise ValueError(f"Transcript reference escapes the store root: {ref}")
        key = "/".join(p for p in (self.prefix, ref) if p)
        client = self._get_client()
        response = await asyncio.to_thread(client.get_object, Bucket=self.bucket, Key=key)
        return gzip.decompress(response["Body"].read())


_store: TranscriptStore | None = None


def build_transcript_store(backend: str | None = None) -> TranscriptStore:
    """Construct the configured backend. Unknown names fail loudly."""
    name = (backend or settings.transcript_store_backend or "filesystem").strip().lower()
    if name == "filesystem":
        return FilesystemTranscriptStore()
    if name == "s3":
        return S3TranscriptStore()
    raise RuntimeError(
        f"Unknown transcript_store_backend: {name!r}. Expected 'filesystem' or 's3'."
    )


def get_transcript_store() -> TranscriptStore:
    global _store
    if _store is None:
        _store = build_transcript_store()
    return _store


def reset_transcript_store() -> None:
    """Drop the memoized store. For tests and config reloads."""
    global _store
    _store = None
