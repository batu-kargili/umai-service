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

import gzip
import hashlib
import os
import tempfile
import uuid
from pathlib import Path
from typing import Protocol

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


_store: TranscriptStore | None = None


def get_transcript_store() -> TranscriptStore:
    global _store
    if _store is None:
        _store = FilesystemTranscriptStore()
    return _store
