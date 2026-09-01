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
import base64
import binascii
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


# Written at the head of every encrypted blob. Its purpose is to make the two
# formats tell themselves apart: turning encryption on must not orphan the
# transcripts already on disk, and turning it off must not hide them.
# The trailing NUL keeps it from colliding with the start of any plausible
# gzip or JSON payload.
_ENVELOPE_MAGIC = b"UMAI1\x00"
_NONCE_BYTES = 12


class TranscriptDecryptionError(RuntimeError):
    """A blob is encrypted and the configured key cannot open it.

    Distinct from a missing blob: the evidence is there and the deployment is
    misconfigured. Treating it as "expired" would quietly lose evidence.
    """


def _decode_key(configured: str, name: str) -> bytes:
    try:
        key = base64.b64decode(configured, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise RuntimeError(
            f"{name} must be base64. "
            "Generate one with: python -c \"import os,base64;"
            "print(base64.b64encode(os.urandom(32)).decode())\""
        ) from exc
    if len(key) != 32:
        raise RuntimeError(f"{name} must decode to 32 bytes, got {len(key)}.")
    return key


def _encryption_key() -> bytes | None:
    """The key new transcripts are sealed with, or None when encryption is off.

    Only ever the current key. A rotation must not start writing blobs the operator
    is about to stop accepting.
    """
    configured = (settings.transcript_encryption_key or "").strip()
    if not configured:
        return None
    return _decode_key(configured, "UMAI_TRANSCRIPT_ENCRYPTION_KEY")


def _decryption_keys() -> list[bytes]:
    """Keys that may open a sealed blob, current first (UMA-84).

    During a rotation the previous key is still the only thing that can read
    transcripts already on disk. Accepting it here is what makes rotating the
    transcript key survivable: without it, rotation is permanent evidence loss.
    """
    keys: list[bytes] = []
    current = (settings.transcript_encryption_key or "").strip()
    if current:
        keys.append(_decode_key(current, "UMAI_TRANSCRIPT_ENCRYPTION_KEY"))
    previous = (settings.transcript_encryption_key_previous or "").strip()
    if previous:
        candidate = _decode_key(previous, "UMAI_TRANSCRIPT_ENCRYPTION_KEY_PREVIOUS")
        if candidate not in keys:
            keys.append(candidate)
    return keys


def seal(payload: bytes) -> bytes:
    """Encrypt if a key is configured, otherwise pass the bytes through."""
    key = _encryption_key()
    if key is None:
        return payload
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: PLC0415

    nonce = os.urandom(_NONCE_BYTES)
    return _ENVELOPE_MAGIC + nonce + AESGCM(key).encrypt(nonce, payload, None)


def unseal(blob: bytes) -> bytes:
    """Decrypt a sealed blob; return an unsealed one unchanged.

    Reading is driven by what is on disk, not by what is configured. A blob
    written before encryption was enabled stays readable, and a key that is
    removed while encrypted blobs exist produces a clear error rather than
    garbage.
    """
    if not blob.startswith(_ENVELOPE_MAGIC):
        return blob

    keys = _decryption_keys()
    if not keys:
        raise TranscriptDecryptionError(
            "This transcript is encrypted but UMAI_TRANSCRIPT_ENCRYPTION_KEY is not set."
        )

    from cryptography.exceptions import InvalidTag  # noqa: PLC0415
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: PLC0415

    header = len(_ENVELOPE_MAGIC)
    nonce = blob[header : header + _NONCE_BYTES]
    ciphertext = blob[header + _NONCE_BYTES :]
    for key in keys:
        try:
            return AESGCM(key).decrypt(nonce, ciphertext, None)
        except InvalidTag:
            continue
    raise TranscriptDecryptionError(
        "This transcript could not be decrypted with the configured key, or with "
        "UMAI_TRANSCRIPT_ENCRYPTION_KEY_PREVIOUS if one is set. It was written with "
        "a different key."
    )


def needs_resealing(blob: bytes) -> bool:
    """Whether this blob is sealed with something other than the current key.

    Used by the rotation runbook: a rotation is only finished once nothing needs
    resealing, because only then can the previous key be cleared.
    """
    if not blob.startswith(_ENVELOPE_MAGIC):
        # Unencrypted. It needs sealing if encryption is now configured.
        return _encryption_key() is not None

    current = _encryption_key()
    if current is None:
        return False

    from cryptography.exceptions import InvalidTag  # noqa: PLC0415
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: PLC0415

    header = len(_ENVELOPE_MAGIC)
    nonce = blob[header : header + _NONCE_BYTES]
    try:
        AESGCM(current).decrypt(nonce, blob[header + _NONCE_BYTES :], None)
    except InvalidTag:
        return True
    return False


class TranscriptStore(Protocol):
    """Blob storage for session transcripts."""

    async def put(self, tenant_id: uuid.UUID, payload: bytes) -> tuple[str, str, int]:
        """Store a transcript. Returns (ref, sha256, stored_bytes)."""

    async def get(self, ref: str) -> bytes:
        """Retrieve a transcript by reference."""

    async def delete(self, ref: str) -> bool:
        """Remove a transcript. Returns whether anything was there to remove."""


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
        # Compress first, then encrypt: ciphertext does not compress.
        compressed = seal(gzip.compress(payload))

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
        resolved = self._resolve(ref)
        return gzip.decompress(unseal(resolved.read_bytes()))

    def _resolve(self, ref: str) -> Path:
        """Reject references that escape the configured root."""
        resolved = (self.root / ref).resolve()
        if not resolved.is_relative_to(self.root.resolve()):
            raise ValueError(f"Transcript reference escapes the store root: {ref}")
        return resolved

    async def delete(self, ref: str) -> bool:
        resolved = self._resolve(ref)
        try:
            resolved.unlink()
        except FileNotFoundError:
            # Already gone. Retention has to be safe to re-run.
            return False
        return True


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
        # Bucket-side SSE is the primary control here; the envelope adds
        # encryption the bucket operator cannot read, when a key is configured.
        compressed = seal(gzip.compress(payload))
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
        key = self._object_key(ref)
        client = self._get_client()
        response = await asyncio.to_thread(client.get_object, Bucket=self.bucket, Key=key)
        return gzip.decompress(unseal(response["Body"].read()))

    async def delete(self, ref: str) -> bool:
        key = self._object_key(ref)
        client = self._get_client()
        # S3 delete_object is idempotent and does not report whether the key
        # existed, so this reports success for an already-absent object too.
        await asyncio.to_thread(client.delete_object, Bucket=self.bucket, Key=key)
        return True

    def _object_key(self, ref: str) -> str:
        if ".." in ref or ref.startswith("/"):
            raise ValueError(f"Transcript reference escapes the store root: {ref}")
        return "/".join(p for p in (self.prefix, ref) if p)


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
