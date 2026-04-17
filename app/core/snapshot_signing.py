from __future__ import annotations

import hashlib
import hmac
import json

from app.core.settings import settings


def sign_snapshot(snapshot: dict) -> tuple[str | None, str | None]:
    """Sign a guardrail snapshot dict with an engine-compatible HMAC.

    Returns ``(signature_hex, key_id)`` when a signing key is configured,
    or ``(None, None)`` when no key is present (unsigned operation).
    """
    use_snapshot_key = bool(settings.snapshot_signing_key)
    signing_key = settings.snapshot_signing_key or settings.ledger_signing_key
    if not signing_key:
        return None, None

    canonical = json.dumps(snapshot, separators=(",", ":"), sort_keys=True).encode("utf-8")
    key_bytes = signing_key.encode("utf-8")
    signature = hmac.new(key_bytes, canonical, hashlib.sha256).hexdigest()
    key_id = (
        settings.snapshot_signing_key_id
        if use_snapshot_key
        else settings.ledger_signing_key_id
    )
    return signature, key_id


def pack_snapshot_record(
    snapshot: dict,
    signature: str | None = None,
    key_id: str | None = None,
) -> str:
    """Serialize a snapshot and its optional signature into a JSON string for Redis storage."""
    record: dict = {"snapshot": snapshot}
    if signature:
        record["signature"] = signature
    if key_id:
        record["key_id"] = key_id
    return json.dumps(record, separators=(",", ":"), ensure_ascii=True)
