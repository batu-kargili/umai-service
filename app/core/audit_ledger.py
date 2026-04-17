from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from typing import Any


# ── Default PII redaction patterns ──────────────────────────────────────────

_DEFAULT_PATTERNS: list[tuple[re.Pattern, str]] = [
    # E-mail addresses
    (re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"), "[EMAIL]"),
    # Credit card numbers (simple 13-19 digit pattern)
    (re.compile(r"\b(?:\d[ -]?){13,19}\b"), "[CARD]"),
    # US SSN
    (re.compile(r"\b\d{3}[-\s]\d{2}[-\s]\d{4}\b"), "[SSN]"),
    # Phone numbers (E.164 / common formats)
    (re.compile(r"\+?1?\s?[-.]?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b"), "[PHONE]"),
]


def _build_custom_patterns(custom_patterns_json: str | None) -> list[tuple[re.Pattern, str]]:
    if not custom_patterns_json:
        return []
    try:
        items = json.loads(custom_patterns_json)
    except json.JSONDecodeError:
        return []
    patterns = []
    for item in items:
        if not isinstance(item, dict):
            continue
        pattern_str = item.get("pattern")
        replacement = item.get("replacement", "[REDACTED]")
        if pattern_str:
            try:
                patterns.append((re.compile(pattern_str), str(replacement)))
            except re.error:
                pass
    return patterns


def _apply_patterns(text: str, patterns: list[tuple[re.Pattern, str]]) -> tuple[str, bool]:
    changed = False
    for pattern, replacement in patterns:
        new_text, n = pattern.subn(replacement, text)
        if n > 0:
            text = new_text
            changed = True
    return text, changed


def redact_text(
    text: str | None,
    custom_patterns_json: str | None = None,
) -> tuple[str | None, bool]:
    """Redact PII from a plain text string.  Returns ``(redacted_text, was_changed)``."""
    if not text:
        return text, False
    all_patterns = _DEFAULT_PATTERNS + _build_custom_patterns(custom_patterns_json)
    return _apply_patterns(text, all_patterns)


def _redact_value(value: Any, patterns: list[tuple[re.Pattern, str]]) -> tuple[Any, bool]:
    if isinstance(value, str):
        return _apply_patterns(value, patterns)
    if isinstance(value, dict):
        return _redact_dict(value, patterns)
    if isinstance(value, list):
        return _redact_list(value, patterns)
    return value, False


def _redact_dict(obj: dict, patterns: list[tuple[re.Pattern, str]]) -> tuple[dict, bool]:
    changed = False
    result = {}
    for k, v in obj.items():
        new_v, c = _redact_value(v, patterns)
        result[k] = new_v
        changed = changed or c
    return result, changed


def _redact_list(items: list, patterns: list[tuple[re.Pattern, str]]) -> tuple[list, bool]:
    changed = False
    result = []
    for item in items:
        new_item, c = _redact_value(item, patterns)
        result.append(new_item)
        changed = changed or c
    return result, changed


def redact_payload(
    payload: dict,
    custom_patterns_json: str | None = None,
) -> tuple[dict, bool]:
    """Recursively redact PII from a JSON-serialisable dict.
    Returns ``(redacted_payload, was_changed)``."""
    all_patterns = _DEFAULT_PATTERNS + _build_custom_patterns(custom_patterns_json)
    result, changed = _redact_dict(payload, all_patterns)
    return result, changed


# ── Ledger hash / signing ────────────────────────────────────────────────────

def compute_event_hash(
    prev_event_hash: str | None,
    ledger_payload: dict,
) -> str:
    """Compute a SHA-256 hash chaining the previous event hash with the current payload."""
    canonical = json.dumps(
        {
            "prev": prev_event_hash or "",
            "payload": ledger_payload,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def sign_event_hash(
    event_hash: str,
    signing_key: str | None,
    key_id: str = "default",
) -> tuple[str | None, str | None]:
    """HMAC-sign an event hash string.  Returns ``(signature_b64url, key_id)`` or
    ``(None, None)`` when no signing key is configured."""
    if not signing_key:
        return None, None
    key_bytes = signing_key.encode("utf-8")
    sig_bytes = hmac.new(key_bytes, event_hash.encode("utf-8"), hashlib.sha256).digest()
    signature = base64.urlsafe_b64encode(sig_bytes).decode("ascii").rstrip("=")
    return signature, key_id
