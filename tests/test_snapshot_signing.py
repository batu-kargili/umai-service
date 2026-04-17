from __future__ import annotations

import unittest
from contextlib import contextmanager
from typing import Iterator

from app.core.settings import settings
from app.core.snapshot_signing import sign_snapshot


@contextmanager
def patched_settings(**overrides: object) -> Iterator[None]:
    original = {name: getattr(settings, name) for name in overrides}
    try:
        for name, value in overrides.items():
            setattr(settings, name, value)
        yield
    finally:
        for name, value in original.items():
            setattr(settings, name, value)


class SnapshotSigningTests(unittest.TestCase):
    def test_sign_snapshot_uses_engine_compatible_hex_hmac(self) -> None:
        snapshot = {"guardrail_id": "gr-1", "version": 2}
        with patched_settings(
            snapshot_signing_key="secret-key",
            snapshot_signing_key_id="snapshot-v1",
            ledger_signing_key=None,
        ):
            signature, key_id = sign_snapshot(snapshot)
        self.assertRegex(signature or "", r"^[0-9a-f]{64}$")
        self.assertEqual(key_id, "snapshot-v1")

    def test_sign_snapshot_falls_back_to_legacy_ledger_key(self) -> None:
        snapshot = {"guardrail_id": "gr-1", "version": 2}
        with patched_settings(
            snapshot_signing_key=None,
            ledger_signing_key="legacy-secret",
            ledger_signing_key_id="legacy",
        ):
            signature, key_id = sign_snapshot(snapshot)
        self.assertRegex(signature or "", r"^[0-9a-f]{64}$")
        self.assertEqual(key_id, "legacy")


if __name__ == "__main__":
    unittest.main()
