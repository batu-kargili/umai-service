from __future__ import annotations

import asyncio
import json
import unittest
import uuid
from contextlib import contextmanager
from typing import Iterator

from app.api import admin
from app.core.settings import settings
from app.models.db import GuardrailVersion


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


class FakeRedis:
    def __init__(self) -> None:
        self.values: dict[str, str] = {}

    async def set(self, key: str, value: str) -> None:
        self.values[key] = value


class AdminSnapshotSyncTests(unittest.TestCase):
    def test_sync_engine_snapshot_signs_and_writes_engine_key(self) -> None:
        tenant_id = uuid.UUID("11111111-1111-1111-1111-111111111111")
        snapshot = {
            "guardrail_id": "gr-test",
            "version": 7,
            "mode": "ENFORCE",
            "phases": ["PRE_LLM"],
            "preflight": {"target": "LAST_MESSAGE", "rules": [], "max_length": 8000},
            "policies": [],
            "llm_config": {
                "provider": "test",
                "base_url": "http://llm.example.test",
                "model": "test-model",
            },
        }
        version_row = GuardrailVersion(
            tenant_id=tenant_id,
            environment_id="dev",
            project_id="proj",
            guardrail_id="gr-test",
            version=7,
            snapshot_json=json.dumps(snapshot, separators=(",", ":"), ensure_ascii=True),
            signature=None,
            key_id=None,
            created_by="tester",
        )
        fake_redis = FakeRedis()
        original_get_redis = admin.get_redis
        admin.get_redis = lambda: fake_redis  # type: ignore[assignment]
        try:
            with patched_settings(
                snapshot_signing_key="snapshot-secret",
                snapshot_signing_key_id="snapshot-v1",
                ledger_signing_key=None,
            ):
                redis_key = asyncio.run(admin._sync_engine_snapshot(version_row))
        finally:
            admin.get_redis = original_get_redis  # type: ignore[assignment]

        self.assertEqual(
            redis_key,
            "guardrail:11111111-1111-1111-1111-111111111111:dev:proj:gr-test:7",
        )
        self.assertIn(redis_key, fake_redis.values)
        record = json.loads(fake_redis.values[redis_key])
        self.assertEqual(record["snapshot"], snapshot)
        self.assertRegex(record["signature"], r"^[0-9a-f]{64}$")
        self.assertEqual(record["key_id"], "snapshot-v1")
        self.assertEqual(version_row.signature, record["signature"])
        self.assertEqual(version_row.key_id, "snapshot-v1")


if __name__ == "__main__":
    unittest.main()
