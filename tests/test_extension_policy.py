from __future__ import annotations

import copy
import json
import os
import unittest
from contextlib import contextmanager
from typing import Any, Iterator
from unittest import mock

from app.api.extension import DEFAULT_POLICY_PACK, _load_policy_pack
from app.core.extension_policy import ExtensionPolicyError, parse_extension_policy_pack
from app.core.runtime_validation import validate_service_runtime
from app.core.settings import settings

# The Smarttech starter pack from docs/development-plan-smarttech-go-live.md.
VALID_PACK: dict[str, Any] = {
    "version": "smarttech-2026-10",
    "default_action": "allow",
    "rules": [
        {
            "id": "block_secrets",
            "enabled": True,
            "match": {"dlp_tags_any": ["SECRET_TOKEN", "SECRET_PRIVATE_KEY"]},
            "action": {"type": "block"},
            "message": "Secret detected.",
        },
        {
            "id": "redact_fin",
            "enabled": True,
            "match": {"dlp_tags_any": ["PII_CREDITCARD", "PII_IBAN_TR"]},
            "action": {"type": "redact", "strategy": "mask"},
        },
        {
            "id": "justify_pii",
            "enabled": False,
            "match": {"dlp_tags_any": ["PII_EMAIL"]},
            "action": {"type": "justify", "min_chars": 12},
        },
    ],
}

_PRODUCTION_ENV = {
    "UMAI_ENVIRONMENT": "production",
    "UMAI_LICENSE_TOKEN": "fake-token",
    "UMAI_LICENSE_PUBLIC_KEY": "fake-key",
}

_PRODUCTION_SETTINGS = dict(
    database_url="postgresql+asyncpg://u:p@db/u",
    database_engine="postgresql",
    ai_engine_base_url="http://umai-engine:9000",
    cors_allow_origins=["https://app.example.com"],
    extension_ingest_jwt_hs256_secret="ext-secret",
    adr_ingest_jwt_hs256_secret="adr-secret",
    admin_auth_mode="jwt",
    admin_jwt_hs256_secret="admin-secret",
    redis_url="redis://redis:6379/0",
    snapshot_signing_key="snapshot-key",
)


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


def _pack_with(mutate) -> str:
    pack = copy.deepcopy(VALID_PACK)
    mutate(pack)
    return json.dumps(pack)


class ParseExtensionPolicyPackTests(unittest.TestCase):
    def test_accepts_valid_pack(self) -> None:
        self.assertEqual(parse_extension_policy_pack(json.dumps(VALID_PACK)), VALID_PACK)

    def test_accepts_empty_rule_list(self) -> None:
        raw = json.dumps({"version": "v1", "default_action": "block", "rules": []})
        self.assertEqual(parse_extension_policy_pack(raw)["default_action"], "block")

    def test_rejections(self) -> None:
        cases = {
            "not json": "{not json",
            "not an object": "[]",
            "missing version": _pack_with(lambda p: p.pop("version")),
            "blank version": _pack_with(lambda p: p.update(version="  ")),
            "unknown default action": _pack_with(lambda p: p.update(default_action="deny")),
            "rules not a list": _pack_with(lambda p: p.update(rules={})),
            "rule not an object": _pack_with(lambda p: p["rules"].append("x")),
            "missing rule id": _pack_with(lambda p: p["rules"][0].pop("id")),
            "duplicate rule id": _pack_with(lambda p: p["rules"][1].update(id="block_secrets")),
            # The extension skips rules whose `enabled` is falsy, so a missing
            # flag would silently disable the rule.
            "missing enabled": _pack_with(lambda p: p["rules"][0].pop("enabled")),
            "enabled as string": _pack_with(lambda p: p["rules"][0].update(enabled="true")),
            "missing match": _pack_with(lambda p: p["rules"][0].pop("match")),
            "empty tag list": _pack_with(lambda p: p["rules"][0].update(match={"dlp_tags_any": []})),
            "non-string tag": _pack_with(lambda p: p["rules"][0].update(match={"dlp_tags_any": [1]})),
            "unknown action": _pack_with(lambda p: p["rules"][0].update(action={"type": "deny"})),
            "missing action": _pack_with(lambda p: p["rules"][0].pop("action")),
        }
        for name, raw in cases.items():
            with self.subTest(name):
                with self.assertRaises(ExtensionPolicyError):
                    parse_extension_policy_pack(raw)


class LoadPolicyPackTests(unittest.TestCase):
    def test_unset_serves_default_pack(self) -> None:
        with patched_settings(extension_policy_json=None):
            self.assertEqual(_load_policy_pack(), DEFAULT_POLICY_PACK)

    def test_valid_pack_is_served(self) -> None:
        with patched_settings(extension_policy_json=json.dumps(VALID_PACK)):
            self.assertEqual(_load_policy_pack()["version"], "smarttech-2026-10")

    def test_invalid_pack_falls_back_in_development(self) -> None:
        with patched_settings(extension_policy_json='{"version": "v1"}'):
            with self.assertLogs("umai.service.extension", level="WARNING"):
                self.assertEqual(_load_policy_pack(), DEFAULT_POLICY_PACK)


class RuntimeValidationPolicyTests(unittest.TestCase):
    def test_production_refuses_invalid_pack(self) -> None:
        with mock.patch.dict(os.environ, _PRODUCTION_ENV, clear=False):
            with patched_settings(**_PRODUCTION_SETTINGS, extension_policy_json="{broken"):
                with self.assertRaisesRegex(RuntimeError, "UMAI_EXTENSION_POLICY_JSON"):
                    validate_service_runtime()

    def test_production_accepts_valid_pack(self) -> None:
        with mock.patch.dict(os.environ, _PRODUCTION_ENV, clear=False):
            with patched_settings(
                **_PRODUCTION_SETTINGS, extension_policy_json=json.dumps(VALID_PACK)
            ):
                validate_service_runtime()

    def test_development_only_warns(self) -> None:
        with mock.patch.dict(os.environ, {"UMAI_ENVIRONMENT": "development"}, clear=False):
            with patched_settings(extension_policy_json="{broken"):
                with self.assertLogs("umai.service.runtime", level="WARNING") as logs:
                    validate_service_runtime()
        self.assertTrue(any("UMAI_EXTENSION_POLICY_JSON" in line for line in logs.output))


if __name__ == "__main__":
    unittest.main()
