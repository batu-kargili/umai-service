from __future__ import annotations

import os
import unittest
from contextlib import contextmanager
from typing import Iterator

from app.core.library import get_guardrail_template
from app.core.runtime_validation import validate_service_runtime
from app.core.settings import settings
from app.models import admin as admin_models


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


@contextmanager
def patched_environ(**updates: str | None) -> Iterator[None]:
    original = {key: os.environ.get(key) for key in updates}
    try:
        for key, value in updates.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        yield
    finally:
        for key, value in original.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


class AgtSupportTests(unittest.TestCase):
    def test_agt_model_rejects_non_action_phase(self) -> None:
        with self.assertRaisesRegex(ValueError, "AGT v1 only supports"):
            admin_models.AgtConfig(
                enabled=True,
                mode="ENFORCE",
                enforced_phases=["PRE_LLM"],
                fail_closed=True,
                policy_document=admin_models.AgtPolicyDocument(
                    version="1",
                    default_action="ALLOW",
                    rules=[],
                ),
            )

    def test_regulated_telecom_guardrail_exposes_mixed_policy_stack(self) -> None:
        template = get_guardrail_template("gr-tr-regulated-telecom-sovereign-shield")
        self.assertIsNotNone(template)
        policy_types = {policy["type"] for policy in template["policies"]}
        self.assertEqual(policy_types, {"HEURISTIC", "CONTEXT_AWARE"})
        self.assertTrue(template["agt"]["enabled"])
        self.assertIn("PRE_LLM", template["phases"])
        self.assertIn("POST_LLM", template["phases"])
        self.assertIn("TOOL_INPUT", template["phases"])
        self.assertIn("TOOL_OUTPUT", template["phases"])
        self.assertIn("MCP_REQUEST", template["phases"])
        self.assertIn("MCP_RESPONSE", template["phases"])
        self.assertIn("MEMORY_WRITE", template["phases"])

    def test_production_runtime_requires_explicit_admin_auth_mode(self) -> None:
        with patched_environ(NODE_ENV="production"):
            with patched_settings(
                database_url="oracle+oracledb_async://umai_app:password@db-host:1521/?service_name=FREEPDB1",
                database_engine="oracle",
                ai_engine_base_url="http://engine:8000",
                redis_url="redis://redis:6379/0",
                snapshot_signing_key="secret-key",
                ledger_signing_key=None,
                admin_auth_mode=None,
                enforce_admin_jwt=False,
                admin_jwt_hs256_secret=None,
            ):
                with self.assertRaisesRegex(RuntimeError, "UMAI_ADMIN_AUTH_MODE"):
                    validate_service_runtime()


if __name__ == "__main__":
    unittest.main()
