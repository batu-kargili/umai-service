from __future__ import annotations

import unittest
from contextlib import contextmanager
from typing import Iterator

from app.core.default_guardrail_llm import build_default_guardrail_llm_config
from app.core.runtime_validation import validate_database_configuration
from app.core.settings import settings


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


class RuntimeValidationTests(unittest.TestCase):
    def test_accepts_oracle_driver_when_engine_matches(self) -> None:
        with patched_settings(
            database_engine="oracle",
            database_url="oracle+oracledb_async://umai_app:password@db-host:1521/?service_name=FREEPDB1",
        ):
            engine, driver = validate_database_configuration()
        self.assertEqual(engine, "oracle")
        self.assertEqual(driver, "oracle+oracledb_async")

    def test_rejects_mysql_for_current_package(self) -> None:
        with patched_settings(
            database_engine="mysql",
            database_url="mysql+asyncmy://umai_app:password@db-host:3306/umai",
        ):
            with self.assertRaisesRegex(RuntimeError, "next package release"):
                validate_database_configuration()

    def test_build_default_guardrail_llm_config_supports_header_auth(self) -> None:
        with patched_settings(
            default_guardrail_llm_provider="AZURE_OPENAI",
            default_guardrail_llm_base_url="https://llm.internal/openai/v1",
            default_guardrail_llm_model="gpt-4o-mini",
            default_guardrail_llm_timeout_ms=1500,
            default_guardrail_llm_auth_type="header",
            default_guardrail_llm_auth_secret_env="AZURE_OPENAI_API_KEY",
            default_guardrail_llm_auth_header_name="api-key",
        ):
            config = build_default_guardrail_llm_config()
        self.assertEqual(config["provider"], "AZURE_OPENAI")
        self.assertEqual(config["auth"]["type"], "header")
        self.assertEqual(config["auth"]["secret_env"], "AZURE_OPENAI_API_KEY")
        self.assertEqual(config["auth"]["header_name"], "api-key")


if __name__ == "__main__":
    unittest.main()
