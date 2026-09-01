from __future__ import annotations

import os
import unittest
from contextlib import contextmanager
from typing import Iterator
from unittest import mock

from app.core.default_guardrail_llm import build_default_guardrail_llm_config
from app.core.runtime_validation import (
    _assert_production_required,
    validate_database_configuration,
)
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


_PRODUCTION_OK_ENV = {
    "UMAI_LICENSE_TOKEN": "fake-token",
    "UMAI_LICENSE_PUBLIC_KEY": "fake-key",
    "UMAI_LICENSE_PUBLIC_KEYS": "",
}

_PRODUCTION_OK_SETTINGS = dict(
    database_url="postgresql+asyncpg://u:p@db/u",
    ai_engine_base_url="http://umai-engine:9000",
    cors_allow_origins=["https://app.example.com"],
    extension_ingest_jwt_hs256_secret="ext-secret",
    adr_ingest_jwt_hs256_secret="adr-secret",
)


def _run_assert(env_overrides: dict[str, str] | None = None) -> None:
    env = dict(_PRODUCTION_OK_ENV)
    if env_overrides:
        env.update(env_overrides)
    with mock.patch.dict(os.environ, env, clear=False):
        _assert_production_required(production=True)


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


class ProductionRequiredTests(unittest.TestCase):
    def test_non_production_skips_all_checks(self) -> None:
        with patched_settings(**{**_PRODUCTION_OK_SETTINGS, "database_url": None}):
            # Missing DB does not raise outside production.
            _assert_production_required(production=False)

    def test_passes_with_all_required_set(self) -> None:
        with patched_settings(**_PRODUCTION_OK_SETTINGS):
            _run_assert()

    def test_missing_database_url_raises(self) -> None:
        with patched_settings(**{**_PRODUCTION_OK_SETTINGS, "database_url": None}):
            with self.assertRaisesRegex(RuntimeError, "UMAI_DATABASE_URL"):
                _run_assert()

    def test_missing_ai_engine_url_raises(self) -> None:
        with patched_settings(**{**_PRODUCTION_OK_SETTINGS, "ai_engine_base_url": None}):
            with self.assertRaisesRegex(RuntimeError, "UMAI_AI_ENGINE_BASE_URL"):
                _run_assert()

    def test_missing_license_token_raises(self) -> None:
        with patched_settings(**_PRODUCTION_OK_SETTINGS):
            with self.assertRaisesRegex(RuntimeError, "UMAI_LICENSE_TOKEN"):
                _run_assert({"UMAI_LICENSE_TOKEN": ""})

    def test_missing_license_public_key_raises(self) -> None:
        with patched_settings(**_PRODUCTION_OK_SETTINGS):
            with self.assertRaisesRegex(RuntimeError, "UMAI_LICENSE_PUBLIC_KEY"):
                _run_assert({"UMAI_LICENSE_PUBLIC_KEY": ""})

    def test_public_keys_alternative_accepted(self) -> None:
        with patched_settings(**_PRODUCTION_OK_SETTINGS):
            _run_assert({"UMAI_LICENSE_PUBLIC_KEY": "", "UMAI_LICENSE_PUBLIC_KEYS": "k"})

    def test_localhost_in_cors_raises(self) -> None:
        with patched_settings(
            **{
                **_PRODUCTION_OK_SETTINGS,
                "cors_allow_origins": ["https://app.example.com", "http://localhost:3000"],
            }
        ):
            with self.assertRaisesRegex(RuntimeError, "localhost"):
                _run_assert()

    def test_loopback_ip_in_cors_raises(self) -> None:
        with patched_settings(
            **{
                **_PRODUCTION_OK_SETTINGS,
                "cors_allow_origins": ["http://127.0.0.1:3000"],
            }
        ):
            with self.assertRaisesRegex(RuntimeError, "127.0.0.1"):
                _run_assert()

    def test_missing_extension_ingest_jwt_secret_raises(self) -> None:
        with patched_settings(
            **{**_PRODUCTION_OK_SETTINGS, "extension_ingest_jwt_hs256_secret": None}
        ):
            with self.assertRaisesRegex(
                RuntimeError, "UMAI_EXTENSION_INGEST_JWT_HS256_SECRET"
            ):
                _run_assert()

    def test_missing_adr_ingest_jwt_secret_raises(self) -> None:
        with patched_settings(
            **{**_PRODUCTION_OK_SETTINGS, "adr_ingest_jwt_hs256_secret": None}
        ):
            with self.assertRaisesRegex(
                RuntimeError, "UMAI_ADR_INGEST_JWT_HS256_SECRET"
            ):
                _run_assert()


if __name__ == "__main__":
    unittest.main()
