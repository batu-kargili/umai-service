from __future__ import annotations

from typing import Any

from pydantic_settings import BaseSettings, PydanticBaseSettingsSource, SettingsConfigDict
from pydantic_settings.sources import EnvSettingsSource

from app.core.env import load_env

load_env()


class _CsvFriendlyEnvSource(EnvSettingsSource):
    """EnvSettingsSource that accepts comma-separated strings for list fields."""

    def prepare_field_value(
        self,
        field_name: str,
        field: Any,
        value: Any,
        value_is_complex: bool,
    ) -> Any:
        # Allow comma-separated strings for list fields (e.g. UMAI_CORS_ALLOW_ORIGINS)
        if (
            value_is_complex
            and isinstance(value, str)
            and not value.strip().startswith(("[", "{"))
        ):
            return [v.strip() for v in value.split(",") if v.strip()]
        return super().prepare_field_value(field_name, field, value, value_is_complex)


class Settings(BaseSettings):
    service_name: str = "umai-service"
    log_level: str = "INFO"
    log_request_payloads: bool = False
    store_request_payloads: bool = False
    audit_redaction_enabled: bool = True
    audit_redaction_patterns_json: str | None = None
    ledger_signing_key: str | None = None
    ledger_signing_key_id: str = "default"
    snapshot_signing_key: str | None = None
    snapshot_signing_key_id: str = "default"
    audit_default_retention_days: int | None = None
    free_license_days: int = 365
    free_plan_tier: str = "free"
    free_allow_llm_calls: bool = True
    free_max_projects: int = 1
    free_environment_id: str = "env-free"
    free_environment_name: str = "Free"
    free_project_id: str = "proj-default"
    free_project_name: str = "Default"
    database_engine: str | None = None
    database_url: str | None = None
    database_pool_size: int = 5
    database_max_overflow: int = 10
    database_connect_timeout_seconds: float | None = None
    redis_url: str | None = None
    require_redis: bool = False
    default_guardrail_llm_provider: str = "OPENROUTER"
    default_guardrail_llm_base_url: str = "https://openrouter.ai/api/v1"
    default_guardrail_llm_model: str = "openai/gpt-oss-safeguard-20b"
    default_guardrail_llm_timeout_ms: int = 2000
    default_guardrail_llm_auth_type: str = "bearer"
    default_guardrail_llm_auth_secret_env: str | None = "OPENROUTER_API_KEY"
    default_guardrail_llm_auth_header_name: str | None = None
    ai_engine_base_url: str | None = None
    cors_allow_origins: list[str] = ["http://localhost:3000"]
    openai_api_key: str | None = None
    openai_model: str = "gpt-4o-mini"
    openai_base_url: str = "https://api.openai.com/v1"
    openai_timeout_seconds: float = 25.0
    publish_gate_min_expected_action_accuracy: float | None = 0.7
    publish_gate_min_expected_allowed_accuracy: float | None = None
    publish_gate_min_eval_cases: int = 10
    publish_gate_max_p95_latency_ms: float | None = None
    publish_gate_require_bypass_reason: bool = True
    siem_endpoints_json: str | None = None
    siem_max_retries: int = 3
    siem_timeout_seconds: float = 3.0
    async_job_webhook_timeout_seconds: float = 5.0
    admin_jwt_hs256_secret: str | None = None
    enforce_admin_jwt: bool = False
    admin_auth_mode: str | None = None
    extension_ingest_bearer_token: str | None = None
    extension_ingest_jwt_hs256_secret: str | None = None
    extension_device_token_ttl_seconds: int = 60 * 60 * 24 * 30
    extension_policy_json: str | None = None
    extension_bootstrap_public_key_pem: str | None = None

    model_config = SettingsConfigDict(env_prefix="UMAI_", case_sensitive=False)

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        del env_settings
        sources = (
            init_settings,
            _CsvFriendlyEnvSource(settings_cls, env_prefix="UMAI_", case_sensitive=False),
            dotenv_settings,
            file_secret_settings,
        )
        return tuple(source for source in sources if source is not None)


settings = Settings()
