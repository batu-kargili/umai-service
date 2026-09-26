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
    # Eval gate on POST /guardrails/{id}/publish/{version} (go-live decision D4):
    # a version needs a COMPLETED evaluation run that meets the thresholds above,
    # or an explicit bypass with a reason. False turns the gate off everywhere.
    publish_gate_enforced: bool = True
    # Library-template deploys and the auto-published first version are exempt by
    # default (there can be no eval run before the guardrail exists). True applies
    # the gate to them too: a library deploy with publish=true is rejected and the
    # first version is created as an unpublished draft.
    publish_gate_enforce_on_library_deploy: bool = False
    evaluation_timeout_ms: int = 10000
    siem_endpoints_json: str | None = None
    siem_max_retries: int = 3
    siem_timeout_seconds: float = 3.0
    # Outbox drain. Off by default so an operator opts in deliberately;
    # enqueueing happens regardless, so nothing is lost while it is off.
    siem_drain_enabled: bool = False
    siem_drain_interval_seconds: float = 5.0
    # How long a *delivered* outbox row is kept (UMA-93). A delivered row is a receipt:
    # the finding itself lives in `findings`, so keeping the copy forever grew the
    # fastest-growing table the platform owns for no recoverable value. Pending and
    # dead-letter rows are never pruned — a dead letter is a finding the SOC has not
    # seen. Set to 0 to keep everything, which is the pre-UMA-93 behaviour.
    siem_outbox_retention_days: int = 7
    siem_outbox_prune_interval_seconds: float = 60 * 60
    async_job_webhook_timeout_seconds: float = 5.0
    # Request limits (UMA-83). The rate and concurrency numbers are PER WORKER
    # PROCESS: there is no shared counter, so a deployment running N workers admits
    # N times the configured rate. Fleet capacity is workers x limit.
    request_limits_enabled: bool = True
    # Metrics cardinality caps (UMA-86). A label fed from request data grows one
    # time series per distinct value; past the cap further values report as 'other'.
    metrics_route_cardinality_cap: int = 200
    # Analysis queue gauges (UMA-87). Sampled by a background loop rather than on
    # scrape: a scrape must not fail because the database is slow, which is exactly
    # when the metrics matter most.
    analysis_metrics_enabled: bool = True
    analysis_metrics_interval_seconds: float = 30.0
    # Tenant is off by default: it would multiply every histogram's series count.
    metrics_tenant_label_enabled: bool = False
    metrics_tenant_cardinality_cap: int = 50
    # Collector and extension upload. High rate, large bodies: a fleet uploads often.
    rate_limit_ingest_per_minute: int = 600
    max_body_bytes_ingest: int = 32 * 1024 * 1024
    max_concurrent_ingest: int = 32
    # Enrolment issues credentials, so it is the tightest surface by a wide margin.
    rate_limit_bootstrap_per_minute: int = 30
    max_concurrent_bootstrap: int = 8
    rate_limit_admin_per_minute: int = 600
    max_concurrent_admin: int = 64
    # The analysis worker polls, so its rate is higher than an operator's.
    rate_limit_worker_per_minute: int = 1200
    max_concurrent_worker: int = 32
    rate_limit_public_per_minute: int = 1200
    max_concurrent_public: int = 64
    max_body_bytes_default: int = 1 * 1024 * 1024
    admin_jwt_hs256_secret: str | None = None
    # Rotation overlap (UMA-84). While a _previous value is set, credentials signed
    # with it still verify, but nothing new is ever minted or sealed with it.
    # Clearing the _previous value is what completes a rotation.
    admin_jwt_hs256_secret_previous: str | None = None
    # Optional. When set, an admin JWT must carry exactly this audience. Left unset,
    # the service only refuses audiences it knows belong to another surface.
    admin_jwt_audience: str | None = None
    enforce_admin_jwt: bool = False
    admin_auth_mode: str | None = None
    extension_ingest_bearer_token: str | None = None
    extension_ingest_jwt_hs256_secret: str | None = None
    extension_ingest_jwt_hs256_secret_previous: str | None = None
    extension_device_token_ttl_seconds: int = 60 * 60 * 24 * 30
    # Ceiling on an enrollment (bootstrap) token's lifetime, enforced both when one
    # is minted and on the `exp - iat` of every token presented. It is the default
    # lifetime too: a managed-policy token is normally rotated weekly.
    extension_bootstrap_token_max_ttl_seconds: int = 60 * 60 * 24 * 7
    extension_policy_json: str | None = None
    extension_bootstrap_public_key_pem: str | None = None
    # ADR Collector authentication and fleet freshness.
    adr_ingest_jwt_hs256_secret: str | None = None
    adr_ingest_jwt_hs256_secret_previous: str | None = None
    adr_device_token_ttl_seconds: int = 60 * 60 * 24
    # Three missed runs of the collector's scheduled task. The shipped Windows
    # installer registers a 15-minute repetition
    # (`UMAI-ADR/Sensor/packaging/windows/Install-ScheduledTask.ps1`), and the
    # collector heartbeats once per run — so this has to be a multiple of that
    # interval, not of anything else. At the old 180s a correctly installed,
    # perfectly healthy device showed `stale` for twelve minutes out of every
    # fifteen, which made the fleet screen red by default and the signal
    # worthless. `POST /adr/heartbeat` derives the interval it asks for from
    # this value (stale / 3), so the two cannot drift apart.
    adr_heartbeat_stale_seconds: int = 45 * 60
    # UMAI: blob root for agent session transcripts (ai_sessions.transcript_ref)
    transcript_store_path: str = "./data/transcripts"
    # `filesystem` (default) or `s3`. The filesystem backend needs a persistent
    # volume — see deploy/docker-compose.yaml. Losing this directory loses the
    # evidence behind every finding.
    transcript_store_backend: str = "filesystem"
    transcript_s3_bucket: str | None = None
    transcript_s3_prefix: str = "transcripts"
    transcript_s3_endpoint_url: str | None = None
    transcript_s3_region: str | None = None
    # Server-side encryption is required for full_session transcripts
    # (contract: transcript-data-modes.md §5).
    transcript_s3_sse: str = "AES256"
    # UMAI: base64 of a 32-byte key. Set it and filesystem transcripts are
    # written AES-256-GCM encrypted; leave it unset and they are written in
    # the clear, which is only defensible when the volume itself is encrypted.
    # Blobs already on disk stay readable either way — the format is tagged.
    transcript_encryption_key: str | None = None
    # Rotation overlap. Transcripts sealed with the previous key stay readable
    # while this is set; nothing is ever sealed with it. Re-seal the existing
    # blobs, then clear it — see docs/secret-rotation.md.
    transcript_encryption_key_previous: str | None = None
    # UMAI: retention sweep. Off by default so an upgrade never deletes
    # evidence a customer did not agree to lose.
    transcript_retention_enabled: bool = False
    transcript_retention_interval_seconds: float = 60 * 60
    # UMAI: posture rule inputs. Both empty by default — an unconfigured
    # control produces no findings rather than false ones.
    # UMAI: shared secret for the analysis worker's internal endpoints.
    analysis_worker_token: str | None = None
    analysis_worker_token_previous: str | None = None
    analysis_claim_lease_seconds: int = 30 * 60
    approved_mcp_servers: str | None = None
    sensitive_project_patterns: str | None = None

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
