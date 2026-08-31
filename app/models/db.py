from __future__ import annotations

import datetime as dt
import uuid

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    Index,
    Integer,
    String,
    UnicodeText,
    UniqueConstraint,
    Uuid,
    text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Tenant(Base):
    __tablename__ = "tenants"

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    status: Mapped[str] = mapped_column(String(32), server_default=text("'active'"))
    # What the collector may send and the operator API may return:
    # `posture_only` | `metadata` | `full_session`.
    collection_mode: Mapped[str] = mapped_column(
        String(16), nullable=False, server_default=text("'metadata'")
    )
    # Transcripts age out separately from the sessions and findings that point
    # at them. Retention is a contractual term, so it lives per tenant.
    transcript_retention_days: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default=text("30")
    )
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("CURRENT_TIMESTAMP")
    )


class ApiKey(Base):
    __tablename__ = "api_keys"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid, primary_key=True, default=uuid.uuid4
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    environment_id: Mapped[str] = mapped_column(String(64), nullable=False)
    project_id: Mapped[str | None] = mapped_column(String(64))
    name: Mapped[str | None] = mapped_column(String(200))
    key_preview: Mapped[str | None] = mapped_column(String(32))
    key_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("CURRENT_TIMESTAMP")
    )
    revoked: Mapped[bool] = mapped_column(Boolean, server_default=text("false"))


class License(Base):
    __tablename__ = "licenses"

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, primary_key=True, nullable=False
    )
    status: Mapped[str] = mapped_column(String(32), server_default=text("'active'"))
    expires_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))
    features_json: Mapped[str | None] = mapped_column(UnicodeText)


class Environment(Base):
    __tablename__ = "environments"

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, primary_key=True, nullable=False
    )
    environment_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)


class Project(Base):
    __tablename__ = "projects"

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, primary_key=True, nullable=False
    )
    environment_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    project_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)


class Guardrail(Base):
    __tablename__ = "guardrails"

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, primary_key=True, nullable=False
    )
    environment_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    project_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    guardrail_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    current_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    mode: Mapped[str] = mapped_column(String(16), nullable=False)


class GuardrailVersion(Base):
    __tablename__ = "guardrail_versions"

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, primary_key=True, nullable=False
    )
    environment_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    project_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    guardrail_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    version: Mapped[int] = mapped_column(Integer, primary_key=True)
    snapshot_json: Mapped[str] = mapped_column(UnicodeText, nullable=False)
    signature: Mapped[str | None] = mapped_column(String(256))
    key_id: Mapped[str | None] = mapped_column(String(64))
    created_by: Mapped[str | None] = mapped_column(String(128))
    approved_by: Mapped[str | None] = mapped_column(String(128))
    approved_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("CURRENT_TIMESTAMP")
    )


class Policy(Base):
    __tablename__ = "policies"

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, primary_key=True, nullable=False
    )
    environment_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    project_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    policy_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    type: Mapped[str] = mapped_column(String(32), nullable=False)
    scope: Mapped[str] = mapped_column(
        String(16), nullable=False, server_default=text("'PROJECT'")
    )
    enabled: Mapped[bool] = mapped_column(Boolean, server_default=text("true"))
    phases_json: Mapped[str] = mapped_column(UnicodeText, nullable=False)
    config_json: Mapped[str] = mapped_column(UnicodeText, nullable=False)
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("CURRENT_TIMESTAMP")
    )


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid, primary_key=True, default=uuid.uuid4
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    environment_id: Mapped[str] = mapped_column(String(64), nullable=False)
    project_id: Mapped[str] = mapped_column(String(64), nullable=False)
    guardrail_id: Mapped[str] = mapped_column(String(64), nullable=False)
    guardrail_version: Mapped[int] = mapped_column(Integer, nullable=False)
    request_id: Mapped[str] = mapped_column(String(64), nullable=False)
    phase: Mapped[str] = mapped_column(String(16), nullable=False)
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    allowed: Mapped[bool] = mapped_column(Boolean, nullable=False)
    category: Mapped[str | None] = mapped_column(String(32))
    decision_severity: Mapped[str | None] = mapped_column(String(16))
    decision_reason: Mapped[str | None] = mapped_column(UnicodeText)
    latency_ms: Mapped[float | None] = mapped_column(Float)
    conversation_id: Mapped[str | None] = mapped_column(String(128))
    message: Mapped[str | None] = mapped_column(UnicodeText)
    request_payload_json: Mapped[str | None] = mapped_column(UnicodeText)
    response_payload_json: Mapped[str | None] = mapped_column(UnicodeText)
    triggering_policy_json: Mapped[str | None] = mapped_column(UnicodeText)
    run_id: Mapped[str | None] = mapped_column(String(64))
    step_id: Mapped[str | None] = mapped_column(String(64))
    agent_id: Mapped[str | None] = mapped_column(String(64))
    agent_did: Mapped[str | None] = mapped_column(String(256))
    action_resource_json: Mapped[str | None] = mapped_column(UnicodeText)
    prev_event_hash: Mapped[str | None] = mapped_column(String(64))
    event_hash: Mapped[str | None] = mapped_column(String(64))
    event_signature: Mapped[str | None] = mapped_column(String(128))
    hash_key_id: Mapped[str | None] = mapped_column(String(64))
    redacted: Mapped[bool] = mapped_column(Boolean, server_default=text("false"))
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("CURRENT_TIMESTAMP")
    )


class BrowserExtensionEvent(Base):
    __tablename__ = "browser_extension_events"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid, primary_key=True, default=uuid.uuid4
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    event_id: Mapped[str] = mapped_column(String(64), nullable=False)
    event_type: Mapped[str] = mapped_column(String(32), nullable=False)
    site: Mapped[str] = mapped_column(String(32), nullable=False)
    url: Mapped[str] = mapped_column(UnicodeText, nullable=False)
    tab_id: Mapped[int | None] = mapped_column(Integer)
    user_email: Mapped[str | None] = mapped_column(String(320))
    user_idp_subject: Mapped[str | None] = mapped_column(String(128))
    device_id: Mapped[str] = mapped_column(String(128), nullable=False)
    browser_profile_id: Mapped[str | None] = mapped_column(String(128))
    captured_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    prev_event_hash: Mapped[str | None] = mapped_column(String(64))
    event_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    chain_valid: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("true")
    )
    chain_error: Mapped[str | None] = mapped_column(UnicodeText)
    decision: Mapped[str | None] = mapped_column(String(32))
    message: Mapped[str | None] = mapped_column(UnicodeText)
    status: Mapped[str | None] = mapped_column(String(16))
    prompt_hash: Mapped[str | None] = mapped_column(String(64))
    response_hash: Mapped[str | None] = mapped_column(String(64))
    prompt_len: Mapped[int | None] = mapped_column(Integer)
    response_len: Mapped[int | None] = mapped_column(Integer)
    session_id: Mapped[str | None] = mapped_column(String(36))
    payload_json: Mapped[str] = mapped_column(UnicodeText, nullable=False)
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("CURRENT_TIMESTAMP")
    )


class AiApplication(Base):
    __tablename__ = "ai_applications"

    tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, nullable=False)
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    slug: Mapped[str] = mapped_column(String(64), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    vendor: Mapped[str | None] = mapped_column(String(200))
    category: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'other'"))
    risk_level: Mapped[str] = mapped_column(String(16), nullable=False, server_default=text("'none'"))
    icon_key: Mapped[str | None] = mapped_column(String(64))
    domains_json: Mapped[str] = mapped_column(UnicodeText, nullable=False, default="[]")
    process_names_json: Mapped[str] = mapped_column(UnicodeText, nullable=False, default="[]")
    ports_json: Mapped[str] = mapped_column(UnicodeText, nullable=False, default="[]")
    app_type: Mapped[str] = mapped_column(String(16), nullable=False, server_default=text("'web'"))
    is_sanctioned: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    is_training: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    sensor_capture: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))
    inventory_only: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    path_hint: Mapped[str | None] = mapped_column(String(128))
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))
    source: Mapped[str] = mapped_column(String(16), nullable=False, server_default=text("'builtin'"))
    is_customized: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("CURRENT_TIMESTAMP")
    )
    updated_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))


class AiUsageSession(Base):
    __tablename__ = "ai_usage_sessions"

    tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, nullable=False)
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    app_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    app_slug: Mapped[str | None] = mapped_column(String(64))
    user_key: Mapped[str] = mapped_column(String(320), nullable=False)
    device_id: Mapped[str] = mapped_column(String(128), nullable=False)
    source: Mapped[str] = mapped_column(String(16), nullable=False)
    session_type: Mapped[str] = mapped_column(String(16), nullable=False)
    started_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_activity_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    event_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    dlp_hit_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("CURRENT_TIMESTAMP")
    )


class EndpointSensorEvent(Base):
    __tablename__ = "endpoint_sensor_events"

    tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, nullable=False)
    event_id: Mapped[str] = mapped_column(String(64), primary_key=True, nullable=False)
    event_type: Mapped[str] = mapped_column(String(48), nullable=False)
    process_name: Mapped[str | None] = mapped_column(String(260))
    process_path: Mapped[str | None] = mapped_column(UnicodeText)
    parent_process: Mapped[str | None] = mapped_column(String(260))
    destination_host: Mapped[str | None] = mapped_column(String(255))
    destination_sni: Mapped[str | None] = mapped_column(String(255))
    destination_port: Mapped[int | None] = mapped_column(Integer)
    user_email: Mapped[str | None] = mapped_column(String(320))
    user_idp_subject: Mapped[str | None] = mapped_column(String(128))
    device_id: Mapped[str] = mapped_column(String(128), nullable=False)
    captured_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    prev_event_hash: Mapped[str | None] = mapped_column(String(64))
    event_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    chain_valid: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("true")
    )
    chain_error: Mapped[str | None] = mapped_column(UnicodeText)
    decision: Mapped[str | None] = mapped_column(String(32))
    message: Mapped[str | None] = mapped_column(UnicodeText)
    prompt_hash: Mapped[str | None] = mapped_column(String(64))
    prompt_len: Mapped[int | None] = mapped_column(Integer)
    dlp_tags_json: Mapped[str | None] = mapped_column(UnicodeText)
    file_context_json: Mapped[str | None] = mapped_column(UnicodeText)
    session_id: Mapped[str | None] = mapped_column(String(36))
    payload_json: Mapped[str] = mapped_column(UnicodeText, nullable=False)
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("CURRENT_TIMESTAMP")
    )


class EndpointSensorDevice(Base):
    __tablename__ = "endpoint_sensor_devices"

    tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, nullable=False)
    device_id: Mapped[str] = mapped_column(String(128), primary_key=True, nullable=False)
    hostname: Mapped[str | None] = mapped_column(String(255))
    os: Mapped[str | None] = mapped_column(String(64))
    os_version: Mapped[str | None] = mapped_column(String(128))
    agent_version: Mapped[str | None] = mapped_column(String(64))
    last_heartbeat_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    last_policy_etag: Mapped[str | None] = mapped_column(String(128))
    last_user_email: Mapped[str | None] = mapped_column(String(320))
    identity_status: Mapped[str | None] = mapped_column(String(64))
    queue_depth: Mapped[int | None] = mapped_column(Integer)
    last_successful_upload_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    metadata_json: Mapped[str | None] = mapped_column(UnicodeText)
    enrolled_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("CURRENT_TIMESTAMP")
    )
    status: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'active'"))


class EndpointSensorBootstrapToken(Base):
    __tablename__ = "endpoint_sensor_bootstrap_tokens"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    token_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    device_id: Mapped[str | None] = mapped_column(String(128))
    subject: Mapped[str | None] = mapped_column(String(256))
    expires_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[str | None] = mapped_column(String(128))
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("CURRENT_TIMESTAMP")
    )


class EndpointSensorDownloadSession(Base):
    __tablename__ = "endpoint_sensor_download_sessions"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    employee_idp_subject: Mapped[str] = mapped_column(String(256), nullable=False)
    employee_upn: Mapped[str | None] = mapped_column(String(320))
    employee_display_name: Mapped[str | None] = mapped_column(String(200))
    created_ip: Mapped[str | None] = mapped_column(String(64))
    installer_version: Mapped[str | None] = mapped_column(String(64))
    bootstrap_token_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    bootstrap_token_expires_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    artifact_id: Mapped[str | None] = mapped_column(String(128))
    artifact_sha256: Mapped[str | None] = mapped_column(String(64))
    artifact_filename: Mapped[str | None] = mapped_column(String(260))
    artifact_expires_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    downloaded_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    device_id: Mapped[str | None] = mapped_column(String(128))
    first_heartbeat_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    last_heartbeat_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    first_event_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    identity_status: Mapped[str | None] = mapped_column(String(64))
    failure_reason: Mapped[str | None] = mapped_column(UnicodeText)
    status: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'requested'"))
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("CURRENT_TIMESTAMP")
    )
    updated_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))


class EvidencePack(Base):
    __tablename__ = "evidence_packs"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    environment_id: Mapped[str | None] = mapped_column(String(64))
    project_id: Mapped[str | None] = mapped_column(String(64))
    regime: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, server_default=text("'READY'")
    )
    timeframe_start: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    timeframe_end: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    artifact_json: Mapped[str] = mapped_column(UnicodeText, nullable=False)
    created_by: Mapped[str | None] = mapped_column(String(128))
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("CURRENT_TIMESTAMP")
    )


class ApprovalRequest(Base):
    __tablename__ = "approval_requests"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    environment_id: Mapped[str] = mapped_column(String(64), nullable=False)
    project_id: Mapped[str] = mapped_column(String(64), nullable=False)
    guardrail_id: Mapped[str] = mapped_column(String(64), nullable=False)
    guardrail_version: Mapped[int] = mapped_column(Integer, nullable=False)
    request_id: Mapped[str] = mapped_column(String(64), nullable=False)
    phase: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, server_default=text("'PENDING'"))
    reason: Mapped[str | None] = mapped_column(UnicodeText)
    resolved_by: Mapped[str | None] = mapped_column(String(128))
    resolved_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("CURRENT_TIMESTAMP")
    )


class GuardrailJob(Base):
    __tablename__ = "guardrail_jobs"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    environment_id: Mapped[str] = mapped_column(String(64), nullable=False)
    project_id: Mapped[str] = mapped_column(String(64), nullable=False)
    guardrail_id: Mapped[str] = mapped_column(String(64), nullable=False)
    guardrail_version: Mapped[int] = mapped_column(Integer, nullable=False)
    request_id: Mapped[str] = mapped_column(String(64), nullable=False)
    phase: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, server_default=text("'QUEUED'"))
    conversation_id: Mapped[str | None] = mapped_column(String(128))
    request_payload_json: Mapped[str] = mapped_column(UnicodeText, nullable=False)
    response_payload_json: Mapped[str | None] = mapped_column(UnicodeText)
    webhook_url: Mapped[str | None] = mapped_column(String(500))
    webhook_secret: Mapped[str | None] = mapped_column(String(256))
    error_message: Mapped[str | None] = mapped_column(UnicodeText)
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("CURRENT_TIMESTAMP")
    )
    updated_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))


class GuardrailPublishGate(Base):
    __tablename__ = "guardrail_publish_gates"

    tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, nullable=False)
    environment_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    project_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    guardrail_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    min_expected_action_accuracy: Mapped[float | None] = mapped_column(Float)
    min_expected_allowed_accuracy: Mapped[float | None] = mapped_column(Float)
    min_eval_cases: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("10"))
    max_p95_latency_ms: Mapped[float | None] = mapped_column(Float)
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("CURRENT_TIMESTAMP")
    )


class ModelRegistryEntry(Base):
    __tablename__ = "model_registry_entries"

    tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, nullable=False)
    environment_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    project_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    model_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    display_name: Mapped[str] = mapped_column(String(200), nullable=False)
    provider: Mapped[str] = mapped_column(String(64), nullable=False)
    model_type: Mapped[str] = mapped_column(String(32), nullable=False)
    owner: Mapped[str | None] = mapped_column(String(128))
    risk_tier: Mapped[str] = mapped_column(
        String(16), nullable=False, server_default=text("'MEDIUM'")
    )
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, server_default=text("'ACTIVE'")
    )
    metadata_json: Mapped[str | None] = mapped_column(UnicodeText)
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("CURRENT_TIMESTAMP")
    )
    updated_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))


class AgentRegistryEntry(Base):
    __tablename__ = "agent_registry_entries"

    tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, nullable=False)
    environment_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    project_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    agent_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    display_name: Mapped[str] = mapped_column(String(200), nullable=False)
    runtime: Mapped[str] = mapped_column(String(64), nullable=False)
    owner: Mapped[str | None] = mapped_column(String(128))
    risk_tier: Mapped[str] = mapped_column(
        String(16), nullable=False, server_default=text("'MEDIUM'")
    )
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, server_default=text("'ACTIVE'")
    )
    agent_did: Mapped[str | None] = mapped_column(String(256))
    public_key_fingerprint: Mapped[str | None] = mapped_column(String(128))
    capabilities_json: Mapped[str | None] = mapped_column(UnicodeText)
    trust_score: Mapped[float] = mapped_column(Float, nullable=False, server_default=text("0.25"))
    trust_tier: Mapped[str] = mapped_column(
        String(24), nullable=False, server_default=text("'SANDBOX'")
    )
    identity_status: Mapped[str] = mapped_column(
        String(24), nullable=False, server_default=text("'UNREGISTERED'")
    )
    kill_switch_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    kill_switch_reason: Mapped[str | None] = mapped_column(UnicodeText)
    last_seen_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    metadata_json: Mapped[str | None] = mapped_column(UnicodeText)
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("CURRENT_TIMESTAMP")
    )
    updated_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))


class AgentIdentityBootstrapToken(Base):
    __tablename__ = "agent_identity_bootstrap_tokens"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    environment_id: Mapped[str] = mapped_column(String(64), nullable=False)
    project_id: Mapped[str] = mapped_column(String(64), nullable=False)
    agent_id: Mapped[str] = mapped_column(String(64), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    expires_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[str | None] = mapped_column(String(128))
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("CURRENT_TIMESTAMP")
    )


class AgentIdentityCredential(Base):
    __tablename__ = "agent_identity_credentials"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    environment_id: Mapped[str] = mapped_column(String(64), nullable=False)
    project_id: Mapped[str] = mapped_column(String(64), nullable=False)
    agent_id: Mapped[str] = mapped_column(String(64), nullable=False)
    agent_did: Mapped[str] = mapped_column(String(256), nullable=False)
    public_key_b64: Mapped[str] = mapped_column(UnicodeText, nullable=False)
    public_key_fingerprint: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False, server_default=text("'ACTIVE'"))
    revoked_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    rotated_from_credential_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    bootstrap_token_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("CURRENT_TIMESTAMP")
    )


class AgentIdentityNonce(Base):
    __tablename__ = "agent_identity_nonces"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    environment_id: Mapped[str] = mapped_column(String(64), nullable=False)
    project_id: Mapped[str] = mapped_column(String(64), nullable=False)
    agent_id: Mapped[str] = mapped_column(String(64), nullable=False)
    nonce: Mapped[str] = mapped_column(String(128), nullable=False)
    signed_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("CURRENT_TIMESTAMP")
    )


class AgentRunSession(Base):
    __tablename__ = "agent_run_sessions"

    tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, nullable=False)
    environment_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    project_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    agent_id: Mapped[str] = mapped_column(String(64), nullable=False)
    agent_did: Mapped[str] = mapped_column(String(256), nullable=False)
    guardrail_id: Mapped[str | None] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(24), nullable=False, server_default=text("'RUNNING'"))
    decision_action: Mapped[str | None] = mapped_column(String(32))
    decision_severity: Mapped[str | None] = mapped_column(String(16))
    trust_score: Mapped[float | None] = mapped_column(Float)
    trust_tier: Mapped[str | None] = mapped_column(String(24))
    summary_json: Mapped[str | None] = mapped_column(UnicodeText)
    started_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("CURRENT_TIMESTAMP")
    )
    updated_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))


class AgentRunStep(Base):
    __tablename__ = "agent_run_steps"

    tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, nullable=False)
    environment_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    project_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    step_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    parent_step_id: Mapped[str | None] = mapped_column(String(64))
    sequence: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    event_type: Mapped[str] = mapped_column(String(32), nullable=False)
    phase: Mapped[str | None] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(24), nullable=False, server_default=text("'RECORDED'"))
    agent_id: Mapped[str] = mapped_column(String(64), nullable=False)
    agent_did: Mapped[str] = mapped_column(String(256), nullable=False)
    action: Mapped[str | None] = mapped_column(String(64))
    resource_type: Mapped[str | None] = mapped_column(String(64))
    resource_name: Mapped[str | None] = mapped_column(String(256))
    decision_action: Mapped[str | None] = mapped_column(String(32))
    decision_severity: Mapped[str | None] = mapped_column(String(16))
    decision_reason: Mapped[str | None] = mapped_column(UnicodeText)
    policy_id: Mapped[str | None] = mapped_column(String(128))
    matched_rule_id: Mapped[str | None] = mapped_column(String(128))
    latency_ms: Mapped[float | None] = mapped_column(Float)
    payload_summary: Mapped[str | None] = mapped_column(UnicodeText)
    metadata_json: Mapped[str | None] = mapped_column(UnicodeText)
    input_hash: Mapped[str | None] = mapped_column(String(64))
    output_hash: Mapped[str | None] = mapped_column(String(64))
    prev_step_hash: Mapped[str | None] = mapped_column(String(64))
    step_hash: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("CURRENT_TIMESTAMP")
    )


class EvaluationRun(Base):
    __tablename__ = "evaluation_runs"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid, primary_key=True, default=uuid.uuid4
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    environment_id: Mapped[str] = mapped_column(String(64), nullable=False)
    project_id: Mapped[str] = mapped_column(String(64), nullable=False)
    guardrail_id: Mapped[str] = mapped_column(String(64), nullable=False)
    guardrail_version: Mapped[int] = mapped_column(Integer, nullable=False)
    name: Mapped[str | None] = mapped_column(String(200))
    dataset_id: Mapped[str | None] = mapped_column(String(64))
    phase: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    total_cases: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    processed_cases: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    metrics_json: Mapped[str | None] = mapped_column(UnicodeText)
    error_message: Mapped[str | None] = mapped_column(UnicodeText)
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("CURRENT_TIMESTAMP")
    )
    completed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))


class EvaluationCase(Base):
    __tablename__ = "evaluation_cases"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid, primary_key=True, default=uuid.uuid4
    )
    run_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    environment_id: Mapped[str] = mapped_column(String(64), nullable=False)
    project_id: Mapped[str] = mapped_column(String(64), nullable=False)
    guardrail_id: Mapped[str] = mapped_column(String(64), nullable=False)
    guardrail_version: Mapped[int] = mapped_column(Integer, nullable=False)
    index: Mapped[int] = mapped_column(Integer, nullable=False)
    label: Mapped[str | None] = mapped_column(String(128))
    prompt: Mapped[str] = mapped_column(UnicodeText, nullable=False)
    expected_action: Mapped[str | None] = mapped_column(String(24))
    expected_allowed: Mapped[bool | None] = mapped_column(Boolean)
    expected_severity: Mapped[str | None] = mapped_column(String(16))
    decision_action: Mapped[str | None] = mapped_column(String(24))
    decision_allowed: Mapped[bool | None] = mapped_column(Boolean)
    decision_severity: Mapped[str | None] = mapped_column(String(16))
    decision_reason: Mapped[str | None] = mapped_column(UnicodeText)
    triggering_policy_json: Mapped[str | None] = mapped_column(UnicodeText)
    latency_ms: Mapped[float | None] = mapped_column(Float)
    errors_json: Mapped[str | None] = mapped_column(UnicodeText)
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("CURRENT_TIMESTAMP")
    )


class AiSession(Base):
    """A single agent conversation, normalized across collection channels.

    This is the *analysis* unit. `umai.ai_event.v1` (RFC-1) stays the query unit
    and is derived from these rows — a detector reasons over a transcript, not
    over one event at a time.

    The transcript itself lives in the blob store; `transcript_ref` points at it.
    """

    __tablename__ = "ai_sessions"

    tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, nullable=False)
    # sha256("{source}|{source_session_id}|{raw_log_path}") — sub-agent runs share
    # their parent's session id in separate files, so the id alone is not unique.
    session_key: Mapped[str] = mapped_column(String(64), primary_key=True, nullable=False)

    source: Mapped[str] = mapped_column(String(32), nullable=False)
    source_session_id: Mapped[str] = mapped_column(String(256), nullable=False)
    raw_log_path: Mapped[str | None] = mapped_column(UnicodeText)

    actor_user: Mapped[str | None] = mapped_column(String(320))
    actor_device_id: Mapped[str | None] = mapped_column(String(128))
    hostname: Mapped[str | None] = mapped_column(String(255))
    username: Mapped[str | None] = mapped_column(String(255))

    model: Mapped[str | None] = mapped_column(String(128))
    project_path: Mapped[str | None] = mapped_column(UnicodeText)
    title: Mapped[str | None] = mapped_column(UnicodeText)

    observed_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    ingested_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("CURRENT_TIMESTAMP")
    )

    message_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    tool_call_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))

    # Session configuration: permission mode, connected MCP servers, granted
    # permissions. Drives detection without reading a single message.
    posture_json: Mapped[str | None] = mapped_column(UnicodeText)

    # Null once retention has reaped the blob, or when the tenant collects in
    # a mode that stores no content at all.
    transcript_ref: Mapped[str | None] = mapped_column(UnicodeText)
    transcript_sha256: Mapped[str | None] = mapped_column(String(64))
    transcript_bytes: Mapped[int | None] = mapped_column(Integer)

    collector_name: Mapped[str | None] = mapped_column(String(64))
    collector_version: Mapped[str | None] = mapped_column(String(32))

    analysis_status: Mapped[str] = mapped_column(
        String(24), nullable=False, server_default=text("'ingested'")
    )
    threat_tactic: Mapped[str | None] = mapped_column(String(64))
    verdict: Mapped[str | None] = mapped_column(String(24))
    confidence: Mapped[float | None] = mapped_column(Float)
    analyzed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    # Lease held by an analysis worker while a stage is in flight. A worker that
    # dies mid-stage leaves a stale lease, which the claim query reclaims.
    # Why the last analysis attempt did not produce a verdict. A timed-out or
    # over-budget session must not read as "clean".
    analysis_error: Mapped[str | None] = mapped_column(UnicodeText)
    analysis_attempts: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default=text("0")
    )
    claimed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    claimed_by: Mapped[str | None] = mapped_column(String(64))

    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("CURRENT_TIMESTAMP")
    )


class Finding(Base):
    """A security finding raised against an agent session.

    Findings are idempotent per (session, rule): re-evaluating a session
    produces the same `finding_key`, so an ingest replay updates rather than
    duplicates.
    """

    __tablename__ = "findings"

    tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, nullable=False)
    # sha256("{session_key}|{rule_id}")
    finding_key: Mapped[str] = mapped_column(String(64), primary_key=True, nullable=False)

    session_key: Mapped[str] = mapped_column(String(64), nullable=False)

    rule_id: Mapped[str] = mapped_column(String(64), nullable=False)
    technique_id: Mapped[str | None] = mapped_column(String(16))
    technique_name: Mapped[str | None] = mapped_column(String(128))
    tactic: Mapped[str | None] = mapped_column(String(64))

    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    title: Mapped[str] = mapped_column(UnicodeText, nullable=False)
    summary: Mapped[str | None] = mapped_column(UnicodeText)
    evidence_json: Mapped[str | None] = mapped_column(UnicodeText)

    # The axis the queue is filtered on: which channel produced this finding.
    # `adr` | `extension` | `sdk` | `red_team` | `policy`. Not the AI tool —
    # that lives on the session and is reached through `session_key`.
    source: Mapped[str] = mapped_column(String(32), nullable=False)
    # Operator-facing grouping. See the category set in the frozen contract.
    category: Mapped[str] = mapped_column(String(48), nullable=False)

    actor_user: Mapped[str | None] = mapped_column(String(320))
    actor_device_id: Mapped[str | None] = mapped_column(String(128))
    project_path: Mapped[str | None] = mapped_column(UnicodeText)
    observed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))

    # Which detector fired: `posture` | `triage` | `reasoning` | `red_team` | `policy`.
    detector: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, server_default=text("'open'")
    )
    assignee: Mapped[str | None] = mapped_column(String(320))
    # Proposed action or a reference to a draft policy change.
    remediation_json: Mapped[str | None] = mapped_column(UnicodeText)
    detected_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("CURRENT_TIMESTAMP")
    )
    emitted_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))


class FindingStatusEvent(Base):
    """One audited transition in a finding's lifecycle.

    Deliberately not folded into `audit_events`: that table is shaped for
    guardrail decisions and makes `environment_id`, `project_id`,
    `guardrail_id`, `guardrail_version`, `phase`, `action` and `allowed`
    NOT NULL. A finding transition has no counterpart for any of them, and
    filling them with placeholders would corrupt the audit trail this exists
    to protect.
    """

    __tablename__ = "finding_status_events"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    finding_key: Mapped[str] = mapped_column(String(64), nullable=False)

    # Empty on the row that records the finding being opened.
    from_status: Mapped[str | None] = mapped_column(String(16))
    to_status: Mapped[str] = mapped_column(String(16), nullable=False)

    actor: Mapped[str] = mapped_column(String(320), nullable=False)
    # Required on the transitions that assert a judgement: `false_positive`
    # and `accepted_risk`. Enforced at the API layer, not by the schema.
    note: Mapped[str | None] = mapped_column(UnicodeText)

    occurred_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("CURRENT_TIMESTAMP"), nullable=False
    )


class SiemOutbox(Base):
    """A SIEM delivery waiting to happen, or a record that it did.

    Written in the same transaction as the event it describes. Fire-and-forget
    delivery loses security findings to a QRadar restart or a network blip and
    tells nobody; this makes the loss impossible and the failure visible.
    """

    __tablename__ = "siem_outbox"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)

    # The producer's id for this event — a finding key today. With the schema
    # it forms the uniqueness that makes enqueueing idempotent.
    event_id: Mapped[str] = mapped_column(String(128), nullable=False)
    event_schema: Mapped[str] = mapped_column(String(64), nullable=False)
    payload_json: Mapped[str] = mapped_column(UnicodeText, nullable=False)

    # `pending` | `delivered` | `dead_letter`
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, server_default=text("'pending'")
    )
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    last_error: Mapped[str | None] = mapped_column(UnicodeText)
    next_attempt_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))

    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("CURRENT_TIMESTAMP"), nullable=False
    )
    delivered_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))

    # Who put a dead letter back in the queue. Replay is an operator action on
    # a security event that failed to reach the SOC; the row has to say who.
    replayed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    replayed_by: Mapped[str | None] = mapped_column(String(320))

    __table_args__ = (
        UniqueConstraint("tenant_id", "event_id", "event_schema", name="uq_siem_outbox_event"),
    )


class TranscriptAuditEvent(Base):
    """Who touched conversation content, and why.

    Covers reads as well as deletions. Read-only collection does not make this
    low-sensitivity data: these are employees' own words and customers' data,
    and the product claims access to them is audited.
    """

    __tablename__ = "transcript_audit_events"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    session_key: Mapped[str] = mapped_column(String(128), nullable=False)
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    # Null for the retention sweep: nobody asked, the clock did.
    actor: Mapped[str | None] = mapped_column(String(256))
    reason: Mapped[str | None] = mapped_column(UnicodeText)
    transcript_bytes: Mapped[int | None] = mapped_column(Integer)
    occurred_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    __table_args__ = (
        Index("ix_transcript_audit_session", "tenant_id", "session_key", "occurred_at"),
        Index("ix_transcript_audit_recent", "tenant_id", "occurred_at"),
    )
