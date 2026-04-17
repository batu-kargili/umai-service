from __future__ import annotations

import datetime as dt
import uuid

from sqlalchemy import Boolean, DateTime, Float, Integer, String, UnicodeText, Uuid, text
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
    action: Mapped[str] = mapped_column(String(16), nullable=False)
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
    payload_json: Mapped[str] = mapped_column(UnicodeText, nullable=False)
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("CURRENT_TIMESTAMP")
    )


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
    metadata_json: Mapped[str | None] = mapped_column(UnicodeText)
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("CURRENT_TIMESTAMP")
    )
    updated_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))


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
