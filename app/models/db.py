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
