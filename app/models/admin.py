from __future__ import annotations

import datetime as dt
import uuid
from typing import Literal

from pydantic import BaseModel, Field, model_validator

from app.models.public import GuardrailPhase, InputPayload


class TenantCreateRequest(BaseModel):
    tenant_id: uuid.UUID | None = None
    name: str


class TenantResponse(BaseModel):
    tenant_id: uuid.UUID
    name: str
    status: str
    created_at: dt.datetime | None = None


class LicenseCreateRequest(BaseModel):
    tenant_id: uuid.UUID
    expires_at: dt.datetime
    status: str = "active"
    features_json: dict | None = None


class LicenseResponse(BaseModel):
    tenant_id: uuid.UUID
    status: str
    expires_at: dt.datetime
    features_json: dict | None = None


class LicenseTokenApplyRequest(BaseModel):
    token: str


class ApiKeyCreateRequest(BaseModel):
    tenant_id: uuid.UUID
    environment_id: str
    project_id: str | None = None
    api_key: str | None = None
    name: str | None = Field(default=None, max_length=200)


class ApiKeyResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    environment_id: str
    project_id: str | None = None
    api_key: str | None = None
    name: str | None = None
    key_preview: str | None = None
    created_at: dt.datetime | None = None
    revoked: bool = False


class EnvironmentCreateRequest(BaseModel):
    tenant_id: uuid.UUID
    environment_id: str
    name: str


class EnvironmentResponse(BaseModel):
    tenant_id: uuid.UUID
    environment_id: str
    name: str


class ProjectCreateRequest(BaseModel):
    tenant_id: uuid.UUID
    environment_id: str
    project_id: str
    name: str


class ProjectResponse(BaseModel):
    tenant_id: uuid.UUID
    environment_id: str
    project_id: str
    name: str



PolicyPhase = GuardrailPhase
PolicyScope = Literal["ORGANIZATION", "ENVIRONMENT", "PROJECT"]
LlmAuthType = Literal["none", "bearer", "header"]


class LlmAuthConfig(BaseModel):
    type: LlmAuthType = "bearer"
    secret_env: str | None = None
    header_name: str | None = None

    @model_validator(mode="after")
    def validate_auth(self) -> "LlmAuthConfig":
        if self.type == "none":
            return self
        if not self.secret_env or not self.secret_env.strip():
            raise ValueError("auth.secret_env is required unless auth.type is 'none'")
        if self.type == "header" and (not self.header_name or not self.header_name.strip()):
            raise ValueError("auth.header_name is required when auth.type is 'header'")
        return self


class GuardrailLlmConfig(BaseModel):
    provider: str
    base_url: str
    model: str
    timeout_ms: int = Field(default=2000, ge=1)
    auth: LlmAuthConfig | None = None


class PolicyCreateRequest(BaseModel):
    tenant_id: uuid.UUID
    environment_id: str
    project_id: str
    policy_id: str
    name: str
    type: Literal["HEURISTIC", "CONTEXT_AWARE"]
    enabled: bool = True
    phases: list[PolicyPhase]
    config: dict
    scope: PolicyScope = "PROJECT"


class PolicyUpdateRequest(BaseModel):
    name: str | None = None
    enabled: bool | None = None
    phases: list[PolicyPhase] | None = None
    config: dict | None = None


class PolicyResponse(BaseModel):
    tenant_id: uuid.UUID
    environment_id: str
    project_id: str
    policy_id: str
    name: str
    type: str
    enabled: bool
    phases: list[PolicyPhase]
    config: dict
    scope: PolicyScope
    created_at: dt.datetime | None = None


class GuardrailCreateRequest(BaseModel):
    tenant_id: uuid.UUID
    environment_id: str
    project_id: str
    guardrail_id: str
    name: str
    mode: Literal["ENFORCE", "MONITOR"] = "ENFORCE"
    current_version: int = 1


class GuardrailResponse(BaseModel):
    tenant_id: uuid.UUID
    environment_id: str
    project_id: str
    guardrail_id: str
    name: str
    mode: str
    current_version: int


class GuardrailVersionCreateRequest(BaseModel):
    tenant_id: uuid.UUID
    environment_id: str
    project_id: str
    version: int
    created_by: str | None = None
    snapshot_json: dict | None = None
    policy_ids: list[str] | None = None
    preflight: dict | None = None
    llm_config: GuardrailLlmConfig | None = None
    phases: list[PolicyPhase] | None = None


class GuardrailVersionResponse(BaseModel):
    tenant_id: uuid.UUID
    environment_id: str
    project_id: str
    guardrail_id: str
    version: int
    created_at: dt.datetime | None = None
    created_by: str | None = None
    approved_by: str | None = None
    approved_at: dt.datetime | None = None
    signature_present: bool = False


class PublishRequest(BaseModel):
    tenant_id: uuid.UUID
    environment_id: str
    project_id: str
    publisher_id: str | None = None
    approver_id: str | None = None
    bypass_eval_gate: bool = False
    bypass_reason: str | None = None
    break_glass_reason: str | None = None


class PublishResponse(BaseModel):
    redis_key: str
    signature: str | None = None
    key_id: str | None = None


class PolicyLibraryItem(BaseModel):
    template_id: str
    default_policy_id: str
    name: str
    description: str | None = None
    type: Literal["HEURISTIC", "CONTEXT_AWARE"]
    enabled: bool
    phases: list[PolicyPhase]
    config: dict
    managed: bool = True
    tags: list[str] | None = None


class GuardrailLibraryPolicy(BaseModel):
    template_id: str
    default_policy_id: str
    name: str
    description: str | None = None
    type: Literal["HEURISTIC", "CONTEXT_AWARE"]
    enabled: bool
    phases: list[PolicyPhase]
    config: dict
    managed: bool = True
    tags: list[str] | None = None


class GuardrailLibraryItem(BaseModel):
    template_id: str
    default_guardrail_id: str
    name: str
    description: str | None = None
    mode: Literal["ENFORCE", "MONITOR"]
    version: int
    phases: list[PolicyPhase]
    preflight: dict
    llm_config: GuardrailLlmConfig
    policies: list[GuardrailLibraryPolicy]
    managed: bool = True
    tags: list[str] | None = None


class PolicyLibraryDeployRequest(BaseModel):
    tenant_id: uuid.UUID
    environment_id: str
    project_id: str
    template_id: str
    policy_id: str | None = None
    name: str | None = None


class GuardrailLibraryDeployRequest(BaseModel):
    tenant_id: uuid.UUID
    environment_id: str
    project_id: str
    template_id: str
    guardrail_id: str | None = None
    name: str | None = None
    mode: Literal["ENFORCE", "MONITOR"] | None = None
    publish: bool = True


class GuardrailLibraryDeployResponse(BaseModel):
    guardrail: GuardrailResponse
    version: GuardrailVersionResponse
    policy_ids: list[str]
    published: bool = False
    redis_key: str | None = None


class AgenticGuardrailRequest(BaseModel):
    tenant_id: uuid.UUID
    environment_id: str
    project_id: str
    agent_description: str
    agent_type: str
    target_audience: str
    available_countries: list[str] = Field(default_factory=list)
    architecture: list[str] = Field(default_factory=list)


class AgenticPolicySuggestion(BaseModel):
    policy_id: str
    name: str
    type: Literal["HEURISTIC", "CONTEXT_AWARE"]
    enabled: bool = True
    phases: list[PolicyPhase]
    config: dict


class AgenticGuardrailSuggestion(BaseModel):
    guardrail_id: str
    name: str
    mode: Literal["ENFORCE", "MONITOR"]
    phases: list[PolicyPhase]
    preflight: dict
    llm_config: GuardrailLlmConfig


class AgenticGuardrailResponse(BaseModel):
    guardrail: AgenticGuardrailSuggestion
    policies: list[AgenticPolicySuggestion]
    rationale: str
    notes: list[str] = Field(default_factory=list)


class GuardrailTestRequest(BaseModel):
    tenant_id: uuid.UUID
    environment_id: str
    project_id: str
    guardrail_id: str
    guardrail_version: int | None = None
    phase: Literal["PRE_LLM", "POST_LLM"]
    input: InputPayload
    timeout_ms: int | None = 1500
    allow_llm_calls: bool = True


class GuardrailTestDecision(BaseModel):
    action: str
    allowed: bool
    severity: str
    reason: str


class GuardrailTestTriggeringPolicy(BaseModel):
    policy_id: str
    type: str
    name: str
    status: str
    severity: str
    score: float | None = None
    details: dict
    latency_ms: float


class GuardrailTestLatency(BaseModel):
    total: float
    preflight: float | None = None


class GuardrailTestResponse(BaseModel):
    request_id: str
    guardrail_id: str
    guardrail_version: int
    phase: Literal["PRE_LLM", "POST_LLM"]
    decision: GuardrailTestDecision
    triggering_policy: GuardrailTestTriggeringPolicy | None = None
    latency_ms: GuardrailTestLatency
    errors: list[dict] = Field(default_factory=list)


AlertDecision = Literal["BLOCK", "FLAG"]
AlertSeverity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]


class AlertResponse(BaseModel):
    id: uuid.UUID
    workflow: str
    flow: str
    category: str
    policy: str
    guardrail_id: str
    decision: AlertDecision
    severity: AlertSeverity
    phase: PolicyPhase
    latency_ms: float
    created_at: dt.datetime
    message: str
    request_id: str
    matched_rule: str


class ApprovalResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    environment_id: str
    project_id: str
    guardrail_id: str
    guardrail_version: int
    request_id: str
    phase: PolicyPhase
    status: Literal["PENDING", "APPROVED", "DENIED", "EXPIRED"]
    reason: str | None = None
    created_at: dt.datetime | None = None
    resolved_at: dt.datetime | None = None
    resolved_by: str | None = None


class ApprovalResolveRequest(BaseModel):
    resolved_by: str
    reason: str | None = None


class PublishGateUpsertRequest(BaseModel):
    tenant_id: uuid.UUID
    environment_id: str
    project_id: str
    guardrail_id: str
    min_expected_action_accuracy: float | None = Field(default=0.7, ge=0.0, le=1.0)
    min_expected_allowed_accuracy: float | None = Field(default=None, ge=0.0, le=1.0)
    min_eval_cases: int = Field(default=10, ge=1, le=10000)
    max_p95_latency_ms: float | None = Field(default=None, ge=1.0, le=120000.0)


class PublishGateResponse(BaseModel):
    tenant_id: uuid.UUID
    environment_id: str
    project_id: str
    guardrail_id: str
    min_expected_action_accuracy: float | None = None
    min_expected_allowed_accuracy: float | None = None
    min_eval_cases: int = 10
    max_p95_latency_ms: float | None = None
    updated_at: dt.datetime | None = None


class EvaluationSetResponse(BaseModel):
    id: str
    name: str
    description: str | None = None
    total_cases: int


class EvaluationRunResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    environment_id: str
    project_id: str
    guardrail_id: str
    guardrail_version: int
    name: str | None = None
    dataset_id: str | None = None
    phase: PolicyPhase
    status: str
    total_cases: int
    processed_cases: int
    metrics: dict | None = None
    error_message: str | None = None
    created_at: dt.datetime | None = None
    completed_at: dt.datetime | None = None


class EvaluationCaseResponse(BaseModel):
    id: uuid.UUID
    run_id: uuid.UUID
    index: int
    label: str | None = None
    prompt: str
    expected_action: str | None = None
    expected_allowed: bool | None = None
    expected_severity: str | None = None
    decision_action: str | None = None
    decision_allowed: bool | None = None
    decision_severity: str | None = None
    decision_reason: str | None = None
    expected_action_match: bool | None = None
    expected_allowed_match: bool | None = None
    expected_severity_match: bool | None = None
    triggering_policy: dict | None = None
    latency_ms: float | None = None
    errors: list[dict] | None = None


class EvaluationRunDetailResponse(EvaluationRunResponse):
    cases: list[EvaluationCaseResponse]


class AuditEventResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    environment_id: str
    project_id: str
    guardrail_id: str
    guardrail_version: int
    request_id: str
    phase: str
    action: str
    allowed: bool
    category: str | None = None
    decision_severity: str | None = None
    decision_reason: str | None = None
    latency_ms: float | None = None
    conversation_id: str | None = None
    message: str | None = None
    triggering_policy: dict | None = None
    redacted: bool = False
    prev_event_hash: str | None = None
    event_hash: str | None = None
    event_signature: str | None = None
    hash_key_id: str | None = None
    created_at: dt.datetime


class AuditEventPurgeRequest(BaseModel):
    tenant_id: uuid.UUID
    before: dt.datetime | None = None
    retain_days: int | None = Field(default=None, ge=1, le=36500)
    environment_id: str | None = None
    project_id: str | None = None


class AuditEventPurgeResponse(BaseModel):
    deleted_count: int
    cutoff: dt.datetime


EvidenceRegime = Literal["EU_AI_ACT", "GDPR", "CPRA_ADMT", "SEC_CYBER", "CUSTOM"]


class EvidencePackCreateRequest(BaseModel):
    tenant_id: uuid.UUID
    regime: EvidenceRegime
    environment_id: str | None = None
    project_id: str | None = None
    timeframe_start: dt.datetime | None = None
    timeframe_end: dt.datetime | None = None
    created_by: str | None = None


class EvidencePackResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    environment_id: str | None = None
    project_id: str | None = None
    regime: EvidenceRegime
    status: str
    timeframe_start: dt.datetime | None = None
    timeframe_end: dt.datetime | None = None
    summary: dict
    artifact: dict | None = None
    created_by: str | None = None
    created_at: dt.datetime


class PolicySimulationRequest(BaseModel):
    tenant_id: uuid.UUID
    environment_id: str
    project_id: str
    guardrail_version: int | None = None
    phase: PolicyPhase = "PRE_LLM"
    limit: int = Field(default=50, ge=1, le=250)


class PolicySimulationCaseResponse(BaseModel):
    audit_event_id: uuid.UUID
    request_id: str
    previous_action: str
    simulated_action: str
    previous_allowed: bool
    simulated_allowed: bool
    match: bool
    severity: str
    reason: str
    latency_ms: float | None = None
    created_at: dt.datetime


class PolicySimulationResponse(BaseModel):
    compared_cases: int
    matches: int
    mismatches: int
    match_rate: float
    skipped_cases: int
    results: list[PolicySimulationCaseResponse]


RegistryRiskTier = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
RegistryStatus = Literal["ACTIVE", "DISABLED", "DEPRECATED"]


class ModelRegistryUpsertRequest(BaseModel):
    tenant_id: uuid.UUID
    environment_id: str
    project_id: str
    model_id: str
    display_name: str
    provider: str
    model_type: str
    owner: str | None = None
    risk_tier: RegistryRiskTier = "MEDIUM"
    status: RegistryStatus = "ACTIVE"
    metadata: dict | None = None


class ModelRegistryResponse(BaseModel):
    tenant_id: uuid.UUID
    environment_id: str
    project_id: str
    model_id: str
    display_name: str
    provider: str
    model_type: str
    owner: str | None = None
    risk_tier: RegistryRiskTier
    status: RegistryStatus
    metadata: dict | None = None
    created_at: dt.datetime | None = None
    updated_at: dt.datetime | None = None


class AgentRegistryUpsertRequest(BaseModel):
    tenant_id: uuid.UUID
    environment_id: str
    project_id: str
    agent_id: str
    display_name: str
    runtime: str
    owner: str | None = None
    risk_tier: RegistryRiskTier = "MEDIUM"
    status: RegistryStatus = "ACTIVE"
    metadata: dict | None = None


class AgentRegistryResponse(BaseModel):
    tenant_id: uuid.UUID
    environment_id: str
    project_id: str
    agent_id: str
    display_name: str
    runtime: str
    owner: str | None = None
    risk_tier: RegistryRiskTier
    status: RegistryStatus
    metadata: dict | None = None
    created_at: dt.datetime | None = None
    updated_at: dt.datetime | None = None
