from __future__ import annotations

from typing import Literal

import datetime as dt
import uuid

from pydantic import BaseModel, Field

GuardrailPhase = Literal[
    "PRE_LLM",
    "POST_LLM",
    "TOOL_INPUT",
    "TOOL_OUTPUT",
    "MCP_REQUEST",
    "MCP_RESPONSE",
    "MEMORY_WRITE",
]

GuardrailAction = Literal[
    "ALLOW",
    "BLOCK",
    "FLAG",
    "ALLOW_WITH_MODIFICATIONS",
    "ALLOW_WITH_WARNINGS",
    "STEP_UP_APPROVAL",
]


class ChatMessage(BaseModel):
    role: Literal["system", "user", "assistant"]
    content: str


class InputArtifact(BaseModel):
    artifact_type: Literal[
        "TOOL_INPUT",
        "TOOL_OUTPUT",
        "MCP_REQUEST",
        "MCP_RESPONSE",
        "MEMORY_WRITE",
        "CUSTOM",
    ] = "CUSTOM"
    name: str | None = None
    payload_summary: str | None = None
    content: str | None = None
    content_type: Literal["text", "markdown", "json"] = "text"
    metadata: dict = Field(default_factory=dict)


class InputPayload(BaseModel):
    messages: list[ChatMessage]
    phase_focus: Literal["LAST_USER_MESSAGE", "LAST_ASSISTANT_MESSAGE"]
    content_type: Literal["text", "markdown", "json"] = "text"
    language: str | None = None
    artifacts: list[InputArtifact] = Field(default_factory=list)


class AgentSignedContext(BaseModel):
    agent_id: str
    agent_did: str
    nonce: str
    signed_at: dt.datetime
    signature: str
    run_id: str | None = None
    step_id: str | None = None
    parent_step_id: str | None = None
    public_key_fingerprint: str | None = None


class PublicGuardRequest(BaseModel):
    conversation_id: str | None = None
    phase: GuardrailPhase
    input: InputPayload
    timeout_ms: int = 1500
    agent_context: AgentSignedContext | None = None


class Decision(BaseModel):
    action: GuardrailAction
    allowed: bool
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    reason: str


class TriggeringPolicy(BaseModel):
    policy_id: str
    type: str
    status: str


class PublicGuardResponse(BaseModel):
    request_id: str
    decision: Decision
    category: str | None = None
    triggering_policy: TriggeringPolicy | None = None
    output_modifications: dict | None = None
    latency_ms: int
    errors: list[dict] = Field(default_factory=list)


JobStatus = Literal[
    "QUEUED",
    "RUNNING",
    "COMPLETED",
    "FAILED",
    "TIMEOUT",
    "CANCELED",
]


class PublicGuardAsyncRequest(PublicGuardRequest):
    webhook_url: str | None = None
    webhook_secret: str | None = None


class PublicGuardAsyncResponse(BaseModel):
    job_id: uuid.UUID
    status: JobStatus
    created_at: dt.datetime


class GuardrailJobStatusResponse(BaseModel):
    job_id: uuid.UUID
    status: JobStatus
    request_id: str
    created_at: dt.datetime
    updated_at: dt.datetime | None = None
    completed_at: dt.datetime | None = None
    error: str | None = None
    result: PublicGuardResponse | None = None


class GuardrailJobWaitRequest(BaseModel):
    timeout_ms: int = Field(default=15000, ge=100, le=60000)
    poll_interval_ms: int = Field(default=250, ge=50, le=2000)


class ErrorBody(BaseModel):
    type: str
    message: str
    retryable: bool = False


class ErrorResponse(BaseModel):
    error: ErrorBody


class FreeSubscriptionRequest(BaseModel):
    tenant_name: str = Field(min_length=1, max_length=200)
    admin_email: str | None = Field(default=None, max_length=320)


class FreeSubscriptionResponse(BaseModel):
    tenant_id: uuid.UUID
    plan: str
    license_expires_at: dt.datetime


AgentRunStatus = Literal["RUNNING", "COMPLETED", "FAILED", "CANCELED", "TIMEOUT"]
AgentStepStatus = Literal["RECORDED", "RUNNING", "COMPLETED", "FAILED", "BLOCKED", "WARNED"]


class AgentIdentityRegisterRequest(BaseModel):
    agent_id: str
    bootstrap_token: str
    public_key_b64: str
    display_name: str | None = None
    runtime: str | None = None
    capabilities: list[str] = Field(default_factory=list)
    metadata: dict = Field(default_factory=dict)


class AgentIdentityRegisterResponse(BaseModel):
    tenant_id: uuid.UUID
    environment_id: str
    project_id: str
    agent_id: str
    agent_did: str
    public_key_fingerprint: str
    trust_score: float
    trust_tier: str
    identity_status: str


class AgentRunStartRequest(BaseModel):
    run_id: str | None = None
    guardrail_id: str | None = None
    agent_context: AgentSignedContext
    metadata: dict = Field(default_factory=dict)


class AgentRunPatchRequest(BaseModel):
    status: AgentRunStatus
    decision_action: str | None = None
    decision_severity: str | None = None
    summary: dict | None = None
    agent_context: AgentSignedContext


class AgentRunSessionResponse(BaseModel):
    tenant_id: uuid.UUID
    environment_id: str
    project_id: str
    run_id: str
    agent_id: str
    agent_did: str
    guardrail_id: str | None = None
    status: str
    decision_action: str | None = None
    decision_severity: str | None = None
    trust_score: float | None = None
    trust_tier: str | None = None
    summary: dict | None = None
    started_at: dt.datetime | None = None
    updated_at: dt.datetime | None = None
    completed_at: dt.datetime | None = None


class AgentRunStepCreateRequest(BaseModel):
    step_id: str | None = None
    parent_step_id: str | None = None
    event_type: str
    phase: GuardrailPhase | None = None
    status: AgentStepStatus = "RECORDED"
    action: str | None = None
    resource_type: str | None = None
    resource_name: str | None = None
    payload_summary: str | None = None
    metadata: dict = Field(default_factory=dict)
    input_hash: str | None = None
    output_hash: str | None = None
    latency_ms: float | None = None
    decision_action: str | None = None
    decision_severity: str | None = None
    decision_reason: str | None = None
    policy_id: str | None = None
    matched_rule_id: str | None = None
    agent_context: AgentSignedContext


class AgentRunStepResponse(BaseModel):
    run_id: str
    step_id: str
    parent_step_id: str | None = None
    sequence: int
    event_type: str
    phase: str | None = None
    status: str
    agent_id: str
    agent_did: str
    action: str | None = None
    resource_type: str | None = None
    resource_name: str | None = None
    decision_action: str | None = None
    decision_severity: str | None = None
    decision_reason: str | None = None
    policy_id: str | None = None
    matched_rule_id: str | None = None
    latency_ms: float | None = None
    payload_summary: str | None = None
    metadata: dict | None = None
    input_hash: str | None = None
    output_hash: str | None = None
    prev_step_hash: str | None = None
    step_hash: str | None = None
    created_at: dt.datetime | None = None
