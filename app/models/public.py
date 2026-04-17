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
    metadata: dict = Field(default_factory=dict)


class InputPayload(BaseModel):
    messages: list[ChatMessage]
    phase_focus: Literal["LAST_USER_MESSAGE", "LAST_ASSISTANT_MESSAGE"]
    content_type: Literal["text", "markdown", "json"] = "text"
    language: str | None = None
    artifacts: list[InputArtifact] = Field(default_factory=list)


class PublicGuardRequest(BaseModel):
    conversation_id: str | None = None
    phase: GuardrailPhase
    input: InputPayload
    timeout_ms: int = 1500


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
