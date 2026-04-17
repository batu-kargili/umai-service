from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from app.models.public import GuardrailPhase, InputPayload


class EngineFlags(BaseModel):
    allow_llm_calls: bool = True


class EngineRequest(BaseModel):
    request_id: str
    timestamp: str
    tenant_id: str
    environment_id: str
    project_id: str
    guardrail_id: str
    guardrail_version: int
    phase: GuardrailPhase
    input: InputPayload
    timeout_ms: int | None = 1500
    flags: EngineFlags = Field(default_factory=EngineFlags)


class EngineDecision(BaseModel):
    action: str
    allowed: bool
    severity: str
    reason: str


class EngineTriggeringPolicy(BaseModel):
    policy_id: str
    type: str
    name: str
    status: str
    severity: str
    score: float | None = None
    details: dict
    latency_ms: float


class EngineLatency(BaseModel):
    total: float
    preflight: float | None = None


class EngineError(BaseModel):
    type: str
    source: str | None = None
    message: str | None = None
    retryable: bool | None = None


class EngineResponse(BaseModel):
    request_id: str
    tenant_id: str
    environment_id: str
    project_id: str
    guardrail_id: str
    guardrail_version: int
    phase: str
    decision: EngineDecision
    triggering_policy: EngineTriggeringPolicy | None = None
    output_modifications: dict | None = None
    latency_ms: EngineLatency
    errors: list[EngineError] = Field(default_factory=list)
