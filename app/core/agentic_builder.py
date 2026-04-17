from __future__ import annotations

import json
from typing import Any

import httpx
from pydantic import ValidationError

from app.core.default_guardrail_llm import (
    build_default_guardrail_llm_config,
    default_guardrail_llm_instruction,
)
from app.core.errors import ServiceError
from app.core.settings import settings
from app.models import admin as admin_models

PHASE_ORDER = (
    "PRE_LLM",
    "POST_LLM",
    "TOOL_INPUT",
    "TOOL_OUTPUT",
    "MCP_REQUEST",
    "MCP_RESPONSE",
    "MEMORY_WRITE",
)
PHASE_ALIASES = {
    "PRE": "PRE_LLM",
    "PRE_LM": "PRE_LLM",
    "PRELLM": "PRE_LLM",
    "BEFORE": "PRE_LLM",
    "BEFORE_LLM": "PRE_LLM",
    "POST": "POST_LLM",
    "POST_LM": "POST_LLM",
    "POSTLLM": "POST_LLM",
    "AFTER": "POST_LLM",
    "AFTER_LLM": "POST_LLM",
}

AGENTIC_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["guardrail", "policies", "rationale", "notes"],
    "properties": {
        "guardrail": {
            "type": "object",
            "additionalProperties": False,
            "required": ["guardrail_id", "name", "mode", "phases", "preflight", "llm_config"],
            "properties": {
                "guardrail_id": {"type": "string"},
                "name": {"type": "string"},
                "mode": {"type": "string", "enum": ["ENFORCE", "MONITOR"]},
                "phases": {
                    "type": "array",
                    "items": {
                        "type": "string",
                        "enum": [
                            "PRE_LLM",
                            "POST_LLM",
                            "TOOL_INPUT",
                            "TOOL_OUTPUT",
                            "MCP_REQUEST",
                            "MCP_RESPONSE",
                            "MEMORY_WRITE",
                        ],
                    },
                    "minItems": 1,
                },
                "preflight": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["target", "rules"],
                    "properties": {
                        "target": {
                            "type": "string",
                            "enum": ["LAST_MESSAGE", "FULL_HISTORY"],
                        },
                        "rules": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "additionalProperties": False,
                                "required": ["id", "mode", "pattern", "block_on_match"],
                                "properties": {
                                    "id": {"type": "string"},
                                    "mode": {"type": "string", "enum": ["REGEX", "EXACT"]},
                                    "pattern": {"type": "string"},
                                    "block_on_match": {"type": "boolean"},
                                },
                            },
                        },
                        "max_length": {"type": "integer"},
                    },
                },
                "llm_config": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["provider", "base_url", "model", "timeout_ms"],
                    "properties": {
                        "provider": {"type": "string"},
                        "base_url": {"type": "string"},
                        "model": {"type": "string"},
                        "timeout_ms": {"type": "integer"},
                        "auth": {
                            "type": "object",
                            "additionalProperties": False,
                            "properties": {
                                "type": {
                                    "type": "string",
                                    "enum": ["none", "bearer", "header"],
                                },
                                "secret_env": {"type": "string"},
                                "header_name": {"type": "string"},
                            },
                        },
                    },
                },
            },
        },
        "policies": {
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["policy_id", "name", "type", "enabled", "phases", "config"],
                "properties": {
                    "policy_id": {"type": "string"},
                    "name": {"type": "string"},
                    "type": {"type": "string", "enum": ["HEURISTIC", "CONTEXT_AWARE"]},
                    "enabled": {"type": "boolean"},
                    "phases": {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "enum": [
                                "PRE_LLM",
                                "POST_LLM",
                                "TOOL_INPUT",
                                "TOOL_OUTPUT",
                                "MCP_REQUEST",
                                "MCP_RESPONSE",
                                "MEMORY_WRITE",
                            ],
                        },
                        "minItems": 1,
                    },
                    "config": {"type": "object"},
                },
            },
        },
        "rationale": {"type": "string"},
        "notes": {"type": "array", "items": {"type": "string"}},
    },
}

SYSTEM_PROMPT_PREFIX = """You are DuvarAI Guardrail Builder. Generate a guardrail and policy set for an AI agent based on the questionnaire.
Return JSON that matches the provided schema exactly. Use only these policy types:
- HEURISTIC: config has { target, rules, max_length } where rules = [{ id, mode, pattern, block_on_match }]
- CONTEXT_AWARE: config has { target, instructions, definitions_and_category_map, examples, output_schema, min_confidence_for_block, fail_closed_on_error }
Use target LAST_MESSAGE by default unless full history is required.
Keep the list to 3-6 policies. Make IDs lowercase kebab-case.
Include preflight rules for prompt-injection and system prompt probing. Set preflight max_length to 8000."""


def _system_prompt() -> str:
    return "\n".join([SYSTEM_PROMPT_PREFIX, default_guardrail_llm_instruction()])


def _build_user_prompt(payload: dict[str, Any]) -> str:
    countries = payload.get("available_countries") or []
    architecture = payload.get("architecture") or []
    return "\n".join(
        [
            "Agent questionnaire:",
            f"1) Description: {payload.get('agent_description', '')}",
            f"2) Agent type: {payload.get('agent_type', '')}",
            f"3) Target audience: {payload.get('target_audience', '')}",
            f"4) Available countries: {', '.join(countries) if countries else 'Not specified'}",
            f"5) Architecture: {', '.join(architecture) if architecture else 'Not specified'}",
            "",
            "Generate guardrails and policies that match the context, compliance needs, and risks.",
        ]
    )


def _validate_plan(plan: dict[str, Any]) -> admin_models.AgenticGuardrailResponse | None:
    try:
        return admin_models.AgenticGuardrailResponse(**plan)
    except ValidationError:
        return None


def _validation_error_summary(plan: dict[str, Any]) -> str | None:
    try:
        admin_models.AgenticGuardrailResponse(**plan)
    except ValidationError as exc:
        if exc.errors():
            first = exc.errors()[0]
            loc = ".".join(str(item) for item in first.get("loc", []))
            msg = first.get("msg", "Invalid response")
            return f"{loc}: {msg}" if loc else str(msg)
        return "Invalid response"
    return None


def _normalize_phase_value(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip().upper().replace("-", "_").replace(" ", "_")
    if normalized in PHASE_ORDER:
        return normalized
    return PHASE_ALIASES.get(normalized)


def _normalize_phase_list(values: object) -> list[str]:
    if not isinstance(values, list):
        return []
    seen: set[str] = set()
    phases: list[str] = []
    for item in values:
        normalized = _normalize_phase_value(item)
        if normalized and normalized not in seen:
            phases.append(normalized)
            seen.add(normalized)
    return [phase for phase in PHASE_ORDER if phase in phases]


def _normalize_plan_phases(plan: dict[str, Any]) -> dict[str, Any]:
    guardrail = plan.get("guardrail")
    policies = plan.get("policies")

    guardrail_phases = []
    if isinstance(guardrail, dict):
        guardrail_phases = _normalize_phase_list(guardrail.get("phases"))

    normalized_policies: list[dict[str, Any]] = []
    policy_phase_set: set[str] = set()
    if isinstance(policies, list):
        for policy in policies:
            if not isinstance(policy, dict):
                continue
            policy_phases = _normalize_phase_list(policy.get("phases"))
            if not policy_phases:
                policy_phases = guardrail_phases or ["PRE_LLM"]
            policy["phases"] = policy_phases
            for phase in policy_phases:
                policy_phase_set.add(phase)
            normalized_policies.append(policy)

    if isinstance(guardrail, dict):
        if not guardrail_phases:
            guardrail_phases = _normalize_phase_list(list(policy_phase_set))
            if not guardrail_phases:
                guardrail_phases = ["PRE_LLM"]
        guardrail["phases"] = guardrail_phases

    if normalized_policies:
        plan["policies"] = normalized_policies
    if isinstance(guardrail, dict):
        plan["guardrail"] = guardrail
    return plan


def _normalize_plan_llm_config(plan: dict[str, Any]) -> dict[str, Any]:
    guardrail = plan.get("guardrail")
    if not isinstance(guardrail, dict):
        return plan

    default_config = build_default_guardrail_llm_config()
    raw_llm_config = guardrail.get("llm_config")
    if not isinstance(raw_llm_config, dict):
        guardrail["llm_config"] = default_config
        plan["guardrail"] = guardrail
        return plan

    merged = dict(default_config)
    merged.update(raw_llm_config)
    default_auth = default_config.get("auth")
    raw_auth = raw_llm_config.get("auth")
    if isinstance(default_auth, dict):
        if isinstance(raw_auth, dict):
            merged_auth = dict(default_auth)
            merged_auth.update(raw_auth)
            merged["auth"] = merged_auth
        elif raw_auth is None:
            merged["auth"] = default_auth
    guardrail["llm_config"] = merged
    plan["guardrail"] = guardrail
    return plan


async def generate_agentic_guardrail(payload: dict[str, Any]) -> dict[str, Any]:
    if not settings.openai_api_key:
        raise ServiceError(
            "OPENAI_API_KEY_MISSING",
            "OpenAI API key is not configured.",
            503,
        )

    def build_request_body(structured: bool, messages: list[dict[str, str]]) -> dict[str, Any]:
        response_format: dict[str, Any]
        if structured:
            response_format = {
                "type": "json_schema",
                "name": "agentic_guardrail_plan",
                "strict": True,
                "schema": AGENTIC_SCHEMA,
            }
        else:
            response_format = {"type": "json_object"}

        return {
            "model": settings.openai_model,
            "input": messages,
            "temperature": 0.2,
            "text": {"format": response_format},
        }

    base_url = settings.openai_base_url.rstrip("/")
    url = f"{base_url}/responses"
    headers = {
        "Authorization": f"Bearer {settings.openai_api_key}",
        "Content-Type": "application/json",
    }

    async def send_request(structured: bool, messages: list[dict[str, str]]) -> httpx.Response:
        try:
            async with httpx.AsyncClient(timeout=settings.openai_timeout_seconds) as client:
                return await client.post(
                    url, headers=headers, json=build_request_body(structured, messages)
                )
        except httpx.RequestError as exc:
            raise ServiceError(
                "OPENAI_REQUEST_FAILED",
                "OpenAI request failed.",
                502,
                retryable=True,
            ) from exc

    def extract_error_detail(response: httpx.Response) -> str | None:
        try:
            data = response.json()
        except ValueError:
            return None
        if isinstance(data, dict):
            error = data.get("error")
            if isinstance(error, dict):
                message = error.get("message")
                if message:
                    return str(message)
        return None

    system_prompt = _system_prompt()
    base_messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": _build_user_prompt(payload)},
    ]

    response = await send_request(structured=True, messages=base_messages)
    if response.status_code >= 400:
        detail = extract_error_detail(response)
        detail_text = detail or f"OpenAI API returned status {response.status_code}."
        if response.status_code == 400 and detail:
            lowered = detail.lower()
            if "response_format" in lowered or "json_schema" in lowered or "structured" in lowered:
                response = await send_request(structured=False, messages=base_messages)
                if response.status_code >= 400:
                    fallback_detail = extract_error_detail(response)
                    message = fallback_detail or detail_text
                    raise ServiceError(
                        "OPENAI_ERROR",
                        message,
                        502,
                        retryable=response.status_code >= 500,
                    )
            else:
                raise ServiceError(
                    "OPENAI_ERROR",
                    detail_text,
                    502,
                    retryable=response.status_code >= 500,
                )
        else:
            raise ServiceError(
                "OPENAI_ERROR",
                detail_text,
                502,
                retryable=response.status_code >= 500,
            )

    data = response.json()

    def extract_output_text(payload: dict[str, Any]) -> str | None:
        output_text = payload.get("output_text")
        if isinstance(output_text, str) and output_text.strip():
            return output_text
        output_items = payload.get("output")
        if not isinstance(output_items, list):
            return None
        parts: list[str] = []
        for item in output_items:
            if not isinstance(item, dict):
                continue
            if item.get("type") != "message":
                continue
            content = item.get("content")
            if not isinstance(content, list):
                continue
            for part in content:
                if not isinstance(part, dict):
                    continue
                if part.get("type") in {"output_text", "text"}:
                    text = part.get("text")
                    if isinstance(text, str):
                        parts.append(text)
        joined = "".join(parts).strip()
        return joined or None

    content = extract_output_text(data)
    if not content:
        raise ServiceError(
            "OPENAI_EMPTY_RESPONSE",
            "OpenAI response was empty.",
            502,
        )

    try:
        plan = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ServiceError(
            "OPENAI_INVALID_JSON",
            "OpenAI did not return valid JSON.",
            502,
            retryable=True,
        ) from exc

    plan = _normalize_plan_phases(plan)
    plan = _normalize_plan_llm_config(plan)
    validated = _validate_plan(plan)
    if validated:
        return validated.model_dump()

    validation_issue = _validation_error_summary(plan) or "Invalid response schema."
    repair_prompt = "\n".join(
        [
            "The JSON response did not match the required schema.",
            "Fix the JSON to exactly match this schema:",
            json.dumps(AGENTIC_SCHEMA, separators=(",", ":"), ensure_ascii=True),
            "",
            "Invalid JSON response:",
            json.dumps(plan, separators=(",", ":"), ensure_ascii=True),
            "",
            "Return only corrected JSON.",
        ]
    )
    repair_messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": _build_user_prompt(payload)},
        {"role": "user", "content": repair_prompt},
    ]

    repair_response = await send_request(structured=False, messages=repair_messages)
    if repair_response.status_code >= 400:
        detail = extract_error_detail(repair_response)
        message = detail or validation_issue
        raise ServiceError(
            "OPENAI_INVALID_SCHEMA",
            message,
            502,
            retryable=repair_response.status_code >= 500,
        )

    try:
        repair_data = repair_response.json()
    except ValueError as exc:
        raise ServiceError(
            "OPENAI_INVALID_SCHEMA",
            "OpenAI response was not valid JSON.",
            502,
            retryable=True,
        ) from exc

    repair_content = extract_output_text(repair_data)
    if not repair_content:
        raise ServiceError(
            "OPENAI_EMPTY_RESPONSE",
            "OpenAI response was empty.",
            502,
        )
    try:
        repaired_plan = json.loads(repair_content)
    except json.JSONDecodeError as exc:
        raise ServiceError(
            "OPENAI_INVALID_SCHEMA",
            "OpenAI returned an invalid JSON schema response.",
            502,
            retryable=True,
        ) from exc

    repaired_plan = _normalize_plan_phases(repaired_plan)
    repaired_plan = _normalize_plan_llm_config(repaired_plan)
    validated = _validate_plan(repaired_plan)
    if validated:
        return validated.model_dump()

    final_issue = _validation_error_summary(repaired_plan) or validation_issue
    raise ServiceError(
        "OPENAI_INVALID_SCHEMA",
        final_issue,
        502,
        retryable=True,
    )
