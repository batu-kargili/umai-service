"""Generate a single context-aware policy draft in gpt-oss-safeguard format.

Turns a plain-language operator requirement into a deep, reviewable
CONTEXT_AWARE policy whose ``instructions`` / ``definitions_and_category_map`` /
``examples`` fields follow the gpt-oss-safeguard policy structure (GOAL,
DEFINITIONS, graded CATEGORY MAP, OUTPUT FORMAT, EXAMPLES).

The engine concatenates those three text fields into the classifier system
prompt (see umai-engine ``app/policies/context_aware.py``), so the safeguard
structure maps onto the runtime with no engine changes.
"""

from __future__ import annotations

import json
import re
from typing import Any

import httpx

from app.core.errors import ServiceError
from app.core.settings import settings
from app.models import admin as admin_models

PHASES = [
    "PRE_LLM",
    "POST_LLM",
    "TOOL_INPUT",
    "TOOL_OUTPUT",
    "MCP_REQUEST",
    "MCP_RESPONSE",
    "MEMORY_WRITE",
]

DEFAULT_OUTPUT_SCHEMA = {
    "violation_field": "violation",
    "category_field": "policy_category",
    "confidence_field": "confidence",
    "rationale_field": "rationale",
}

POLICY_DRAFT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "name",
        "policy_id",
        "summary",
        "phases",
        "rationale",
        "instructions",
        "definitions_and_category_map",
        "examples",
        "min_confidence_for_block",
        "preview_examples",
    ],
    "properties": {
        "name": {"type": "string"},
        "policy_id": {"type": "string"},
        "summary": {"type": "string"},
        "phases": {
            "type": "array",
            "items": {"type": "string", "enum": PHASES},
            "minItems": 1,
        },
        "rationale": {
            "type": "array",
            "items": {"type": "string"},
            "minItems": 2,
        },
        "instructions": {"type": "string"},
        "definitions_and_category_map": {"type": "string"},
        "examples": {"type": "string"},
        "min_confidence_for_block": {
            "type": "string",
            "enum": ["low", "medium", "high"],
        },
        "preview_examples": {
            "type": "array",
            "minItems": 3,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["text", "decision"],
                "properties": {
                    "text": {"type": "string"},
                    "decision": {"type": "string", "enum": ["BLOCK", "ALLOW"]},
                },
            },
        },
    },
}

SYSTEM_PROMPT = """You are UMAI Policy Builder. Turn the operator's plain-language requirement into ONE deep, reviewable CONTEXT_AWARE guardrail policy, written in the gpt-oss-safeguard policy style.

CRITICAL FRAMING - this is an AI SYSTEM INPUT guardrail, not a rule about what a human end-customer does, and NOT about where an agent forwards data afterward.
At runtime the policy sits at the INPUT BOUNDARY of an AI system / agent and inspects the content that is about to be submitted INTO the AI model. It decides whether that content is allowed to ENTER the AI at all.

For data-protection requirements (the common case): the goal is to STOP protected/sensitive data from ENTERING the AI system in the first place - the data must not be shared with, pasted into, or submitted to the AI model. A VIOLATION is protected data appearing in the content being fed INTO the AI. This is an INGRESS guardrail:
- It is NOT about the agent's outbound actions, handoffs, tool calls, or which external destination receives data.
- It is about preventing the sensitive data from reaching the AI model at all.
Think of it like blocking someone from pasting a customer's TCKN into ChatGPT: the data simply must not enter the AI.

The engine concatenates three text fields - instructions, definitions_and_category_map, examples - into the classifier system prompt, then appends `Content: <input to the AI>\\nAnswer:`. The classifier MUST answer with a JSON object using these exact fields: violation (0 or 1), confidence ("low"|"medium"|"high"), policy_category (a code from your map), rationale (one short sentence).

Produce these fields:

1) instructions  -> gpt-oss-safeguard GOAL + decision instruction + OUTPUT FORMAT.
   - State the GOAL as keeping protected data OUT of the AI input (e.g. "Prevent protected customer data such as TCKN, IBAN, account/card numbers from being submitted into the AI system").
   - Tell the classifier it is inspecting the content being submitted to the AI and to return ONLY the JSON object.
   - violation=0 only for the lowest (allowed) category; violation=1 otherwise.

2) definitions_and_category_map  -> DEFINITIONS + a GRADED CATEGORY MAP.
   - Define the concrete protected entities that must not enter the AI. Infer the domain from the requirement (banking: TCKN, IBAN, account/card numbers, balances; insurance: policy/claim/customer numbers; healthcare: patient records). Do NOT default to insurance unless the requirement is about insurance.
   - Use 4-5 graded severity bands graded by PRESENCE AND CLARITY OF PROTECTED DATA IN THE INPUT, with short codes, e.g. CD0 (Allowed: no protected data, generic question, or anonymized/synthetic), CD2 (a partial or ambiguous identifier - medium), CD3 (one clear real customer identifier in the input - strong), CD4 (multiple identifiers or a full customer record entering the AI - maximum, escalate). Adapt to the topic.
   - Do NOT grade by destination or by what happens after - only by what protected data is present in the input.

3) examples  -> a PLAIN TEXT block of 5-8 lines. NOT a JSON array, NOT wrapped in brackets - just newline-separated lines. Each line MUST follow EXACTLY this format (an `Input to AI:` submission, an arrow, then the full JSON verdict):
   Input to AI: <submitted text> -> {"violation":1,"confidence":"high","policy_category":"CD4","rationale":"<short>"}
   For example (each on its own line):
   Input to AI: Müşteri TCKN'si 12345678901, bu kişinin durumunu özetle -> {"violation":1,"confidence":"high","policy_category":"CD4","rationale":"Gerçek müşteri tanımlayıcısı girişte"}
   Input to AI: Hesap özetimi nasıl alırım? -> {"violation":0,"confidence":"low","policy_category":"CD0","rationale":"Korunan veri yok"}
   Cover allowed, borderline, and clear-violation cases. Incorporate any operator-provided examples but RE-PHRASE them as `Input to AI:` submissions. Do NOT put quotes around the submitted text, do NOT output a JSON array, and do NOT add any keys like "text". NEVER phrase an example as "a customer sent X", and NEVER frame it as the agent forwarding/handoff to a tool or external destination.

Also produce: name (a clear, descriptive NOUN PHRASE a compliance officer would immediately understand - it must say WHAT is protected and convey that it guards the AI input. 4-8 words, Title Case, in the operator's language; include the key entity types when it adds clarity. GOOD: "Müşteri Kimlik ve Hesap Verisi AI Giriş Koruması", "Hassas Müşteri Verisi Giriş Engeli (TCKN, IBAN)". BAD: a verb fragment like "Korunan Veriyi AI'ya Alma", or vague names like "Veri Politikası" or "AI Guardrail"), policy_id (lowercase kebab-case, prefixed `pol-`), summary (one sentence about blocking protected data at the AI input), phases (this is an INGRESS guardrail - use PRE_LLM, the input boundary to the model; do NOT include the agent's outbound channels like TOOL_INPUT or MCP_REQUEST unless the operator explicitly asks to govern outbound sharing), rationale (2-4 short bullet strings explaining the design choices as an input guardrail), min_confidence_for_block ("medium" by default; "high" only if the operator gave rich examples), and preview_examples (3-5 short {text, decision} items written as `Input to AI:` submissions, mixing BLOCK and ALLOW).

Language: write instructions/definitions/examples and rationale in the SAME language as the operator's requirement (e.g. Turkish if they wrote Turkish). Keep the JSON field NAMES and the confidence VALUES (low/medium/high) and the JSON verdict keys in English so the runtime can parse them.

Return JSON that matches the provided schema exactly. No prose outside the JSON."""


def _build_user_prompt(payload: dict[str, Any]) -> str:
    blocked = payload.get("blocked_examples") or []
    allowed = payload.get("allowed_examples") or []
    tailoring = (payload.get("tailoring") or "").strip()
    lines = [
        "Operator requirement:",
        (payload.get("intent") or "").strip() or "(none provided)",
    ]
    if tailoring:
        lines += ["", "Business notes / tailoring:", tailoring]
    if blocked:
        lines += ["", "Examples that MUST be blocked:"]
        lines += [f"- {item}" for item in blocked[:8]]
    if allowed:
        lines += ["", "Examples that MUST be allowed:"]
        lines += [f"- {item}" for item in allowed[:8]]
    lines += [
        "",
        "Generate the deepest, most specific AI INPUT guardrail policy that satisfies this requirement. "
        "This is an INGRESS guardrail: the goal is to stop the protected data from ENTERING the AI system "
        "(being submitted/pasted/shared into the model). Examples must be `Input to AI:` submissions - "
        "never 'a customer did X', and never about the agent forwarding data to a tool or external destination.",
    ]
    return "\n".join(lines)


_TURKISH_TRANSLITERATION = str.maketrans(
    {
        "ç": "c", "Ç": "c", "ğ": "g", "Ğ": "g", "ı": "i", "İ": "i",
        "ö": "o", "Ö": "o", "ş": "s", "Ş": "s", "ü": "u", "Ü": "u",
    }
)


def _slugify(value: str) -> str:
    transliterated = value.strip().translate(_TURKISH_TRANSLITERATION).lower()
    slug = re.sub(r"[^a-z0-9]+", "-", transliterated).strip("-")
    return slug or "custom-policy"


def _normalize(plan: dict[str, Any]) -> dict[str, Any]:
    """Coerce the model output into a valid PolicyDraftResponse payload."""

    phases = [p for p in (plan.get("phases") or []) if p in PHASES]
    if not phases:
        phases = ["PRE_LLM"]

    confidence = str(plan.get("min_confidence_for_block") or "medium").lower()
    if confidence not in {"low", "medium", "high"}:
        confidence = "medium"

    policy_id = str(plan.get("policy_id") or "").strip()
    slug = _slugify(policy_id.replace("pol-", "", 1) or str(plan.get("name") or "policy"))
    policy_id = f"pol-{slug[:48]}"

    previews = []
    for item in plan.get("preview_examples") or []:
        if not isinstance(item, dict):
            continue
        text = str(item.get("text") or "").strip()
        decision = str(item.get("decision") or "").upper()
        if text and decision in {"BLOCK", "ALLOW"}:
            previews.append({"text": text, "decision": decision})
    if len(previews) < 2:
        previews = previews or [
            {"text": "Example that violates the policy", "decision": "BLOCK"},
            {"text": "A normal, safe request", "decision": "ALLOW"},
        ]

    rationale = [str(item) for item in (plan.get("rationale") or []) if str(item).strip()]
    if not rationale:
        rationale = [
            "Context-aware review was chosen because the rule is described in business language.",
            "The category map grades severity so borderline cases are flagged rather than hard-blocked.",
        ]

    config = {
        "target": "LAST_MESSAGE",
        "instructions": str(plan.get("instructions") or "").strip(),
        "definitions_and_category_map": str(plan.get("definitions_and_category_map") or "").strip(),
        "examples": str(plan.get("examples") or "").strip(),
        "output_schema": dict(DEFAULT_OUTPUT_SCHEMA),
        "min_confidence_for_block": confidence,
        "fail_closed_on_error": True,
    }

    return {
        "name": str(plan.get("name") or "Custom Policy").strip(),
        "policy_id": policy_id,
        "type": "CONTEXT_AWARE",
        "phases": phases,
        "summary": str(plan.get("summary") or "").strip()
        or "Turns your requirement into a context-aware safeguard policy.",
        "source_label": "AI safeguard draft",
        "rationale": rationale,
        "config": config,
        "preview_examples": previews,
    }


async def generate_policy_draft(payload: dict[str, Any]) -> dict[str, Any]:
    if not settings.openai_api_key:
        raise ServiceError(
            "OPENAI_API_KEY_MISSING",
            "OpenAI API key is not configured.",
            503,
        )

    base_url = settings.openai_base_url.rstrip("/")
    url = f"{base_url}/responses"
    headers = {
        "Authorization": f"Bearer {settings.openai_api_key}",
        "Content-Type": "application/json",
    }
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": _build_user_prompt(payload)},
    ]

    def build_body(structured: bool) -> dict[str, Any]:
        if structured:
            response_format: dict[str, Any] = {
                "type": "json_schema",
                "name": "policy_draft",
                "strict": True,
                "schema": POLICY_DRAFT_SCHEMA,
            }
        else:
            response_format = {"type": "json_object"}
        return {
            "model": settings.openai_model,
            "input": messages,
            "temperature": 0.3,
            "text": {"format": response_format},
        }

    async def send(structured: bool) -> httpx.Response:
        try:
            async with httpx.AsyncClient(timeout=settings.openai_timeout_seconds) as client:
                return await client.post(url, headers=headers, json=build_body(structured))
        except httpx.RequestError as exc:
            raise ServiceError(
                "OPENAI_REQUEST_FAILED",
                "OpenAI request failed.",
                502,
                retryable=True,
            ) from exc

    def error_detail(response: httpx.Response) -> str | None:
        try:
            data = response.json()
        except ValueError:
            return None
        if isinstance(data, dict) and isinstance(data.get("error"), dict):
            return data["error"].get("message")
        return None

    response = await send(structured=True)
    if response.status_code == 400:
        detail = (error_detail(response) or "").lower()
        if any(token in detail for token in ("response_format", "json_schema", "structured")):
            response = await send(structured=False)
    if response.status_code >= 400:
        message = error_detail(response) or f"OpenAI API returned status {response.status_code}."
        raise ServiceError(
            "OPENAI_ERROR", message, 502, retryable=response.status_code >= 500
        )

    data = response.json()

    def extract_text(body: dict[str, Any]) -> str | None:
        text = body.get("output_text")
        if isinstance(text, str) and text.strip():
            return text
        parts: list[str] = []
        for item in body.get("output") or []:
            if not isinstance(item, dict) or item.get("type") != "message":
                continue
            for part in item.get("content") or []:
                if isinstance(part, dict) and part.get("type") in {"output_text", "text"}:
                    value = part.get("text")
                    if isinstance(value, str):
                        parts.append(value)
        joined = "".join(parts).strip()
        return joined or None

    content = extract_text(data)
    if not content:
        raise ServiceError("OPENAI_EMPTY_RESPONSE", "OpenAI response was empty.", 502)

    try:
        plan = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ServiceError(
            "OPENAI_INVALID_JSON",
            "OpenAI did not return valid JSON.",
            502,
            retryable=True,
        ) from exc

    normalized = _normalize(plan)
    # Validate against the response model so the route can trust it.
    return admin_models.PolicyDraftResponse(**normalized).model_dump()
