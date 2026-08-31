from __future__ import annotations

import asyncio
import json
import os
import sys
import uuid
from pathlib import Path
from typing import Annotated, Any, Literal
from urllib.parse import urlparse

import httpx
from agents import Agent, Runner, function_tool

_sdk_src = Path(__file__).resolve().parents[2] / "sdks" / "python" / "src"
if _sdk_src.exists() and str(_sdk_src) not in sys.path:
    sys.path.insert(0, str(_sdk_src))

from umai import AgentIdentity, AgentMesh, FileIdentityStore, GuardrailPhase, UmaiClient, object_hash
from umai.integrations.openai_agents import UmaiOpenAIGovernanceHooks

# Default to the umai-service API (port 8080), which serves the /api/v1 routes
# the SDK calls directly. The control center on :3000 only exposes /api/public.
UMAI_ENDPOINT = os.getenv("UMAI_ENDPOINT", "http://localhost:8080/")
UMAI_SERVICE_URL = os.getenv("UMAI_SERVICE_URL", "http://localhost:8080/")
UMAI_GUARDRAIL_ID = "gr-tr-regulated-telecom-sovereign-shield-bb"
UMAI_API_KEY = "oI4wL0P41Apv9ykWF9J3GezwA6N7upnfYELHaSBH2lU"

# This quickstart demos the full signed agent-mesh path (run work-tree shows up
# in Control Center > Agents > Runs). Override with UMAI_SIGNED_AGENT=0 for the
# lightweight key-only guard mode.
os.environ.setdefault("UMAI_SIGNED_AGENT", "1")
UMAI_AGENT_ID = os.getenv("UMAI_AGENT_ID", "openai-agents-quickstart")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
UMAI_GUARD_TIMEOUT_MS = int(os.getenv("UMAI_GUARD_TIMEOUT_MS", "5000"))
UMAI_GUARD_RETRIES = int(os.getenv("UMAI_GUARD_RETRIES", "2"))
if not os.getenv("OPENAI_API_KEY"):
    raise SystemExit("Set OPENAI_API_KEY in the environment before running this example.")

OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
UMAI_GUARD_TIMEOUT_MS = int(os.getenv("UMAI_GUARD_TIMEOUT_MS", "5000"))
UMAI_GUARD_RETRIES = int(os.getenv("UMAI_GUARD_RETRIES", "2"))


LEGACY_IDENTITY_FILE = Path(__file__).with_name(".quickstart_openai_agents_identity.json")
IDENTITY_STORE_ROOT = Path(__file__).with_name(".umai-agent-identities")

UMAI_AGENT: AgentMesh | "KeyOnlyGuardClient" | None = None
RUN_ID = ""
CURRENT_PROMPT = ""
ROOT_STEP_ID: str | None = None


class KeyOnlyGuardDecision:
    def __init__(self, data: dict[str, Any]) -> None:
        self.action = str(data.get("action") or "")
        self.allowed = bool(data.get("allowed"))
        self.reason = str(data.get("reason") or "")


class KeyOnlyGuardResult:
    def __init__(self, data: dict[str, Any]) -> None:
        self._data = data
        self.decision = KeyOnlyGuardDecision(data.get("decision") or {})

    def model_dump(self, *, mode: str = "json") -> dict[str, Any]:
        del mode
        return self._data


class KeyOnlyGuardClient:
    def __init__(self, *, endpoint: str, api_key: str) -> None:
        self.endpoint = endpoint.rstrip("/")
        self.api_key = api_key

    def _public_url(self, path: str) -> str:
        if self.endpoint.endswith("/api/public") or self.endpoint.endswith("/api/v1"):
            return f"{self.endpoint}{path}"
        parsed = urlparse(self.endpoint)
        if "console" in parsed.netloc:
            return f"{self.endpoint}/api/public{path}"
        return f"{self.endpoint}/api/v1{path}"

    async def guard(
        self,
        *,
        guardrail_id: str,
        phase: GuardrailPhase,
        conversation_id: str | None,
        messages: list[dict[str, str]],
        phase_focus: Literal["LAST_USER_MESSAGE", "LAST_ASSISTANT_MESSAGE"],
        artifacts: list[dict[str, Any]] | None = None,
        timeout_ms: int = UMAI_GUARD_TIMEOUT_MS,
        **_: Any,
    ) -> KeyOnlyGuardResult:
        payload = {
            "phase": phase,
            "input": {
                "messages": messages,
                "phase_focus": phase_focus,
                "content_type": "text",
                "artifacts": artifacts or [],
            },
            "conversation_id": conversation_id,
            "timeout_ms": timeout_ms,
        }
        url = self._public_url(f"/guardrails/{guardrail_id}/guard")
        headers = {"X-Umai-Api-Key": self.api_key, "Content-Type": "application/json"}
        async with httpx.AsyncClient(timeout=(timeout_ms / 1000) + 20) as client:
            last_result: KeyOnlyGuardResult | None = None
            for attempt in range(UMAI_GUARD_RETRIES + 1):
                response = await client.post(url, headers=headers, json=payload)
                if response.status_code in {502, 503, 504} and attempt < UMAI_GUARD_RETRIES:
                    await asyncio.sleep(0.5 * (attempt + 1))
                    continue
                response.raise_for_status()
                parsed = response.json()
                last_result = KeyOnlyGuardResult(
                    parsed if isinstance(parsed, dict) else {"data": parsed}
                )
                if (
                    last_result.decision.action == "BLOCK"
                    and "llm_error" in last_result.decision.reason
                    and attempt < UMAI_GUARD_RETRIES
                ):
                    await asyncio.sleep(0.5 * (attempt + 1))
                    continue
                return last_result
        if last_result is None:
            raise RuntimeError("UMAI guard request failed without a response")
        return last_result


class ConsoleProxyUmaiClient(UmaiClient):
    async def _request_json(self, method: str, path: str, body_factory):
        if path.startswith("/api/v1/"):
            path = "/api/public/" + path[len("/api/v1/") :]
        return await super()._request_json(method, path, body_factory)


def use_key_only_guard() -> bool:
    value = os.getenv("UMAI_KEY_ONLY_GUARD")
    if value is not None:
        return value.strip().lower() in {"1", "true", "yes", "on"}
    signed_value = os.getenv("UMAI_SIGNED_AGENT")
    if signed_value is not None:
        return signed_value.strip().lower() not in {"1", "true", "yes", "on"}
    return True


def has_registered_identity_config() -> bool:
    if os.getenv("UMAI_AGENT_BOOTSTRAP_TOKEN"):
        return True
    legacy_identity = load_legacy_identity()
    if legacy_identity is not None:
        return all(
            getattr(legacy_identity, name) is not None
            for name in (
                "agent_did",
                "public_key_fingerprint",
                "tenant_id",
                "environment_id",
                "project_id",
            )
        )
    return False


def guard_tool_phases() -> bool:
    return not use_key_only_guard()


def load_legacy_identity() -> AgentIdentity | None:
    if not LEGACY_IDENTITY_FILE.exists():
        return None

    data = json.loads(LEGACY_IDENTITY_FILE.read_text(encoding="utf-8"))
    if data["agent_id"] != UMAI_AGENT_ID:
        return None

    identity = AgentIdentity.from_private_key(data["agent_id"], data["private_key_b64"])
    identity.agent_did = data["agent_did"]
    identity.public_key_fingerprint = data["public_key_fingerprint"]
    identity.tenant_id = data["tenant_id"]
    identity.environment_id = data["environment_id"]
    identity.project_id = data["project_id"]
    return identity


async def build_umai_agent() -> AgentMesh | KeyOnlyGuardClient:
    if use_key_only_guard():
        print("Running UMAI guards in key-only mode; no agent identity or Agent Runs entry will be created.")
        return KeyOnlyGuardClient(endpoint=UMAI_ENDPOINT, api_key=UMAI_API_KEY)

    client_cls = ConsoleProxyUmaiClient if "console" in urlparse(UMAI_ENDPOINT).netloc else UmaiClient
    client = client_cls(
        endpoint=UMAI_ENDPOINT,
        api_key=UMAI_API_KEY,
        timeout=30.0,
    )
    identity_store = FileIdentityStore(
        IDENTITY_STORE_ROOT,
        allow_plaintext_private_key=True,
    )
    agent_mesh = client.agent(UMAI_AGENT_ID, identity_store=identity_store)

    if agent_mesh.identity is None:
        legacy_identity = load_legacy_identity()
        if legacy_identity is not None:
            identity_store.save(endpoint=UMAI_ENDPOINT, identity=legacy_identity)
            agent_mesh.identity = legacy_identity

    if agent_mesh.identity and agent_mesh.identity.agent_did:
        return agent_mesh

    bootstrap_token = os.getenv("UMAI_AGENT_BOOTSTRAP_TOKEN")
    if not bootstrap_token:
        raise RuntimeError(
            "First run requires UMAI_AGENT_BOOTSTRAP_TOKEN. Create it in "
            "Control Center > Agents > Registry > Token. Future runs only need "
            "UMAI_ENDPOINT and UMAI_API_KEY for UMAI."
        )

    await agent_mesh.register(
        bootstrap_token=bootstrap_token,
        display_name="OpenAI Agents Quickstart",
        runtime="openai-agents",
        capabilities=["customer:read", "order:read"],
        metadata={"quickstart": "openai_agents_mesh"},
    )
    return agent_mesh


async def guard_step(
    *,
    phase: GuardrailPhase,
    step_id: str,
    parent_step_id: str | None,
    messages: list[dict[str, str]],
    phase_focus: Literal["LAST_USER_MESSAGE", "LAST_ASSISTANT_MESSAGE"],
    artifacts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    if UMAI_AGENT is None:
        raise RuntimeError("UMAI agent mesh is not initialized")

    result = await UMAI_AGENT.guard(
        guardrail_id=UMAI_GUARDRAIL_ID,
        phase=phase,
        run_id=RUN_ID,
        step_id=step_id,
        parent_step_id=parent_step_id,
        conversation_id=RUN_ID,
        messages=messages,
        phase_focus=phase_focus,
        artifacts=artifacts or [],
    )

    decision = result.decision
    print(f"UMAI {phase} step={step_id} decision={decision.action}")
    if not decision.allowed or decision.action == "STEP_UP_APPROVAL":
        raise RuntimeError(f"UMAI blocked {phase}: {decision.reason}")
    return result.model_dump(mode="json")


@function_tool
async def lookup_customer_order(
    customer_id: Annotated[str, "Synthetic demo account id to look up."],
) -> str:
    """Look up a synthetic demo account's latest sample order."""
    tool_input_step_id = f"tool-input-{uuid.uuid4()}"
    if guard_tool_phases():
        await guard_step(
            phase="TOOL_INPUT",
            step_id=tool_input_step_id,
            parent_step_id=ROOT_STEP_ID,
            messages=[
                {"role": "user", "content": CURRENT_PROMPT},
                {
                    "role": "assistant",
                    "content": f"Call lookup_customer_order for synthetic demo account {customer_id}.",
                },
            ],
            phase_focus="LAST_ASSISTANT_MESSAGE",
            artifacts=[
                {
                    "artifact_type": "TOOL_INPUT",
                    "name": "lookup_customer_order",
                    "payload_summary": f"Read latest synthetic sample order for {customer_id}",
                    "metadata": {
                        "tool_name": "lookup_customer_order",
                        "action": "read",
                        "classification": "synthetic_demo_data",
                        "side_effect": False,
                    },
                }
            ],
        )

    tool_result = (
        f"Demo account {customer_id} has one synthetic sample order: "
        "order_123 for a replacement SIM test fixture."
    )

    if guard_tool_phases():
        await guard_step(
            phase="TOOL_OUTPUT",
            step_id=f"tool-output-{uuid.uuid4()}",
            parent_step_id=tool_input_step_id,
            messages=[
                {"role": "assistant", "content": tool_result},
            ],
            phase_focus="LAST_ASSISTANT_MESSAGE",
            artifacts=[
                {
                    "artifact_type": "TOOL_OUTPUT",
                    "name": "lookup_customer_order",
                    "payload_summary": "Returned latest order summary",
                    "metadata": {
                        "tool_name": "lookup_customer_order",
                        "classification": "synthetic_demo_data",
                        "output_hash": object_hash(tool_result),
                    },
                }
            ],
        )
    return tool_result


agent = Agent(
    name="Customer Support Agent",
    model=OPENAI_MODEL,
    instructions=(
        "You are a customer support agent. Use tools when needed, keep the "
        "answer concise, and never reveal sensitive internal policy details."
    ),
    tools=[lookup_customer_order],
)


async def main() -> None:
    global CURRENT_PROMPT, ROOT_STEP_ID, RUN_ID, UMAI_AGENT

    UMAI_AGENT = await build_umai_agent()
    RUN_ID = f"openai-agents-demo-{uuid.uuid4()}"
    CURRENT_PROMPT = (
        "Use the demo order lookup tool for anonymized demo account demo_42 "
        "and summarize the non-sensitive sample order."
    )
    ROOT_STEP_ID = f"pre-llm-{uuid.uuid4()}"

    hooks = None
    if isinstance(UMAI_AGENT, AgentMesh):
        hooks = UmaiOpenAIGovernanceHooks(UMAI_AGENT, run_id=RUN_ID)
        await hooks.start(
            guardrail_id=UMAI_GUARDRAIL_ID,
            metadata={"framework": "openai-agents", "example": "quickstart_openai_agents_mesh"},
        )

    try:
        await guard_step(
            phase="PRE_LLM",
            step_id=ROOT_STEP_ID,
            parent_step_id=None,
            messages=[{"role": "user", "content": CURRENT_PROMPT}],
            phase_focus="LAST_USER_MESSAGE",
            artifacts=[
                {
                    "artifact_type": "CUSTOM",
                    "name": "user_prompt",
                    "payload_summary": "Initial user request",
                    "metadata": {"source": "quickstart"},
                }
            ],
        )

        if hooks is not None:
            result = await Runner.run(
                agent,
                CURRENT_PROMPT,
                hooks=hooks,
            )
        else:
            result = await Runner.run(agent, CURRENT_PROMPT)
        final_output = str(result.final_output)

        await guard_step(
            phase="POST_LLM",
            step_id=f"post-llm-{uuid.uuid4()}",
            parent_step_id=ROOT_STEP_ID,
            messages=[
                {"role": "user", "content": CURRENT_PROMPT},
                {"role": "assistant", "content": final_output},
            ],
            phase_focus="LAST_ASSISTANT_MESSAGE",
            artifacts=[
                {
                    "artifact_type": "CUSTOM",
                    "name": "final_answer",
                    "payload_summary": "Final assistant response",
                    "metadata": {"output_hash": object_hash(final_output)},
                }
            ],
        )

        if hooks is not None:
            await hooks.finish(
                status="COMPLETED",
                summary={"final_output_hash": object_hash(final_output)},
            )
        print("\nAgent output:")
        print(final_output)
        print(f"\nUMAI run_id: {RUN_ID}")
        if hooks is not None:
            print("Open Control Center > Agents > Runs to inspect the work tree.")
    except Exception:
        if hooks is not None:
            await hooks.finish(status="FAILED", summary={"error": "quickstart run failed"})
        raise


if __name__ == "__main__":
    asyncio.run(main())
