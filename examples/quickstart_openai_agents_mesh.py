from __future__ import annotations

import asyncio
import json
import os
import uuid
from pathlib import Path
from typing import Annotated, Any, Literal

from agents import Agent, Runner, function_tool

from umai import AgentIdentity, AgentMesh, FileIdentityStore, GuardrailPhase, UmaiClient, object_hash
from umai.integrations.openai_agents import UmaiOpenAIGovernanceHooks

"""
Quickstart: OpenAI Agents SDK protected by UMAI Agent Mesh Governance.

UMAI customer configuration:
  UMAI_ENDPOINT=http://localhost:8080
  UMAI_API_KEY=<project API key>

Runtime configuration:
  OPENAI_API_KEY=<OpenAI API key>
  UMAI_GUARDRAIL_ID=<guardrail id to evaluate>

First run only:
  UMAI_AGENT_BOOTSTRAP_TOKEN=<Control Center > Agents > Registry > Token>

After the first run, the agent identity is saved by the UMAI SDK identity store,
so future runs only need the endpoint/API key for UMAI plus the OpenAI runtime
key.
"""

UMAI_ENDPOINT = os.getenv("UMAI_ENDPOINT", "http://localhost:8080")
UMAI_API_KEY = os.environ["UMAI_API_KEY"]
UMAI_GUARDRAIL_ID = os.environ["UMAI_GUARDRAIL_ID"]
UMAI_AGENT_ID = os.getenv("UMAI_AGENT_ID", "openai-agents-quickstart")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")


LEGACY_IDENTITY_FILE = Path(__file__).with_name(".quickstart_openai_agents_identity.json")
IDENTITY_STORE_ROOT = Path(__file__).with_name(".umai-agent-identities")

UMAI_AGENT: AgentMesh | None = None
RUN_ID = ""
CURRENT_PROMPT = ""
ROOT_STEP_ID: str | None = None


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


async def build_umai_agent() -> AgentMesh:
    client = UmaiClient(
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

        result = await Runner.run(
            agent,
            CURRENT_PROMPT,
            hooks=hooks,
        )
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

        await hooks.finish(
            status="COMPLETED",
            summary={"final_output_hash": object_hash(final_output)},
        )
        print("\nAgent output:")
        print(final_output)
        print(f"\nUMAI run_id: {RUN_ID}")
        print("Open Control Center > Agents > Runs to inspect the work tree.")
    except Exception:
        await hooks.finish(status="FAILED", summary={"error": "quickstart run failed"})
        raise


if __name__ == "__main__":
    asyncio.run(main())
