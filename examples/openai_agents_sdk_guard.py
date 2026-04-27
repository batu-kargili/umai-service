from __future__ import annotations

import asyncio
import os
import uuid
from typing import Annotated, Any

from agents import Agent, Runner, ToolSearchTool, function_tool, tool_namespace

from umai_agent_sdk import UmaiAgentClient, UmaiAgentIdentity, object_hash

# Required:
#   OPENAI_API_KEY
#   UMAI_API_KEY
#   UMAI_GUARDRAIL_ID
#
# First registration run:
#   UMAI_AGENT_BOOTSTRAP_TOKEN=<token from Control Center/Admin API>
#   UMAI_AGENT_ID=operations-assistant
#
# Later runs:
#   UMAI_AGENT_PRIVATE_KEY_B64=<printed from first registration>
#   UMAI_AGENT_DID=<returned by registration>
#   UMAI_AGENT_PUBLIC_KEY_FINGERPRINT=<returned by registration>
#   UMAI_TENANT_ID / UMAI_ENVIRONMENT_ID / UMAI_PROJECT_ID=<returned by registration>

UMAI_SERVICE_URL = os.getenv("UMAI_SERVICE_URL", "http://127.0.0.1:8080")
UMAI_GUARDRAIL_ID = os.environ["UMAI_GUARDRAIL_ID"]
UMAI_API_KEY = os.environ["UMAI_API_KEY"]
UMAI_AGENT_ID = os.getenv("UMAI_AGENT_ID", "operations-assistant")

CURRENT_USER_PROMPT = "selam"
RUN_ID = str(uuid.uuid4())
UMAI_CLIENT: UmaiAgentClient | None = None


def build_identity() -> UmaiAgentIdentity:
    private_key = os.getenv("UMAI_AGENT_PRIVATE_KEY_B64")
    identity = (
        UmaiAgentIdentity.from_private_key(UMAI_AGENT_ID, private_key)
        if private_key
        else UmaiAgentIdentity.generate(UMAI_AGENT_ID)
    )
    identity.agent_did = os.getenv("UMAI_AGENT_DID")
    identity.public_key_fingerprint = os.getenv("UMAI_AGENT_PUBLIC_KEY_FINGERPRINT")
    identity.tenant_id = os.getenv("UMAI_TENANT_ID")
    identity.environment_id = os.getenv("UMAI_ENVIRONMENT_ID")
    identity.project_id = os.getenv("UMAI_PROJECT_ID")
    return identity


async def build_client() -> UmaiAgentClient:
    identity = build_identity()
    client = UmaiAgentClient(
        base_url=UMAI_SERVICE_URL,
        api_key=UMAI_API_KEY,
        identity=identity,
    )
    bootstrap_token = os.getenv("UMAI_AGENT_BOOTSTRAP_TOKEN")
    if bootstrap_token:
        result = await client.register_identity(
            bootstrap_token=bootstrap_token,
            display_name="Operations Assistant",
            runtime="openai-agents",
            capabilities=["crm:read", "orders:read"],
            metadata={"example": "openai_agents_sdk_guard"},
        )
        print("Registered UMAI agent identity:")
        print(result)
        print("Persist UMAI_AGENT_PRIVATE_KEY_B64 for later runs:")
        print(identity.private_key_b64)
    return client


async def umai_guard(
    *,
    phase: str,
    messages: list[dict[str, str]],
    phase_focus: str,
    artifacts: list[dict[str, Any]] | None = None,
    parent_step_id: str | None = None,
) -> None:
    if UMAI_CLIENT is None:
        raise RuntimeError("UMAI client is not initialized")
    step_id = str(uuid.uuid4())
    result = await UMAI_CLIENT.guard(
        guardrail_id=UMAI_GUARDRAIL_ID,
        phase=phase,
        run_id=RUN_ID,
        step_id=step_id,
        parent_step_id=parent_step_id,
        input_payload={
            "messages": messages,
            "phase_focus": phase_focus,
            "content_type": "text",
            "artifacts": artifacts or [],
        },
        conversation_id=RUN_ID,
    )
    decision = result["decision"]
    if decision["action"] == "STEP_UP_APPROVAL" or not decision["allowed"]:
        raise RuntimeError(f"UMAI blocked {phase}: {decision['reason']}")


async def guard_tool(tool_name: str, customer_id: str, classification: str) -> None:
    await umai_guard(
        phase="TOOL_INPUT",
        messages=[
            {"role": "user", "content": CURRENT_USER_PROMPT},
            {"role": "assistant", "content": f"Call {tool_name} for {customer_id}."},
        ],
        phase_focus="LAST_ASSISTANT_MESSAGE",
        artifacts=[
            {
                "artifact_type": "TOOL_INPUT",
                "name": tool_name,
                "payload_summary": f"{tool_name} for {customer_id}",
                "metadata": {
                    "tool_name": tool_name,
                    "action": "lookup",
                    "classification": classification,
                    "side_effect": False,
                },
            }
        ],
    )


@function_tool(defer_loading=True)
async def get_customer_profile(
    customer_id: Annotated[str, "The customer ID to look up."],
) -> str:
    """Fetch a CRM customer profile."""
    await guard_tool("crm.get_customer_profile", customer_id, "customer_pii")
    return f"profile for {customer_id}"


@function_tool(defer_loading=True)
async def list_open_orders(
    customer_id: Annotated[str, "The customer ID to look up."],
) -> str:
    """List open orders for a customer."""
    await guard_tool("crm.list_open_orders", customer_id, "business_record")
    return f"open orders for {customer_id}"


crm_tools = tool_namespace(
    name="crm",
    description="CRM tools for customer lookups.",
    tools=[get_customer_profile, list_open_orders],
)


agent = Agent(
    name="Operations assistant",
    model=os.getenv("OPENAI_MODEL", "gpt-5.5"),
    instructions="Load the crm namespace before using CRM tools.",
    tools=[*crm_tools, ToolSearchTool()],
)


async def run_guarded(prompt: str) -> str:
    global CURRENT_USER_PROMPT, UMAI_CLIENT
    UMAI_CLIENT = await build_client()
    CURRENT_USER_PROMPT = prompt

    await UMAI_CLIENT.start_run(
        run_id=RUN_ID,
        guardrail_id=UMAI_GUARDRAIL_ID,
        metadata={"prompt_hash": object_hash(prompt)},
    )
    try:
        await umai_guard(
            phase="PRE_LLM",
            messages=[{"role": "user", "content": prompt}],
            phase_focus="LAST_USER_MESSAGE",
        )

        result = await Runner.run(agent, prompt)
        final_output = str(result.final_output)

        await umai_guard(
            phase="POST_LLM",
            messages=[
                {"role": "user", "content": prompt},
                {"role": "assistant", "content": final_output},
            ],
            phase_focus="LAST_ASSISTANT_MESSAGE",
        )
        await UMAI_CLIENT.complete_run(
            run_id=RUN_ID,
            status="COMPLETED",
            decision_action="ALLOW",
            decision_severity="LOW",
            summary={"output_hash": object_hash(final_output)},
        )
        return final_output
    except Exception:
        await UMAI_CLIENT.complete_run(run_id=RUN_ID, status="FAILED")
        raise


async def main() -> None:
    result = await run_guarded("Look up customer_42 and list their open orders.")
    print(result)


if __name__ == "__main__":
    asyncio.run(main())
