from __future__ import annotations

import uuid

from app.core.agent_mesh import public_key_fingerprint, signature_payload, trust_tier_for_score, verify_signature
from app.models.public import AgentSignedContext
from umai_agent_sdk import UmaiAgentClient, UmaiAgentIdentity, object_hash


def test_sdk_signature_matches_service_contract() -> None:
    tenant_id = uuid.uuid4()
    identity = UmaiAgentIdentity.generate("agent-1")
    identity.tenant_id = str(tenant_id)
    identity.environment_id = "dev"
    identity.project_id = "project"
    identity.agent_did = f"did:umai:test:{identity.agent_id}"
    identity.public_key_fingerprint = public_key_fingerprint(identity.public_key_b64)
    client = UmaiAgentClient(
        base_url="https://umai.example",
        api_key="uk_test",
        identity=identity,
    )
    body = {
        "phase": "TOOL_INPUT",
        "input": {"messages": [], "phase_focus": "LAST_ASSISTANT_MESSAGE", "artifacts": []},
        "timeout_ms": 1500,
    }

    context = AgentSignedContext.model_validate(
        client.agent_context(
            event="guard",
            body_hash=object_hash(body),
            run_id="run-1",
            step_id="step-1",
            extra={"guardrail_id": "gr-1", "phase": "TOOL_INPUT"},
        )
    )

    payload = signature_payload(
        tenant_id=tenant_id,
        environment_id="dev",
        project_id="project",
        context=context,
        event="guard",
        body_hash=object_hash(body),
        extra={"guardrail_id": "gr-1", "phase": "TOOL_INPUT"},
    )
    verify_signature(identity.public_key_b64, context.signature, payload)


def test_trust_tier_boundaries() -> None:
    assert trust_tier_for_score(0.10) == "SANDBOX"
    assert trust_tier_for_score(0.60) == "STANDARD"
    assert trust_tier_for_score(0.95) == "PRIVILEGED"
