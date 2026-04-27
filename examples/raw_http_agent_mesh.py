from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import os
import uuid
from pathlib import Path
from typing import Any

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

# Required for normal runs:
#   UMAI_ENDPOINT=http://localhost:8080
#   UMAI_API_KEY=<project API key>
#
# Required only once, when .raw_http_agent_identity.json does not exist:
#   UMAI_AGENT_BOOTSTRAP_TOKEN=<token from Control Center Agents > Registry > Token>

UMAI_ENDPOINT = os.getenv("UMAI_ENDPOINT", "http://localhost:8080").rstrip("/")
UMAI_API_KEY = os.environ["UMAI_API_KEY"]

AGENT_ID = os.getenv("UMAI_AGENT_ID", "raw-http-demo-agent")
IDENTITY_FILE = Path(__file__).with_name(".raw_http_agent_identity.json")


def canonical_json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def object_hash(data: Any) -> str:
    return hashlib.sha256(canonical_json(data).encode("utf-8")).hexdigest()


def b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + padding).encode("ascii"))


def utcnow() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def generate_identity() -> dict[str, Any]:
    private_key = Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        encoding=Encoding.Raw,
        format=PrivateFormat.Raw,
        encryption_algorithm=NoEncryption(),
    )
    public_bytes = private_key.public_key().public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw,
    )
    return {
        "agent_id": AGENT_ID,
        "private_key_b64": b64encode(private_bytes),
        "public_key_b64": b64encode(public_bytes),
    }


def sign(identity: dict[str, Any], payload: dict[str, Any]) -> str:
    private_key = Ed25519PrivateKey.from_private_bytes(b64decode(identity["private_key_b64"]))
    return b64encode(private_key.sign(canonical_json(payload).encode("utf-8")))


def agent_context(
    identity: dict[str, Any],
    *,
    event: str,
    body_hash: str,
    run_id: str | None = None,
    step_id: str | None = None,
    parent_step_id: str | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    signed_at = utcnow()
    nonce = str(uuid.uuid4())
    payload = {
        "event": event,
        "tenant_id": identity["tenant_id"],
        "environment_id": identity["environment_id"],
        "project_id": identity["project_id"],
        "agent_id": identity["agent_id"],
        "agent_did": identity["agent_did"],
        "run_id": run_id,
        "step_id": step_id,
        "parent_step_id": parent_step_id,
        "nonce": nonce,
        "signed_at": signed_at,
        "body_hash": body_hash,
    }
    if extra:
        payload.update(extra)
    return {
        "agent_id": identity["agent_id"],
        "agent_did": identity["agent_did"],
        "run_id": run_id,
        "step_id": step_id,
        "parent_step_id": parent_step_id,
        "nonce": nonce,
        "signed_at": signed_at,
        "public_key_fingerprint": identity["public_key_fingerprint"],
        "signature": sign(identity, payload),
    }


async def post(client: httpx.AsyncClient, path: str, body: dict[str, Any]) -> dict[str, Any]:
    response = await client.post(path, json=body)
    response.raise_for_status()
    return response.json()


async def patch(client: httpx.AsyncClient, path: str, body: dict[str, Any]) -> dict[str, Any]:
    response = await client.patch(path, json=body)
    response.raise_for_status()
    return response.json()


async def load_or_register_identity(client: httpx.AsyncClient) -> dict[str, Any]:
    if IDENTITY_FILE.exists():
        return json.loads(IDENTITY_FILE.read_text(encoding="utf-8"))

    bootstrap_token = os.getenv("UMAI_AGENT_BOOTSTRAP_TOKEN")
    if not bootstrap_token:
        raise RuntimeError(
            "First run requires UMAI_AGENT_BOOTSTRAP_TOKEN. Create it in "
            "Control Center > Agents > Registry > Token."
        )

    identity = generate_identity()
    registered = await post(
        client,
        "/api/v1/agent-identities/register",
        {
            "agent_id": identity["agent_id"],
            "bootstrap_token": bootstrap_token,
            "public_key_b64": identity["public_key_b64"],
            "display_name": "Raw HTTP Demo Agent",
            "runtime": "raw-http-python",
            "capabilities": ["demo:run", "tool:read"],
            "metadata": {"example": "raw_http_agent_mesh"},
        },
    )
    identity.update(
        {
            "tenant_id": registered["tenant_id"],
            "environment_id": registered["environment_id"],
            "project_id": registered["project_id"],
            "agent_did": registered["agent_did"],
            "public_key_fingerprint": registered["public_key_fingerprint"],
        }
    )
    IDENTITY_FILE.write_text(json.dumps(identity, indent=2), encoding="utf-8")
    return identity


async def start_run(client: httpx.AsyncClient, identity: dict[str, Any], run_id: str) -> None:
    body = {
        "run_id": run_id,
        "guardrail_id": None,
        "metadata": {"source": "raw_http_agent_mesh.py"},
    }
    body["agent_context"] = agent_context(
        identity,
        event="agent_run_start",
        body_hash=object_hash(body),
        run_id=run_id,
    )
    await post(client, "/api/v1/agent-runs", body)


async def record_step(
    client: httpx.AsyncClient,
    identity: dict[str, Any],
    *,
    run_id: str,
    step_id: str,
    parent_step_id: str | None,
    event_type: str,
    phase: str | None,
    status: str,
    summary: str,
    resource_type: str | None = None,
    resource_name: str | None = None,
) -> None:
    body = {
        "step_id": step_id,
        "parent_step_id": parent_step_id,
        "event_type": event_type,
        "phase": phase,
        "status": status,
        "action": None,
        "resource_type": resource_type,
        "resource_name": resource_name,
        "payload_summary": summary,
        "metadata": {"demo": True},
        "input_hash": None,
        "output_hash": None,
        "latency_ms": None,
        "decision_action": None,
        "decision_severity": None,
        "decision_reason": None,
        "policy_id": None,
        "matched_rule_id": None,
    }
    body["agent_context"] = agent_context(
        identity,
        event="agent_run_step",
        body_hash=object_hash(body),
        run_id=run_id,
        step_id=step_id,
        parent_step_id=parent_step_id,
    )
    await post(client, f"/api/v1/agent-runs/{run_id}/steps", body)


async def complete_run(client: httpx.AsyncClient, identity: dict[str, Any], run_id: str) -> None:
    body = {
        "status": "COMPLETED",
        "decision_action": "ALLOW",
        "decision_severity": "LOW",
        "summary": {"result": "demo work tree created"},
    }
    body["agent_context"] = agent_context(
        identity,
        event="agent_run_update",
        body_hash=object_hash(body),
        run_id=run_id,
    )
    await patch(client, f"/api/v1/agent-runs/{run_id}", body)


async def main() -> None:
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "X-Umai-Api-Key": UMAI_API_KEY,
    }
    async with httpx.AsyncClient(base_url=UMAI_ENDPOINT, headers=headers, timeout=15.0) as client:
        identity = await load_or_register_identity(client)
        run_id = f"raw-http-demo-{uuid.uuid4()}"

        await start_run(client, identity, run_id)
        await record_step(
            client,
            identity,
            run_id=run_id,
            step_id="agent-start",
            parent_step_id=None,
            event_type="agent.start",
            phase="PRE_LLM",
            status="COMPLETED",
            summary="Agent run started",
        )
        await record_step(
            client,
            identity,
            run_id=run_id,
            step_id="tool-input",
            parent_step_id="agent-start",
            event_type="tool.start",
            phase="TOOL_INPUT",
            status="COMPLETED",
            summary="Agent requested a demo tool call",
            resource_type="tool",
            resource_name="demo.lookup",
        )
        await record_step(
            client,
            identity,
            run_id=run_id,
            step_id="tool-output",
            parent_step_id="tool-input",
            event_type="tool.end",
            phase="TOOL_OUTPUT",
            status="COMPLETED",
            summary="Demo tool returned a safe result",
            resource_type="tool",
            resource_name="demo.lookup",
        )
        await record_step(
            client,
            identity,
            run_id=run_id,
            step_id="agent-final",
            parent_step_id="agent-start",
            event_type="agent.end",
            phase="POST_LLM",
            status="COMPLETED",
            summary="Agent produced final response",
        )
        await complete_run(client, identity, run_id)

    print(f"Created UMAI agent work tree run_id={run_id}")
    print("Open Control Center > Agents > Runs and select this run.")


if __name__ == "__main__":
    import asyncio

    asyncio.run(main())
