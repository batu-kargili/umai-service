"""What an alert says about the action that triggered it.

An operator looking at a wall of alerts asks two things first: which agent, and
where in its run. The phase answers the second. The first used to be
unanswerable on channels that do not carry a signed agent identity -- Copilot
Studio sends its agent id in the artifact metadata, and the old fixed whitelist
dropped it along with every correlation id, so the alert could not be traced
back to the agent or the conversation it came from.

Only identifiers are carried. `params` holds the tool's input values, which are
request content: storing those is governed by `store_request_payloads`, and
widening this would route around that setting.
"""

from __future__ import annotations

from typing import Any

#: Descriptors of the action itself.
_ACTION_FIELDS = (
    "action",
    "tool_name",
    "server_name",
    "method",
    "memory_scope",
    "resource_id",
    "classification",
)

#: Identity and correlation. These are what make an alert traceable at scale.
_CORRELATION_FIELDS = (
    "agent_id",
    "agent_version",
    "conversation_id",
    "plan_id",
    "plan_step_id",
    "tool_id",
    "correlation_id",
    "source",
)


def extract_action_resource(request_payload: Any) -> dict | None:
    """Summarise the first artifact of a guard request, or None if there is none."""

    artifacts = getattr(getattr(request_payload, "input", None), "artifacts", None)
    if not artifacts:
        return None

    artifact = artifacts[0]
    metadata = artifact.metadata or {}

    resource: dict[str, Any] = {
        "artifact_type": artifact.artifact_type,
        "name": artifact.name,
    }
    for field in _ACTION_FIELDS + _CORRELATION_FIELDS:
        resource[field] = metadata.get(field)
    return resource


def agent_identity(action_resource: dict | None) -> str | None:
    """The agent id a channel reported in metadata, when it signed nothing.

    Used only as a fallback: a verified `AgentSignedContext` always wins, since
    that identity is cryptographic and this one is self-asserted.
    """

    if not action_resource:
        return None
    value = action_resource.get("agent_id")
    return str(value) if value else None
