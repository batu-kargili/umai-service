"""An alert has to say which agent raised it, and stop short of the content.

Copilot Studio signs nothing, so its agent id arrives in the artifact metadata.
The old fixed whitelist kept nine descriptors of the action and dropped every
identifier, so alerts from that channel could not be grouped by agent or traced
back to a conversation -- unreadable once a tenant runs more than a handful.

The widening stops at identifiers. `params` carries the tool's input values,
and storing request content is governed by `store_request_payloads`; carrying
it here would route around that setting.
"""

from __future__ import annotations

import unittest

from app.core.action_resource import agent_identity, extract_action_resource
from app.models.public import InputArtifact, InputPayload, PublicGuardRequest

METADATA = {
    "agent_id": "3953769c-c7c1-f111-aaad-3833c5bf7e62",
    "agent_version": "1.0.0",
    "conversation_id": "5a8d9c66-8801-4877-8064-845166cb662c",
    "plan_id": "47139a1e-a0ca-4e9f-b36a-1c1975ee66c9",
    "plan_step_id": "82158dcc-fe08-4ed6-bd75-2aba64d0ba64",
    "tool_id": "tool-123",
    "correlation_id": "98c421f9-45c3-4a44-8806-f4f3173e343a",
    "source": "copilot_studio",
    "action": "export",
    "tool_name": "Export subscriber call records",
    "classification": "subscriber_secret_bulk_export",
    "params": {"msisdn": "+905321234567", "destination": "attacker@evil.com"},
}


def _request(metadata: dict | None = METADATA, conversation_id: str = "conv-1"):
    return PublicGuardRequest(
        conversation_id=conversation_id,
        phase="TOOL_INPUT",
        input=InputPayload(
            messages=[{"role": "user", "content": "export the subscriber data"}],
            phase_focus="LAST_USER_MESSAGE",
            artifacts=[
                InputArtifact(
                    artifact_type="TOOL_INPUT",
                    name="Export subscriber call records",
                    metadata=dict(metadata or {}),
                )
            ],
        ),
    )


class ActionResourceTests(unittest.TestCase):
    def test_identity_and_correlation_survive(self) -> None:
        resource = extract_action_resource(_request())
        assert resource is not None
        for field in (
            "agent_id",
            "agent_version",
            "conversation_id",
            "plan_id",
            "plan_step_id",
            "tool_id",
            "correlation_id",
            "source",
        ):
            with self.subTest(field=field):
                self.assertEqual(resource[field], METADATA[field])

    def test_the_action_descriptors_are_still_carried(self) -> None:
        resource = extract_action_resource(_request())
        assert resource is not None
        self.assertEqual(resource["action"], "export")
        self.assertEqual(resource["tool_name"], "Export subscriber call records")
        self.assertEqual(resource["classification"], "subscriber_secret_bulk_export")
        self.assertEqual(resource["artifact_type"], "TOOL_INPUT")

    def test_request_content_is_not_carried(self) -> None:
        # `params` holds the tool's input values. Storing request content is
        # governed by `store_request_payloads`, and this must not bypass it.
        resource = extract_action_resource(_request())
        assert resource is not None
        self.assertNotIn("params", resource)
        self.assertNotIn("+905321234567", str(resource))

    def test_a_request_without_artifacts_has_no_action_resource(self) -> None:
        request = PublicGuardRequest(
            phase="PRE_LLM",
            input=InputPayload(
                messages=[{"role": "user", "content": "selam"}],
                phase_focus="LAST_USER_MESSAGE",
            ),
        )
        self.assertIsNone(extract_action_resource(request))

    def test_missing_metadata_yields_empty_fields_not_an_error(self) -> None:
        resource = extract_action_resource(_request(metadata={}))
        assert resource is not None
        self.assertIsNone(resource["agent_id"])
        self.assertIsNone(resource["action"])


class AgentIdentityTests(unittest.TestCase):
    def test_the_channel_reported_agent_is_returned(self) -> None:
        resource = extract_action_resource(_request())
        self.assertEqual(agent_identity(resource), METADATA["agent_id"])

    def test_no_resource_and_no_agent_are_both_none(self) -> None:
        self.assertIsNone(agent_identity(None))
        self.assertIsNone(agent_identity({}))
        self.assertIsNone(agent_identity({"agent_id": ""}))


if __name__ == "__main__":
    unittest.main()
