"""An alert in the list has to name its agent and its conversation.

Both were being read from places that are empty in the default configuration:
the agent was never on the response at all, and the conversation was read from
the stored request payload, which only exists when `store_request_payloads` is
on. With a thousand agents an alert that names neither cannot be triaged.
"""

from __future__ import annotations

import datetime as dt
import unittest
import uuid

from app.api.admin import _audit_event_to_alert
from app.models.db import AuditEvent


def _event(**overrides) -> AuditEvent:
    defaults = dict(
        id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        environment_id="prod",
        project_id="poc",
        guardrail_id="gr-cps-telekom",
        guardrail_version=1,
        request_id="req-1",
        phase="TOOL_INPUT",
        action="BLOCK",
        allowed=False,
        category="HEURISTIC",
        decision_severity="HIGH",
        decision_reason="Preflight: rule preflight-tool-coercion matched",
        latency_ms=6.8,
        conversation_id="5a8d9c66-8801-4877-8064-845166cb662c",
        agent_id="3953769c-c7c1-f111-aaad-3833c5bf7e62",
        message=None,
        request_payload_json=None,
        response_payload_json=None,
        triggering_policy_json=None,
        created_at=dt.datetime.now(dt.timezone.utc),
    )
    defaults.update(overrides)
    return AuditEvent(**defaults)


class AlertIdentityTests(unittest.TestCase):
    def test_the_alert_names_its_agent(self) -> None:
        alert = _audit_event_to_alert(_event())
        self.assertEqual(alert.agent_id, "3953769c-c7c1-f111-aaad-3833c5bf7e62")

    def test_the_conversation_comes_from_the_column(self) -> None:
        # No stored payload: the default configuration.
        alert = _audit_event_to_alert(_event())
        self.assertEqual(alert.workflow, "5a8d9c66-8801-4877-8064-845166cb662c")

    def test_an_unattributed_alert_still_renders(self) -> None:
        alert = _audit_event_to_alert(_event(agent_id=None, conversation_id=None))
        self.assertIsNone(alert.agent_id)
        self.assertEqual(alert.workflow, "poc")

    def test_the_phase_is_still_the_flow(self) -> None:
        self.assertEqual(_audit_event_to_alert(_event()).flow, "TOOL_INPUT")


if __name__ == "__main__":
    unittest.main()
