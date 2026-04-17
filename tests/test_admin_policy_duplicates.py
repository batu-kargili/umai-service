from __future__ import annotations

import unittest
from types import SimpleNamespace

from app.api.admin import _policy_duplicate_filters, _policy_duplicate_message


class PolicyDuplicateHelpersTests(unittest.TestCase):
    def test_project_scope_filters_include_project_id(self) -> None:
        payload = SimpleNamespace(
            tenant_id="tenant-id",
            environment_id="prod",
            project_id="chatbot",
            policy_id="pol-duplicate",
        )
        filters = _policy_duplicate_filters(payload, "PROJECT")
        self.assertEqual([filter_.left.key for filter_ in filters], [
            "tenant_id",
            "policy_id",
            "environment_id",
            "project_id",
        ])

    def test_project_scope_duplicate_message_is_project_specific(self) -> None:
        self.assertEqual(
            _policy_duplicate_message("PROJECT"),
            "Policy ID already exists in this project.",
        )


if __name__ == "__main__":
    unittest.main()
