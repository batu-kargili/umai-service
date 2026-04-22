from __future__ import annotations

import unittest

from app.core.eval_sets import get_eval_set, list_eval_sets


class EvalSetsTests(unittest.TestCase):
    def test_regulated_telecom_eval_sets_are_listed(self) -> None:
        ids = {item["id"] for item in list_eval_sets()}
        self.assertIn("tr-regulated-telecom-pre-llm", ids)
        self.assertIn("tr-regulated-telecom-post-llm", ids)
        self.assertIn("tr-regulated-telecom-tool-input", ids)
        self.assertIn("tr-regulated-telecom-mcp-request", ids)
        self.assertIn("tr-regulated-telecom-memory-write", ids)

    def test_action_eval_set_cases_include_required_metadata(self) -> None:
        tool_input = get_eval_set("tr-regulated-telecom-tool-input")
        self.assertIsNotNone(tool_input)
        for case in tool_input["cases"]:
            self.assertIn("agent_id", case)
            self.assertIn("action", case)
            self.assertIn("tool_name", case)

        mcp_request = get_eval_set("tr-regulated-telecom-mcp-request")
        self.assertIsNotNone(mcp_request)
        for case in mcp_request["cases"]:
            self.assertIn("agent_id", case)
            self.assertIn("action", case)
            self.assertIn("server_name", case)
            self.assertIn("method", case)

        memory_write = get_eval_set("tr-regulated-telecom-memory-write")
        self.assertIsNotNone(memory_write)
        for case in memory_write["cases"]:
            self.assertIn("agent_id", case)
            self.assertIn("action", case)
            self.assertIn("memory_scope", case)


if __name__ == "__main__":
    unittest.main()
