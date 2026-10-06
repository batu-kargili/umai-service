"""Policies attached to MEMORY_WRITE must be able to allow a routine write.

`pol-owasp-excessive-agency` classified "writes memory" as STATE_CHANGE and
allowed a 0 only for read-only operations. On the MEMORY_WRITE phase nothing is
read-only, so the policy could not return SAFE for any case: two benign writes
in the TR evaluation set (a non-sensitive session summary and a stated contact
preference) were escalated for human approval.

`pol-kvkk-gdpr-privacy-compliance` blocked on DATA_MINIMISATION_FAILURE.
Whether a field exceeds the purpose is a judgement, and the AGT bundle already
treats `customer_pii` as step-up rather than block, so blocking contradicted
the surrounding design and left the operator no way forward.
"""

from __future__ import annotations

import unittest

from app.core.library import POLICY_LIBRARY

EXCESSIVE_AGENCY = "pol-owasp-excessive-agency"
KVKK = "pol-kvkk-gdpr-privacy-compliance"


class ExcessiveAgencyOnMemoryWriteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = POLICY_LIBRARY[EXCESSIVE_AGENCY]
        self.config = self.policy["config"]

    def test_policy_still_covers_the_memory_write_phase(self) -> None:
        self.assertIn("MEMORY_WRITE", self.policy["phases"])

    def test_a_routine_memory_write_has_a_category_to_land_in(self) -> None:
        self.assertIn("SAFE_ROUTINE_MEMORY", self.config["definitions_and_category_map"])

    def test_that_category_is_excluded_from_the_violating_set(self) -> None:
        self.assertIn(
            "except SAFE_READ_ONLY or SAFE_ROUTINE_MEMORY",
            self.config["definitions_and_category_map"],
        )

    def test_that_category_is_not_a_step_up_category(self) -> None:
        # Anything listed here is escalated even when the model returns 0.
        self.assertNotIn("SAFE_ROUTINE_MEMORY", self.config["step_up_categories"])

    def test_regulated_memory_writes_are_still_state_changes(self) -> None:
        definitions = self.config["definitions_and_category_map"]
        self.assertIn("regulated, special-category or otherwise protected data", definitions)
        self.assertIn("STATE_CHANGE", self.config["step_up_categories"])


class KvkkMinimisationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = POLICY_LIBRARY[KVKK]["config"]

    def test_minimisation_asks_a_human_rather_than_blocking(self) -> None:
        self.assertIn("DATA_MINIMISATION_FAILURE", self.config["step_up_categories"])

    def test_unlawful_categories_still_block(self) -> None:
        for category in (
            "SPECIAL_CATEGORY_PERSONAL_DATA",
            "TELECOM_SUBSCRIBER_SECRECY",
            "UNLAWFUL_DISCLOSURE_OR_SHARING",
            "CHILD_OR_VULNERABLE_DATA",
        ):
            with self.subTest(category=category):
                self.assertIn(category, self.config["definitions_and_category_map"])
                self.assertNotIn(category, self.config["step_up_categories"])


if __name__ == "__main__":
    unittest.main()
