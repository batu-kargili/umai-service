"""Every category a policy can emit must fit the audit column.

`audit_events.category` was varchar(32) while the policy library shipped four
longer names, among them SIM_SWAP_OR_NUMBER_PORT_OUT_ABUSE and
LAWFUL_INTERCEPT_OR_SURVEILLANCE_ABUSE. A decision in one of those failed its
audit insert with StringDataRightTruncationError, which failed the whole guard
request with a 500 -- so the most serious detections returned no decision to
the caller at all.
"""

from __future__ import annotations

import re
import unittest

from app.core.library import POLICY_LIBRARY
from app.models.db import AuditEvent

#: Token shape used for policy categories throughout the library.
_CATEGORY = re.compile(r"\b[A-Z][A-Z0-9_]{6,}\b")

#: Words that match the token shape but are prose or JSON scaffolding, not
#: categories the engine would ever write to the audit row.
_NOT_CATEGORIES = {"INSTRUCTIONS", "DEFINITIONS", "EXAMPLES", "VIOLATES", "OUTPUT", "UNSPECIFIED"}


def shipped_categories() -> set[str]:
    found: set[str] = set()
    for template in POLICY_LIBRARY.values():
        config = template.get("config") or {}
        for value in config.values():
            if isinstance(value, str):
                found.update(_CATEGORY.findall(value))
            elif isinstance(value, list):
                # Only plain category tokens; `rules` holds dicts whose repr
                # would otherwise be mistaken for very long category names.
                found.update(
                    item for item in value
                    if isinstance(item, str) and _CATEGORY.fullmatch(item)
                )
    return {c for c in found if c not in _NOT_CATEGORIES}


class AuditCategoryWidthTests(unittest.TestCase):
    def test_the_column_fits_every_shipped_category(self) -> None:
        limit = AuditEvent.__table__.c.category.type.length
        too_long = sorted(
            (len(c), c) for c in shipped_categories() if len(c) > limit
        )
        self.assertEqual(
            too_long,
            [],
            f"categories longer than audit_events.category ({limit}): {too_long}",
        )

    def test_the_previously_breaking_categories_are_still_covered(self) -> None:
        limit = AuditEvent.__table__.c.category.type.length
        for category in (
            "SIM_SWAP_OR_NUMBER_PORT_OUT_ABUSE",
            "EXECUTIVE_OR_REGULATOR_IMPERSONATION",
            "LAWFUL_INTERCEPT_OR_SURVEILLANCE_ABUSE",
            "HIGH_RISK_PROFILING_OR_AUTOMATED_DECISION",
        ):
            with self.subTest(category=category):
                self.assertGreater(len(category), 32, "sample no longer exercises the old limit")
                self.assertLessEqual(len(category), limit)


if __name__ == "__main__":
    unittest.main()
