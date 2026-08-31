from __future__ import annotations

import unittest

from app.api.extension import _is_security_relevant_extension_event


class ExtensionSiemFilterTests(unittest.TestCase):
    def test_block_decision_is_forwarded(self) -> None:
        self.assertTrue(
            _is_security_relevant_extension_event(
                decision="block", chain_is_valid=True, dlp_tags=[]
            )
        )

    def test_decision_is_case_insensitive(self) -> None:
        self.assertTrue(
            _is_security_relevant_extension_event(
                decision="WARN", chain_is_valid=True, dlp_tags=[]
            )
        )

    def test_broken_chain_is_always_forwarded(self) -> None:
        self.assertTrue(
            _is_security_relevant_extension_event(
                decision="allow", chain_is_valid=False, dlp_tags=[]
            )
        )

    def test_dlp_tags_force_forwarding(self) -> None:
        self.assertTrue(
            _is_security_relevant_extension_event(
                decision="allow", chain_is_valid=True, dlp_tags=["PII"]
            )
        )

    def test_benign_allow_is_dropped(self) -> None:
        self.assertFalse(
            _is_security_relevant_extension_event(
                decision="allow", chain_is_valid=True, dlp_tags=[]
            )
        )

    def test_missing_decision_is_dropped(self) -> None:
        self.assertFalse(
            _is_security_relevant_extension_event(
                decision=None, chain_is_valid=True, dlp_tags=[]
            )
        )


if __name__ == "__main__":
    unittest.main()
