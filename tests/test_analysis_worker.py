from __future__ import annotations

import unittest
from contextlib import contextmanager
from typing import Iterator

from app.api import analysis
from app.core.errors import ServiceError
from app.core.settings import settings


@contextmanager
def patched_settings(**overrides: object) -> Iterator[None]:
    original = {name: getattr(settings, name) for name in overrides}
    try:
        for name, value in overrides.items():
            setattr(settings, name, value)
        yield
    finally:
        for name, value in original.items():
            setattr(settings, name, value)


class AnalysisWorkerAuthTests(unittest.TestCase):
    def test_valid_token_is_accepted(self) -> None:
        with patched_settings(analysis_worker_token="worker-secret"):
            analysis._authenticate_worker("Bearer worker-secret")

    def test_wrong_token_is_rejected(self) -> None:
        with patched_settings(analysis_worker_token="worker-secret"):
            with self.assertRaises(ServiceError) as ctx:
                analysis._authenticate_worker("Bearer nope")
        self.assertEqual(ctx.exception.status_code, 401)

    def test_missing_header_is_rejected(self) -> None:
        with patched_settings(analysis_worker_token="worker-secret"):
            for header in (None, "", "worker-secret", "Basic worker-secret"):
                with self.assertRaises(ServiceError) as ctx:
                    analysis._authenticate_worker(header)
                self.assertEqual(ctx.exception.status_code, 401)

    def test_unconfigured_service_fails_closed(self) -> None:
        """No configured token must refuse every caller, not accept them."""
        for value in (None, "", "   "):
            with patched_settings(analysis_worker_token=value):
                with self.assertRaises(ServiceError) as ctx:
                    analysis._authenticate_worker("Bearer anything")
                self.assertEqual(ctx.exception.status_code, 500)


class StageTransitionTests(unittest.TestCase):
    def test_triage_claims_ingested_sessions(self) -> None:
        ready, claimed = analysis.STAGE_TRANSITIONS["triage"]
        self.assertEqual(ready, "ingested")
        self.assertEqual(claimed, "triaging")

    def test_reason_claims_what_triage_escalated(self) -> None:
        """The stages have to chain: triage's output status is reason's input."""
        ready, claimed = analysis.STAGE_TRANSITIONS["reason"]
        self.assertEqual(ready, "triage_suspicious")
        self.assertEqual(claimed, "reasoning")

    def test_claimed_statuses_are_distinct_from_ready_statuses(self) -> None:
        """Otherwise a claim would immediately re-claim its own work."""
        for stage, (ready, claimed) in analysis.STAGE_TRANSITIONS.items():
            self.assertNotEqual(ready, claimed, stage)


class PostureParsingTests(unittest.TestCase):
    def test_valid_posture_is_returned(self) -> None:
        self.assertEqual(
            analysis._parse_posture('{"permission_mode": "bypassPermissions"}'),
            {"permission_mode": "bypassPermissions"},
        )

    def test_absent_or_malformed_posture_is_none(self) -> None:
        for raw in (None, "", "{not json", "[1,2,3]", '"a string"'):
            self.assertIsNone(analysis._parse_posture(raw), raw)


if __name__ == "__main__":
    unittest.main()
