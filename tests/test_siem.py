from __future__ import annotations

import asyncio
import json
import unittest
from contextlib import contextmanager
from typing import Iterator

from app.core import siem
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


SAMPLE_EVENT = {
    "schema": "umai.guardrail.decision.v1",
    "tenant_id": "t-1",
    "action": "BLOCK",
    "allowed": False,
    "severity": "high",
    "ts": 1_700_000_000,
}


class SplunkHecEncoderTests(unittest.TestCase):
    def test_wraps_event_in_hec_envelope(self) -> None:
        endpoint = {
            "url": "https://splunk:8088/services/collector/event",
            "format": "splunk_hec",
            "hec_token": "abc-123",
            "index": "umai",
            "sourcetype": "umai:guardrail",
        }
        payload, headers = siem._encode(SAMPLE_EVENT, endpoint)
        body = json.loads(payload)

        self.assertEqual(body["event"], SAMPLE_EVENT)
        self.assertEqual(body["sourcetype"], "umai:guardrail")
        self.assertEqual(body["source"], "umai-service")
        self.assertEqual(body["index"], "umai")
        self.assertEqual(body["time"], 1_700_000_000.0)
        self.assertEqual(headers["Authorization"], "Splunk abc-123")

    def test_falls_back_to_bearer_token_for_hec(self) -> None:
        endpoint = {
            "url": "https://splunk:8088/services/collector/event",
            "format": "splunk_hec",
            "bearer_token": "fallback-tok",
        }
        _, headers = siem._encode(SAMPLE_EVENT, endpoint)
        self.assertEqual(headers["Authorization"], "Splunk fallback-tok")

    def test_uses_current_time_when_event_has_no_timestamp(self) -> None:
        endpoint = {"url": "https://splunk", "format": "splunk_hec"}
        payload, _ = siem._encode({"action": "ALLOW"}, endpoint)
        self.assertIsInstance(json.loads(payload)["time"], float)

    def test_extra_headers_merge(self) -> None:
        endpoint = {
            "url": "https://splunk",
            "format": "splunk_hec",
            "headers": {"X-Trace": "1"},
        }
        _, headers = siem._encode(SAMPLE_EVENT, endpoint)
        self.assertEqual(headers["X-Trace"], "1")


class SourcetypeDerivationTests(unittest.TestCase):
    def test_derives_sourcetype_from_schema_and_strips_version(self) -> None:
        endpoint = {"url": "https://splunk", "format": "splunk_hec"}
        event = {"schema": "umai.admin.publish.v1", "action": "publish"}
        payload, _ = siem._encode(event, endpoint)
        self.assertEqual(json.loads(payload)["sourcetype"], "umai:admin:publish")

    def test_endpoint_sourcetype_overrides_schema(self) -> None:
        endpoint = {
            "url": "https://splunk",
            "format": "splunk_hec",
            "sourcetype": "custom:type",
        }
        payload, _ = siem._encode({"schema": "umai.admin.publish.v1"}, endpoint)
        self.assertEqual(json.loads(payload)["sourcetype"], "custom:type")

    def test_falls_back_when_schema_missing(self) -> None:
        endpoint = {"url": "https://splunk", "format": "splunk_hec"}
        payload, _ = siem._encode({"action": "x"}, endpoint)
        self.assertEqual(json.loads(payload)["sourcetype"], "umai:event")


class LeefEncoderTests(unittest.TestCase):
    def test_guardrail_decision_encodes_leef_header_and_attrs(self) -> None:
        endpoint = {"url": "https://qradar:514", "format": "leef"}
        event = {
            "schema": "umai.guardrail.decision.v1",
            "occurred_at": "2026-07-14T10:00:00+00:00",
            "tenant_id": "t-1",
            "request_id": "req-1",
            "action": "BLOCK",
            "allowed": False,
            "severity": "high",
            "reason": "tckn_iban_leak",
            "event_hash": "abc123",
        }
        payload, headers = siem._encode(event, endpoint)

        self.assertTrue(payload.startswith("LEEF:2.0|UMAI|umai-service|1.0|guardrail-decision|"))
        attrs = payload.split("|")[-1]
        fields = dict(p.split("=", 1) for p in attrs.split("\t"))
        self.assertEqual(fields["sev"], "8")
        self.assertEqual(fields["cat"], "BLOCK")
        self.assertEqual(fields["usrName"], "unknown")
        self.assertEqual(fields["tenantId"], "t-1")
        self.assertEqual(fields["requestId"], "req-1")
        self.assertEqual(fields["reason"], "tckn_iban_leak")
        self.assertEqual(fields["devTime"], "2026-07-14T10:00:00+00:00")
        self.assertEqual(headers["Content-Type"], "text/plain")

    def test_extension_event_maps_user_and_dlp_tags(self) -> None:
        endpoint = {"url": "https://qradar:514", "format": "leef"}
        event = {
            "schema": "umai.extension.event.v1",
            "event_type": "prompt_submit",
            "ts": 1_700_000_000,
            "user_email": "employee.b@example.com",
            "device_id": "dev-42",
            "decision": "ALLOW",
            "dlp_tags": ["tckn", "iban"],
            "url": "https://chat.openai.com/",
            "site": "chatgpt",
        }
        payload, _ = siem._encode(event, endpoint)

        self.assertTrue(payload.startswith("LEEF:2.0|UMAI|umai-service|1.0|extension-event|"))
        attrs = payload.split("|")[-1]
        fields = dict(p.split("=", 1) for p in attrs.split("\t"))
        self.assertEqual(fields["usrName"], "employee.b@example.com")
        self.assertEqual(fields["deviceId"], "dev-42")
        self.assertEqual(fields["dlpTags"], "tckn,iban")
        self.assertEqual(fields["sev"], "6")  # dlp hit, no explicit severity/decision block
        self.assertEqual(fields["site"], "chatgpt")

    def test_escapes_pipe_and_equals_in_values(self) -> None:
        endpoint = {"url": "https://qradar:514", "format": "leef"}
        event = {
            "schema": "umai.extension.event.v1",
            "reason": "value|with=special\tchars",
        }
        payload, _ = siem._encode(event, endpoint)
        attrs = payload.split("|", 5)[-1]
        self.assertIn("reason=value\\|with\\=special chars", attrs)

    def test_bearer_token_sets_authorization_header(self) -> None:
        endpoint = {"url": "https://qradar:514", "format": "leef", "bearer_token": "tok-1"}
        _, headers = siem._encode({"schema": "umai.event"}, endpoint)
        self.assertEqual(headers["Authorization"], "Bearer tok-1")

    def test_event_key_strips_umai_prefix_and_version_suffix(self) -> None:
        self.assertEqual(siem._leef_event_key("umai.guardrail.decision.v1"), "guardrail-decision")
        self.assertEqual(siem._leef_event_key("umai.extension.event.v1"), "extension-event")
        self.assertEqual(siem._leef_event_key(""), "event")


class JsonEncoderTests(unittest.TestCase):
    def test_default_format_is_raw_json_with_bearer(self) -> None:
        endpoint = {"url": "https://collector", "bearer_token": "tok"}
        payload, headers = siem._encode(SAMPLE_EVENT, endpoint)
        self.assertEqual(json.loads(payload), SAMPLE_EVENT)
        self.assertEqual(headers["Authorization"], "Bearer tok")

    def test_unknown_format_falls_back_to_json(self) -> None:
        endpoint = {"url": "https://collector", "format": "nope"}
        payload, _ = siem._encode(SAMPLE_EVENT, endpoint)
        self.assertEqual(json.loads(payload), SAMPLE_EVENT)


class EmitTests(unittest.TestCase):
    def test_emit_posts_hec_payload_to_endpoint(self) -> None:
        calls: list[dict] = []

        class FakeResponse:
            status_code = 200

        class FakeClient:
            def __init__(self, *a, **k) -> None:
                self.verify = k.get("verify")

            async def __aenter__(self):
                return self

            async def __aexit__(self, *a) -> None:
                return None

            async def post(self, url, content, headers):
                calls.append(
                    {
                        "url": url,
                        "content": content,
                        "headers": headers,
                        "verify": self.verify,
                    }
                )
                return FakeResponse()

        endpoints = json.dumps(
            [
                {
                    "url": "https://splunk:8088/services/collector/event",
                    "format": "splunk_hec",
                    "hec_token": "abc-123",
                }
            ]
        )
        original_client = siem.httpx.AsyncClient
        siem.httpx.AsyncClient = FakeClient  # type: ignore[assignment]
        try:
            with patched_settings(siem_endpoints_json=endpoints):
                asyncio.run(siem.emit_guardrail_event(SAMPLE_EVENT))
        finally:
            siem.httpx.AsyncClient = original_client  # type: ignore[assignment]

        self.assertEqual(len(calls), 1)
        self.assertEqual(
            calls[0]["url"], "https://splunk:8088/services/collector/event"
        )
        self.assertEqual(calls[0]["headers"]["Authorization"], "Splunk abc-123")
        self.assertEqual(json.loads(calls[0]["content"])["event"], SAMPLE_EVENT)
        # verify not set in endpoint -> defaults to True
        self.assertEqual(calls[0]["verify"], True)

    def test_emit_honors_verify_false(self) -> None:
        calls: list[dict] = []

        class FakeResponse:
            status_code = 200

        class FakeClient:
            def __init__(self, *a, **k) -> None:
                self.verify = k.get("verify")

            async def __aenter__(self):
                return self

            async def __aexit__(self, *a) -> None:
                return None

            async def post(self, url, content, headers):
                calls.append({"verify": self.verify})
                return FakeResponse()

        endpoints = json.dumps(
            [
                {
                    "url": "https://splunk:8088/services/collector/event",
                    "format": "splunk_hec",
                    "hec_token": "abc-123",
                    "verify": False,
                }
            ]
        )
        original_client = siem.httpx.AsyncClient
        siem.httpx.AsyncClient = FakeClient  # type: ignore[assignment]
        try:
            with patched_settings(siem_endpoints_json=endpoints):
                asyncio.run(siem.emit_event(SAMPLE_EVENT))
        finally:
            siem.httpx.AsyncClient = original_client  # type: ignore[assignment]

        self.assertEqual(calls[0]["verify"], False)

    def test_emit_noop_when_unconfigured(self) -> None:
        with patched_settings(siem_endpoints_json=None):
            asyncio.run(siem.emit_guardrail_event(SAMPLE_EVENT))


if __name__ == "__main__":
    unittest.main()
