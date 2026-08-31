from __future__ import annotations

import time
import unittest
import uuid
from contextlib import contextmanager
from types import SimpleNamespace
from typing import Iterator

from app.api import sensor
from app.core.errors import ServiceError
from app.core.settings import settings
from app.core.agent_mesh import hash_secret


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


class EndpointSensorContractTests(unittest.TestCase):
    def test_device_token_authenticates_expected_tenant_and_device(self) -> None:
        tenant_id = uuid.uuid4()
        with patched_settings(sensor_ingest_jwt_hs256_secret="sensor-secret"):
            token, expires_at = sensor._issue_sensor_device_token(
                tenant_id=tenant_id,
                device_id="device-1",
                subject="sensor:device-1",
            )
            principal = sensor._authenticate_sensor_request(
                f"Bearer {token}",
                tenant_id,
            )

        self.assertGreater(expires_at, int(time.time()))
        self.assertEqual(principal.tenant_id, tenant_id)
        self.assertEqual(principal.device_id, "device-1")

    def test_device_token_rejects_tenant_mismatch(self) -> None:
        with patched_settings(sensor_ingest_jwt_hs256_secret="sensor-secret"):
            token, _ = sensor._issue_sensor_device_token(
                tenant_id=uuid.uuid4(),
                device_id="device-1",
                subject="sensor:device-1",
            )
            with self.assertRaises(ServiceError) as raised:
                sensor._authenticate_sensor_request(f"Bearer {token}", uuid.uuid4())

        self.assertEqual(raised.exception.status_code, 403)

    def test_policy_defaults_include_enterprise_privacy_controls(self) -> None:
        policy = sensor._with_sensor_policy_defaults({"version": "custom", "rules": []})

        self.assertEqual(policy["schema"], "umai.sensor.policy.v1")
        self.assertEqual(policy["capture_mode_default"], "metadata_only")
        self.assertEqual(policy["capture_mode_max"], "metadata_only")
        self.assertTrue(policy["privacy"]["employee_activity_visible"])
        self.assertFalse(policy["privacy"]["store_prompt_text_by_default"])
        self.assertTrue(policy["vendor_catalog"])
        self.assertTrue(policy["pinned_apps"])

    def test_effective_capture_mode_clamps_client_full_content_to_policy(self) -> None:
        policy = sensor._with_sensor_policy_defaults(
            {
                "capture_mode_default": "metadata_only",
                "capture_mode_max": "metadata_only",
                "privacy": {"content_inspection_requires_managed_policy": True},
            }
        )

        self.assertEqual(
            sensor._effective_capture_mode("full_content", policy),
            "metadata_only",
        )

    def test_effective_capture_mode_allows_full_content_when_policy_allows_it(self) -> None:
        policy = sensor._with_sensor_policy_defaults(
            {
                "capture_mode_default": "metadata_only",
                "capture_mode_max": "full_content",
                "privacy": {"content_inspection_requires_managed_policy": True},
            }
        )

        self.assertEqual(
            sensor._effective_capture_mode("full_content", policy),
            "full_content",
        )

    def test_default_guardrail_ref_can_supply_evaluate_selector(self) -> None:
        policy = sensor._with_sensor_policy_defaults(
            {
                "default_sensor_guardrail": {
                    "environment_id": "prod",
                    "project_id": "ai-governance",
                    "guardrail_id": "endpoint-default",
                    "version": 3,
                }
            }
        )

        self.assertEqual(
            sensor._resolve_sensor_guardrail_selector(
                policy,
                environment_id=None,
                project_id=None,
                guardrail_id=None,
                version=None,
            ),
            ("prod", "ai-governance", "endpoint-default", 3),
        )

    def test_sensor_guard_request_sets_endpoint_metadata(self) -> None:
        payload = sensor.SensorEvaluateRequest(
            prompt_text="Summarize this customer@example.com record",
            device=sensor.SensorDevice(device_id="device-1", hostname="host-1"),
            process=sensor.SensorProcess(pid=42, name="ChatGPT.exe", parent="explorer.exe"),
            destination=sensor.SensorDestination(
                host="api.openai.com",
                sni="api.openai.com",
                port=443,
                protocol="https",
            ),
            dlp=sensor.SensorDlp(tags=["PII_EMAIL"], riskScore=0.7),
            file_context=[
                sensor.SensorFileContextEntry(
                    path="C:\\repo\\.env",
                    opened_at_ms=1_700_000_000_000,
                    bytes_read=128,
                )
            ],
        )

        request = sensor._sensor_public_guard_request(payload)
        metadata = request.input.artifacts[0].metadata

        self.assertEqual(request.phase, "PRE_LLM")
        self.assertEqual(metadata["source"], "endpoint_sensor")
        self.assertEqual(metadata["process_name"], "ChatGPT.exe")
        self.assertEqual(metadata["destination_host"], "api.openai.com")
        self.assertEqual(metadata["device_id"], "device-1")
        self.assertEqual(metadata["dlp_tags"], ["PII_EMAIL"])
        self.assertEqual(metadata["risk_score"], 0.7)
        self.assertEqual(metadata["file_context"][0]["path"], "C:\\repo\\.env")

    def test_metadata_only_audit_sanitizer_removes_prompt_message_text(self) -> None:
        payload = sensor.SensorEvaluateRequest(
            prompt_text="secret customer@example.com",
            device=sensor.SensorDevice(device_id="device-1"),
            destination=sensor.SensorDestination(host="api.openai.com"),
        )
        request = sensor._sensor_public_guard_request(payload)

        sanitized = sensor._sanitize_sensor_request_payload_for_audit(
            request,
            "metadata_only",
        )

        self.assertNotIn("customer@example.com", sanitized.input.messages[0].content)
        self.assertEqual(sanitized.input.messages[0].content, "[metadata_only:27 chars]")

    def test_invalid_file_context_entry_is_rejected_on_evaluate_payload(self) -> None:
        with self.assertRaises(ValueError):
            sensor.SensorEvaluateRequest(
                prompt_text="hello",
                device=sensor.SensorDevice(device_id="device-1"),
                destination=sensor.SensorDestination(host="api.openai.com"),
                file_context=[{"opened_at_ms": 1}],
            )

    def test_event_payload_file_context_is_schema_filtered(self) -> None:
        entries = sensor._parse_file_context_entries(
            [
                {
                    "path": "C:\\repo\\customer.csv",
                    "opened_at_ms": 1_700_000_000_000,
                    "sha256": "a" * 64,
                    "bytes_read": 4096,
                    "extra": "ignored",
                },
                {"opened_at_ms": 1},
            ]
        )

        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].path, "C:\\repo\\customer.csv")
        self.assertEqual(entries[0].bytes_read, 4096)

    def test_sensor_event_hash_ignores_event_hash_field(self) -> None:
        tenant_id = uuid.uuid4()
        envelope = sensor.SensorEventEnvelope(
            event_id="evt-1",
            event_type="evaluate",
            tenant_id=tenant_id,
            device=sensor.SensorDevice(device_id="device-1"),
            destination=sensor.SensorDestination(host="api.openai.com", protocol="https"),
            timestamps=sensor.SensorTimestamps(captured_at_ms=1_700_000_000_000),
            chain=sensor.SensorChain(prev_event_hash=None, event_hash="placeholder"),
            payload={"decision": "allow", "prompt_hash": "abc"},
        )
        first = sensor._compute_event_hash(envelope)
        envelope.chain.event_hash = "different"
        second = sensor._compute_event_hash(envelope)

        self.assertEqual(first, second)
        self.assertEqual(len(first), 64)

    def test_download_session_bootstrap_token_row_stores_hash_only(self) -> None:
        tenant_id = uuid.uuid4()
        with patched_settings(sensor_ingest_jwt_hs256_secret="sensor-secret"):
            token, row = sensor._build_sensor_bootstrap_token_row(
                tenant_id=tenant_id,
                expires_in_seconds=1800,
                created_by="operator@umai.local",
                subject="sensor-download:test",
            )

        self.assertEqual(row.tenant_id, tenant_id)
        self.assertEqual(row.token_hash, hash_secret(token))
        self.assertNotEqual(row.token_hash, token)
        self.assertNotIn(token, repr(row))

    def test_download_session_status_only_moves_forward(self) -> None:
        row = SimpleNamespace(status="downloaded", updated_at=None)

        sensor._set_download_session_status(row, "ready")
        self.assertEqual(row.status, "downloaded")

        sensor._set_download_session_status(row, "heartbeat_seen")
        self.assertEqual(row.status, "heartbeat_seen")

        sensor._set_download_session_status(row, "failed")
        self.assertEqual(row.status, "failed")

        sensor._set_download_session_status(row, "event_seen")
        self.assertEqual(row.status, "failed")

    def test_download_session_response_exposes_no_plaintext_token(self) -> None:
        tenant_id = uuid.uuid4()
        session_id = uuid.uuid4()
        token_id = uuid.uuid4()
        now = sensor.dt.datetime.now(sensor.dt.timezone.utc)
        row = SimpleNamespace(
            id=session_id,
            tenant_id=tenant_id,
            employee_idp_subject="uid=operator,ou=users,dc=umai,dc=local",
            employee_upn="operator@umai.local",
            employee_display_name="Operator User",
            created_ip="127.0.0.1",
            created_at=now,
            updated_at=now,
            installer_version="local",
            bootstrap_token_id=token_id,
            bootstrap_token_expires_at=now + sensor.dt.timedelta(minutes=30),
            artifact_id="artifact-1",
            artifact_sha256="a" * 64,
            artifact_filename="UmaiSensor-local.msi",
            artifact_expires_at=now + sensor.dt.timedelta(hours=1),
            downloaded_at=None,
            device_id=None,
            first_heartbeat_at=None,
            last_heartbeat_at=None,
            first_event_at=None,
            identity_status=None,
            failure_reason=None,
            status="ready",
        )

        response = sensor._download_session_to_response(row)
        dumped = response.model_dump_json()

        self.assertIn(str(token_id), dumped)
        self.assertNotIn('"bootstrap_token":', dumped)
        self.assertNotIn("secret-token", dumped)


if __name__ == "__main__":
    unittest.main()
