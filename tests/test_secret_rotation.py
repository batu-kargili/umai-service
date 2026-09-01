"""Secret rotation with an overlap window (UMA-84).

A rotation that invalidates every live credential the instant it happens is a rotation
nobody performs. Each rotatable secret therefore has a `_previous` companion: it still
verifies (or still decrypts), but nothing is ever minted or sealed with it.

The tests below assert the three states that matter for every secret:

1. before  — only the old secret exists and works
2. overlap — both work, and new credentials are minted with the new one
3. after   — the previous value is cleared and the old secret stops working

Step 3 is the one that is easy to get wrong. If clearing `_previous` does not actually
revoke the old secret, the rotation never completed and nobody notices.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
import uuid

import pytest

from app.api import adr, analysis, extension
from app.core import transcript_store
from app.core.admin_auth import _decode_jwt_principal
from app.core.errors import ServiceError
from app.core.secret_rotation import accepted, matches_any, rotation_state
from app.core.settings import settings
from app.core.token_audiences import (
    ADR_DEVICE_TOKEN_AUDIENCE,
    EXTENSION_DEVICE_TOKEN_AUDIENCE,
)

OLD = "old-secret-value-000000000000000"
NEW = "new-secret-value-111111111111111"
THIRD = "never-configured-2222222222222222"
TENANT = uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def mint(payload: dict, secret: str) -> str:
    header = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = _b64(json.dumps(payload).encode())
    signature = hmac.new(
        secret.encode(), f"{header}.{body}".encode("ascii"), hashlib.sha256
    ).digest()
    return f"{header}.{body}.{_b64(signature)}"


def admin_payload() -> dict:
    return {
        "sub": "operator@example.com",
        "tenant_id": str(TENANT),
        "roles": ["tenant-admin"],
        "exp": int(time.time()) + 600,
    }


def device_payload(audience: str) -> dict:
    return {
        "sub": "device",
        "tenant_id": str(TENANT),
        "device_id": "device-a",
        "aud": audience,
        "roles": ["tenant-device"],
        "exp": int(time.time()) + 600,
    }


class TestAcceptedSet:
    def test_only_the_current_secret_when_no_rotation(self) -> None:
        assert accepted(NEW, None) == [NEW]

    def test_both_secrets_during_a_rotation_current_first(self) -> None:
        assert accepted(NEW, OLD) == [NEW, OLD]

    def test_blank_and_whitespace_values_are_ignored(self) -> None:
        assert accepted("  ", "") == []
        assert accepted(f"  {NEW}  ", None) == [NEW]

    def test_a_duplicated_value_is_not_listed_twice(self) -> None:
        assert accepted(NEW, NEW) == [NEW]

    def test_a_previous_secret_alone_still_verifies(self) -> None:
        """Half-finished rotations happen; the service should not simply fail closed."""
        assert accepted(None, OLD) == [OLD]

    @pytest.mark.parametrize(
        ("current", "previous", "expected"),
        [
            (None, None, "unset"),
            (NEW, None, "single"),
            (NEW, OLD, "overlap"),
            # Looks rotated, is not — worth naming so an operator can be told.
            (NEW, NEW, "identical"),
        ],
    )
    def test_rotation_state_is_reported(self, current, previous, expected) -> None:
        assert rotation_state(current, previous) == expected

    def test_matching_is_constant_time_across_every_candidate(self) -> None:
        assert matches_any(OLD, [NEW, OLD]) is True
        assert matches_any(NEW, [NEW, OLD]) is True
        assert matches_any(THIRD, [NEW, OLD]) is False
        assert matches_any(None, [NEW]) is False
        assert matches_any(OLD, []) is False


class TestAdminJwtRotation:
    @pytest.fixture(autouse=True)
    def _configured(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(settings, "admin_jwt_audience", None)

    def rotate(self, monkeypatch: pytest.MonkeyPatch, current, previous) -> None:
        monkeypatch.setattr(settings, "admin_jwt_hs256_secret", current)
        monkeypatch.setattr(settings, "admin_jwt_hs256_secret_previous", previous)

    def test_before_rotation_the_old_secret_works(self, monkeypatch) -> None:
        self.rotate(monkeypatch, OLD, None)
        assert _decode_jwt_principal(mint(admin_payload(), OLD)).tenant_id == TENANT

    def test_during_the_overlap_both_secrets_work(self, monkeypatch) -> None:
        self.rotate(monkeypatch, NEW, OLD)
        assert _decode_jwt_principal(mint(admin_payload(), OLD)).tenant_id == TENANT
        assert _decode_jwt_principal(mint(admin_payload(), NEW)).tenant_id == TENANT

    def test_after_clearing_previous_the_old_secret_is_dead(self, monkeypatch) -> None:
        self.rotate(monkeypatch, NEW, None)
        with pytest.raises(ServiceError) as caught:
            _decode_jwt_principal(mint(admin_payload(), OLD))
        assert caught.value.status_code == 401
        assert _decode_jwt_principal(mint(admin_payload(), NEW)).tenant_id == TENANT

    def test_an_unrelated_secret_never_works(self, monkeypatch) -> None:
        self.rotate(monkeypatch, NEW, OLD)
        with pytest.raises(ServiceError):
            _decode_jwt_principal(mint(admin_payload(), THIRD))

    def test_expiry_is_still_enforced_under_the_previous_secret(self, monkeypatch) -> None:
        """A rotation window must not become an expiry window."""
        self.rotate(monkeypatch, NEW, OLD)
        expired = {**admin_payload(), "exp": int(time.time()) - 1}
        with pytest.raises(ServiceError) as caught:
            _decode_jwt_principal(mint(expired, OLD))
        assert caught.value.error_type == "TOKEN_EXPIRED"

    def test_a_foreign_audience_is_still_refused_under_the_previous_secret(
        self, monkeypatch
    ) -> None:
        self.rotate(monkeypatch, NEW, OLD)
        payload = {**admin_payload(), "aud": ADR_DEVICE_TOKEN_AUDIENCE}
        with pytest.raises(ServiceError) as caught:
            _decode_jwt_principal(mint(payload, OLD))
        assert "not valid for admin access" in caught.value.message

    def test_no_secret_configured_is_a_misconfiguration_not_a_bypass(
        self, monkeypatch
    ) -> None:
        self.rotate(monkeypatch, None, None)
        with pytest.raises(ServiceError) as caught:
            _decode_jwt_principal(mint(admin_payload(), OLD))
        assert caught.value.status_code == 500


class TestWorkerTokenRotation:
    def rotate(self, monkeypatch: pytest.MonkeyPatch, current, previous) -> None:
        monkeypatch.setattr(settings, "analysis_worker_token", current)
        monkeypatch.setattr(settings, "analysis_worker_token_previous", previous)

    def test_during_the_overlap_both_tokens_work(self, monkeypatch) -> None:
        self.rotate(monkeypatch, NEW, OLD)
        analysis._authenticate_worker(f"Bearer {OLD}")
        analysis._authenticate_worker(f"Bearer {NEW}")

    def test_after_clearing_previous_the_old_token_is_dead(self, monkeypatch) -> None:
        self.rotate(monkeypatch, NEW, None)
        with pytest.raises(ServiceError) as caught:
            analysis._authenticate_worker(f"Bearer {OLD}")
        assert caught.value.status_code == 401

    def test_an_unrelated_token_never_works(self, monkeypatch) -> None:
        self.rotate(monkeypatch, NEW, OLD)
        with pytest.raises(ServiceError):
            analysis._authenticate_worker(f"Bearer {THIRD}")

    def test_no_token_configured_is_a_misconfiguration(self, monkeypatch) -> None:
        self.rotate(monkeypatch, None, None)
        with pytest.raises(ServiceError) as caught:
            analysis._authenticate_worker(f"Bearer {OLD}")
        assert caught.value.status_code == 500


class TestCollectorSecretRotation:
    def rotate(self, monkeypatch: pytest.MonkeyPatch, current, previous) -> None:
        monkeypatch.setattr(settings, "adr_ingest_jwt_hs256_secret", current)
        monkeypatch.setattr(settings, "adr_ingest_jwt_hs256_secret_previous", previous)

    def test_during_the_overlap_a_fleet_keeps_working(self, monkeypatch) -> None:
        """The point of the overlap: live device tokens survive the rotation."""
        self.rotate(monkeypatch, NEW, OLD)
        for secret in (OLD, NEW):
            principal = adr._authenticate_device(
                f"Bearer {mint(device_payload(ADR_DEVICE_TOKEN_AUDIENCE), secret)}", TENANT
            )
            assert principal.tenant_id == TENANT

    def test_after_clearing_previous_old_device_tokens_are_dead(self, monkeypatch) -> None:
        self.rotate(monkeypatch, NEW, None)
        with pytest.raises(ServiceError) as caught:
            adr._authenticate_device(
                f"Bearer {mint(device_payload(ADR_DEVICE_TOKEN_AUDIENCE), OLD)}", TENANT
            )
        assert caught.value.status_code == 401

    def test_new_tokens_are_always_signed_with_the_current_secret(self, monkeypatch) -> None:
        """Minting with the previous secret would issue credentials about to be revoked."""
        self.rotate(monkeypatch, NEW, OLD)
        token, _ = adr._issue_adr_device_token(
            tenant_id=TENANT, device_id="device-a", subject="adr:device-a"
        )
        # Verifies under the new secret alone, i.e. it was not signed with the old one.
        self.rotate(monkeypatch, NEW, None)
        assert adr._authenticate_device(f"Bearer {token}", TENANT).tenant_id == TENANT

    def test_tenant_and_audience_checks_survive_the_overlap(self, monkeypatch) -> None:
        self.rotate(monkeypatch, NEW, OLD)
        wrong_audience = mint(device_payload(EXTENSION_DEVICE_TOKEN_AUDIENCE), OLD)
        with pytest.raises(ServiceError):
            adr._authenticate_device(f"Bearer {wrong_audience}", TENANT)


class TestExtensionSecretRotation:
    def rotate(self, monkeypatch: pytest.MonkeyPatch, current, previous) -> None:
        monkeypatch.setattr(settings, "extension_ingest_jwt_hs256_secret", current)
        monkeypatch.setattr(
            settings, "extension_ingest_jwt_hs256_secret_previous", previous
        )
        monkeypatch.setattr(settings, "extension_ingest_bearer_token", None)

    def test_during_the_overlap_both_secrets_work(self, monkeypatch) -> None:
        self.rotate(monkeypatch, NEW, OLD)
        for secret in (OLD, NEW):
            token = mint(device_payload(EXTENSION_DEVICE_TOKEN_AUDIENCE), secret)
            principal = extension._authenticate_extension_request(
                f"Bearer {token}", TENANT
            )
            assert principal.tenant_id == TENANT

    def test_after_clearing_previous_the_old_secret_is_dead(self, monkeypatch) -> None:
        self.rotate(monkeypatch, NEW, None)
        token = mint(device_payload(EXTENSION_DEVICE_TOKEN_AUDIENCE), OLD)
        with pytest.raises(ServiceError):
            extension._authenticate_extension_request(f"Bearer {token}", TENANT)


class TestTranscriptKeyRotation:
    """The hardest rotation: the old key is the only thing that can read old evidence."""

    @staticmethod
    def key() -> str:
        return base64.b64encode(os.urandom(32)).decode()

    @pytest.fixture(autouse=True)
    def _reset_store(self) -> None:
        transcript_store.reset_transcript_store()

    def configure(self, monkeypatch: pytest.MonkeyPatch, current, previous=None) -> None:
        monkeypatch.setattr(settings, "transcript_encryption_key", current)
        monkeypatch.setattr(settings, "transcript_encryption_key_previous", previous)

    def test_a_blob_sealed_with_the_old_key_is_readable_during_the_overlap(
        self, monkeypatch
    ) -> None:
        old_key, new_key = self.key(), self.key()
        self.configure(monkeypatch, old_key)
        sealed = transcript_store.seal(b'{"messages": []}')

        self.configure(monkeypatch, new_key, old_key)
        assert transcript_store.unseal(sealed) == b'{"messages": []}'

    def test_rotating_without_the_overlap_would_lose_the_evidence(
        self, monkeypatch
    ) -> None:
        """This is what UMA-84 fixes: without _PREVIOUS the old blob is unreadable."""
        old_key, new_key = self.key(), self.key()
        self.configure(monkeypatch, old_key)
        sealed = transcript_store.seal(b'{"messages": []}')

        self.configure(monkeypatch, new_key, None)
        with pytest.raises(transcript_store.TranscriptDecryptionError):
            transcript_store.unseal(sealed)

    def test_new_blobs_are_sealed_with_the_current_key_only(self, monkeypatch) -> None:
        old_key, new_key = self.key(), self.key()
        self.configure(monkeypatch, new_key, old_key)
        sealed = transcript_store.seal(b"fresh")

        # Readable with the new key alone, so it was not sealed with the old one.
        self.configure(monkeypatch, new_key, None)
        assert transcript_store.unseal(sealed) == b"fresh"

    def test_an_unencrypted_blob_stays_readable_through_a_rotation(
        self, monkeypatch
    ) -> None:
        self.configure(monkeypatch, None)
        plain = transcript_store.seal(b"written before encryption")
        self.configure(monkeypatch, self.key(), self.key())
        assert transcript_store.unseal(plain) == b"written before encryption"

    def test_a_blob_from_a_third_key_is_refused_not_silently_garbled(
        self, monkeypatch
    ) -> None:
        stranger = self.key()
        self.configure(monkeypatch, stranger)
        sealed = transcript_store.seal(b"someone else's")

        self.configure(monkeypatch, self.key(), self.key())
        with pytest.raises(transcript_store.TranscriptDecryptionError) as caught:
            transcript_store.unseal(sealed)
        assert "different key" in str(caught.value)

    def test_needs_resealing_identifies_what_blocks_finishing_a_rotation(
        self, monkeypatch
    ) -> None:
        old_key, new_key = self.key(), self.key()
        self.configure(monkeypatch, old_key)
        old_blob = transcript_store.seal(b"old")

        self.configure(monkeypatch, new_key, old_key)
        new_blob = transcript_store.seal(b"new")
        # The old blob still needs resealing; the new one does not. Until the first is
        # false everywhere, the previous key cannot be cleared.
        assert transcript_store.needs_resealing(old_blob) is True
        assert transcript_store.needs_resealing(new_blob) is False

    def test_an_unencrypted_blob_needs_sealing_once_encryption_is_on(
        self, monkeypatch
    ) -> None:
        self.configure(monkeypatch, None)
        plain = transcript_store.seal(b"plaintext")
        assert transcript_store.needs_resealing(plain) is False
        self.configure(monkeypatch, self.key())
        assert transcript_store.needs_resealing(plain) is True

    def test_a_reseal_makes_the_blob_current_and_preserves_the_content(
        self, monkeypatch
    ) -> None:
        old_key, new_key = self.key(), self.key()
        self.configure(monkeypatch, old_key)
        original = b'{"messages": [{"role": "user"}]}'
        old_blob = transcript_store.seal(original)

        self.configure(monkeypatch, new_key, old_key)
        resealed = transcript_store.seal(transcript_store.unseal(old_blob))
        assert transcript_store.needs_resealing(resealed) is False

        # With the rotation finished, the resealed blob is still readable and identical.
        self.configure(monkeypatch, new_key, None)
        assert transcript_store.unseal(resealed) == original

    def test_the_content_digest_is_unchanged_by_a_rotation(self, monkeypatch) -> None:
        """References are digests of plaintext, so resealing must not orphan pointers."""
        payload = b'{"messages": []}'
        before = transcript_store.transcript_sha256(payload)
        self.configure(monkeypatch, self.key(), self.key())
        assert transcript_store.transcript_sha256(payload) == before

    def test_a_malformed_previous_key_fails_loudly(self, monkeypatch) -> None:
        self.configure(monkeypatch, self.key(), "not-base64!!")
        sealed = transcript_store.seal(b"x")
        with pytest.raises(RuntimeError) as caught:
            transcript_store.unseal(sealed)
        assert "PREVIOUS" in str(caught.value)
