from __future__ import annotations

import argparse
import base64
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.append(str(ROOT))

from app.models.license import LicensePayload


def _pad_base64(value: str) -> str:
    return value + "=" * (-len(value) % 4)


def _load_private_key(path: Path) -> Ed25519PrivateKey:
    raw = path.read_bytes()
    try:
        key = serialization.load_pem_private_key(raw, password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise SystemExit("Private key must be Ed25519")
        return key
    except Exception:
        pass
    if len(raw) == 32:
        return Ed25519PrivateKey.from_private_bytes(raw)
    try:
        text = raw.decode("utf-8").strip()
        decoded = base64.urlsafe_b64decode(_pad_base64(text))
        return Ed25519PrivateKey.from_private_bytes(decoded)
    except Exception as exc:
        raise SystemExit("Invalid private key format") from exc


def _load_payload(path: Path) -> LicensePayload:
    data = json.loads(path.read_text(encoding="utf-8"))
    return LicensePayload.model_validate(data)


def _canonical_payload(payload: LicensePayload) -> tuple[dict, bytes]:
    payload_dict = payload.model_dump(mode="json", exclude_none=True)
    canonical = json.dumps(payload_dict, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return payload_dict, canonical


def _write_output(token: dict, out_path: Path | None) -> None:
    output = json.dumps(token, indent=2, ensure_ascii=True)
    if out_path is None:
        print(output)
        return
    out_path.write_text(output, encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Sign a DuvarAI license payload.")
    parser.add_argument("--payload", required=True, help="Path to payload JSON file.")
    parser.add_argument("--private-key", required=True, help="Path to Ed25519 private key.")
    parser.add_argument("--key-id", default=None, help="Optional key id to embed.")
    parser.add_argument("--out", default=None, help="Output path for signed token JSON.")
    args = parser.parse_args()

    payload = _load_payload(Path(args.payload))
    payload_dict, canonical = _canonical_payload(payload)
    private_key = _load_private_key(Path(args.private_key))
    signature = private_key.sign(canonical)
    signature_b64 = base64.urlsafe_b64encode(signature).decode("utf-8").rstrip("=")

    token = {"payload": payload_dict, "signature": signature_b64}
    if args.key_id:
        token["key_id"] = args.key_id

    out_path = Path(args.out) if args.out else None
    _write_output(token, out_path)


if __name__ == "__main__":
    main()
