from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import time
import urllib.error
import urllib.request
import urllib.parse
from typing import Any


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def build_extension_jwt(
    *,
    tenant_id: str,
    secret: str,
    audience: str,
    roles: list[str],
    subject: str,
    ttl_seconds: int = 3600,
) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    now = int(time.time())
    payload = {
        "sub": subject,
        "tenant_id": tenant_id,
        "aud": audience,
        "iat": now,
        "exp": now + ttl_seconds,
        "roles": roles,
    }
    header_b64 = _b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_b64 = _b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    signature = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    return f"{header_b64}.{payload_b64}.{_b64url(signature)}"


def post_json(
    url: str,
    payload: dict[str, Any],
    *,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, Any]]:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", **(headers or {})},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            body = response.read().decode("utf-8")
            return response.status, json.loads(body) if body else {}
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8")
        parsed = json.loads(body) if body else {}
        return exc.code, parsed


def get_json(url: str, headers: dict[str, str]) -> tuple[int, dict[str, Any]]:
    request = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            body = response.read().decode("utf-8")
            return response.status, json.loads(body) if body else {}
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8")
        parsed = json.loads(body) if body else {}
        return exc.code, parsed


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Deploy the local telecom sovereign shield guardrail and print extension config."
    )
    parser.add_argument("--service-base", default="http://localhost:8080")
    parser.add_argument("--tenant-id", default="72c1e7a6-cd8b-4e69-b0a4-1549582a98f8")
    parser.add_argument("--environment-id", default="testlocal")
    parser.add_argument("--project-id", default="chattest")
    parser.add_argument("--guardrail-id", default="gr-tr-regulated-telecom-sovereign-shield")
    parser.add_argument("--guardrail-version", type=int, default=None)
    parser.add_argument("--template-id", default="gr-tr-regulated-telecom-sovereign-shield")
    parser.add_argument("--evaluation-mode", choices=["local", "server"], default="server")
    parser.add_argument("--capture-mode", choices=["metadata_only", "full_content"], default="full_content")
    parser.add_argument("--jwt-secret", default="local-extension-secret")
    parser.add_argument("--connect-origin", default="http://localhost:3000")
    parser.add_argument("--device-id", default="local-browser-device")
    args = parser.parse_args()

    deploy_payload = {
        "tenant_id": args.tenant_id,
        "environment_id": args.environment_id,
        "project_id": args.project_id,
        "template_id": args.template_id,
        "guardrail_id": args.guardrail_id,
        "publish": True,
    }
    deploy_url = f"{args.service_base}/api/v1/admin/library/guardrails/deploy"
    status, deploy_response = post_json(deploy_url, deploy_payload)
    if status not in {200, 409}:
        print("Guardrail deploy failed:")
        print(json.dumps(deploy_response, indent=2))
        return 1

    bootstrap_token = build_extension_jwt(
        tenant_id=args.tenant_id,
        secret=args.jwt_secret,
        audience="umai-ext-bootstrap",
        roles=["tenant-bootstrap"],
        subject="local-browser-bootstrap",
    )
    bootstrap_url = f"{args.service_base}/api/v1/ext/bootstrap"
    guardrail_query = {
        "environment_id": args.environment_id,
        "project_id": args.project_id,
        "guardrail_id": args.guardrail_id,
    }
    if args.guardrail_version is not None:
        guardrail_query["version"] = str(args.guardrail_version)
    guardrail_query_string = urllib.parse.urlencode(guardrail_query)
    policy_url = f"{args.service_base}/api/v1/ext/policy?{guardrail_query_string}"
    evaluate_url = f"{args.service_base}/api/v1/ext/evaluate?{guardrail_query_string}"
    monitoring_url = f"{args.connect_origin}/extension-monitoring"
    connect_url = (
        f"{monitoring_url}"
        f"?environmentId={urllib.parse.quote(args.environment_id)}"
        f"&projectId={urllib.parse.quote(args.project_id)}"
        f"&guardrailId={urllib.parse.quote(args.guardrail_id)}"
        f"&extId=<your-unpacked-extension-id>"
    )
    ingest_base_url = f"{args.service_base}/api"
    config = {
        "tenantId": args.tenant_id,
        "environment": "stage",
        "ingestBaseUrl": ingest_base_url,
        "policyUrl": policy_url,
        "evaluateUrl": evaluate_url,
        "evaluationMode": args.evaluation_mode,
        "bootstrapUrl": bootstrap_url,
        "bootstrapToken": bootstrap_token,
        "controlCenterUrl": args.connect_origin,
        "captureMode": args.capture_mode,
        "retentionLocalDays": 7,
        "debug": True,
        "allowedDomains": [
            "chatgpt.com",
            "chat.openai.com",
            "gemini.google.com",
            "claude.ai",
        ],
        "browserSecurity": {
            "enabled": True,
            "mode": "enforce",
            "shadowAiDomains": [
                "copilot.microsoft.com",
                "perplexity.ai",
                "poe.com",
                "chat.deepseek.com",
                "meta.ai",
                "grok.com",
            ],
        },
    }

    bootstrap_status, bootstrap_response = post_json(
        bootstrap_url,
        {
            "tenant_id": args.tenant_id,
            "device_id": args.device_id,
            "extension_id": "local-unpacked-test",
        },
        headers={
            "Authorization": f"Bearer {bootstrap_token}",
            "X-Tenant-Id": args.tenant_id,
        },
    )
    if bootstrap_status != 200:
        print("Bootstrap failed:")
        print(json.dumps(bootstrap_response, indent=2))
        return 1

    device_token = str(bootstrap_response.get("device_token") or "")
    policy_status, policy_response = get_json(
        policy_url,
        headers={
            "Authorization": f"Bearer {device_token}",
            "X-Tenant-Id": args.tenant_id,
        },
    )
    if policy_status != 200:
        print("Guardrail deploy status:", status)
        print("Bootstrap status:", bootstrap_status)
        print("Policy fetch status:", policy_status)
        print("\nPolicy fetch failed:\n")
        print(json.dumps(policy_response, indent=2))
        if args.guardrail_version is not None and policy_status == 404:
            print(
                "\nRequested guardrail version was not found in this local UMAI Service database. "
                "Run without --guardrail-version to use the current local version, or pass the "
                "environment/project/guardrail that actually contains that version."
            )
        return 1

    evaluate_status = None
    evaluate_response: dict[str, Any] | None = None
    if args.evaluation_mode == "server":
        evaluate_status, evaluate_response = post_json(
            evaluate_url,
            {
                "tenant_id": args.tenant_id,
                "site": "chatgpt",
                "url": "https://chatgpt.com/",
                "prompt_text": "Local UMAI browser extension guardrail connectivity test.",
                "device": {"device_id": args.device_id},
                "dlp": {"tags": [], "findings": [], "riskScore": 0},
                "timeout_ms": 2500,
            },
            headers={
                "Authorization": f"Bearer {device_token}",
                "X-Tenant-Id": args.tenant_id,
                "X-Device-Id": args.device_id,
            },
        )

    print("Guardrail deploy status:", status)
    print("Bootstrap status:", bootstrap_status)
    print("Policy fetch status:", policy_status)
    if evaluate_status is not None:
        print("Server evaluate status:", evaluate_status)
    if args.capture_mode == "full_content":
        print(
            "\nFull-content capture is enabled for this local test. "
            "Prompt, response, and justification text will be stored in extension event payloads."
        )
    print("\nRecommended extension monitoring URL:\n")
    print(connect_url)
    print("\nExtension local config JSON:\n")
    print(json.dumps(config, indent=2))
    print("\nBootstrap response:\n")
    print(json.dumps(bootstrap_response, indent=2))
    print("\nPolicy pack preview:\n")
    print(json.dumps(policy_response, indent=2))
    if evaluate_response is not None:
        print("\nServer evaluate preview:\n")
        print(json.dumps(evaluate_response, indent=2))
    print("\nChrome DevTools snippet:\n")
    print(
        "chrome.storage.local.set({ umai_dev_config_v1: "
        + json.dumps(config, separators=(",", ":"))
        + " })"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
