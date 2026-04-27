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

LOCAL_SERVICE_BASE = "http://localhost:8080"
LOCAL_CONTROL_CENTER_ORIGIN = "http://localhost:3000"
POC_SERVICE_BASE = "https://umai-service-mhkvrwuj2q-ey.a.run.app"
POC_CONTROL_CENTER_ORIGIN = "https://umai-controlcenter-mhkvrwuj2q-ey.a.run.app"
POC_CONSOLE_ORIGIN = "https://pocttconsole.umaisolutions.com"
POC_CONSOLE_EXTENSION_API_BASE = f"{POC_CONSOLE_ORIGIN}/api/public"


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
        description="Deploy or validate a guardrail and print browser extension config."
    )
    parser.add_argument("--profile", choices=["local", "poc-cloud-run", "poc-console"], default="local")
    parser.add_argument("--service-base", default=None)
    parser.add_argument("--tenant-id", default="72c1e7a6-cd8b-4e69-b0a4-1549582a98f8")
    parser.add_argument("--environment-id", default=None)
    parser.add_argument("--project-id", default=None)
    parser.add_argument("--guardrail-id", default="gr-tr-regulated-telecom-sovereign-shield")
    parser.add_argument("--guardrail-version", type=int, default=None)
    parser.add_argument("--template-id", default="gr-tr-regulated-telecom-sovereign-shield")
    parser.add_argument("--skip-deploy", action="store_true")
    parser.add_argument("--print-only", action="store_true")
    parser.add_argument("--evaluation-mode", choices=["local", "server"], default="server")
    parser.add_argument("--capture-mode", choices=["metadata_only", "full_content"], default="full_content")
    parser.add_argument("--jwt-secret", default="local-extension-secret")
    parser.add_argument("--connect-origin", default=None)
    parser.add_argument("--device-token", default=None)
    parser.add_argument("--events-url", default=None)
    parser.add_argument("--policy-url", default=None)
    parser.add_argument("--evaluate-url", default=None)
    parser.add_argument("--device-id", default="local-browser-device")
    args = parser.parse_args()

    service_base = args.service_base
    connect_origin = args.connect_origin
    if args.profile == "poc-cloud-run":
        service_base = service_base or POC_SERVICE_BASE
        connect_origin = connect_origin or POC_CONTROL_CENTER_ORIGIN
    elif args.profile == "poc-console":
        service_base = service_base or POC_CONSOLE_EXTENSION_API_BASE
        connect_origin = connect_origin or POC_CONSOLE_ORIGIN
    else:
        service_base = service_base or LOCAL_SERVICE_BASE
        connect_origin = connect_origin or LOCAL_CONTROL_CENTER_ORIGIN

    environment_id = args.environment_id or ("prod" if args.profile == "poc-console" else "testlocal")
    project_id = args.project_id or ("poc" if args.profile == "poc-console" else "chattest")
    extension_environment = "prod" if args.profile == "poc-console" else "stage"
    api_base = service_base.rstrip("/")
    if args.profile in {"local", "poc-cloud-run"}:
        api_base = f"{api_base}/api/v1"
    direct_device_token = (args.device_token or "").strip()

    deploy_payload = {
        "tenant_id": args.tenant_id,
        "environment_id": environment_id,
        "project_id": project_id,
        "template_id": args.template_id,
        "guardrail_id": args.guardrail_id,
        "publish": True,
    }
    status: int | None = None
    if not args.skip_deploy and not args.print_only and args.profile != "poc-console":
        deploy_url = f"{api_base.replace('/api/v1', '')}/api/v1/admin/library/guardrails/deploy"
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
    bootstrap_url = f"{api_base}/ext/bootstrap"
    guardrail_query = {
        "environment_id": environment_id,
        "project_id": project_id,
        "guardrail_id": args.guardrail_id,
    }
    if args.guardrail_version is not None:
        guardrail_query["version"] = str(args.guardrail_version)
    guardrail_query_string = urllib.parse.urlencode(guardrail_query)
    policy_url = args.policy_url or f"{api_base}/ext/policy?{guardrail_query_string}"
    evaluate_url = args.evaluate_url or f"{api_base}/ext/evaluate?{guardrail_query_string}"
    events_url = args.events_url or f"{api_base}/ext/events"
    monitoring_url = f"{connect_origin}/extension-monitoring"
    connect_url = (
        f"{monitoring_url}"
        f"?environmentId={urllib.parse.quote(environment_id)}"
        f"&projectId={urllib.parse.quote(project_id)}"
        f"&guardrailId={urllib.parse.quote(args.guardrail_id)}"
        f"&extId=<your-unpacked-extension-id>"
    )
    ingest_base_url = api_base if args.profile == "poc-console" else f"{service_base}/api"
    config = {
        "tenantId": args.tenant_id,
        "environment": extension_environment,
        "ingestBaseUrl": ingest_base_url,
        "eventsUrl": events_url,
        "policyUrl": policy_url,
        "evaluateUrl": evaluate_url,
        "evaluationMode": args.evaluation_mode,
        "controlCenterUrl": connect_origin,
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
    if direct_device_token:
        config["deviceToken"] = direct_device_token
    elif args.profile == "poc-console":
        config["deviceToken"] = "<paste-device-token-from-control-center>"
    else:
        config["bootstrapUrl"] = bootstrap_url
        config["bootstrapToken"] = bootstrap_token

    if args.print_only or (args.profile == "poc-console" and not direct_device_token):
        print("Profile:", args.profile)
        print("Service base:", service_base)
        print("Extension API base:", api_base)
        print("Control Center origin:", connect_origin)
        if args.profile == "poc-console" and not direct_device_token:
            print(
                "\nPOC note: replace <paste-device-token-from-control-center> with the device token "
                "minted from the logged-in Control Center extension connect flow."
            )
        print("\nExtension local config JSON:\n")
        print(json.dumps(config, indent=2))
        print("\nChrome DevTools snippet:\n")
        print(
            "chrome.storage.local.set({ umai_dev_config_v1: "
            + json.dumps(config, separators=(",", ":"))
            + " })"
        )
        return 0

    bootstrap_status: int | str = "skipped"
    bootstrap_response: dict[str, Any] = {}
    if direct_device_token:
        device_token = direct_device_token
    else:
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

    print("Profile:", args.profile)
    print("Service base:", service_base)
    print("Extension API base:", api_base)
    print("Control Center origin:", connect_origin)
    print("Guardrail deploy status:", status if status is not None else "skipped")
    print("Bootstrap status:", bootstrap_status)
    print("Policy fetch status:", policy_status)
    if evaluate_status is not None:
        print("Server evaluate status:", evaluate_status)
    if args.capture_mode == "full_content":
        print(
            "\nFull-content capture is enabled for this extension config. "
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
