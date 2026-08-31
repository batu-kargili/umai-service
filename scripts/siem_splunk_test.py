"""Send a sample UMAI event to a Splunk Cloud HEC endpoint to verify connectivity.

This exercises the real ``app.core.siem`` encoder + emit path (not a mock), so a
success here proves the production code can deliver to your Splunk stack.

Usage (PowerShell):

    $env:SPLUNK_HEC_URL = "https://http-inputs-<stack>.splunkcloud.com/services/collector/event"
    $env:SPLUNK_HEC_TOKEN = "00000000-0000-0000-0000-000000000000"
    # optional:
    $env:SPLUNK_INDEX = "umai"
    .venv/Scripts/python.exe scripts/siem_splunk_test.py

Then in Splunk search:  index=umai sourcetype="umai:guardrail:decision"
"""
from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.append(str(ROOT))

from app.core import siem  # noqa: E402
from app.core.settings import settings  # noqa: E402


def _sample_event() -> dict:
    now = dt.datetime.now(dt.timezone.utc)
    return {
        "schema": "umai.guardrail.decision.v1",
        "ts": now.timestamp(),
        "occurred_at": now.isoformat(),
        "tenant_id": "00000000-0000-0000-0000-000000000001",
        "environment_id": "prod",
        "project_id": "demo",
        "guardrail_id": "gr-customer-data-leak",
        "guardrail_version": 1,
        "request_id": "siem-connectivity-test",
        "phase": "PRE",
        "action": "BLOCK",
        "allowed": False,
        "severity": "high",
        "reason": "SIEM connectivity test event (safe to ignore)",
        "latency_ms_total": 0,
        "source": "siem_splunk_test.py",
    }


async def _run(url: str, token: str, index: str | None, verify: bool) -> int:
    endpoint = {
        "url": url,
        "format": "splunk_hec",
        "hec_token": token,
    }
    if index:
        endpoint["index"] = index

    settings.siem_endpoints_json = json.dumps([endpoint])

    payload, headers = siem._encode(_sample_event(), endpoint)
    print("POST", url)
    print("Authorization:", headers.get("Authorization", "<none>"))
    print("Body:", payload)
    print("-" * 60)

    import httpx

    try:
        async with httpx.AsyncClient(
            timeout=settings.siem_timeout_seconds, verify=verify
        ) as client:
            resp = await client.post(url, content=payload, headers=headers)
    except httpx.RequestError as exc:
        print(f"REQUEST FAILED: {exc}")
        return 2

    print(f"HTTP {resp.status_code}")
    print("Response:", resp.text)
    # Splunk HEC returns {"text":"Success","code":0} on success.
    if resp.status_code < 400:
        try:
            body = resp.json()
        except ValueError:
            body = {}
        if body.get("code") == 0:
            print("OK — event accepted by Splunk HEC.")
            return 0
        print("WARNING — 2xx but HEC did not report code=0; check token/index.")
        return 0
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default=os.environ.get("SPLUNK_HEC_URL"))
    parser.add_argument("--token", default=os.environ.get("SPLUNK_HEC_TOKEN"))
    parser.add_argument("--index", default=os.environ.get("SPLUNK_INDEX"))
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Skip TLS certificate verification (debug only).",
    )
    args = parser.parse_args()

    if not args.url or not args.token:
        parser.error(
            "Set SPLUNK_HEC_URL and SPLUNK_HEC_TOKEN (env vars or --url/--token)."
        )

    return asyncio.run(_run(args.url, args.token, args.index, verify=not args.insecure))


if __name__ == "__main__":
    raise SystemExit(main())
