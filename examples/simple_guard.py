"""The smallest possible UMAI example: guard one user prompt.

No agent identity, no agent run, no LLM. Just ask UMAI whether a prompt is
allowed by a guardrail and print the decision. Run it with:

    python simple_guard.py "your prompt here"
"""

from __future__ import annotations

import sys

from umai import SyncUmaiClient

UMAI_ENDPOINT = "http://localhost:3000/"
UMAI_API_KEY = "F-OHO_E2PYoXvm5EZMMgaKKBOaJ5eAQydH9NltdhKeA"
UMAI_GUARDRAIL_ID = "gr-tr-regulated-telecom-sovereign-shield-bb"


def guard(prompt: str) -> dict:
    client = SyncUmaiClient(endpoint=UMAI_ENDPOINT, api_key=UMAI_API_KEY)
    response = client.raw.post(
        f"/api/public/guardrails/{UMAI_GUARDRAIL_ID}/guard",
        json={
            "phase": "PRE_LLM",
            "input": {
                "messages": [{"role": "user", "content": prompt}],
                "phase_focus": "LAST_USER_MESSAGE",
                "content_type": "text",
            },
            "timeout_ms": 5000,
        },
    )
    return response["decision"]


def main() -> None:
    prompt = "hi"
    decision = guard(prompt)
    verdict = "ALLOWED" if decision["allowed"] else "BLOCKED"
    print(f"{verdict} ({decision['action']})")
    if decision.get("reason"):
        print(decision)


if __name__ == "__main__":
    main()
