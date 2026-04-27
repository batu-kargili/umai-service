from __future__ import annotations

import json
import logging

import httpx

from app.core.settings import settings

logger = logging.getLogger("umai.service.siem")


def _load_endpoints() -> list[dict]:
    """Load SIEM endpoint configs from ``UMAI_SIEM_ENDPOINTS_JSON``."""
    if not settings.siem_endpoints_json:
        return []
    try:
        endpoints = json.loads(settings.siem_endpoints_json)
    except json.JSONDecodeError:
        logger.warning("siem.config.invalid reason=json_parse_error")
        return []
    if not isinstance(endpoints, list):
        return []
    return [e for e in endpoints if isinstance(e, dict) and e.get("url")]


async def emit_guardrail_event(event: dict) -> None:
    """Fire-and-forget: POST the guardrail decision event to all configured SIEM endpoints."""
    endpoints = _load_endpoints()
    if not endpoints:
        return

    payload = json.dumps(event, separators=(",", ":"), ensure_ascii=True, default=str)

    for endpoint in endpoints:
        url: str = endpoint["url"]
        headers: dict[str, str] = {"Content-Type": "application/json"}
        token = endpoint.get("bearer_token")
        if token:
            headers["Authorization"] = f"Bearer {token}"
        extra_headers = endpoint.get("headers") or {}
        if isinstance(extra_headers, dict):
            headers.update({str(k): str(v) for k, v in extra_headers.items()})

        for attempt in range(1, settings.siem_max_retries + 1):
            try:
                async with httpx.AsyncClient(
                    timeout=settings.siem_timeout_seconds
                ) as client:
                    resp = await client.post(url, content=payload, headers=headers)
                    if resp.status_code < 400:
                        logger.debug(
                            "siem.emit.ok url=%s status=%s", url, resp.status_code
                        )
                        break
                    logger.warning(
                        "siem.emit.error url=%s status=%s attempt=%d",
                        url,
                        resp.status_code,
                        attempt,
                    )
            except httpx.RequestError as exc:
                logger.warning(
                    "siem.emit.request_error url=%s error=%s attempt=%d",
                    url,
                    exc,
                    attempt,
                )
