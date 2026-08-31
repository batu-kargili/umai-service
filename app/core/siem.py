from __future__ import annotations

import datetime as dt
import json
import logging
import time
from typing import Tuple

import httpx

from app.core.settings import settings

logger = logging.getLogger("umai.service.siem")

LEEF_VENDOR = "UMAI"
LEEF_PRODUCT = "umai-service"
LEEF_PRODUCT_VERSION = "1.0"
LEEF_DEV_TIME_FORMAT = "yyyy-MM-dd'T'HH:mm:ssZ"

_LEEF_SEVERITY_BY_LEVEL = {
    "critical": 10,
    "high": 8,
    "medium": 5,
    "low": 3,
    "info": 2,
}


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


def _encode_json(event: dict, endpoint: dict) -> Tuple[str, dict[str, str]]:
    """Default encoder: raw event as a single JSON object."""
    payload = json.dumps(event, separators=(",", ":"), ensure_ascii=True, default=str)
    headers: dict[str, str] = {"Content-Type": "application/json"}
    token = endpoint.get("bearer_token")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return payload, headers


def _encode_splunk_hec(event: dict, endpoint: dict) -> Tuple[str, dict[str, str]]:
    """Encode an event for Splunk HTTP Event Collector (HEC).

    Wraps the raw event in the HEC envelope and authenticates with the
    ``Authorization: Splunk <token>`` scheme. Endpoint config keys:
    ``hec_token`` (falls back to ``bearer_token``), ``sourcetype``, ``source``,
    ``index``, and ``host``.
    """
    envelope: dict = {
        "event": event,
        "sourcetype": endpoint.get("sourcetype") or _default_sourcetype(event),
        "source": endpoint.get("source", "umai-service"),
        "time": _event_epoch(event),
    }
    if endpoint.get("index"):
        envelope["index"] = endpoint["index"]
    if endpoint.get("host"):
        envelope["host"] = endpoint["host"]

    payload = json.dumps(
        envelope, separators=(",", ":"), ensure_ascii=True, default=str
    )
    headers: dict[str, str] = {"Content-Type": "application/json"}
    token = endpoint.get("hec_token") or endpoint.get("bearer_token")
    if token:
        headers["Authorization"] = f"Splunk {token}"
    return payload, headers


def _default_sourcetype(event: dict) -> str:
    """Derive a Splunk sourcetype from the event ``schema``.

    ``umai.admin.publish.v1`` -> ``umai:admin:publish``. Falls back to a
    generic value when the schema is missing or unrecognized.
    """
    schema = event.get("schema")
    if isinstance(schema, str) and schema:
        parts = schema.split(".")
        # drop a trailing version segment like ``v1``
        if parts and parts[-1].startswith("v") and parts[-1][1:].isdigit():
            parts = parts[:-1]
        if parts:
            return ":".join(parts)
    return "umai:event"


def _event_epoch(event: dict) -> float:
    """Best-effort event timestamp in epoch seconds for Splunk's ``time`` field."""
    ts = event.get("ts") or event.get("timestamp")
    if isinstance(ts, (int, float)):
        return float(ts)
    return time.time()


def _leef_event_key(schema: str) -> str:
    """``umai.guardrail.decision.v1`` -> ``guardrail-decision``."""
    parts = [p for p in schema.split(".") if p]
    if parts and parts[-1].startswith("v") and parts[-1][1:].isdigit():
        parts = parts[:-1]
    if parts and parts[0] == "umai":
        parts = parts[1:]
    return "-".join(parts) if parts else "event"


def _leef_severity(event: dict) -> int:
    """Map whatever severity signal the event carries onto LEEF's required 1-10 ``sev``."""
    level = str(event.get("severity") or "").lower()
    if level in _LEEF_SEVERITY_BY_LEVEL:
        return _LEEF_SEVERITY_BY_LEVEL[level]
    if event.get("allowed") is False:
        return 8
    decision = str(event.get("decision") or "").upper()
    if decision in {"BLOCK", "DENY"}:
        return 8
    if decision in {"WARN", "JUSTIFY"}:
        return 5
    if event.get("dlp_tags"):
        return 6
    return 3


def _leef_dev_time(event: dict) -> str:
    occurred_at = event.get("occurred_at")
    if isinstance(occurred_at, str) and occurred_at:
        return occurred_at
    return dt.datetime.fromtimestamp(_event_epoch(event), tz=dt.timezone.utc).isoformat()


def _leef_escape(value: object) -> str:
    """Escape LEEF attribute values: backslash-escape ``=``/``|`` and flatten whitespace."""
    text = str(value)
    text = text.replace("\\", "\\\\")
    text = text.replace("\t", " ").replace("\n", " ").replace("\r", " ")
    text = text.replace("=", "\\=").replace("|", "\\|")
    return text


def _leef_attributes(event: dict) -> dict[str, object]:
    dlp_tags = event.get("dlp_tags")
    return {
        "devTime": _leef_dev_time(event),
        "devTimeFormat": LEEF_DEV_TIME_FORMAT,
        "cat": event.get("event_type") or event.get("action") or _leef_event_key(str(event.get("schema") or "")),
        "sev": _leef_severity(event),
        "usrName": event.get("user_email") or event.get("agent_id") or "unknown",
        "tenantId": event.get("tenant_id"),
        "requestId": event.get("request_id") or event.get("event_id"),
        "deviceId": event.get("device_id"),
        "action": event.get("action"),
        "decision": event.get("decision"),
        "allowed": event.get("allowed"),
        "reason": event.get("reason") or event.get("message"),
        "url": event.get("url"),
        "site": event.get("site"),
        "dlpTags": ",".join(dlp_tags) if isinstance(dlp_tags, list) and dlp_tags else None,
        "eventHash": event.get("event_hash"),
    }


def _encode_leef(event: dict, endpoint: dict) -> Tuple[str, dict[str, str]]:
    """Encode an event as a LEEF 2.0 record for IBM QRadar's HTTP Receiver / syslog log sources.

    Works over the existing HTTP transport against a QRadar HTTP Receiver log
    source; auto-discovery parses the header + tab-separated ``key=value``
    attributes without a custom DSM.
    """
    schema = str(event.get("schema") or "umai.event")
    header = (
        f"LEEF:2.0|{LEEF_VENDOR}|{LEEF_PRODUCT}|{LEEF_PRODUCT_VERSION}|"
        f"{_leef_event_key(schema)}|"
    )
    body = "\t".join(
        f"{key}={_leef_escape(value)}"
        for key, value in _leef_attributes(event).items()
        if value is not None
    )
    payload = header + body
    headers: dict[str, str] = {"Content-Type": "text/plain"}
    token = endpoint.get("bearer_token")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return payload, headers


_ENCODERS = {
    "json": _encode_json,
    "splunk_hec": _encode_splunk_hec,
    "leef": _encode_leef,
}


def _encode(event: dict, endpoint: dict) -> Tuple[str, dict[str, str]]:
    fmt = str(endpoint.get("format", "json")).lower()
    encoder = _ENCODERS.get(fmt)
    if encoder is None:
        logger.warning("siem.config.unknown_format format=%s falling_back=json", fmt)
        encoder = _encode_json
    payload, headers = encoder(event, endpoint)
    extra_headers = endpoint.get("headers") or {}
    if isinstance(extra_headers, dict):
        headers.update({str(k): str(v) for k, v in extra_headers.items()})
    return payload, headers


async def emit_event(event: dict) -> None:
    """Fire-and-forget: deliver an event to all configured SIEM endpoints."""
    endpoints = _load_endpoints()
    if not endpoints:
        return

    for endpoint in endpoints:
        url: str = endpoint["url"]
        payload, headers = _encode(event, endpoint)
        # Per-endpoint TLS verification. Defaults to on; set ``verify: false`` for
        # endpoints behind a TLS-intercepting proxy (e.g. the UMAI sensor) or with
        # a self-signed cert. Demo-grade — prefer trusting the proxy CA in prod.
        verify = endpoint.get("verify", True)

        for attempt in range(1, settings.siem_max_retries + 1):
            try:
                async with httpx.AsyncClient(
                    timeout=settings.siem_timeout_seconds, verify=verify
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


# Back-compat alias: the original API only emitted guardrail decisions.
emit_guardrail_event = emit_event
