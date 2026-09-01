"""AI application registry: seed catalog, tenant materialization, matching.

Single source of truth for AI application identity. Feeds:
- server-side classification of incoming collector/extension events (AppMatcher)
- the Control Center "Application catalog" admin UI (ai_applications table)
"""

from __future__ import annotations

import datetime as dt
import json
import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.db import AiApplication

CATEGORIES = ("llm_chat", "code_assistant", "image_gen", "ai_search", "productivity", "other")
RISK_LEVELS = ("critical", "high", "medium", "low", "none")
APP_TYPES = ("web", "desktop", "both")

SEED_APPLICATIONS: list[dict[str, Any]] = [
    {
        "slug": "chatgpt",
        "name": "ChatGPT",
        "vendor": "OpenAI",
        "category": "llm_chat",
        "risk_level": "high",
        "icon_key": "chatgpt",
        "domains": ["chatgpt.com", "chat.openai.com", "api.openai.com"],
        "process_names": ["ChatGPT.exe"],
        "app_type": "both",
        "is_training": True,
    },
    {
        "slug": "claude",
        "name": "Claude",
        "vendor": "Anthropic",
        "category": "llm_chat",
        "risk_level": "medium",
        "icon_key": "claude",
        "domains": ["claude.ai", "api.anthropic.com"],
        "process_names": ["Claude.exe"],
        "app_type": "both",
    },
    {
        "slug": "gemini",
        "name": "Gemini",
        "vendor": "Google",
        "category": "llm_chat",
        "risk_level": "medium",
        "icon_key": "gemini",
        "domains": ["gemini.google.com", "generativelanguage.googleapis.com", "aistudio.google.com"],
        "app_type": "web",
    },
    {
        "slug": "microsoft-copilot",
        "name": "Microsoft Copilot",
        "vendor": "Microsoft",
        "category": "llm_chat",
        "risk_level": "low",
        "icon_key": "microsoft-copilot",
        "domains": ["copilot.microsoft.com", "www.bing.com"],
        "app_type": "web",
        "is_sanctioned": True,
    },
    {
        "slug": "github-copilot",
        "name": "GitHub Copilot",
        "vendor": "GitHub",
        "category": "code_assistant",
        "risk_level": "low",
        "icon_key": "github-copilot",
        "domains": ["api.githubcopilot.com", "copilot-proxy.githubusercontent.com"],
        "process_names": ["copilot-language-server.exe"],
        "app_type": "desktop",
        "is_sanctioned": True,
    },
    {
        "slug": "claude-code",
        "name": "Claude Code",
        "vendor": "Anthropic",
        "category": "code_assistant",
        "risk_level": "medium",
        "icon_key": "claude-code",
        # Claude Code ships inside the Claude Desktop install and is
        # literally the same executable name (claude.exe); path_hint is what
        # tells the two apart. No domains
        # here on purpose — network-only observations of anthropic.com stay
        # attributed to the "claude" chat-app entry; only a process-level
        # match with this path hint reclassifies as Claude Code.
        "process_names": ["claude.exe"],
        "path_hint": "claude-code",
        "app_type": "desktop",
    },
    {
        "slug": "cursor",
        "name": "Cursor",
        "vendor": "Anysphere",
        "category": "code_assistant",
        "risk_level": "medium",
        "icon_key": "cursor",
        "domains": ["cursor.com", "cursor.sh", "api2.cursor.sh"],
        "process_names": ["Cursor.exe"],
        "app_type": "desktop",
    },
    {
        "slug": "windsurf",
        "name": "Windsurf",
        "vendor": "Codeium",
        "category": "code_assistant",
        "risk_level": "medium",
        "icon_key": "windsurf",
        "domains": ["windsurf.com", "codeium.com", "server.codeium.com"],
        "process_names": ["Windsurf.exe"],
        "app_type": "desktop",
    },
    {
        "slug": "ollama",
        "name": "Ollama",
        "vendor": "Ollama",
        "category": "other",
        "risk_level": "high",
        "icon_key": "ollama",
        "domains": ["localhost", "127.0.0.1"],
        "process_names": ["Ollama.exe"],
        "ports": [11434],
        "app_type": "desktop",
        "collector_capture": False,
        "inventory_only": True,
    },
    {
        "slug": "lm-studio",
        "name": "LM Studio",
        "vendor": "LM Studio",
        "category": "other",
        "risk_level": "high",
        "icon_key": "lm-studio",
        "domains": ["localhost", "127.0.0.1"],
        "process_names": ["LM Studio.exe"],
        "ports": [1234],
        "app_type": "desktop",
        "collector_capture": False,
        "inventory_only": True,
    },
    {
        "slug": "midjourney",
        "name": "Midjourney",
        "vendor": "Midjourney",
        "category": "image_gen",
        "risk_level": "medium",
        "icon_key": "midjourney",
        "domains": ["midjourney.com", "www.midjourney.com"],
        "app_type": "web",
    },
    {
        "slug": "stable-diffusion",
        "name": "Stable Diffusion",
        "vendor": "Stability AI",
        "category": "image_gen",
        "risk_level": "medium",
        "icon_key": "stable-diffusion",
        "domains": ["stability.ai", "dreamstudio.ai", "platform.stability.ai"],
        "app_type": "web",
    },
    {
        "slug": "perplexity",
        "name": "Perplexity",
        "vendor": "Perplexity",
        "category": "ai_search",
        "risk_level": "high",
        "icon_key": "perplexity",
        "domains": ["perplexity.ai", "www.perplexity.ai", "api.perplexity.ai"],
        "app_type": "web",
        "is_training": True,
    },
    {
        "slug": "deepseek",
        "name": "DeepSeek",
        "vendor": "DeepSeek",
        "category": "llm_chat",
        "risk_level": "critical",
        "icon_key": "deepseek",
        "domains": ["chat.deepseek.com", "api.deepseek.com"],
        "app_type": "web",
        "is_training": True,
    },
    {
        "slug": "mistral-le-chat",
        "name": "Le Chat (Mistral)",
        "vendor": "Mistral AI",
        "category": "llm_chat",
        "risk_level": "medium",
        "icon_key": "mistral",
        "domains": ["chat.mistral.ai", "api.mistral.ai"],
        "app_type": "web",
    },
    {
        "slug": "grammarly",
        "name": "Grammarly",
        "vendor": "Grammarly",
        "category": "productivity",
        "risk_level": "none",
        "icon_key": "grammarly",
        "domains": ["grammarly.com", "app.grammarly.com"],
        "app_type": "web",
    },
]

_SEED_DEFAULTS: dict[str, Any] = {
    "vendor": None,
    "category": "other",
    "risk_level": "none",
    "icon_key": None,
    "domains": [],
    "process_names": [],
    "ports": [],
    "app_type": "web",
    "is_sanctioned": False,
    "is_training": False,
    "collector_capture": True,
    "inventory_only": False,
    "path_hint": None,
}

_ENSURED_TENANTS: set[str] = set()


def _json_list(value: Any) -> str:
    return json.dumps(list(value or []), separators=(",", ":"), ensure_ascii=True)


def _parse_json_list(raw: str | None) -> list[Any]:
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return []
    return parsed if isinstance(parsed, list) else []


def seed_entry(slug: str) -> dict[str, Any] | None:
    for entry in SEED_APPLICATIONS:
        if entry["slug"] == slug:
            return {**_SEED_DEFAULTS, **entry}
    return None


async def ensure_tenant_catalog(session: AsyncSession, tenant_id: uuid.UUID) -> None:
    """Materialize the builtin seed catalog for a tenant (idempotent, memoized)."""
    cache_key = str(tenant_id)
    if cache_key in _ENSURED_TENANTS:
        return
    result = await session.execute(
        select(AiApplication.slug).where(AiApplication.tenant_id == tenant_id)
    )
    existing_slugs = set(result.scalars().all())
    now = dt.datetime.now(dt.timezone.utc)
    for raw_entry in SEED_APPLICATIONS:
        entry = {**_SEED_DEFAULTS, **raw_entry}
        if entry["slug"] in existing_slugs:
            continue
        session.add(
            AiApplication(
                tenant_id=tenant_id,
                id=uuid.uuid4(),
                slug=entry["slug"],
                name=entry["name"],
                vendor=entry["vendor"],
                category=entry["category"],
                risk_level=entry["risk_level"],
                icon_key=entry["icon_key"],
                domains_json=_json_list(entry["domains"]),
                process_names_json=_json_list(entry["process_names"]),
                ports_json=_json_list(entry["ports"]),
                app_type=entry["app_type"],
                is_sanctioned=entry["is_sanctioned"],
                is_training=entry["is_training"],
                collector_capture=entry["collector_capture"],
                inventory_only=entry["inventory_only"],
                path_hint=entry["path_hint"],
                enabled=True,
                source="builtin",
                is_customized=False,
                created_at=now,
                updated_at=now,
            )
        )
    _ENSURED_TENANTS.add(cache_key)


def reset_catalog_memo() -> None:
    """Test hook: forget which tenants already had the seed catalog ensured."""
    _ENSURED_TENANTS.clear()


async def load_enabled_applications(
    session: AsyncSession, tenant_id: uuid.UUID
) -> list[AiApplication]:
    result = await session.execute(
        select(AiApplication)
        .where(AiApplication.tenant_id == tenant_id, AiApplication.enabled == True)  # noqa: E712
        .order_by(AiApplication.slug.asc())
    )
    return list(result.scalars().all())




def _normalize_host(host: str) -> str:
    return host.strip().rstrip(".").lstrip("[").rstrip("]").lower()


class AppMatcher:
    """Classify an observed destination/process against the tenant catalog.

    Built once per ingest batch. Match precedence: process name
    (path-disambiguated) first — a specific app-identifying process signal
    beats a domain shared by multiple apps (e.g. Claude Desktop and Claude
    Code both call api.anthropic.com) — then exact domain, then parent-domain
    suffix, then localhost port (inventory-only local models).
    """

    _LOCAL_HOSTS = ("localhost", "127.0.0.1", "::1")

    def __init__(self, rows: list[AiApplication]) -> None:
        self._by_domain: dict[str, AiApplication] = {}
        self._by_process: dict[str, list[AiApplication]] = {}
        self._by_port: dict[int, AiApplication] = {}
        self._suffix_domains: list[tuple[str, AiApplication]] = []
        for row in rows:
            for domain in _parse_json_list(row.domains_json):
                normalized = _normalize_host(str(domain))
                # localhost entries match on their registered port, never bare host
                if not normalized or normalized in self._LOCAL_HOSTS:
                    continue
                self._by_domain.setdefault(normalized, row)
                self._suffix_domains.append((f".{normalized}", row))
            for process in _parse_json_list(row.process_names_json):
                self._by_process.setdefault(str(process).lower(), []).append(row)
            for port in _parse_json_list(row.ports_json):
                self._by_port.setdefault(int(port), row)

    def match(
        self,
        host_or_sni: str | None,
        port: int | None = None,
        process_name: str | None = None,
        process_path: str | None = None,
    ) -> AiApplication | None:
        if process_name:
            candidates = self._by_process.get(process_name.strip().lower())
            if candidates:
                # An entry whose path_hint is contained in the observed path
                # wins over a generic (no-hint) entry with the same basename
                # (e.g. Claude Code vs. Claude Desktop, both claude.exe) —
                # checked before domain matching since it's the more specific
                # signal when both a hinted and an unhinted candidate share a
                # basename and destination domain.
                path_lower = process_path.lower() if process_path else None
                if path_lower:
                    for candidate in candidates:
                        if candidate.path_hint and candidate.path_hint.lower() in path_lower:
                            return candidate
                for candidate in candidates:
                    if not candidate.path_hint:
                        return candidate
        if host_or_sni:
            normalized = _normalize_host(host_or_sni)
            if normalized in self._LOCAL_HOSTS:
                if port is not None and port in self._by_port:
                    return self._by_port[port]
            else:
                direct = self._by_domain.get(normalized)
                if direct is not None:
                    return direct
                for suffix, row in self._suffix_domains:
                    if normalized.endswith(suffix):
                        return row
        if port is not None and port in self._by_port:
            return self._by_port[port]
        return None


async def build_matcher(session: AsyncSession, tenant_id: uuid.UUID) -> AppMatcher:
    await ensure_tenant_catalog(session, tenant_id)
    rows = await load_enabled_applications(session, tenant_id)
    return AppMatcher(rows)
