from __future__ import annotations

from app.core.settings import settings


def build_default_guardrail_llm_config() -> dict:
    """Build the default LLM config dict from service settings."""
    config: dict = {
        "provider": settings.default_guardrail_llm_provider,
        "base_url": settings.default_guardrail_llm_base_url,
        "model": settings.default_guardrail_llm_model,
        "timeout_ms": settings.default_guardrail_llm_timeout_ms,
    }
    auth_type = settings.default_guardrail_llm_auth_type
    if auth_type and auth_type != "none":
        auth: dict = {"type": auth_type}
        if settings.default_guardrail_llm_auth_secret_env:
            auth["secret_env"] = settings.default_guardrail_llm_auth_secret_env
        if settings.default_guardrail_llm_auth_header_name:
            auth["header_name"] = settings.default_guardrail_llm_auth_header_name
        config["auth"] = auth
    return config


def default_guardrail_llm_instruction() -> str:
    """Return the instruction suffix describing the default LLM provider."""
    return (
        f"Use the default LLM provider ({settings.default_guardrail_llm_provider}) "
        f"with model {settings.default_guardrail_llm_model} for context-aware policies "
        f"unless the operator has configured a custom provider."
    )
