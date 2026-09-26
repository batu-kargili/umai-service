"""Validation for the env-supplied extension DLP policy pack.

``UMAI_EXTENSION_POLICY_JSON`` is served verbatim at ``/api/v1/ext/policy``
when a request carries no guardrail selector. The extension evaluates it with
its own policy engine, which silently skips anything it does not understand —
a rule without ``"enabled": true`` never fires. A pack that is set but
malformed therefore enforces nothing, so this module rejects it outright
instead of letting the endpoint degrade to allow-all.
"""

from __future__ import annotations

import json
from typing import Any

# Mirrors PolicyActionType in umai-browser-extention/src/shared/types.ts.
EXTENSION_POLICY_ACTIONS = frozenset({"allow", "warn", "block", "redact", "justify"})


class ExtensionPolicyError(ValueError):
    """The configured policy pack cannot be enforced as written."""


def parse_extension_policy_pack(raw: str) -> dict[str, Any]:
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ExtensionPolicyError(f"not valid JSON ({exc.msg} at char {exc.pos})") from exc
    if not isinstance(parsed, dict):
        raise ExtensionPolicyError(f"must be a JSON object, got {type(parsed).__name__}")

    version = parsed.get("version")
    if not isinstance(version, str) or not version.strip():
        raise ExtensionPolicyError("'version' must be a non-empty string")
    default_action = parsed.get("default_action")
    if default_action not in EXTENSION_POLICY_ACTIONS:
        raise ExtensionPolicyError(
            f"'default_action' must be one of {sorted(EXTENSION_POLICY_ACTIONS)}"
        )
    rules = parsed.get("rules")
    if not isinstance(rules, list):
        raise ExtensionPolicyError("'rules' must be a list")

    seen_ids: set[str] = set()
    for index, rule in enumerate(rules):
        where = f"rules[{index}]"
        if not isinstance(rule, dict):
            raise ExtensionPolicyError(f"{where} must be an object")
        rule_id = rule.get("id")
        if not isinstance(rule_id, str) or not rule_id.strip():
            raise ExtensionPolicyError(f"{where}.id must be a non-empty string")
        if rule_id in seen_ids:
            raise ExtensionPolicyError(f"{where}.id {rule_id!r} is duplicated")
        seen_ids.add(rule_id)
        if not isinstance(rule.get("enabled"), bool):
            raise ExtensionPolicyError(
                f"{where}.enabled must be true or false (a missing value disables the rule)"
            )
        match = rule.get("match")
        if not isinstance(match, dict):
            raise ExtensionPolicyError(f"{where}.match must be an object")
        tags = match.get("dlp_tags_any")
        if not isinstance(tags, list) or not tags or not all(isinstance(t, str) for t in tags):
            raise ExtensionPolicyError(
                f"{where}.match.dlp_tags_any must be a non-empty list of strings"
            )
        action = rule.get("action")
        if not isinstance(action, dict) or action.get("type") not in EXTENSION_POLICY_ACTIONS:
            raise ExtensionPolicyError(
                f"{where}.action.type must be one of {sorted(EXTENSION_POLICY_ACTIONS)}"
            )
    return parsed
