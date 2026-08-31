"""Canonical value sets for findings, and derivation of the ones a producer omits.

Single source for the vocabulary frozen in
``docs/contracts/finding-and-worker-result-schema.md`` (platform repo, UMA-40).
Both finding producers — the posture path in ``session_recorder`` and the
reasoning path in ``api.analysis`` — read the sets from here so the queue cannot
drift into two vocabularies.
"""

from __future__ import annotations

from typing import Final

# Which channel produced the finding. This is the axis the operator queue is
# filtered on. It is NOT the AI tool: `claude`, `cursor` and friends live on
# `ai_sessions.source` and are reached through `Finding.session_key`.
SOURCE_ADR: Final = "adr"
SOURCE_EXTENSION: Final = "extension"
SOURCE_SDK: Final = "sdk"
SOURCE_RED_TEAM: Final = "red_team"
SOURCE_POLICY: Final = "policy"

SOURCES: Final[frozenset[str]] = frozenset(
    {SOURCE_ADR, SOURCE_EXTENSION, SOURCE_SDK, SOURCE_RED_TEAM, SOURCE_POLICY}
)

# Which detector fired inside that channel.
DETECTOR_POSTURE: Final = "posture"
DETECTOR_TRIAGE: Final = "triage"
DETECTOR_REASONING: Final = "reasoning"
DETECTOR_RED_TEAM: Final = "red_team"
DETECTOR_POLICY: Final = "policy"

DETECTORS: Final[frozenset[str]] = frozenset(
    {DETECTOR_POSTURE, DETECTOR_TRIAGE, DETECTOR_REASONING, DETECTOR_RED_TEAM, DETECTOR_POLICY}
)

# Operator-facing grouping. Closed set: widening it is a contract change.
CATEGORY_DATA_EXPOSURE: Final = "data_exposure"
CATEGORY_CREDENTIAL_EXPOSURE: Final = "credential_exposure"
CATEGORY_PROMPT_INJECTION: Final = "prompt_injection"
CATEGORY_UNSAFE_TOOL_USE: Final = "unsafe_tool_use"
CATEGORY_POLICY_EVASION: Final = "policy_evasion"
CATEGORY_SHADOW_AI: Final = "shadow_ai"
CATEGORY_AGENT_MISBEHAVIOR: Final = "agent_misbehavior"
CATEGORY_OTHER: Final = "other"

CATEGORIES: Final[frozenset[str]] = frozenset(
    {
        CATEGORY_DATA_EXPOSURE,
        CATEGORY_CREDENTIAL_EXPOSURE,
        CATEGORY_PROMPT_INJECTION,
        CATEGORY_UNSAFE_TOOL_USE,
        CATEGORY_POLICY_EVASION,
        CATEGORY_SHADOW_AI,
        CATEGORY_AGENT_MISBEHAVIOR,
        CATEGORY_OTHER,
    }
)

# Lifecycle. Transitions are enforced at the API layer (UMA-46), not here.
STATUS_OPEN: Final = "open"
STATUS_INVESTIGATING: Final = "investigating"
STATUS_RESOLVED: Final = "resolved"
STATUS_FALSE_POSITIVE: Final = "false_positive"
STATUS_ACCEPTED_RISK: Final = "accepted_risk"

STATUSES: Final[frozenset[str]] = frozenset(
    {
        STATUS_OPEN,
        STATUS_INVESTIGATING,
        STATUS_RESOLVED,
        STATUS_FALSE_POSITIVE,
        STATUS_ACCEPTED_RISK,
    }
)

# Transitions that assert a judgement and therefore require a note.
STATUSES_REQUIRING_NOTE: Final[frozenset[str]] = frozenset(
    {STATUS_FALSE_POSITIVE, STATUS_ACCEPTED_RISK}
)

# A decision has been recorded. Reaching one of these closes the finding.
TERMINAL_STATUSES: Final[frozenset[str]] = frozenset(
    {STATUS_RESOLVED, STATUS_FALSE_POSITIVE, STATUS_ACCEPTED_RISK}
)

# Where a finding may go from where it is.
#
# `resolved` is only reachable through `investigating`: saying a finding was
# dealt with without recording that anyone looked at it is the shape of a
# queue that gets cleared rather than worked. Dismissing outright
# (`false_positive`, `accepted_risk`) is allowed directly, because both
# already demand a written reason.
#
# Every terminal state leads back to `open` and nowhere else — reopening is
# how a closed finding re-enters the queue, not a shortcut between verdicts.
_TRANSITIONS: Final[dict[str, frozenset[str]]] = {
    STATUS_OPEN: frozenset({STATUS_INVESTIGATING, STATUS_FALSE_POSITIVE, STATUS_ACCEPTED_RISK}),
    STATUS_INVESTIGATING: frozenset(
        {STATUS_RESOLVED, STATUS_FALSE_POSITIVE, STATUS_ACCEPTED_RISK}
    ),
    STATUS_RESOLVED: frozenset({STATUS_OPEN}),
    STATUS_FALSE_POSITIVE: frozenset({STATUS_OPEN}),
    STATUS_ACCEPTED_RISK: frozenset({STATUS_OPEN}),
}


def allowed_transitions(from_status: str) -> frozenset[str]:
    return _TRANSITIONS.get(from_status, frozenset())


def transition_requires_note(from_status: str, to_status: str) -> bool:
    """Whether this move has to be explained.

    Two cases: asserting a judgement (`false_positive`, `accepted_risk`), and
    undoing one (leaving a terminal state). Both are the moments a reader
    months later will want a reason for.
    """
    return to_status in STATUSES_REQUIRING_NOTE or from_status in TERMINAL_STATUSES

# Rule id -> category, for producers that do not classify their own finding.
# Only rules that exist today are listed; anything else falls back to `other`.
_RULE_CATEGORIES: Final[dict[str, str]] = {
    # An agent that ran with permission checks bypassed had more capability
    # than the policy grants — that is excessive permission, not evasion by
    # the user.
    "posture.bypass_permissions": CATEGORY_UNSAFE_TOOL_USE,
    "posture.browser_checks_skipped": CATEGORY_UNSAFE_TOOL_USE,
    # An MCP server nobody approved is an unsanctioned capability reaching the
    # agent, which is the shadow-AI problem in tool form.
    "posture.unapproved_mcp_server": CATEGORY_SHADOW_AI,
}


def derive_category(rule_id: str | None) -> str:
    """Best category for a producer that did not supply one.

    Returns ``other`` when the rule is unknown. That is a deliberate debt
    marker rather than a guess: a queue filling up with ``other`` means the
    detectors are not classifying their own output, which is a defect to fix
    at the detector, not to paper over here.

    The reasoning path currently lands here for every finding, because its
    rule ids are built from the ADR tactic at runtime (``detector.<tactic>``)
    and cannot be enumerated. That path starts sending an explicit category
    with the worker-result contract (UMA-51).
    """
    if not rule_id:
        return CATEGORY_OTHER
    return _RULE_CATEGORIES.get(rule_id, CATEGORY_OTHER)


# Transcript collection modes (contract: transcript-data-modes.md §2).
MODE_POSTURE_ONLY: Final = "posture_only"
MODE_METADATA: Final = "metadata"
MODE_FULL_SESSION: Final = "full_session"

COLLECTION_MODES: Final[frozenset[str]] = frozenset(
    {MODE_POSTURE_ONLY, MODE_METADATA, MODE_FULL_SESSION}
)

# Only this mode stores message and tool content.
MODES_WITH_CONTENT: Final[frozenset[str]] = frozenset({MODE_FULL_SESSION})


SEVERITY_CRITICAL: Final = "critical"
SEVERITY_HIGH: Final = "high"
SEVERITY_MEDIUM: Final = "medium"
SEVERITY_LOW: Final = "low"

SEVERITIES: Final[frozenset[str]] = frozenset(
    {SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW}
)


def derive_severity(
    supplied: str | None, confidence: float | None
) -> tuple[str, str]:
    """Severity for a finding, plus how it was arrived at.

    Order per the contract: what the detector declared, then the confidence it
    reported. ``critical`` is never derived — it only ever comes from a rule
    that says so, because an automatic path to the top of the scale makes the
    top of the scale meaningless.

    The basis is returned so it can be recorded alongside the finding. An
    operator asking "why is this high?" deserves an answer better than the
    number itself.
    """
    if supplied and supplied in SEVERITIES:
        return supplied, "detector"

    if confidence is None:
        # Nothing to reason from. Medium rather than high: an unexplained
        # finding should not outrank one a detector actually rated.
        return SEVERITY_MEDIUM, "default"

    if confidence >= 0.90:
        return SEVERITY_HIGH, "confidence"
    if confidence >= 0.70:
        return SEVERITY_MEDIUM, "confidence"
    return SEVERITY_LOW, "confidence"


def normalize_category(category: str | None, rule_id: str | None = None) -> str:
    """Accept a producer-supplied category, or derive one.

    An unrecognised value is not passed through: it would silently widen a
    closed set and make queue filters lie.
    """
    if category and category in CATEGORIES:
        return category
    return derive_category(rule_id)
