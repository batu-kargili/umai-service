from __future__ import annotations

import sys
import warnings
from pathlib import Path

_sdk_src = Path(__file__).resolve().parents[2] / "sdks" / "python" / "src"
if _sdk_src.exists() and str(_sdk_src) not in sys.path:
    sys.path.insert(0, str(_sdk_src))

warnings.warn(
    "`umai_agent_sdk` is deprecated; import from `umai` instead.",
    DeprecationWarning,
    stacklevel=2,
)

from umai import *  # noqa: F403
from umai import AgentIdentity as UmaiAgentIdentity
from umai.client import UmaiAgentClient
from umai.integrations.openai_agents import UmaiOpenAIGovernanceHooks

__all__ = [
    "UmaiAgentClient",
    "UmaiAgentIdentity",
    "UmaiOpenAIGovernanceHooks",
    "canonical_json",
    "object_hash",
]

