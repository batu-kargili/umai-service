from __future__ import annotations

import sys
import warnings
from pathlib import Path

_sdk_src = Path(__file__).resolve().parents[2] / "sdks" / "python" / "src"
if _sdk_src.exists() and str(_sdk_src) not in sys.path:
    sys.path.insert(0, str(_sdk_src))

warnings.warn(
    "`umai_agent_sdk.client` is deprecated; import from `umai` instead.",
    DeprecationWarning,
    stacklevel=2,
)

from umai.client import UmaiAgentClient
from umai.crypto import canonical_json, object_hash
from umai.identity import AgentIdentity as UmaiAgentIdentity

__all__ = ["UmaiAgentClient", "UmaiAgentIdentity", "canonical_json", "object_hash"]

