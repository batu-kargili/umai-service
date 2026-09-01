"""Overlap-window support for rotating secrets (UMA-84).

Rotating a shared secret has a window problem. The moment the service starts verifying
with a new value, every credential signed with the old one becomes invalid — every live
collector token, every operator session. Without an overlap, "rotate the secret" means
"take an outage", so in practice it never happens.

The same problem is worse for the transcript encryption key: the old key is not just
verifying, it is the only thing that can *read* transcripts already on disk. Rotating it
without an overlap does not cause an outage, it causes permanent evidence loss.

Every rotatable secret therefore has an optional `_previous` companion:

* **verification and decryption** accept the current value or the previous one
* **minting and encryption** only ever use the current value

So a rotation is: set `_PREVIOUS` to the old value, set the main setting to the new one,
restart, let old credentials expire (or re-seal transcripts), then clear `_PREVIOUS`.
While `_PREVIOUS` is set the old secret still works, which is the point — and clearing it
is what actually completes the rotation.
"""

from __future__ import annotations

import hmac
from collections.abc import Sequence


def accepted(current: str | None, previous: str | None) -> list[str]:
    """Secrets that may verify, most-current first.

    The order matters only for cost: the common case is the current secret, so it is
    tried first and the previous one is reached only during a rotation window.
    """
    values = []
    for value in (current, previous):
        stripped = (value or "").strip()
        if stripped and stripped not in values:
            values.append(stripped)
    return values


def matches_any(presented: str | None, accepted_values: Sequence[str]) -> bool:
    """Constant-time comparison against every accepted secret.

    Every candidate is compared even after a match, so the time taken does not reveal
    which secret matched — otherwise an attacker could learn whether a deployment is
    mid-rotation.
    """
    if not presented:
        return False
    matched = False
    for candidate in accepted_values:
        if hmac.compare_digest(presented, candidate):
            matched = True
    return matched


def rotation_state(current: str | None, previous: str | None) -> str:
    """How far through a rotation this secret is. Reported by the ops surface.

    ``unset`` — nothing configured.
    ``single`` — one secret, no rotation in progress.
    ``overlap`` — two secrets accepted; the rotation is not finished until the previous
    one is cleared.
    ``identical`` — both set to the same value, which looks like a rotation but is not
    one. Worth surfacing: an operator who believes they rotated has not.
    """
    values = accepted(current, previous)
    if not values:
        return "unset"
    has_previous = bool((previous or "").strip())
    if not has_previous:
        return "single"
    return "identical" if len(values) == 1 else "overlap"
