"""The service's JWT audiences, in one place.

Each credential type the service issues carries its own ``aud``. Keeping the values
together makes one property checkable: a token minted for one surface must not be
accepted on another. The admin verifier in particular needs to know which audiences
belong to *other* surfaces, so it can reject them even when a deployment happens to
configure the same HS256 secret for more than one surface.
"""

from __future__ import annotations

ADR_DEVICE_TOKEN_AUDIENCE = "umai-adr-ingest"
ADR_BOOTSTRAP_TOKEN_AUDIENCE = "umai-adr-bootstrap"
EXTENSION_DEVICE_TOKEN_AUDIENCE = "umai-ext-ingest"
EXTENSION_BOOTSTRAP_TOKEN_AUDIENCE = "umai-ext-bootstrap"

# Audiences that are never valid for an admin request. Admin tokens are minted by the
# customer's identity provider, so the service cannot require a specific admin audience
# without breaking existing issuers — but it can refuse tokens that were plainly issued
# for a device or a collector.
NON_ADMIN_AUDIENCES = frozenset(
    {
        ADR_DEVICE_TOKEN_AUDIENCE,
        ADR_BOOTSTRAP_TOKEN_AUDIENCE,
        EXTENSION_DEVICE_TOKEN_AUDIENCE,
        EXTENSION_BOOTSTRAP_TOKEN_AUDIENCE,
    }
)
