from __future__ import annotations

import datetime as dt
import uuid
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class LicensePayload(BaseModel):
    model_config = ConfigDict(extra="allow")

    license_id: str
    tenant_id: uuid.UUID
    issued_at: dt.datetime
    expires_at: dt.datetime
    status: Literal["active", "suspended"] = "active"
    tenant_name: str | None = None
    issuer: str | None = None
    features: dict = Field(default_factory=dict)


class LicenseToken(BaseModel):
    model_config = ConfigDict(extra="allow")

    payload: LicensePayload
    signature: str
    key_id: str | None = None
