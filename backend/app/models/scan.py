import ipaddress
import re
from typing import Literal

from pydantic import BaseModel, field_validator, model_validator

from app.scanners.scope_manager import ScopeConfig, enforce_scope_rules

FORBIDDEN_SCHEMES = ("http://", "https://", "ftp://")
HOSTNAME_PATTERN = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
)


class ScanRequest(BaseModel):
    target: str
    profile: Literal["quick", "standard", "deep", "bug_bounty"] = "standard"
    scope: ScopeConfig | None = None

    @field_validator("target")
    @classmethod
    def validate_target(cls, value: str) -> str:
        target = value.strip()
        if not target:
            raise ValueError("target must not be empty or whitespace")

        lower_target = target.lower()
        for scheme in FORBIDDEN_SCHEMES:
            if lower_target.startswith(scheme):
                raise ValueError("target must not include a URL scheme")

        if lower_target == "localhost":
            return target

        try:
            ipaddress.IPv4Address(target)
            return target
        except ipaddress.AddressValueError:
            pass

        if HOSTNAME_PATTERN.match(target):
            return target

        raise ValueError("target must be a hostname, IPv4 address, or localhost")

    @model_validator(mode="after")
    def validate_scope(self):
        enforce_scope_rules(self.target, self.profile, self.scope)
        return self


class ScanResponse(BaseModel):
    status: Literal["accepted"]
    target: str
    message: str
