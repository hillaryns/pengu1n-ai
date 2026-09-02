import ipaddress
import re

from pydantic import BaseModel, Field, field_validator

ScopeProfile = str

WILDCARD_HOST_PATTERN = re.compile(r"^\*\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")


class ScopeConfig(BaseModel):
    allowed_hosts: list[str] = Field(default_factory=list)
    excluded_hosts: list[str] = Field(default_factory=list)
    requests_per_second: float | None = None

    @field_validator("requests_per_second")
    @classmethod
    def validate_requests_per_second(cls, value: float | None) -> float | None:
        if value is not None and value <= 0:
            raise ValueError("requests_per_second must be greater than zero")
        return value


def host_matches_pattern(host: str, pattern: str) -> bool:
    host_lower = host.strip().lower()
    pattern_lower = pattern.strip().lower()

    if not host_lower or not pattern_lower:
        return False

    if pattern_lower == host_lower:
        return True

    try:
        ipaddress.IPv4Address(host_lower)
        return host_lower == pattern_lower
    except ipaddress.AddressValueError:
        pass

    if pattern_lower.startswith("*."):
        if not WILDCARD_HOST_PATTERN.match(pattern_lower):
            return False

        base_domain = pattern_lower[2:]
        if host_lower == base_domain:
            return False

        return host_lower.endswith(f".{base_domain}")

    return False


def validate_target_scope(target: str, scope: ScopeConfig) -> bool:
    normalized_target = target.strip().lower()

    for excluded_host in scope.excluded_hosts:
        if host_matches_pattern(normalized_target, excluded_host):
            return False

    if scope.allowed_hosts:
        return any(
            host_matches_pattern(normalized_target, allowed_host)
            for allowed_host in scope.allowed_hosts
        )

    return True


def should_enforce_scope(profile: ScopeProfile, scope: ScopeConfig | None) -> bool:
    return profile == "bug_bounty" or scope is not None


def enforce_scope_rules(
    target: str,
    profile: ScopeProfile,
    scope: ScopeConfig | None,
) -> None:
    if profile == "bug_bounty" and (scope is None or not scope.allowed_hosts):
        raise ValueError("bug_bounty profile requires scope with at least one allowed host")

    if not should_enforce_scope(profile, scope):
        return

    if scope is None:
        raise ValueError("scope configuration is required for this scan profile")

    if not validate_target_scope(target, scope):
        raise ValueError("target is outside the configured scan scope")


def get_effective_requests_per_second(
  profile_requests_per_second: float | None,
  scope: ScopeConfig | None,
) -> float | None:
    if scope is not None and scope.requests_per_second is not None:
        return scope.requests_per_second
    return profile_requests_per_second
