"""Optional AI enhancement for security reports.

Disabled by default. No external API calls are made unless an enhancer is
explicitly enabled and configured via environment variables.
"""

from __future__ import annotations

import os
from typing import Protocol

from app.core.config import load_environment
from app.models.result import Finding, ScanResult


class ReportEnhancer(Protocol):
    """Interface for optionally enhancing report prose with an LLM."""

    def enhance_executive_summary(
        self,
        summary: str,
        scan_result: ScanResult,
        prioritized_findings: list[Finding],
    ) -> str:
        ...

    def enhance_recommendations(
        self,
        recommendations: list[str],
        scan_result: ScanResult,
        prioritized_findings: list[Finding],
    ) -> list[str]:
        ...


class DisabledReportEnhancer:
    """Pass-through enhancer that never contacts an external provider."""

    def enhance_executive_summary(
        self,
        summary: str,
        scan_result: ScanResult,
        prioritized_findings: list[Finding],
    ) -> str:
        return summary

    def enhance_recommendations(
        self,
        recommendations: list[str],
        scan_result: ScanResult,
        prioritized_findings: list[Finding],
    ) -> list[str]:
        return recommendations


def is_ai_report_enhancement_enabled() -> bool:
    load_environment()
    raw_value = os.getenv("PENGU1N_AI_REPORT_ENABLED", "false").strip().lower()
    return raw_value in {"1", "true", "yes", "on"}


def get_report_enhancer() -> ReportEnhancer:
    """Return the configured report enhancer.

    Currently always returns the disabled/pass-through enhancer. External LLM
    providers can be plugged in later behind this factory without changing
    scanner or report-generation call sites. API keys must come from the
    environment (for example PENGU1N_AI_API_KEY) and must never be hardcoded.
    """
    # Keep disabled even when the flag is true until a real provider is wired.
    # This guarantees no outbound AI calls in the current release.
    if not is_ai_report_enhancement_enabled():
        return DisabledReportEnhancer()
    return DisabledReportEnhancer()
