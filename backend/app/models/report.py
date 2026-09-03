from datetime import datetime

from pydantic import BaseModel, Field

from app.models.result import Finding, RiskSummary, Service


class CveSummaryItem(BaseModel):
    cve_id: str
    finding_id: str
    title: str
    severity: str
    confidence: str | None = None
    service_name: str | None = None
    service_version: str | None = None
    port: int | None = None
    references: list[str] = Field(default_factory=list)


class SecurityReport(BaseModel):
    report_id: str
    scan_id: str
    target: str
    profile: str
    generated_at: datetime
    duration_seconds: float
    risk: RiskSummary
    services: list[Service] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    prioritized_findings: list[Finding] = Field(default_factory=list)
    cve_summary: list[CveSummaryItem] = Field(default_factory=list)
    executive_summary: str
    recommendations: list[str] = Field(default_factory=list)
    ai_enhanced: bool = False
