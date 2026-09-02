from datetime import datetime

from pydantic import BaseModel, Field

from app.models.result import Finding, RiskSummary, Service


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
    executive_summary: str
    recommendations: list[str] = Field(default_factory=list)
