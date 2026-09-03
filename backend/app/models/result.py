from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class Finding(BaseModel):
    id: str
    title: str
    description: str
    severity: str
    category: str
    recommendation: str
    target: str | None = None
    port: int | None = None
    evidence: str | None = None
    cve_id: str | None = None
    confidence: str | None = None
    references: list[str] = Field(default_factory=list)


class Service(BaseModel):
    port: int
    name: str
    version: str | None = None

class RiskSummary(BaseModel):
    severity: str
    counts: dict[str, int] = Field(default_factory=dict)

class ScanSummary(BaseModel):
    scan_id: str
    target: str
    profile: str
    status: str
    started_at: datetime
    completed_at: datetime
    duration_seconds: float
    risk_severity: str
    finding_count: int
    risk_counts: dict[str, int] = Field(default_factory=dict)

class ScanResult(BaseModel):
    scan_id: str
    target: str
    profile: Literal["quick", "standard", "deep", "bug_bounty"]
    status: str
    requests_per_second: float | None = None
    started_at: datetime
    completed_at: datetime
    duration_seconds: float
    findings: list[Finding] = Field(default_factory=list)
    open_ports: list[int] = Field(default_factory=list)
    services: list[Service] = Field(default_factory=list)
    risk: RiskSummary