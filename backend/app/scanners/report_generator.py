import uuid
from datetime import datetime, timezone

from app.models.report import SecurityReport
from app.models.result import Finding, ScanResult
from app.scanners.risk_engine import SEVERITY_ORDER


def _affected_service_count(scan_result: ScanResult) -> int:
    finding_ports = {
        finding.port
        for finding in scan_result.findings
        if finding.port is not None
    }
    return sum(1 for service in scan_result.services if service.port in finding_ports)


def _highest_severity_finding(findings: list[Finding]) -> Finding | None:
    if not findings:
        return None

    return max(
        findings,
        key=lambda finding: SEVERITY_ORDER.get(finding.severity.upper(), 0),
    )


def build_executive_summary(scan_result: ScanResult) -> str:
    findings_count = len(scan_result.findings)
    affected_services = _affected_service_count(scan_result)
    highest_finding = _highest_severity_finding(scan_result.findings)
    cve_findings = [
        finding for finding in scan_result.findings if finding.cve_id
    ]

    summary_parts = [
        f"Overall risk severity is {scan_result.risk.severity}.",
        f"The scan identified {findings_count} finding(s) across "
        f"{affected_services} affected service(s).",
    ]

    if highest_finding is not None:
        summary_parts.append(
            "Highest severity finding: "
            f"{highest_finding.severity} - {highest_finding.title}."
        )
    else:
        summary_parts.append("No security findings were identified.")

    if cve_findings:
        summary_parts.append(
            f"{len(cve_findings)} vulnerability finding(s) with CVE IDs were detected."
        )
    else:
        summary_parts.append("No CVE-linked vulnerabilities were detected.")

    return " ".join(summary_parts)


def build_recommendations(findings: list[Finding]) -> list[str]:
    seen: set[str] = set()
    recommendations: list[str] = []

    for finding in findings:
        if finding.recommendation in seen:
            continue
        seen.add(finding.recommendation)
        recommendations.append(finding.recommendation)

    return recommendations


def generate_security_report(scan_result: ScanResult) -> SecurityReport:
    return SecurityReport(
        report_id=str(uuid.uuid4()),
        scan_id=scan_result.scan_id,
        target=scan_result.target,
        profile=scan_result.profile,
        generated_at=datetime.now(timezone.utc),
        duration_seconds=scan_result.duration_seconds,
        risk=scan_result.risk,
        services=scan_result.services,
        findings=scan_result.findings,
        executive_summary=build_executive_summary(scan_result),
        recommendations=build_recommendations(scan_result.findings),
    )
