import uuid
from datetime import datetime, timezone

from app.models.report import CveSummaryItem, SecurityReport
from app.models.result import Finding, ScanResult, Service
from app.scanners.report_ai import ReportEnhancer, get_report_enhancer
from app.scanners.risk_engine import SEVERITY_ORDER


def prioritize_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda finding: (
            -SEVERITY_ORDER.get(finding.severity.upper(), 0),
            finding.id,
        ),
    )


def _service_for_port(services: list[Service], port: int | None) -> Service | None:
    if port is None:
        return None
    for service in services:
        if service.port == port:
            return service
    return None


def _affected_service_labels(scan_result: ScanResult) -> list[str]:
    finding_ports = {
        finding.port
        for finding in scan_result.findings
        if finding.port is not None
    }
    labels: list[str] = []
    for service in scan_result.services:
        if service.port not in finding_ports:
            continue
        version_suffix = f" {service.version}" if service.version else ""
        labels.append(f"{service.name}{version_suffix} on port {service.port}")
    return labels


def _affected_service_count(scan_result: ScanResult) -> int:
    return len(_affected_service_labels(scan_result))


def _highest_severity_finding(findings: list[Finding]) -> Finding | None:
    prioritized = prioritize_findings(findings)
    if not prioritized:
        return None
    return prioritized[0]


def build_cve_summary(
    findings: list[Finding],
    services: list[Service],
) -> list[CveSummaryItem]:
    summary: list[CveSummaryItem] = []
    for finding in prioritize_findings(findings):
        if not finding.cve_id:
            continue
        service = _service_for_port(services, finding.port)
        summary.append(
            CveSummaryItem(
                cve_id=finding.cve_id,
                finding_id=finding.id,
                title=finding.title,
                severity=finding.severity,
                confidence=finding.confidence,
                service_name=service.name if service else None,
                service_version=service.version if service else None,
                port=finding.port,
                references=list(finding.references),
            )
        )
    return summary


def build_executive_summary(scan_result: ScanResult) -> str:
    findings_count = len(scan_result.findings)
    if findings_count == 0:
        return (
            "No findings identified. "
            f"Overall risk severity is {scan_result.risk.severity}. "
            f"The scan of {scan_result.target} using the {scan_result.profile} "
            "profile completed without detecting security issues across the "
            "assessed services and ports. No CVE-linked vulnerabilities were identified."
        )

    affected_labels = _affected_service_labels(scan_result)
    affected_services = len(affected_labels)
    highest_finding = _highest_severity_finding(scan_result.findings)
    cve_findings = [finding for finding in scan_result.findings if finding.cve_id]

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

    if affected_labels:
        summary_parts.append(
            "Affected services/ports: " + "; ".join(affected_labels) + "."
        )

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

    for finding in prioritize_findings(findings):
        recommendation = finding.recommendation.strip()
        if not recommendation or recommendation in seen:
            continue
        seen.add(recommendation)
        recommendations.append(recommendation)

    return recommendations


def generate_security_report(
    scan_result: ScanResult,
    *,
    enhancer: ReportEnhancer | None = None,
) -> SecurityReport:
    prioritized = prioritize_findings(scan_result.findings)
    cve_summary = build_cve_summary(scan_result.findings, scan_result.services)
    executive_summary = build_executive_summary(scan_result)
    recommendations = build_recommendations(scan_result.findings)

    active_enhancer = enhancer if enhancer is not None else get_report_enhancer()
    enhanced_summary = active_enhancer.enhance_executive_summary(
        executive_summary,
        scan_result,
        prioritized,
    )
    enhanced_recommendations = active_enhancer.enhance_recommendations(
        recommendations,
        scan_result,
        prioritized,
    )
    ai_enhanced = (
        enhanced_summary != executive_summary
        or enhanced_recommendations != recommendations
    )

    return SecurityReport(
        report_id=str(uuid.uuid4()),
        scan_id=scan_result.scan_id,
        target=scan_result.target,
        profile=scan_result.profile,
        generated_at=datetime.now(timezone.utc),
        duration_seconds=scan_result.duration_seconds,
        risk=scan_result.risk,
        services=list(scan_result.services),
        findings=prioritized,
        prioritized_findings=prioritized,
        cve_summary=cve_summary,
        executive_summary=enhanced_summary,
        recommendations=enhanced_recommendations,
        ai_enhanced=ai_enhanced,
    )
