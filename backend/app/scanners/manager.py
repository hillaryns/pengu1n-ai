from datetime import datetime, timezone
import uuid

from app.models.result import Finding, ScanResult, Service
from app.scanners.http_scanner import scan_http_service
from app.scanners.port_scanner import scan_ports
from app.scanners.scan_profiles import ScanProfile, get_profile_config
from app.scanners.scope_manager import (
    ScopeConfig,
    enforce_scope_rules,
    get_effective_requests_per_second,
)
from app.scanners.service_detector import detect_services
from app.scanners.risk_engine import calculate_risk
from app.scanners.tls_scanner import scan_tls_service
from app.scanners.vulnerability_intel import lookup_vulnerabilities


def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str | None, int | None]] = set()
    deduplicated = []

    for finding in findings:
        key = (finding.id, finding.target, finding.port)
        if key in seen:
            continue
        seen.add(key)
        deduplicated.append(finding)

    return deduplicated


class ScanManager:
    def scan(
        self,
        target: str,
        profile: ScanProfile = "standard",
        scope: ScopeConfig | None = None,
    ) -> ScanResult:
        enforce_scope_rules(target, profile, scope)

        scan_id = str(uuid.uuid4())
        started_at = datetime.now(timezone.utc)
        profile_config = get_profile_config(profile)
        requests_per_second = get_effective_requests_per_second(
            profile_config.requests_per_second,
            scope,
        )

        open_ports = scan_ports(target, list(profile_config.ports))

        services: list[Service] = detect_services(target, open_ports)

        findings = []

        for service in services:
            if profile_config.enable_http_scan and service.name in ("HTTP", "HTTPS"):
                findings.extend(
                    scan_http_service(
                        target,
                        service.port,
                        service.name,
                    )
                )
            if profile_config.enable_tls_scan and service.name == "HTTPS":
                findings.extend(
                    scan_tls_service(target, service.port)
                )

        findings.extend(lookup_vulnerabilities(target, services))
        findings = deduplicate_findings(findings)
        risk = calculate_risk(findings)
        completed_at = datetime.now(timezone.utc)
        duration_seconds = (completed_at - started_at).total_seconds()

        return ScanResult(
            scan_id=scan_id,
            target=target,
            profile=profile_config.name,
            status="completed",
            requests_per_second=requests_per_second,
            started_at=started_at,
            completed_at=completed_at,
            duration_seconds=duration_seconds,
            findings=findings,
            open_ports=open_ports,
            services=services,
            risk=risk,
        )