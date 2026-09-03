from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import joinedload

from app.db.database import get_session
from app.db.models import FindingRecord, ReportRecord, ScanRecord, ServiceRecord
from app.models.report import CveSummaryItem, SecurityReport
from app.models.result import Finding, RiskSummary, ScanResult, ScanSummary, Service
from app.scanners.report_generator import build_cve_summary, prioritize_findings


class DatabaseError(Exception):
    pass


def _to_finding(record: FindingRecord) -> Finding:
    return Finding(
        id=record.finding_id,
        title=record.title,
        description=record.description,
        severity=record.severity,
        category=record.category,
        recommendation=record.recommendation,
        target=record.target,
        port=record.port,
        evidence=record.evidence,
        cve_id=record.cve_id,
        confidence=record.confidence,
        references=record.references or [],
    )


def _to_service(record: ServiceRecord) -> Service:
    return Service(
        port=record.port,
        name=record.name,
        version=record.version,
    )


def _to_scan_result(record: ScanRecord) -> ScanResult:
    return ScanResult(
        scan_id=record.scan_id,
        target=record.target,
        profile=record.profile,
        status=record.status,
        requests_per_second=record.requests_per_second,
        started_at=record.started_at,
        completed_at=record.completed_at,
        duration_seconds=record.duration_seconds,
        findings=[_to_finding(finding) for finding in record.findings],
        open_ports=record.open_ports or [],
        services=[_to_service(service) for service in record.services],
        risk=RiskSummary(
            severity=record.risk_severity,
            counts=record.risk_counts,
        ),
    )


def _to_cve_summary_items(raw_items: list | None, scan_result: ScanResult) -> list[CveSummaryItem]:
    if raw_items:
        return [CveSummaryItem.model_validate(item) for item in raw_items]
    return build_cve_summary(scan_result.findings, scan_result.services)


def _to_security_report(record: ScanRecord, report: ReportRecord) -> SecurityReport:
    scan_result = _to_scan_result(record)
    prioritized = prioritize_findings(scan_result.findings)
    return SecurityReport(
        report_id=report.report_id,
        scan_id=record.scan_id,
        target=record.target,
        profile=record.profile,
        generated_at=report.generated_at,
        duration_seconds=record.duration_seconds,
        risk=scan_result.risk,
        services=scan_result.services,
        findings=prioritized,
        prioritized_findings=prioritized,
        cve_summary=_to_cve_summary_items(report.cve_summary, scan_result),
        executive_summary=report.executive_summary,
        recommendations=report.recommendations or [],
        ai_enhanced=bool(report.ai_enhanced),
    )


class ScanRepository:
    def save(self, scan_result: ScanResult, report: SecurityReport) -> None:
        session = get_session()
        try:
            scan_record = ScanRecord(
                scan_id=scan_result.scan_id,
                target=scan_result.target,
                profile=scan_result.profile,
                status=scan_result.status,
                started_at=scan_result.started_at,
                completed_at=scan_result.completed_at,
                duration_seconds=scan_result.duration_seconds,
                risk_severity=scan_result.risk.severity,
                risk_counts=scan_result.risk.counts,
                requests_per_second=scan_result.requests_per_second,
                open_ports=scan_result.open_ports,
            )

            scan_record.services = [
                ServiceRecord(
                    scan_id=scan_result.scan_id,
                    port=service.port,
                    name=service.name,
                    version=service.version,
                )
                for service in scan_result.services
            ]

            scan_record.findings = [
                FindingRecord(
                    scan_id=scan_result.scan_id,
                    finding_id=finding.id,
                    title=finding.title,
                    description=finding.description,
                    severity=finding.severity,
                    category=finding.category,
                    recommendation=finding.recommendation,
                    target=finding.target,
                    port=finding.port,
                    evidence=finding.evidence,
                    cve_id=finding.cve_id,
                    confidence=finding.confidence,
                    references=finding.references,
                )
                for finding in scan_result.findings
            ]

            scan_record.report = ReportRecord(
                report_id=report.report_id,
                scan_id=scan_result.scan_id,
                generated_at=report.generated_at,
                executive_summary=report.executive_summary,
                recommendations=report.recommendations,
                cve_summary=[item.model_dump() for item in report.cve_summary],
                ai_enhanced=report.ai_enhanced,
            )

            session.add(scan_record)
            session.commit()
        except SQLAlchemyError as error:
            session.rollback()
            raise DatabaseError("Failed to save scan result") from error
        finally:
            session.close()

    def get_scan(self, scan_id: str) -> ScanResult | None:
        session = get_session()
        try:
            record = (
                session.query(ScanRecord)
                .options(
                    joinedload(ScanRecord.services),
                    joinedload(ScanRecord.findings),
                )
                .filter(ScanRecord.scan_id == scan_id)
                .one_or_none()
            )
            if record is None:
                return None
            return _to_scan_result(record)
        except SQLAlchemyError as error:
            raise DatabaseError("Failed to retrieve scan result") from error
        finally:
            session.close()

    def get_report(self, scan_id: str) -> SecurityReport | None:
        session = get_session()
        try:
            record = (
                session.query(ScanRecord)
                .options(
                    joinedload(ScanRecord.services),
                    joinedload(ScanRecord.findings),
                    joinedload(ScanRecord.report),
                )
                .filter(ScanRecord.scan_id == scan_id)
                .one_or_none()
            )
            if record is None or record.report is None:
                return None
            return _to_security_report(record, record.report)
        except SQLAlchemyError as error:
            raise DatabaseError("Failed to retrieve security report") from error
        finally:
            session.close()

    def list_scans(self) -> list[ScanSummary]:
        session = get_session()
        try:
            records = (
                session.query(ScanRecord)
                .options(joinedload(ScanRecord.findings))
                .order_by(ScanRecord.started_at.desc())
                .all()
            )
            return [
                ScanSummary(
                    scan_id=record.scan_id,
                    target=record.target,
                    profile=record.profile,
                    status=record.status,
                    started_at=record.started_at,
                    completed_at=record.completed_at,
                    duration_seconds=record.duration_seconds,
                    risk_severity=record.risk_severity,
                    finding_count=len(record.findings),
                )
                for record in records
            ]
        except SQLAlchemyError as error:
            raise DatabaseError("Failed to list scans") from error
        finally:
            session.close()
