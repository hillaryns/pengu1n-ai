from app.db.repository import DatabaseError, ScanRepository
from app.models.report import SecurityReport
from app.models.result import ScanResult, ScanSummary

_repository = ScanRepository()


def save_scan_result(scan_result: ScanResult, report: SecurityReport) -> None:
    _repository.save(scan_result, report)


def get_scan_result(scan_id: str) -> ScanResult | None:
    return _repository.get_scan(scan_id)


def get_security_report(scan_id: str) -> SecurityReport | None:
    return _repository.get_report(scan_id)


def list_scan_summaries() -> list[ScanSummary]:
    return _repository.list_scans()


def clear_scan_store() -> None:
    from app.db.database import reset_database

    reset_database()
