from fastapi import APIRouter, Depends, HTTPException

from app.core.security import require_api_key
from app.db.repository import DatabaseError
from app.models.report import SecurityReport
from app.models.result import ScanResult, ScanSummary
from app.models.scan import ScanRequest
from app.scanners.manager import ScanManager
from app.scanners.report_generator import generate_security_report
from app.scanners.scan_store import (
    get_scan_result,
    get_security_report,
    list_scan_summaries,
    save_scan_result,
)

router = APIRouter(dependencies=[Depends(require_api_key)])

scan_manager = ScanManager()


def _handle_database_error() -> None:
    raise HTTPException(
        status_code=500,
        detail="Unable to process scan storage request",
    )


@router.post("/scan", response_model=ScanResult)
def create_scan(request: ScanRequest) -> ScanResult:
    scan_result = scan_manager.scan(request.target, request.profile, request.scope)
    report = generate_security_report(scan_result)
    try:
        save_scan_result(scan_result, report)
    except DatabaseError:
        _handle_database_error()
    return scan_result


@router.get("/scans", response_model=list[ScanSummary])
def list_scans() -> list[ScanSummary]:
    try:
        return list_scan_summaries()
    except DatabaseError:
        _handle_database_error()


@router.get("/scans/{scan_id}", response_model=ScanResult)
def get_scan(scan_id: str) -> ScanResult:
    try:
        scan_result = get_scan_result(scan_id)
    except DatabaseError:
        _handle_database_error()

    if scan_result is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan_result


@router.get("/scan/{scan_id}/report", response_model=SecurityReport)
def get_scan_report(scan_id: str) -> SecurityReport:
    try:
        report = get_security_report(scan_id)
    except DatabaseError:
        _handle_database_error()

    if report is None:
        raise HTTPException(status_code=404, detail="Scan report not found")
    return report
