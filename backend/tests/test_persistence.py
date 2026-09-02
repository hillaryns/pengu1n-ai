import os
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, r"C:\Users\halcy\pengu1nai\pengu1n-ai\backend")

from app.db.database import configure_database, dispose_database, init_db, reset_database
from app.db.repository import DatabaseError, ScanRepository
from app.models.result import Finding, RiskSummary, ScanResult, Service
from app.scanners.report_generator import generate_security_report
from app.scanners.scan_store import (
    clear_scan_store,
    get_scan_result,
    get_security_report,
    list_scan_summaries,
    save_scan_result,
)
from tests.auth_helpers import auth_headers, configure_test_api_keys


def _sample_scan_result(scan_id: str = "scan-db-1") -> ScanResult:
    findings = [
        Finding(
            id="HTTP-MISSING-CSP",
            title="Missing Content-Security-Policy Header (port 8000)",
            description="CSP helps prevent XSS.",
            severity="MEDIUM",
            category="HTTP Security",
            recommendation="Define a Content-Security-Policy header.",
            target="127.0.0.1",
            port=8000,
            evidence="HTTP response from port 8000 did not include CSP.",
        ),
        Finding(
            id="VULN-CVE-2024-1234",
            title="CVE-2024-1234 affects MySQL 8.0.46 (port 3306)",
            description="Test CVE finding.",
            severity="HIGH",
            category="Vulnerability Intelligence",
            recommendation="Apply the vendor patch.",
            target="127.0.0.1",
            port=3306,
            evidence="Detected MySQL version 8.0.46 on port 3306.",
            cve_id="CVE-2024-1234",
            confidence="HIGH",
            references=["https://nvd.nist.gov/vuln/detail/CVE-2024-1234"],
        ),
    ]
    return ScanResult(
        scan_id=scan_id,
        target="127.0.0.1",
        profile="standard",
        status="completed",
        started_at="2026-09-02T12:00:00Z",
        completed_at="2026-09-02T12:00:07Z",
        duration_seconds=7.0,
        findings=findings,
        open_ports=[3306, 8000],
        services=[
            Service(port=3306, name="MySQL", version="8.0.46"),
            Service(port=8000, name="HTTP", version="uvicorn"),
        ],
        risk=RiskSummary(
            severity="HIGH",
            counts={
                "CRITICAL": 0,
                "HIGH": 1,
                "MEDIUM": 1,
                "LOW": 0,
                "INFO": 0,
            },
        ),
    )


class PersistenceTests(unittest.TestCase):
    def setUp(self):
        configure_test_api_keys()
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
        self.temp_db.close()
        configure_database(f"sqlite:///{self.temp_db.name}")
        init_db()

    def tearDown(self):
        dispose_database()
        try:
            os.unlink(self.temp_db.name)
        except PermissionError:
            pass

    def test_database_initialization(self):
        repository = ScanRepository()
        self.assertEqual(repository.list_scans(), [])

    def test_saving_completed_scan(self):
        scan_result = _sample_scan_result()
        report = generate_security_report(scan_result)
        save_scan_result(scan_result, report)

        stored = get_scan_result("scan-db-1")
        self.assertIsNotNone(stored)
        self.assertEqual(stored.target, "127.0.0.1")

    def test_retrieving_scan_by_scan_id(self):
        scan_result = _sample_scan_result("scan-db-2")
        report = generate_security_report(scan_result)
        save_scan_result(scan_result, report)

        stored = get_scan_result("scan-db-2")
        self.assertEqual(stored.scan_id, "scan-db-2")
        self.assertEqual(stored.risk.severity, "HIGH")

    def test_listing_scans(self):
        first = _sample_scan_result("scan-db-3")
        second = _sample_scan_result("scan-db-4")
        save_scan_result(first, generate_security_report(first))
        save_scan_result(second, generate_security_report(second))

        summaries = list_scan_summaries()
        self.assertEqual(len(summaries), 2)
        self.assertEqual(summaries[0].finding_count, 2)

    def test_retrieving_persisted_report(self):
        scan_result = _sample_scan_result("scan-db-5")
        report = generate_security_report(scan_result)
        save_scan_result(scan_result, report)

        stored_report = get_security_report("scan-db-5")
        self.assertIsNotNone(stored_report)
        self.assertEqual(stored_report.scan_id, "scan-db-5")
        self.assertEqual(len(stored_report.findings), 2)

    def test_unknown_scan_returns_none(self):
        self.assertIsNone(get_scan_result("missing-scan"))
        self.assertIsNone(get_security_report("missing-scan"))

    def test_services_persist_correctly(self):
        scan_result = _sample_scan_result("scan-db-6")
        save_scan_result(scan_result, generate_security_report(scan_result))

        stored = get_scan_result("scan-db-6")
        self.assertEqual(len(stored.services), 2)
        self.assertEqual(stored.services[0].name, "MySQL")
        self.assertEqual(stored.services[0].version, "8.0.46")

    def test_findings_persist_correctly(self):
        scan_result = _sample_scan_result("scan-db-7")
        save_scan_result(scan_result, generate_security_report(scan_result))

        stored = get_scan_result("scan-db-7")
        self.assertEqual(len(stored.findings), 2)
        self.assertEqual(stored.findings[0].id, "HTTP-MISSING-CSP")

    def test_cve_metadata_persists_correctly(self):
        scan_result = _sample_scan_result("scan-db-8")
        save_scan_result(scan_result, generate_security_report(scan_result))

        stored = get_scan_result("scan-db-8")
        cve_finding = next(
            finding for finding in stored.findings if finding.cve_id == "CVE-2024-1234"
        )
        self.assertEqual(cve_finding.confidence, "HIGH")
        self.assertEqual(
            cve_finding.references,
            ["https://nvd.nist.gov/vuln/detail/CVE-2024-1234"],
        )

    def test_database_failure_is_handled_safely(self):
        from fastapi.testclient import TestClient
        from app.main import app

        with patch(
            "app.api.scan.save_scan_result",
            side_effect=DatabaseError("Failed to save scan result"),
        ):
            client = TestClient(app)
            with patch("app.api.scan.scan_manager.scan", return_value=_sample_scan_result("scan-db-9")):
                response = client.post(
                    "/scan",
                    json={"target": "127.0.0.1"},
                    headers=auth_headers(),
                )

        self.assertEqual(response.status_code, 500)
        self.assertEqual(
            response.json()["detail"],
            "Unable to process scan storage request",
        )

    def test_post_scan_still_returns_200(self):
        from fastapi.testclient import TestClient
        from app.main import app

        scan_result = _sample_scan_result("scan-db-10")
        with patch("app.api.scan.scan_manager.scan", return_value=scan_result):
            client = TestClient(app)
            response = client.post(
                "/scan",
                json={"target": "127.0.0.1"},
                headers=auth_headers(),
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["scan_id"], "scan-db-10")

    def test_get_scan_endpoint_returns_404_for_unknown_scan(self):
        from fastapi.testclient import TestClient
        from app.main import app

        client = TestClient(app)
        response = client.get("/scans/unknown-scan", headers=auth_headers())
        self.assertEqual(response.status_code, 404)

    def test_report_endpoint_reads_persisted_report_without_new_scan(self):
        from fastapi.testclient import TestClient
        from app.main import app

        scan_result = _sample_scan_result("scan-db-11")
        report = generate_security_report(scan_result)
        save_scan_result(scan_result, report)

        with patch("app.api.scan.scan_manager.scan") as mock_scan:
            client = TestClient(app)
            response = client.get("/scan/scan-db-11/report", headers=auth_headers())

        self.assertEqual(response.status_code, 200)
        mock_scan.assert_not_called()
        self.assertEqual(response.json()["scan_id"], "scan-db-11")


if __name__ == "__main__":
    unittest.main()
