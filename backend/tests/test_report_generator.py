import os
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, r"C:\Users\halcy\pengu1nai\pengu1n-ai\backend")

from app.db.database import configure_database, dispose_database, init_db
from app.models.result import Finding, RiskSummary, ScanResult, Service
from app.scanners.report_generator import (
    build_executive_summary,
    build_recommendations,
    generate_security_report,
)
from app.scanners.scan_store import clear_scan_store, get_security_report, save_scan_result
from tests.auth_helpers import auth_headers, configure_test_api_keys


def _sample_scan_result() -> ScanResult:
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
            id="HTTP-MISSING-X-FRAME-OPTIONS",
            title="Missing X-Frame-Options Header (port 8000)",
            description="X-Frame-Options helps prevent clickjacking.",
            severity="LOW",
            category="HTTP Security",
            recommendation="Define a Content-Security-Policy header.",
            target="127.0.0.1",
            port=8000,
            evidence="HTTP response from port 8000 did not include X-Frame-Options.",
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
        scan_id="scan-123",
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
                "LOW": 1,
                "INFO": 0,
            },
        ),
    )


class ReportGeneratorTests(unittest.TestCase):
    def setUp(self):
        configure_test_api_keys()
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
        self.temp_db.close()
        configure_database(f"sqlite:///{self.temp_db.name}")
        init_db()
        clear_scan_store()

    def tearDown(self):
        dispose_database()
        try:
            os.unlink(self.temp_db.name)
        except PermissionError:
            pass

    def test_report_generation(self):
        scan_result = _sample_scan_result()
        report = generate_security_report(scan_result)

        self.assertEqual(report.scan_id, "scan-123")
        self.assertEqual(report.target, "127.0.0.1")
        self.assertEqual(len(report.findings), 3)
        self.assertEqual(report.risk.severity, "HIGH")

    def test_report_id_generation(self):
        scan_result = _sample_scan_result()
        first = generate_security_report(scan_result)
        second = generate_security_report(scan_result)

        self.assertTrue(first.report_id)
        self.assertTrue(second.report_id)
        self.assertNotEqual(first.report_id, second.report_id)

    def test_scan_id_preservation(self):
        report = generate_security_report(_sample_scan_result())
        self.assertEqual(report.scan_id, "scan-123")

    def test_deterministic_executive_summary(self):
        scan_result = _sample_scan_result()
        first = build_executive_summary(scan_result)
        second = build_executive_summary(scan_result)

        self.assertEqual(first, second)
        self.assertIn("Overall risk severity is HIGH", first)
        self.assertIn("3 finding(s)", first)
        self.assertIn("2 affected service(s)", first)
        self.assertIn("CVE IDs were detected", first)

    def test_recommendation_deduplication(self):
        recommendations = build_recommendations(_sample_scan_result().findings)
        self.assertEqual(len(recommendations), 2)
        self.assertEqual(recommendations[0], "Define a Content-Security-Policy header.")
        self.assertEqual(recommendations[1], "Apply the vendor patch.")

    def test_cve_finding_preservation(self):
        report = generate_security_report(_sample_scan_result())
        cve_finding = next(
            finding for finding in report.findings if finding.cve_id == "CVE-2024-1234"
        )

        self.assertEqual(cve_finding.id, "VULN-CVE-2024-1234")
        self.assertEqual(cve_finding.confidence, "HIGH")
        self.assertEqual(
            cve_finding.references,
            ["https://nvd.nist.gov/vuln/detail/CVE-2024-1234"],
        )

    def test_known_scan_id_returns_report(self):
        scan_result = _sample_scan_result()
        report = generate_security_report(scan_result)
        save_scan_result(scan_result, report)

        stored = get_security_report("scan-123")
        self.assertIsNotNone(stored)
        self.assertEqual(stored.report_id, report.report_id)

    def test_unknown_scan_id_returns_none(self):
        self.assertIsNone(get_security_report("missing-scan"))

    def test_report_endpoint_returns_404_for_unknown_scan(self):
        from fastapi.testclient import TestClient
        from app.main import app

        client = TestClient(app)
        response = client.get("/scan/unknown-scan/report", headers=auth_headers())
        self.assertEqual(response.status_code, 404)

    def test_report_endpoint_never_triggers_new_scan(self):
        from fastapi.testclient import TestClient
        from app.main import app

        scan_result = _sample_scan_result()
        report = generate_security_report(scan_result)
        save_scan_result(scan_result, report)

        with patch("app.api.scan.scan_manager.scan") as mock_scan:
            client = TestClient(app)
            response = client.get("/scan/scan-123/report", headers=auth_headers())

        self.assertEqual(response.status_code, 200)
        mock_scan.assert_not_called()
        self.assertEqual(response.json()["scan_id"], "scan-123")

    def test_post_scan_still_works_with_mocked_scanning(self):
        from fastapi.testclient import TestClient
        from app.main import app

        scan_result = _sample_scan_result()

        with patch("app.api.scan.scan_manager.scan", return_value=scan_result):
            client = TestClient(app)
            response = client.post(
                "/scan",
                json={"target": "127.0.0.1"},
                headers=auth_headers(),
            )

        self.assertEqual(response.status_code, 200)
        report = get_security_report("scan-123")
        self.assertIsNotNone(report)


if __name__ == "__main__":
    unittest.main()
