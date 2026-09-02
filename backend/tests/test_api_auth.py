import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.core.security import reset_api_key_cache
from app.main import app
from fastapi.testclient import TestClient
from tests.auth_helpers import (
    TEST_API_KEY,
    TEST_API_KEY_SECONDARY,
    auth_headers,
    configure_test_api_keys,
)


class ApiAuthTests(unittest.TestCase):
    def setUp(self):
        configure_test_api_keys()

    def tearDown(self):
        os.environ.pop("PENGU1N_API_KEYS", None)
        reset_api_key_cache()

    def test_missing_api_key_returns_401(self):
        client = TestClient(app)
        response = client.post("/scan", json={"target": "127.0.0.1"})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["detail"], "Invalid or missing API key")

    def test_invalid_api_key_returns_401(self):
        client = TestClient(app)
        response = client.post(
            "/scan",
            json={"target": "127.0.0.1"},
            headers=auth_headers("invalid-api-key"),
        )
        self.assertEqual(response.status_code, 401)

    def test_valid_api_key_allows_protected_endpoint(self):
        from app.models.result import RiskSummary, ScanResult

        scan_result = ScanResult(
            scan_id="auth-scan-1",
            target="127.0.0.1",
            profile="standard",
            status="completed",
            started_at="2026-09-02T12:00:00Z",
            completed_at="2026-09-02T12:00:07Z",
            duration_seconds=1.0,
            findings=[],
            open_ports=[],
            services=[],
            risk=RiskSummary(severity="INFO", counts={"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}),
        )

        with patch("app.api.scan.scan_manager.scan", return_value=scan_result):
            with patch("app.api.scan.save_scan_result"):
                client = TestClient(app)
                response = client.post(
                    "/scan",
                    json={"target": "127.0.0.1"},
                    headers=auth_headers(),
                )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["scan_id"], "auth-scan-1")

    def test_health_endpoint_works_without_key(self):
        client = TestClient(app)
        response = client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "healthy")

    def test_root_endpoint_works_without_key(self):
        client = TestClient(app)
        response = client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["name"], "Pengu1n AI")

    def test_openapi_contains_api_key_security_scheme(self):
        client = TestClient(app)
        schema = client.get("/openapi.json").json()
        security_schemes = schema.get("components", {}).get("securitySchemes", {})
        self.assertIn("APIKeyHeader", security_schemes)
        self.assertEqual(security_schemes["APIKeyHeader"]["name"], "X-API-Key")
        self.assertEqual(security_schemes["APIKeyHeader"]["in"], "header")

    def test_multiple_configured_api_keys_work(self):
        from app.models.result import RiskSummary, ScanResult

        scan_result = ScanResult(
            scan_id="auth-scan-2",
            target="127.0.0.1",
            profile="standard",
            status="completed",
            started_at="2026-09-02T12:00:00Z",
            completed_at="2026-09-02T12:00:07Z",
            duration_seconds=1.0,
            findings=[],
            open_ports=[],
            services=[],
            risk=RiskSummary(severity="INFO", counts={"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}),
        )

        with patch("app.api.scan.scan_manager.scan", return_value=scan_result):
            with patch("app.api.scan.save_scan_result"):
                client = TestClient(app)
                response = client.post(
                    "/scan",
                    json={"target": "127.0.0.1"},
                    headers=auth_headers(TEST_API_KEY_SECONDARY),
                )

        self.assertEqual(response.status_code, 200)


if __name__ == "__main__":
    unittest.main()
