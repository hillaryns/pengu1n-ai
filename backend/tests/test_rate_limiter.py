import unittest
from unittest.mock import Mock, patch

from app.scanners.manager import ScanManager
from app.scanners.rate_limiter import RateLimiter, create_rate_limiter
from app.scanners.scope_manager import ScopeConfig, get_effective_requests_per_second
from app.scanners.scan_profiles import get_profile_config


class RateLimiterTests(unittest.TestCase):
    def test_accepts_valid_positive_rates(self):
        limiter = RateLimiter(2.0)
        self.assertAlmostEqual(limiter._interval, 0.5)

        limiter = RateLimiter(100.0)
        self.assertAlmostEqual(limiter._interval, 0.01)

    def test_rejects_zero_rate(self):
        with self.assertRaises(ValueError):
            RateLimiter(0)

    def test_rejects_negative_rate(self):
        with self.assertRaises(ValueError):
            RateLimiter(-1.0)

    def test_create_rate_limiter_returns_none_when_unconfigured(self):
        self.assertIsNone(create_rate_limiter(None))

    def test_rate_limiter_introduces_expected_delay(self):
        with patch(
            "app.scanners.rate_limiter.time.monotonic",
            side_effect=[1.0, 1.0, 1.0, 1.02, 1.12],
        ):
            with patch("app.scanners.rate_limiter.time.sleep") as sleep_mock:
                limiter = RateLimiter(10.0)
                limiter.acquire()
                limiter.acquire()

        sleep_mock.assert_called_once()
        sleep_seconds = sleep_mock.call_args[0][0]
        self.assertGreater(sleep_seconds, 0)
        self.assertAlmostEqual(sleep_seconds, 0.08, places=2)

    def test_rate_limiter_does_not_sleep_for_first_acquire(self):
        with patch("app.scanners.rate_limiter.time.monotonic", return_value=1.0):
            with patch("app.scanners.rate_limiter.time.sleep") as sleep_mock:
                limiter = RateLimiter(5.0)
                limiter.acquire()

        sleep_mock.assert_not_called()


class ScanManagerRateLimitIntegrationTests(unittest.TestCase):
    def _run_scan_with_patched_network(self, **scan_kwargs):
        manager = ScanManager()
        with patch("app.scanners.manager.scan_ports", return_value=[]) as scan_ports_mock:
            with patch("app.scanners.manager.detect_services", return_value=[]):
                with patch("app.scanners.manager.lookup_vulnerabilities", return_value=[]):
                    result = manager.scan("127.0.0.1", **scan_kwargs)
        return result, scan_ports_mock

    def test_each_scan_gets_its_own_limiter(self):
        scope = ScopeConfig(allowed_hosts=["127.0.0.1"])
        _, first_scan_ports = self._run_scan_with_patched_network(
            profile="bug_bounty",
            scope=scope,
        )
        _, second_scan_ports = self._run_scan_with_patched_network(
            profile="bug_bounty",
            scope=scope,
        )

        first_limiter = first_scan_ports.call_args.kwargs["rate_limiter"]
        second_limiter = second_scan_ports.call_args.kwargs["rate_limiter"]
        self.assertIsNotNone(first_limiter)
        self.assertIsNotNone(second_limiter)
        self.assertIsNot(first_limiter, second_limiter)

    def test_scope_rate_overrides_profile_default(self):
        scope = ScopeConfig(allowed_hosts=["127.0.0.1"], requests_per_second=5.0)
        result, scan_ports_mock = self._run_scan_with_patched_network(
            profile="bug_bounty",
            scope=scope,
        )

        self.assertEqual(result.requests_per_second, 5.0)
        limiter = scan_ports_mock.call_args.kwargs["rate_limiter"]
        self.assertIsNotNone(limiter)
        self.assertAlmostEqual(limiter._interval, 0.2)

    def test_bug_bounty_profile_default_rate_is_applied(self):
        scope = ScopeConfig(allowed_hosts=["127.0.0.1"])
        result, scan_ports_mock = self._run_scan_with_patched_network(
            profile="bug_bounty",
            scope=scope,
        )

        profile_rate = get_profile_config("bug_bounty").requests_per_second
        self.assertEqual(result.requests_per_second, profile_rate)
        limiter = scan_ports_mock.call_args.kwargs["rate_limiter"]
        self.assertIsNotNone(limiter)
        self.assertAlmostEqual(limiter._interval, 0.5)

    def test_standard_profile_has_no_rate_limiter(self):
        result, scan_ports_mock = self._run_scan_with_patched_network(profile="standard")

        self.assertIsNone(result.requests_per_second)
        self.assertIsNone(scan_ports_mock.call_args.kwargs["rate_limiter"])

    def test_bug_bounty_still_requires_allowed_hosts(self):
        manager = ScanManager()
        with self.assertRaises(ValueError):
            manager.scan("127.0.0.1", profile="bug_bounty")

        with self.assertRaises(ValueError):
            manager.scan(
                "127.0.0.1",
                profile="bug_bounty",
                scope=ScopeConfig(allowed_hosts=[]),
            )

    def test_get_effective_requests_per_second_prefers_scope_override(self):
        profile_rate = get_profile_config("bug_bounty").requests_per_second
        scope = ScopeConfig(allowed_hosts=["example.com"], requests_per_second=3.0)

        effective_rate = get_effective_requests_per_second(profile_rate, scope)
        self.assertEqual(effective_rate, 3.0)

    def test_port_scanner_acquires_before_each_connection(self):
        from app.scanners.port_scanner import scan_ports

        limiter = Mock()
        with patch("app.scanners.port_scanner.socket.socket"):
            scan_ports("127.0.0.1", ports=[80, 443], rate_limiter=limiter)

        self.assertEqual(limiter.acquire.call_count, 2)


if __name__ == "__main__":
    unittest.main()
