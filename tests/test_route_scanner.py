import json
import unittest

from sni_spoof.config import AppConfig
from sni_spoof.route_scanner import format_route_scan, route_scan_to_json, run_route_scan


class RouteScannerTests(unittest.TestCase):
    def test_offline_scan_reports_ready_route(self):
        config = AppConfig.from_mapping(
            {
                "LISTEN_HOST": "127.0.0.1",
                "LISTEN_PORT": 18080,
                "CONNECT_IP": "93.184.216.34",
                "CONNECT_PORT": 443,
                "FAKE_SNI": "example.com",
                "ALLOWED_HOSTS": ["example.com"],
                "ALLOWED_PORTS": [443],
            }
        )

        report = run_route_scan(config, network=False)

        self.assertEqual(report.verdict, "ready")
        self.assertGreaterEqual(report.score, 90)
        self.assertFalse(report.network_probes)
        self.assertIn("Route Scanner", format_route_scan(report))

    def test_scan_warns_on_wildcard_allowlist(self):
        config = AppConfig.from_mapping(
            {
                "FAKE_SNI": "example.com",
                "ALLOWED_HOSTS": ["*"],
            }
        )

        report = run_route_scan(config, network=False)
        warnings = [check for check in report.checks if check.status == "warn"]

        self.assertTrue(any(check.name == "allowlist" for check in warnings))
        self.assertLess(report.score, 100)

    def test_json_output_is_machine_readable(self):
        config = AppConfig.from_mapping(
            {
                "CONNECT_IP": "93.184.216.34",
                "FAKE_SNI": "example.com",
                "ALLOWED_HOSTS": ["example.com"],
            }
        )
        report = run_route_scan(config, network=False)

        payload = json.loads(route_scan_to_json(report))

        self.assertEqual(payload["profile"], "default")
        self.assertEqual(payload["network_probes"], False)
        self.assertIn("checks", payload)


if __name__ == "__main__":
    unittest.main()
