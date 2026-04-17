import unittest

from sni_spoof.config import AppConfig
from sni_spoof.http_connect import HttpConnectError
from sni_spoof.pac import generate_pac
from sni_spoof.policy import ProxyPolicy


class PolicyAndPacTests(unittest.TestCase):
    def test_policy_allows_exact_host(self):
        policy = ProxyPolicy(("auth.vercel.com",), (443,))

        policy.validate_connect("auth.vercel.com", 443)

    def test_policy_rejects_unknown_host(self):
        policy = ProxyPolicy(("auth.vercel.com",), (443,))

        with self.assertRaises(HttpConnectError):
            policy.validate_connect("example.com", 443)

    def test_policy_allows_wildcard_suffix(self):
        policy = ProxyPolicy(("*.example.com",), (443,))

        self.assertTrue(policy.host_allowed("api.example.com"))
        self.assertFalse(policy.host_allowed("example.com"))

    def test_pac_contains_proxy_endpoint(self):
        config = AppConfig.from_mapping({"LISTEN_PORT": 8080, "ALLOWED_HOSTS": ["auth.vercel.com"]})
        pac = generate_pac(config)

        self.assertIn("PROXY 127.0.0.1:8080", pac)
        self.assertIn('host === "auth.vercel.com"', pac)


if __name__ == "__main__":
    unittest.main()
