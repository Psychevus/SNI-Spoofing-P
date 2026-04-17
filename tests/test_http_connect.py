import base64
import unittest

from sni_spoof.http_connect import HttpConnectError, is_proxy_authorized, parse_authority


class HttpConnectTests(unittest.TestCase):
    def test_parse_authority(self):
        host, port = parse_authority("Auth.Vercel.Com:443")

        self.assertEqual(host, "auth.vercel.com")
        self.assertEqual(port, 443)

    def test_parse_authority_requires_port(self):
        with self.assertRaises(HttpConnectError):
            parse_authority("auth.vercel.com")

    def test_bearer_auth(self):
        self.assertTrue(is_proxy_authorized({"proxy-authorization": "Bearer secret"}, "secret"))
        self.assertFalse(is_proxy_authorized({"proxy-authorization": "Bearer wrong"}, "secret"))

    def test_basic_auth_password(self):
        encoded = base64.b64encode(b"user:secret").decode("ascii")

        self.assertTrue(is_proxy_authorized({"proxy-authorization": f"Basic {encoded}"}, "secret"))


if __name__ == "__main__":
    unittest.main()
