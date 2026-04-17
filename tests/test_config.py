import unittest

from sni_spoof.config import AppConfig, ConfigError, normalize_sni


class ConfigTests(unittest.TestCase):
    def test_legacy_config_keys_are_supported(self):
        config = AppConfig.from_mapping(
            {
                "LISTEN_HOST": "127.0.0.1",
                "LISTEN_PORT": 40443,
                "CONNECT_IP": "188.114.98.0",
                "CONNECT_PORT": 443,
                "FAKE_SNI": "auth.vercel.com",
            }
        )

        self.assertEqual(config.listen_host, "127.0.0.1")
        self.assertEqual(config.fake_sni_bytes, b"auth.vercel.com")

    def test_invalid_port_is_rejected(self):
        with self.assertRaises(ConfigError):
            AppConfig.from_mapping({"LISTEN_PORT": 70000})

    def test_sni_rejects_urls(self):
        with self.assertRaises(ConfigError):
            normalize_sni("https://example.com")

    def test_unicode_sni_is_normalized_to_idna(self):
        self.assertEqual(normalize_sni("täst.example"), b"xn--tst-qla.example")


if __name__ == "__main__":
    unittest.main()
