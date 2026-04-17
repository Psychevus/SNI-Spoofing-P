import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

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
        self.assertEqual(config.proxy_mode, "http_connect")
        self.assertEqual(config.allowed_hosts, ("auth.vercel.com",))

    def test_invalid_port_is_rejected(self):
        with self.assertRaises(ConfigError):
            AppConfig.from_mapping({"LISTEN_PORT": 70000})

    def test_sni_rejects_urls(self):
        with self.assertRaises(ConfigError):
            normalize_sni("https://example.com")

    def test_unicode_sni_is_normalized_to_idna(self):
        self.assertEqual(normalize_sni("täst.example"), b"xn--tst-qla.example")

    def test_http_connect_requires_allowed_hosts(self):
        with self.assertRaises(ConfigError):
            AppConfig.from_mapping({"PROXY_MODE": "http_connect", "ALLOWED_HOSTS": []})

    def test_raw_mode_accepts_custom_mode_name(self):
        config = AppConfig.from_mapping({"PROXY_MODE": "raw"})

        self.assertEqual(config.proxy_mode, "raw")

    def test_strict_local_only_rejects_remote_bind(self):
        with self.assertRaises(ConfigError):
            AppConfig.from_mapping({"LISTEN_HOST": "0.0.0.0"})

    def test_json_log_format_is_allowed(self):
        config = AppConfig.from_mapping({"LOG_FORMAT": "json"})

        self.assertEqual(config.log_format, "json")

    def test_named_profile_overrides_base_config(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_text(
                """
{
  "FAKE_SNI": "base.example",
  "ALLOWED_HOSTS": ["base.example"],
  "PROFILES": {
    "demo": {
      "FAKE_SNI": "profile.example",
      "ALLOWED_HOSTS": ["profile.example"]
    }
  }
}
""",
                encoding="utf-8",
            )

            config = AppConfig.load(path, "demo")

        self.assertEqual(config.profile, "demo")
        self.assertEqual(config.fake_sni, "profile.example")
        self.assertEqual(config.allowed_hosts, ("profile.example",))


if __name__ == "__main__":
    unittest.main()
