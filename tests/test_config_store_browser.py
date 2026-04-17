import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from sni_spoof.browser import build_launch_plan
from sni_spoof.config import AppConfig
from sni_spoof.config_store import delete_profile, list_profiles, save_profile, show_profile
from sni_spoof.wizard import run_wizard


class ConfigStoreAndBrowserTests(unittest.TestCase):
    def test_profile_lifecycle(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_text("{}", encoding="utf-8")

            save_profile(path, "demo", {"FAKE_SNI": "demo.example"})

            self.assertIn("demo", list_profiles(path))
            self.assertEqual(show_profile(path, "demo")["FAKE_SNI"], "demo.example")

            delete_profile(path, "demo")

            self.assertNotIn("demo", list_profiles(path))

    def test_browser_launch_plan_uses_pac(self):
        config = AppConfig.from_mapping({"LISTEN_PORT": 8080, "CONTROL_PORT": 9090})

        with patch("sni_spoof.browser.find_browser", return_value="browser.exe"):
            plan = build_launch_plan(config, url="https://auth.vercel.com/")

        self.assertIn("--proxy-pac-url=http://127.0.0.1:9090/proxy.pac", plan.args)
        self.assertIn("https://auth.vercel.com/", plan.args)

    def test_wizard_writes_config(self):
        answers = iter(
            [
                "",
                "",
                "",
                "demo",
                "demo.example",
                "188.114.98.0",
                "443",
                "demo.example",
            ]
        )

        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            run_wizard(path, input_func=lambda _: next(answers), print_func=lambda _: None)
            data = json.loads(path.read_text(encoding="utf-8"))

        self.assertEqual(data["LISTEN_PORT"], 8080)
        self.assertIn("demo", data["PROFILES"])


if __name__ == "__main__":
    unittest.main()
