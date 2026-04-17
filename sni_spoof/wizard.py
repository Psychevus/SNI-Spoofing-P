from __future__ import annotations

from pathlib import Path
from typing import Callable

from .config import AppConfig
from .config_store import base_config_document, save_profile, write_config_document


InputFunc = Callable[[str], str]
PrintFunc = Callable[[str], None]


def run_wizard(path: str | Path, input_func: InputFunc = input, print_func: PrintFunc = print) -> None:
    print_func("SNI Spoofing Proxy setup wizard")
    print_func("Press Enter to accept the default value shown in brackets.")

    listen_host = _ask(input_func, "Local proxy host", "127.0.0.1")
    listen_port = int(_ask(input_func, "Local proxy port", "8080"))
    control_port = int(_ask(input_func, "Dashboard port", "9090"))
    profile_name = _ask(input_func, "Profile name", "default")
    fake_sni = _ask(input_func, "TLS SNI hostname", "auth.vercel.com")
    connect_ip = _ask(input_func, "Target IP", "188.114.98.0")
    connect_port = int(_ask(input_func, "Target port", "443"))
    allowed_hosts = _ask(input_func, "Allowed hosts", fake_sni)

    config = AppConfig.from_mapping(
        {
            "LISTEN_HOST": listen_host,
            "LISTEN_PORT": listen_port,
            "PROXY_MODE": "http_connect",
            "CONNECT_IP": connect_ip,
            "CONNECT_PORT": connect_port,
            "FAKE_SNI": fake_sni,
            "ALLOWED_HOSTS": [item.strip() for item in allowed_hosts.split(",") if item.strip()],
            "ALLOWED_PORTS": [connect_port],
            "CONTROL_ENABLED": True,
            "CONTROL_HOST": "127.0.0.1",
            "CONTROL_PORT": control_port,
            "STRICT_LOCAL_ONLY": True,
            "REQUIRE_AUTH_FOR_REMOTE_BIND": True,
        }
    )

    document = base_config_document(config)
    write_config_document(path, document)
    if profile_name != "default":
        save_profile(
            path,
            profile_name,
            {
                "CONNECT_IP": connect_ip,
                "CONNECT_PORT": connect_port,
                "FAKE_SNI": fake_sni,
                "ALLOWED_HOSTS": list(config.allowed_hosts),
                "ALLOWED_PORTS": list(config.allowed_ports),
            },
        )
    print_func(f"Wrote configuration to {Path(path)}")
    print_func("Next: run `python main.py doctor`, then `python main.py run`.")


def _ask(input_func: InputFunc, label: str, default: str) -> str:
    value = input_func(f"{label} [{default}]: ").strip()
    return value or default
