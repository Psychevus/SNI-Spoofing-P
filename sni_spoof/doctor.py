from __future__ import annotations

import ctypes
import importlib.util
import platform
import socket
import sys
from dataclasses import dataclass
from typing import Iterable

from .config import AppConfig
from .network import get_default_interface_ipv4
from .packets import ClientHelloMaker


@dataclass(frozen=True)
class DoctorCheck:
    name: str
    status: str
    detail: str


def is_admin() -> bool:
    if platform.system().lower() == "windows":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return hasattr(sys, "geteuid") and sys.geteuid() == 0


def run_doctor(config: AppConfig) -> list[DoctorCheck]:
    checks: list[DoctorCheck] = []
    checks.append(DoctorCheck("platform", "ok" if platform.system().lower() == "windows" else "warn", platform.platform()))
    checks.append(DoctorCheck("administrator", "ok" if is_admin() else "fail", "administrator privileges are required for WinDivert"))

    pydivert_spec = importlib.util.find_spec("pydivert")
    checks.append(DoctorCheck("pydivert", "ok" if pydivert_spec else "fail", "pydivert is importable" if pydivert_spec else "pydivert is not installed"))

    try:
        config.validate()
    except Exception as exc:
        checks.append(DoctorCheck("configuration", "fail", str(exc)))
    else:
        checks.append(DoctorCheck("configuration", "ok", "configuration is valid"))

    interface = config.interface_ipv4 or get_default_interface_ipv4(config.connect_ip)
    checks.append(DoctorCheck("interface", "ok" if interface else "fail", interface or "could not detect a route to target"))

    checks.append(_check_tcp_port("listen_port", config.listen_host, config.listen_port))
    if config.control_enabled:
        checks.append(_check_tcp_port("control_port", config.control_host, config.control_port))
    checks.append(_check_target(config))
    checks.append(_check_template(config))
    for warning in config.security_warnings():
        checks.append(DoctorCheck("security", "warn", warning))
    return checks


def _check_tcp_port(name: str, host: str, port: int) -> DoctorCheck:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind((host, port))
    except OSError as exc:
        return DoctorCheck(name, "fail", f"{host}:{port} is not available: {exc}")
    finally:
        sock.close()
    return DoctorCheck(name, "ok", f"{host}:{port} is available")


def _check_target(config: AppConfig) -> DoctorCheck:
    try:
        with socket.create_connection((config.connect_ip, config.connect_port), timeout=min(config.connect_timeout, 5.0)):
            return DoctorCheck("target_tcp", "ok", f"{config.connect_ip}:{config.connect_port} is reachable")
    except OSError as exc:
        return DoctorCheck("target_tcp", "warn", f"{config.connect_ip}:{config.connect_port} is not reachable from this environment: {exc}")


def _check_template(config: AppConfig) -> DoctorCheck:
    try:
        payload = ClientHelloMaker.get_client_hello_with(b"a" * 32, b"b" * 32, config.fake_sni_bytes, b"c" * 32)
    except Exception as exc:
        return DoctorCheck("tls_template", "fail", str(exc))
    return DoctorCheck("tls_template", "ok", f"generated {len(payload)} byte ClientHello")


def format_checks(checks: Iterable[DoctorCheck]) -> str:
    labels = {"ok": "OK", "warn": "WARN", "fail": "FAIL"}
    lines = []
    for check in checks:
        label = labels.get(check.status, check.status.upper())
        lines.append(f"[{label:<4}] {check.name}: {check.detail}")
    return "\n".join(lines)


def has_failures(checks: Iterable[DoctorCheck]) -> bool:
    return any(check.status == "fail" for check in checks)
