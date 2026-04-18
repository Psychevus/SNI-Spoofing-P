from __future__ import annotations

import hashlib
import json
import socket
import ssl
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Iterable

from .config import AppConfig
from .network import get_default_interface_ipv4
from .pac import generate_pac
from .packets import ClientHelloMaker
from .policy import ProxyPolicy


@dataclass(frozen=True)
class ScanCheck:
    category: str
    name: str
    status: str
    detail: str
    recommendation: str = ""


@dataclass(frozen=True)
class RouteScanReport:
    generated_at: str
    profile: str
    target: str
    score: int
    verdict: str
    network_probes: bool
    checks: tuple[ScanCheck, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "generated_at": self.generated_at,
            "profile": self.profile,
            "target": self.target,
            "score": self.score,
            "verdict": self.verdict,
            "network_probes": self.network_probes,
            "checks": [asdict(check) for check in self.checks],
        }


def run_route_scan(config: AppConfig, *, network: bool = True, timeout: float | None = None) -> RouteScanReport:
    checks: list[ScanCheck] = []
    probe_timeout = timeout or min(config.connect_timeout, 5.0)

    checks.extend(_configuration_checks(config))
    checks.extend(_security_checks(config))
    checks.extend(_routing_checks(config))
    checks.extend(_artifact_checks(config))
    if network:
        checks.extend(_network_checks(config, probe_timeout))
    else:
        checks.append(
            ScanCheck(
                "network",
                "network_probes",
                "info",
                "Network probes were skipped.",
                "Run without --scan-offline when you want live DNS, TCP, and TLS checks.",
            )
        )

    score = _score(checks)
    return RouteScanReport(
        generated_at=datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        profile=config.profile or "default",
        target=f"{config.connect_ip}:{config.connect_port}",
        score=score,
        verdict=_verdict(score, checks),
        network_probes=network,
        checks=tuple(checks),
    )


def format_route_scan(report: RouteScanReport) -> str:
    labels = {"pass": "PASS", "warn": "WARN", "fail": "FAIL", "info": "INFO"}
    lines = [
        f"Route Scanner: {report.profile}",
        f"Target: {report.target}",
        f"Score: {report.score}/100",
        f"Verdict: {report.verdict}",
        f"Network probes: {'enabled' if report.network_probes else 'disabled'}",
        "",
    ]
    for check in report.checks:
        label = labels.get(check.status, check.status.upper())
        lines.append(f"[{label:<4}] {check.category}.{check.name}: {check.detail}")
        if check.recommendation:
            lines.append(f"       Recommendation: {check.recommendation}")
    return "\n".join(lines)


def route_scan_to_json(report: RouteScanReport) -> str:
    return json.dumps(report.to_dict(), indent=2, sort_keys=True)


def has_scan_failures(report: RouteScanReport) -> bool:
    return any(check.status == "fail" for check in report.checks)


def _configuration_checks(config: AppConfig) -> list[ScanCheck]:
    checks: list[ScanCheck] = []
    try:
        config.validate()
    except Exception as exc:
        return [ScanCheck("config", "validation", "fail", str(exc), "Fix config.json or CLI overrides before running.")]

    checks.append(ScanCheck("config", "validation", "pass", "Configuration is valid."))
    checks.append(
        ScanCheck(
            "config",
            "mode",
            "pass" if config.proxy_mode == "http_connect" else "info",
            f"Proxy mode is {config.proxy_mode}.",
            "Use http_connect for browser and PAC workflows." if config.proxy_mode != "http_connect" else "",
        )
    )
    checks.append(
        ScanCheck(
            "config",
            "timeouts",
            "pass" if config.handshake_timeout <= 5 and config.connect_timeout <= 15 else "warn",
            f"handshake={config.handshake_timeout}s, connect={config.connect_timeout}s, idle={config.idle_timeout}s.",
            "Keep handshake and connect timeouts tight for faster failure detection."
            if config.handshake_timeout > 5 or config.connect_timeout > 15
            else "",
        )
    )
    return checks


def _security_checks(config: AppConfig) -> list[ScanCheck]:
    checks: list[ScanCheck] = []
    checks.append(
        ScanCheck(
            "security",
            "listen_surface",
            "pass" if config.listen_host.startswith("127.") else "warn",
            f"Proxy listener is bound to {config.listen_host}:{config.listen_port}.",
            "Prefer 127.0.0.1 unless remote clients are explicitly required." if not config.listen_host.startswith("127.") else "",
        )
    )
    checks.append(
        ScanCheck(
            "security",
            "control_surface",
            "pass" if (not config.control_enabled or config.control_host.startswith("127.")) else "fail",
            "Control server is disabled." if not config.control_enabled else f"Control server is bound to {config.control_host}:{config.control_port}.",
            "Keep the dashboard on loopback." if config.control_enabled and not config.control_host.startswith("127.") else "",
        )
    )
    checks.append(
        ScanCheck(
            "security",
            "allowlist",
            "warn" if "*" in config.allowed_hosts else "pass",
            f"Allowed hosts: {', '.join(config.allowed_hosts)}.",
            "Replace wildcard allowlists with explicit hostnames." if "*" in config.allowed_hosts else "",
        )
    )
    checks.append(
        ScanCheck(
            "security",
            "remote_auth",
            "pass" if config.listen_host.startswith("127.") or config.auth_token else "fail",
            "Remote listener authentication is configured." if config.auth_token else "No proxy auth token is configured.",
            "Set AUTH_TOKEN before exposing the proxy beyond loopback." if not config.listen_host.startswith("127.") and not config.auth_token else "",
        )
    )
    for warning in config.security_warnings():
        checks.append(ScanCheck("security", "config_warning", "warn", warning))
    return checks


def _routing_checks(config: AppConfig) -> list[ScanCheck]:
    checks: list[ScanCheck] = []
    policy = ProxyPolicy.from_config(config)
    checks.append(
        ScanCheck(
            "routing",
            "sni_allowed",
            "pass" if policy.host_allowed(config.fake_sni) else "warn",
            f"Fake SNI {config.fake_sni!r} {'is' if policy.host_allowed(config.fake_sni) else 'is not'} covered by allowed_hosts.",
            "Add the fake SNI hostname to ALLOWED_HOSTS for a predictable browser workflow." if not policy.host_allowed(config.fake_sni) else "",
        )
    )
    checks.append(
        ScanCheck(
            "routing",
            "port_allowed",
            "pass" if config.connect_port in config.allowed_ports else "warn",
            f"Target port {config.connect_port} {'is' if config.connect_port in config.allowed_ports else 'is not'} present in allowed_ports.",
            "Keep CONNECT and upstream TLS ports aligned unless this route is intentionally split."
            if config.connect_port not in config.allowed_ports
            else "",
        )
    )

    checks.append(
        ScanCheck(
            "routing",
            "interface",
            "pass" if config.interface_ipv4 else "info",
            f"Interface is pinned to {config.interface_ipv4}." if config.interface_ipv4 else "Interface will be detected at runtime.",
            "Set INTERFACE_IPV4 when route detection is ambiguous." if not config.interface_ipv4 else "",
        )
    )
    return checks


def _artifact_checks(config: AppConfig) -> list[ScanCheck]:
    checks: list[ScanCheck] = []
    pac = generate_pac(config)
    checks.append(
        ScanCheck(
            "artifact",
            "pac",
            "pass",
            f"PAC generated with sha256={hashlib.sha256(pac.encode('utf-8')).hexdigest()[:16]} and {len(pac)} bytes.",
        )
    )
    try:
        payload = ClientHelloMaker.get_client_hello_with(b"a" * 32, b"b" * 32, config.fake_sni_bytes, b"c" * 32)
    except Exception as exc:
        checks.append(ScanCheck("artifact", "client_hello_template", "fail", str(exc), "Review FAKE_SNI and TLS template limits."))
    else:
        checks.append(ScanCheck("artifact", "client_hello_template", "pass", f"ClientHello template generated with {len(payload)} bytes."))
    return checks


def _network_checks(config: AppConfig, timeout: float) -> list[ScanCheck]:
    checks: list[ScanCheck] = []
    checks.append(_interface_check(config))
    checks.extend(_dns_checks(config, timeout))
    checks.append(_tcp_check(config, timeout))
    checks.append(_tls_check(config, timeout))
    checks.append(_bind_check("listen_port", config.listen_host, config.listen_port))
    if config.control_enabled:
        checks.append(_bind_check("control_port", config.control_host, config.control_port))
    return checks


def _interface_check(config: AppConfig) -> ScanCheck:
    interface = config.interface_ipv4 or get_default_interface_ipv4(config.connect_ip)
    return ScanCheck(
        "network",
        "interface",
        "pass" if interface else "warn",
        f"Detected interface {interface}." if interface else "No local route to the configured target was detected.",
        "Set INTERFACE_IPV4 explicitly if route detection is ambiguous." if not interface else "",
    )


def _dns_checks(config: AppConfig, timeout: float) -> list[ScanCheck]:
    del timeout
    checks: list[ScanCheck] = []
    hosts = sorted({config.fake_sni, *[host for host in config.allowed_hosts if host != "*" and not host.startswith("*.")]})
    for host in hosts:
        try:
            addresses = sorted({item[4][0] for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)})
        except socket.gaierror as exc:
            checks.append(ScanCheck("network", f"dns:{host}", "warn", f"DNS lookup failed: {exc}", "Confirm the hostname is resolvable."))
        else:
            checks.append(ScanCheck("network", f"dns:{host}", "pass", f"Resolved {host} to {', '.join(addresses[:4])}."))
    return checks


def _tcp_check(config: AppConfig, timeout: float) -> ScanCheck:
    try:
        with socket.create_connection((config.connect_ip, config.connect_port), timeout=timeout):
            return ScanCheck("network", "target_tcp", "pass", f"{config.connect_ip}:{config.connect_port} accepted TCP.")
    except OSError as exc:
        return ScanCheck(
            "network",
            "target_tcp",
            "warn",
            f"{config.connect_ip}:{config.connect_port} did not accept TCP within {timeout}s: {exc}",
            "Check the endpoint, firewall, VPN, and route selection.",
        )


def _tls_check(config: AppConfig, timeout: float) -> ScanCheck:
    context = ssl.create_default_context()
    try:
        with socket.create_connection((config.connect_ip, config.connect_port), timeout=timeout) as raw_sock:
            raw_sock.settimeout(timeout)
            with context.wrap_socket(raw_sock, server_hostname=config.fake_sni) as tls_sock:
                cipher = tls_sock.cipher()
                tls_version = tls_sock.version() or "unknown TLS"
                cipher_name = cipher[0] if cipher else "unknown cipher"
                return ScanCheck("network", "target_tls", "pass", f"{tls_version} handshake succeeded with {cipher_name}.")
    except (OSError, ssl.SSLError) as exc:
        return ScanCheck(
            "network",
            "target_tls",
            "warn",
            f"TLS handshake to target with fake_sni={config.fake_sni!r} failed: {exc}",
            "Confirm the endpoint expects TLS and the SNI value is valid for the route.",
        )


def _bind_check(name: str, host: str, port: int) -> ScanCheck:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind((host, port))
    except OSError as exc:
        return ScanCheck("network", name, "fail", f"{host}:{port} is not available: {exc}", "Stop the conflicting service or choose another port.")
    finally:
        sock.close()
    return ScanCheck("network", name, "pass", f"{host}:{port} is available.")


def _score(checks: Iterable[ScanCheck]) -> int:
    score = 100
    for check in checks:
        if check.status == "fail":
            score -= 25
        elif check.status == "warn":
            score -= 8
    return max(0, min(100, score))


def _verdict(score: int, checks: Iterable[ScanCheck]) -> str:
    if any(check.status == "fail" for check in checks):
        return "blocked"
    if score >= 90:
        return "ready"
    if score >= 70:
        return "needs attention"
    return "risky"
