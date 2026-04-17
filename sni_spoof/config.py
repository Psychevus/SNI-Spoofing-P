from __future__ import annotations

import ipaddress
import json
import logging
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Mapping


class ConfigError(ValueError):
    """Raised when runtime configuration is invalid."""


def _read_value(data: Mapping[str, Any], *names: str, default: Any = None) -> Any:
    for name in names:
        if name in data:
            return data[name]
    return default


def _parse_port(value: Any, field_name: str) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{field_name} must be an integer") from exc
    if not 1 <= port <= 65535:
        raise ConfigError(f"{field_name} must be between 1 and 65535")
    return port


def normalize_sni(value: str) -> bytes:
    if not isinstance(value, str):
        raise ConfigError("fake_sni must be a string")

    host = value.strip().rstrip(".")
    if not host:
        raise ConfigError("fake_sni must not be empty")
    if any(ch.isspace() for ch in host) or any(ord(ch) < 32 for ch in host):
        raise ConfigError("fake_sni must not contain whitespace or control characters")
    if "://" in host or "/" in host or ":" in host:
        raise ConfigError("fake_sni must be a hostname, not a URL")

    try:
        encoded = host.encode("idna")
    except UnicodeError as exc:
        raise ConfigError("fake_sni is not a valid IDNA hostname") from exc

    if len(encoded) > 219:
        raise ConfigError("fake_sni is too long for the padded TLS template")

    labels = encoded.decode("ascii").split(".")
    for label in labels:
        if not label or len(label) > 63:
            raise ConfigError("fake_sni contains an invalid DNS label")
        if label.startswith("-") or label.endswith("-"):
            raise ConfigError("fake_sni labels must not start or end with '-'")

    return encoded


@dataclass(frozen=True)
class AppConfig:
    listen_host: str = "127.0.0.1"
    listen_port: int = 40443
    connect_ip: str = "188.114.98.0"
    connect_port: int = 443
    fake_sni: str = "auth.vercel.com"
    bypass_method: str = "wrong_seq"
    data_mode: str = "tls"
    interface_ipv4: str | None = None
    handshake_timeout: float = 2.0
    recv_buffer_size: int = 65575
    backlog: int = 128
    log_level: str = "INFO"

    @classmethod
    def load(cls, path: str | Path) -> "AppConfig":
        config_path = Path(path)
        try:
            with config_path.open("r", encoding="utf-8") as fh:
                raw = json.load(fh)
        except FileNotFoundError as exc:
            raise ConfigError(f"config file not found: {config_path}") from exc
        except json.JSONDecodeError as exc:
            raise ConfigError(f"config file is not valid JSON: {exc}") from exc

        if not isinstance(raw, dict):
            raise ConfigError("config root must be a JSON object")
        return cls.from_mapping(raw)

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "AppConfig":
        cfg = cls(
            listen_host=str(_read_value(data, "listen_host", "LISTEN_HOST", default=cls.listen_host)),
            listen_port=_parse_port(_read_value(data, "listen_port", "LISTEN_PORT", default=cls.listen_port), "listen_port"),
            connect_ip=str(_read_value(data, "connect_ip", "CONNECT_IP", default=cls.connect_ip)),
            connect_port=_parse_port(_read_value(data, "connect_port", "CONNECT_PORT", default=cls.connect_port), "connect_port"),
            fake_sni=str(_read_value(data, "fake_sni", "FAKE_SNI", default=cls.fake_sni)),
            bypass_method=str(_read_value(data, "bypass_method", "BYPASS_METHOD", default=cls.bypass_method)),
            data_mode=str(_read_value(data, "data_mode", "DATA_MODE", default=cls.data_mode)),
            interface_ipv4=_read_value(data, "interface_ipv4", "INTERFACE_IPV4", default=None),
            handshake_timeout=float(_read_value(data, "handshake_timeout", "HANDSHAKE_TIMEOUT", default=cls.handshake_timeout)),
            recv_buffer_size=int(_read_value(data, "recv_buffer_size", "RECV_BUFFER_SIZE", default=cls.recv_buffer_size)),
            backlog=int(_read_value(data, "backlog", "BACKLOG", default=cls.backlog)),
            log_level=str(_read_value(data, "log_level", "LOG_LEVEL", default=cls.log_level)).upper(),
        )
        cfg.validate()
        return cfg

    def with_overrides(self, **overrides: Any) -> "AppConfig":
        clean = {key: value for key, value in overrides.items() if value is not None}
        cfg = replace(self, **clean)
        cfg.validate()
        return cfg

    @property
    def fake_sni_bytes(self) -> bytes:
        return normalize_sni(self.fake_sni)

    def validate(self) -> None:
        try:
            ipaddress.ip_address(self.connect_ip)
        except ValueError as exc:
            raise ConfigError("connect_ip must be a valid IP address") from exc

        if self.interface_ipv4:
            try:
                ipaddress.IPv4Address(self.interface_ipv4)
            except ValueError as exc:
                raise ConfigError("interface_ipv4 must be a valid IPv4 address") from exc

        if self.bypass_method != "wrong_seq":
            raise ConfigError("only the 'wrong_seq' bypass method is currently implemented")
        if self.data_mode != "tls":
            raise ConfigError("only the 'tls' data mode is currently implemented")
        if self.handshake_timeout <= 0:
            raise ConfigError("handshake_timeout must be greater than zero")
        if not 1024 <= self.recv_buffer_size <= 262144:
            raise ConfigError("recv_buffer_size must be between 1024 and 262144 bytes")
        if not 1 <= self.backlog <= 4096:
            raise ConfigError("backlog must be between 1 and 4096")
        if not isinstance(getattr(logging, self.log_level, None), int):
            raise ConfigError("log_level must be a valid Python logging level")

        normalize_sni(self.fake_sni)

    def security_warnings(self) -> list[str]:
        warnings: list[str] = []
        target_ip = ipaddress.ip_address(self.connect_ip)
        try:
            listen_ip = ipaddress.ip_address(self.listen_host)
        except ValueError:
            listen_ip = None

        if listen_ip and listen_ip.is_unspecified:
            warnings.append("listen_host is bound to all interfaces; restrict it to 127.0.0.1 unless remote clients are required.")
        if target_ip.is_private or target_ip.is_loopback or target_ip.is_multicast or target_ip.is_unspecified:
            warnings.append("connect_ip is not a normal public unicast address; confirm this is intentional.")
        if self.connect_port != 443:
            warnings.append("connect_port is not 443; confirm the destination expects TLS traffic.")
        if self.handshake_timeout > 10:
            warnings.append("handshake_timeout is high and can keep failed connections open longer than necessary.")
        return warnings

    def public_summary(self) -> dict[str, Any]:
        return {
            "listen": f"{self.listen_host}:{self.listen_port}",
            "target": f"{self.connect_ip}:{self.connect_port}",
            "fake_sni": self.fake_sni,
            "bypass_method": self.bypass_method,
            "data_mode": self.data_mode,
            "interface_ipv4": self.interface_ipv4 or "auto",
            "handshake_timeout": self.handshake_timeout,
            "recv_buffer_size": self.recv_buffer_size,
            "backlog": self.backlog,
            "log_level": self.log_level,
        }
