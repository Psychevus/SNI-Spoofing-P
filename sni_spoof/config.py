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


def _parse_string_list(value: Any, field_name: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        items = [item.strip() for item in value.split(",")]
    elif isinstance(value, (list, tuple)):
        items = [str(item).strip() for item in value]
    else:
        raise ConfigError(f"{field_name} must be a string or list")
    return tuple(item for item in items if item)


def _parse_port_list(value: Any, field_name: str) -> tuple[int, ...]:
    raw_items = _parse_string_list(value, field_name)
    ports = tuple(_parse_port(item, field_name) for item in raw_items)
    if not ports:
        raise ConfigError(f"{field_name} must not be empty")
    return ports


def _parse_positive_float(value: Any, field_name: str) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{field_name} must be a number") from exc
    if parsed <= 0:
        raise ConfigError(f"{field_name} must be greater than zero")
    return parsed


def _parse_positive_int(value: Any, field_name: str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{field_name} must be an integer") from exc
    if parsed <= 0:
        raise ConfigError(f"{field_name} must be greater than zero")
    return parsed


def _parse_bool(value: Any, field_name: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "on"}:
            return True
        if normalized in {"0", "false", "no", "off"}:
            return False
    raise ConfigError(f"{field_name} must be a boolean")


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


def normalize_host_pattern(value: str) -> str:
    if value == "*":
        return "*"
    if value.startswith("*."):
        suffix = normalize_sni(value[2:]).decode("ascii").lower()
        return f"*.{suffix}"
    return normalize_sni(value).decode("ascii").lower()


def normalize_host_patterns(values: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(normalize_host_pattern(value.strip().lower().rstrip(".")) for value in values)


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
    log_format: str = "text"
    proxy_mode: str = "http_connect"
    allowed_hosts: tuple[str, ...] = ("auth.vercel.com",)
    allowed_ports: tuple[int, ...] = (443,)
    auth_token: str | None = None
    connect_timeout: float = 10.0
    idle_timeout: float = 300.0
    max_connect_header_bytes: int = 16384
    max_active_connections: int = 256
    strict_local_only: bool = True
    require_auth_for_remote_bind: bool = True
    control_enabled: bool = True
    control_host: str = "127.0.0.1"
    control_port: int = 9090
    profile: str | None = None

    @classmethod
    def load(cls, path: str | Path, profile: str | None = None) -> "AppConfig":
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
        if profile:
            raw = cls._apply_profile(raw, profile)
        return cls.from_mapping(raw)

    @classmethod
    def _apply_profile(cls, raw: Mapping[str, Any], profile: str) -> dict[str, Any]:
        profiles = _read_value(raw, "profiles", "PROFILES", default={})
        if not isinstance(profiles, Mapping):
            raise ConfigError("profiles must be a JSON object")
        selected = profiles.get(profile)
        if selected is None:
            raise ConfigError(f"profile not found: {profile}")
        if not isinstance(selected, Mapping):
            raise ConfigError(f"profile must be a JSON object: {profile}")
        merged = {key: value for key, value in raw.items() if key not in {"profiles", "PROFILES"}}
        merged.update(selected)
        merged["profile"] = profile
        return merged

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "AppConfig":
        allowed_hosts = normalize_host_patterns(
            _parse_string_list(_read_value(data, "allowed_hosts", "ALLOWED_HOSTS", default=cls.allowed_hosts), "allowed_hosts")
        )
        allowed_ports = _parse_port_list(_read_value(data, "allowed_ports", "ALLOWED_PORTS", default=cls.allowed_ports), "allowed_ports")
        auth_token = _read_value(data, "auth_token", "AUTH_TOKEN", default=None)
        if auth_token is not None:
            auth_token = str(auth_token)
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
            log_format=str(_read_value(data, "log_format", "LOG_FORMAT", default=cls.log_format)).lower(),
            proxy_mode=str(_read_value(data, "proxy_mode", "PROXY_MODE", default=cls.proxy_mode)).lower().replace("-", "_"),
            allowed_hosts=allowed_hosts,
            allowed_ports=allowed_ports,
            auth_token=auth_token,
            connect_timeout=_parse_positive_float(
                _read_value(data, "connect_timeout", "CONNECT_TIMEOUT", default=cls.connect_timeout),
                "connect_timeout",
            ),
            idle_timeout=_parse_positive_float(
                _read_value(data, "idle_timeout", "IDLE_TIMEOUT", default=cls.idle_timeout),
                "idle_timeout",
            ),
            max_connect_header_bytes=_parse_positive_int(
                _read_value(data, "max_connect_header_bytes", "MAX_CONNECT_HEADER_BYTES", default=cls.max_connect_header_bytes),
                "max_connect_header_bytes",
            ),
            max_active_connections=_parse_positive_int(
                _read_value(data, "max_active_connections", "MAX_ACTIVE_CONNECTIONS", default=cls.max_active_connections),
                "max_active_connections",
            ),
            strict_local_only=_parse_bool(
                _read_value(data, "strict_local_only", "STRICT_LOCAL_ONLY", default=cls.strict_local_only),
                "strict_local_only",
            ),
            require_auth_for_remote_bind=_parse_bool(
                _read_value(data, "require_auth_for_remote_bind", "REQUIRE_AUTH_FOR_REMOTE_BIND", default=cls.require_auth_for_remote_bind),
                "require_auth_for_remote_bind",
            ),
            control_enabled=_parse_bool(
                _read_value(data, "control_enabled", "CONTROL_ENABLED", default=cls.control_enabled),
                "control_enabled",
            ),
            control_host=str(_read_value(data, "control_host", "CONTROL_HOST", default=cls.control_host)),
            control_port=_parse_port(_read_value(data, "control_port", "CONTROL_PORT", default=cls.control_port), "control_port"),
            profile=_read_value(data, "profile", "PROFILE", default=None),
        )
        cfg.validate()
        return cfg

    def with_overrides(self, **overrides: Any) -> "AppConfig":
        clean = {key: value for key, value in overrides.items() if value is not None}
        if "proxy_mode" in clean:
            clean["proxy_mode"] = str(clean["proxy_mode"]).lower().replace("-", "_")
        if "allowed_hosts" in clean:
            clean["allowed_hosts"] = normalize_host_patterns(_parse_string_list(clean["allowed_hosts"], "allowed_hosts"))
        if "allowed_ports" in clean:
            clean["allowed_ports"] = _parse_port_list(clean["allowed_ports"], "allowed_ports")
        if "log_level" in clean:
            clean["log_level"] = str(clean["log_level"]).upper()
        if "log_format" in clean:
            clean["log_format"] = str(clean["log_format"]).lower()
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
        try:
            listen_ip = ipaddress.ip_address(self.listen_host)
        except ValueError as exc:
            raise ConfigError("listen_host must be an IP address") from exc
        try:
            control_ip = ipaddress.ip_address(self.control_host)
        except ValueError as exc:
            raise ConfigError("control_host must be an IP address") from exc
        if self.strict_local_only and not listen_ip.is_loopback:
            raise ConfigError("strict_local_only requires listen_host to be a loopback address")
        if self.control_enabled and not control_ip.is_loopback:
            raise ConfigError("control server must bind to a loopback address")
        if self.require_auth_for_remote_bind and self.proxy_mode == "http_connect" and not listen_ip.is_loopback and not self.auth_token:
            raise ConfigError("remote http_connect binding requires auth_token")

        if self.bypass_method != "wrong_seq":
            raise ConfigError("only the 'wrong_seq' bypass method is currently implemented")
        if self.data_mode != "tls":
            raise ConfigError("only the 'tls' data mode is currently implemented")
        if self.proxy_mode not in {"http_connect", "raw"}:
            raise ConfigError("proxy_mode must be either 'http_connect' or 'raw'")
        if self.handshake_timeout <= 0:
            raise ConfigError("handshake_timeout must be greater than zero")
        if self.connect_timeout <= 0:
            raise ConfigError("connect_timeout must be greater than zero")
        if self.idle_timeout <= 0:
            raise ConfigError("idle_timeout must be greater than zero")
        if not 1024 <= self.recv_buffer_size <= 262144:
            raise ConfigError("recv_buffer_size must be between 1024 and 262144 bytes")
        if not 1 <= self.backlog <= 4096:
            raise ConfigError("backlog must be between 1 and 4096")
        if not 1024 <= self.max_connect_header_bytes <= 262144:
            raise ConfigError("max_connect_header_bytes must be between 1024 and 262144 bytes")
        if not 1 <= self.max_active_connections <= 10000:
            raise ConfigError("max_active_connections must be between 1 and 10000")
        if not isinstance(getattr(logging, self.log_level, None), int):
            raise ConfigError("log_level must be a valid Python logging level")
        if self.log_format not in {"text", "json"}:
            raise ConfigError("log_format must be either 'text' or 'json'")
        if self.proxy_mode == "http_connect" and not self.allowed_hosts:
            raise ConfigError("allowed_hosts must not be empty when proxy_mode is 'http_connect'")
        if not self.allowed_ports:
            raise ConfigError("allowed_ports must not be empty")
        if self.auth_token == "":
            raise ConfigError("auth_token must not be empty")

        normalize_sni(self.fake_sni)
        normalize_host_patterns(self.allowed_hosts)

    def security_warnings(self) -> list[str]:
        warnings: list[str] = []
        target_ip = ipaddress.ip_address(self.connect_ip)
        try:
            listen_ip = ipaddress.ip_address(self.listen_host)
        except ValueError:
            listen_ip = None

        if listen_ip and listen_ip.is_unspecified:
            warnings.append("listen_host is bound to all interfaces; restrict it to 127.0.0.1 unless remote clients are required.")
            if self.proxy_mode == "http_connect" and not self.auth_token:
                warnings.append("http_connect mode is reachable from all interfaces without proxy authentication.")
        if self.proxy_mode == "http_connect" and "*" in self.allowed_hosts:
            warnings.append("allowed_hosts contains '*'; this can turn the service into a broad forwarding proxy.")
        if self.control_enabled and self.control_port == self.listen_port and self.control_host == self.listen_host:
            warnings.append("control server uses the same endpoint as the proxy listener.")
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
            "profile": self.profile or "default",
            "proxy_mode": self.proxy_mode,
            "target": f"{self.connect_ip}:{self.connect_port}",
            "fake_sni": self.fake_sni,
            "bypass_method": self.bypass_method,
            "data_mode": self.data_mode,
            "allowed_hosts": list(self.allowed_hosts),
            "allowed_ports": list(self.allowed_ports),
            "auth_enabled": self.auth_token is not None,
            "interface_ipv4": self.interface_ipv4 or "auto",
            "handshake_timeout": self.handshake_timeout,
            "connect_timeout": self.connect_timeout,
            "idle_timeout": self.idle_timeout,
            "recv_buffer_size": self.recv_buffer_size,
            "backlog": self.backlog,
            "max_connect_header_bytes": self.max_connect_header_bytes,
            "max_active_connections": self.max_active_connections,
            "strict_local_only": self.strict_local_only,
            "require_auth_for_remote_bind": self.require_auth_for_remote_bind,
            "control_enabled": self.control_enabled,
            "control": f"{self.control_host}:{self.control_port}" if self.control_enabled else "disabled",
            "log_level": self.log_level,
            "log_format": self.log_format,
        }
