from __future__ import annotations

from dataclasses import dataclass

from .config import AppConfig
from .http_connect import HttpConnectError


@dataclass(frozen=True)
class ProxyPolicy:
    allowed_hosts: tuple[str, ...]
    allowed_ports: tuple[int, ...]

    @classmethod
    def from_config(cls, config: AppConfig) -> "ProxyPolicy":
        return cls(allowed_hosts=config.allowed_hosts, allowed_ports=config.allowed_ports)

    def validate_connect(self, host: str, port: int) -> None:
        if port not in self.allowed_ports:
            raise HttpConnectError(403, "Forbidden", f"CONNECT port {port} is not allowed")
        if not self.host_allowed(host):
            raise HttpConnectError(403, "Forbidden", f"CONNECT host {host!r} is not allowed")

    def host_allowed(self, host: str) -> bool:
        normalized = host.lower().rstrip(".")
        for pattern in self.allowed_hosts:
            if pattern == "*":
                return True
            if pattern.startswith("*."):
                suffix = pattern[1:]
                if normalized.endswith(suffix) and normalized != pattern[2:]:
                    return True
            elif normalized == pattern:
                return True
        return False


def pac_host_condition(patterns: tuple[str, ...]) -> str:
    if "*" in patterns:
        return "true"

    conditions: list[str] = []
    for pattern in patterns:
        if pattern.startswith("*."):
            suffix = pattern[1:]
            bare = pattern[2:]
            conditions.append(f'(dnsDomainIs(host, "{suffix}") && host !== "{bare}")')
        else:
            conditions.append(f'host === "{pattern}"')
    return " || ".join(conditions) if conditions else "false"
