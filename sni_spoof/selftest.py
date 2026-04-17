from __future__ import annotations

import socket
import ssl
import time
from dataclasses import dataclass

from .config import AppConfig


@dataclass(frozen=True)
class TunnelTestResult:
    ok: bool
    detail: str
    elapsed_ms: float
    response_preview: str = ""


def test_tunnel(config: AppConfig, host: str | None = None, path: str = "/") -> TunnelTestResult:
    target_host = (host or config.fake_sni).lower().rstrip(".")
    started = time.perf_counter()
    try:
        raw_sock = socket.create_connection((config.listen_host, config.listen_port), timeout=config.connect_timeout)
        raw_sock.settimeout(config.connect_timeout)
        request_lines = [
            f"CONNECT {target_host}:443 HTTP/1.1",
            f"Host: {target_host}:443",
            "User-Agent: sni-spoof-self-test",
        ]
        if config.auth_token:
            request_lines.append(f"Proxy-Authorization: Bearer {config.auth_token}")
        request_lines.extend(["", ""])
        raw_sock.sendall("\r\n".join(request_lines).encode("ascii"))
        response = _recv_until(raw_sock, b"\r\n\r\n", config.connect_timeout)
        if not response.startswith(b"HTTP/1.1 200"):
            return _result(False, f"proxy CONNECT failed: {response[:160]!r}", started)

        context = ssl.create_default_context()
        tls_sock = context.wrap_socket(raw_sock, server_hostname=target_host)
        tls_sock.settimeout(config.connect_timeout)
        tls_sock.sendall(
            (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {target_host}\r\n"
                "User-Agent: sni-spoof-self-test\r\n"
                "Connection: close\r\n"
                "\r\n"
            ).encode("ascii")
        )
        preview = tls_sock.recv(512).decode("iso-8859-1", errors="replace")
        tls_sock.close()
        if preview.startswith("HTTP/"):
            return _result(True, "HTTP response received through proxy tunnel", started, preview)
        return _result(False, "TLS completed but HTTP response was not recognized", started, preview)
    except Exception as exc:
        return _result(False, str(exc), started)


def _recv_until(sock: socket.socket, marker: bytes, timeout: float) -> bytes:
    sock.settimeout(timeout)
    data = b""
    while marker not in data and len(data) < 65536:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


def _result(ok: bool, detail: str, started: float, preview: str = "") -> TunnelTestResult:
    return TunnelTestResult(ok=ok, detail=detail, elapsed_ms=round((time.perf_counter() - started) * 1000, 2), response_preview=preview)
