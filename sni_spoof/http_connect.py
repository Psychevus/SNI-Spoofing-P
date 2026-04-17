from __future__ import annotations

import asyncio
import base64
import hmac
import socket
from dataclasses import dataclass


class HttpConnectError(ValueError):
    def __init__(self, status_code: int, reason: str, detail: str | None = None) -> None:
        super().__init__(detail or reason)
        self.status_code = status_code
        self.reason = reason
        self.detail = detail or reason


@dataclass(frozen=True)
class ConnectRequest:
    host: str
    port: int
    version: str
    headers: dict[str, str]
    leftover: bytes = b""

    @property
    def authority(self) -> str:
        return f"{self.host}:{self.port}"


def build_response(status_code: int, reason: str, body: str = "", extra_headers: dict[str, str] | None = None) -> bytes:
    payload = body.encode("utf-8")
    headers = [
        f"HTTP/1.1 {status_code} {reason}",
        "Proxy-Agent: sni-spoof",
        "Connection: close" if status_code >= 300 else "Connection: keep-alive",
        f"Content-Length: {len(payload)}",
    ]
    if extra_headers:
        for name, value in extra_headers.items():
            headers.append(f"{name}: {value}")
    headers.extend(["", ""])
    return "\r\n".join(headers).encode("ascii") + payload


def build_connect_established() -> bytes:
    return b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: sni-spoof\r\n\r\n"


async def read_connect_request(
    sock: socket.socket,
    max_header_bytes: int,
    timeout: float,
    recv_buffer_size: int,
) -> ConnectRequest:
    loop = asyncio.get_running_loop()
    data = b""
    marker = b"\r\n\r\n"

    while marker not in data:
        if len(data) >= max_header_bytes:
            raise HttpConnectError(431, "Request Header Fields Too Large", "CONNECT header is too large")
        chunk = await asyncio.wait_for(loop.sock_recv(sock, min(recv_buffer_size, 4096)), timeout=timeout)
        if not chunk:
            raise HttpConnectError(400, "Bad Request", "client closed before sending CONNECT headers")
        data += chunk

    header_bytes, leftover = data.split(marker, 1)
    if len(header_bytes) > max_header_bytes:
        raise HttpConnectError(431, "Request Header Fields Too Large", "CONNECT header is too large")
    try:
        header_text = header_bytes.decode("iso-8859-1")
    except UnicodeDecodeError as exc:
        raise HttpConnectError(400, "Bad Request", "CONNECT header is not valid HTTP text") from exc

    lines = header_text.split("\r\n")
    if not lines or not lines[0]:
        raise HttpConnectError(400, "Bad Request", "missing CONNECT request line")

    parts = lines[0].split()
    if len(parts) != 3:
        raise HttpConnectError(400, "Bad Request", "invalid CONNECT request line")

    method, authority, version = parts
    if method.upper() != "CONNECT":
        raise HttpConnectError(405, "Method Not Allowed", "only CONNECT requests are supported")
    if not version.startswith("HTTP/1."):
        raise HttpConnectError(505, "HTTP Version Not Supported", "only HTTP/1.x CONNECT is supported")

    host, port = parse_authority(authority)
    headers = parse_headers(lines[1:])
    return ConnectRequest(host=host, port=port, version=version, headers=headers, leftover=leftover)


def parse_authority(authority: str) -> tuple[str, int]:
    if authority.startswith("["):
        end = authority.find("]")
        if end == -1 or len(authority) <= end + 2 or authority[end + 1] != ":":
            raise HttpConnectError(400, "Bad Request", "invalid bracketed CONNECT authority")
        host = authority[1:end]
        port_text = authority[end + 2:]
    else:
        if ":" not in authority:
            raise HttpConnectError(400, "Bad Request", "CONNECT authority must include a port")
        host, port_text = authority.rsplit(":", 1)

    host = host.strip().rstrip(".").lower()
    if not host:
        raise HttpConnectError(400, "Bad Request", "CONNECT host must not be empty")
    try:
        port = int(port_text)
    except ValueError as exc:
        raise HttpConnectError(400, "Bad Request", "CONNECT port must be an integer") from exc
    if not 1 <= port <= 65535:
        raise HttpConnectError(400, "Bad Request", "CONNECT port is out of range")
    return host, port


def parse_headers(lines: list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for line in lines:
        if not line:
            continue
        if ":" not in line:
            raise HttpConnectError(400, "Bad Request", "invalid HTTP header")
        name, value = line.split(":", 1)
        headers[name.strip().lower()] = value.strip()
    return headers


def is_proxy_authorized(headers: dict[str, str], token: str | None) -> bool:
    if not token:
        return True

    value = headers.get("proxy-authorization", "")
    bearer_prefix = "Bearer "
    if value.startswith(bearer_prefix):
        return hmac.compare_digest(value[len(bearer_prefix):], token)

    basic_prefix = "Basic "
    if value.startswith(basic_prefix):
        try:
            decoded = base64.b64decode(value[len(basic_prefix):], validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return False
        if ":" in decoded:
            _, password = decoded.split(":", 1)
            return hmac.compare_digest(password, token)
        return hmac.compare_digest(decoded, token)

    return False
