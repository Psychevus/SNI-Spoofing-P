from __future__ import annotations

import asyncio
import json
import socket
from contextlib import suppress
from html import escape
from typing import Any

from .config import AppConfig
from .metrics import RuntimeMetrics
from .pac import generate_pac


class ControlServer:
    def __init__(self, config: AppConfig, metrics: RuntimeMetrics) -> None:
        self.config = config
        self.metrics = metrics
        self._server_sock: socket.socket | None = None

    async def serve(self) -> None:
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setblocking(False)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((self.config.control_host, self.config.control_port))
        server_sock.listen(64)
        self._server_sock = server_sock

        loop = asyncio.get_running_loop()
        try:
            while True:
                client_sock, _ = await loop.sock_accept(server_sock)
                client_sock.setblocking(False)
                asyncio.create_task(self._handle(client_sock))
        finally:
            server_sock.close()

    async def _handle(self, client_sock: socket.socket) -> None:
        try:
            request = await self._read_request(client_sock)
            method, path = self._parse_request_line(request)
            if method != "GET":
                await self._send(client_sock, 405, "Method Not Allowed", "text/plain", b"method not allowed")
                return

            if path in {"/", "/dashboard"}:
                await self._send(client_sock, 200, "OK", "text/html; charset=utf-8", self._dashboard_html().encode("utf-8"))
            elif path == "/health":
                await self._send_json(client_sock, {"status": "ok", "proxy_mode": self.config.proxy_mode})
            elif path == "/metrics":
                await self._send_json(client_sock, self.metrics.snapshot())
            elif path == "/config":
                await self._send_json(client_sock, self.config.public_summary())
            elif path == "/proxy.pac":
                await self._send(client_sock, 200, "OK", "application/x-ns-proxy-autoconfig", generate_pac(self.config).encode("utf-8"))
            else:
                await self._send(client_sock, 404, "Not Found", "text/plain", b"not found")
        finally:
            with suppress(OSError):
                client_sock.close()

    async def _read_request(self, client_sock: socket.socket) -> bytes:
        loop = asyncio.get_running_loop()
        data = b""
        while b"\r\n\r\n" not in data and len(data) < 8192:
            chunk = await asyncio.wait_for(loop.sock_recv(client_sock, 4096), timeout=5.0)
            if not chunk:
                break
            data += chunk
        return data

    @staticmethod
    def _parse_request_line(request: bytes) -> tuple[str, str]:
        try:
            first_line = request.split(b"\r\n", 1)[0].decode("ascii")
            method, path, _ = first_line.split(maxsplit=2)
        except ValueError:
            return "", ""
        return method.upper(), path.split("?", 1)[0]

    async def _send_json(self, client_sock: socket.socket, payload: dict[str, Any]) -> None:
        await self._send(client_sock, 200, "OK", "application/json; charset=utf-8", json.dumps(payload, indent=2, sort_keys=True).encode("utf-8"))

    async def _send(self, client_sock: socket.socket, status: int, reason: str, content_type: str, body: bytes) -> None:
        loop = asyncio.get_running_loop()
        headers = (
            f"HTTP/1.1 {status} {reason}\r\n"
            f"Content-Type: {content_type}\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Cache-Control: no-store\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode("ascii")
        await loop.sock_sendall(client_sock, headers + body)

    def _dashboard_html(self) -> str:
        snapshot = self.metrics.snapshot()
        counters = snapshot["counters"]
        gauges = snapshot["gauges"]
        rows = "\n".join(
            f"<tr><td>{escape(str(key))}</td><td>{escape(str(value))}</td></tr>"
            for key, value in {**counters, **gauges}.items()
        )
        events = "\n".join(
            f"<li><strong>{escape(event['name'])}</strong> {escape(json.dumps(event['details'], sort_keys=True))}</li>"
            for event in snapshot["events"][-20:]
        )
        return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SNI Spoofing Proxy</title>
  <style>
    body {{ font-family: Segoe UI, Arial, sans-serif; margin: 32px; color: #151515; background: #f6f8fa; }}
    main {{ max-width: 980px; margin: 0 auto; }}
    h1 {{ margin-bottom: 8px; }}
    table {{ border-collapse: collapse; width: 100%; background: white; }}
    td {{ border: 1px solid #d0d7de; padding: 10px; }}
    a {{ color: #0756a4; }}
    .panel {{ background: white; border: 1px solid #d0d7de; border-radius: 8px; padding: 16px; margin: 16px 0; }}
    code {{ background: #eef1f4; padding: 2px 5px; border-radius: 4px; }}
  </style>
</head>
<body>
<main>
  <h1>SNI Spoofing Proxy</h1>
  <p>Mode: <code>{escape(self.config.proxy_mode)}</code> | Listener: <code>{escape(self.config.listen_host)}:{self.config.listen_port}</code></p>
  <div class="panel">
    <h2>Runtime</h2>
    <table>{rows}</table>
  </div>
  <div class="panel">
    <h2>Links</h2>
    <p><a href="/health">Health</a> | <a href="/metrics">Metrics JSON</a> | <a href="/config">Config Summary</a> | <a href="/proxy.pac">PAC File</a></p>
  </div>
  <div class="panel">
    <h2>Recent Events</h2>
    <ul>{events}</ul>
  </div>
</main>
</body>
</html>
"""
