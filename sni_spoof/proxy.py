from __future__ import annotations

import asyncio
import itertools
import logging
import os
import socket
import threading
from contextlib import suppress

from .config import AppConfig, ConfigError
from .control import ControlServer
from .http_connect import (
    HttpConnectError,
    build_connect_established,
    build_response,
    is_proxy_authorized,
    read_connect_request,
)
from .injector import ConnectionRegistry, FakeInjectionConnection, FakeTcpInjector
from .metrics import RuntimeMetrics
from .network import build_ipv4_filter, configure_keepalive, get_default_interface_ipv4
from .packets import ClientHelloMaker
from .policy import ProxyPolicy
from .relay import RelaySession


LOGGER = logging.getLogger(__name__)


class SpoofingProxy:
    def __init__(self, config: AppConfig) -> None:
        self.config = config
        self.registry = ConnectionRegistry()
        self.metrics = RuntimeMetrics()
        self.policy = ProxyPolicy.from_config(config)
        self.interface_ipv4 = config.interface_ipv4 or get_default_interface_ipv4(config.connect_ip)
        if not self.interface_ipv4:
            raise ConfigError("could not detect the default IPv4 interface for the target")
        self.filter = build_ipv4_filter(self.interface_ipv4, config.connect_ip)
        self._injector_thread: threading.Thread | None = None
        self._connection_ids = itertools.count(1)
        self._active_count = 0

    def start_injector(self) -> None:
        injector = FakeTcpInjector(self.filter, self.registry)
        ready = threading.Event()
        errors: list[BaseException] = []
        self._injector_thread = threading.Thread(target=injector.run, args=(ready, errors), name="tcp-injector", daemon=True)
        self._injector_thread.start()
        if not ready.wait(timeout=2.0):
            raise RuntimeError("WinDivert injector did not start within 2 seconds")
        if errors:
            raise RuntimeError(f"WinDivert injector failed to start: {errors[0]}") from errors[0]
        LOGGER.info("Injector filter: %s", self.filter)

    async def serve(self) -> None:
        self.config.validate()
        for warning in self.config.security_warnings():
            LOGGER.warning("Security warning: %s", warning)

        self.start_injector()
        if self.config.control_enabled:
            control_server = ControlServer(self.config, self.metrics)
            control_task = asyncio.create_task(control_server.serve())
            control_task.add_done_callback(self._log_control_server_exit)
            LOGGER.info("Control dashboard: http://%s:%s/", self.config.control_host, self.config.control_port)

        listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listen_sock.setblocking(False)
        listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        configure_keepalive(listen_sock)
        listen_sock.bind((self.config.listen_host, self.config.listen_port))
        listen_sock.listen(self.config.backlog)

        LOGGER.info("Listening on %s:%s in %s mode", self.config.listen_host, self.config.listen_port, self.config.proxy_mode)
        LOGGER.info("Forwarding to %s:%s with fake SNI %s", self.config.connect_ip, self.config.connect_port, self.config.fake_sni)

        loop = asyncio.get_running_loop()
        try:
            while True:
                incoming_sock, remote_addr = await loop.sock_accept(listen_sock)
                incoming_sock.setblocking(False)
                configure_keepalive(incoming_sock)
                if self._active_count >= self.config.max_active_connections:
                    LOGGER.warning("Rejecting client %s:%s because capacity is full", remote_addr[0], remote_addr[1])
                    self.metrics.increment("clients_rejected_capacity")
                    self.metrics.event("client_rejected_capacity", remote=f"{remote_addr[0]}:{remote_addr[1]}")
                    self._close_socket(incoming_sock)
                    continue
                connection_id = next(self._connection_ids)
                self._active_count += 1
                self.metrics.gauge("active_connections", self._active_count)
                self.metrics.increment("clients_total")
                self.metrics.event(
                    "client_accepted",
                    connection_id=connection_id,
                    remote=f"{remote_addr[0]}:{remote_addr[1]}",
                )
                task = asyncio.create_task(self._handle_client(connection_id, incoming_sock, remote_addr))
                task.add_done_callback(self._log_client_task_exit)
        finally:
            listen_sock.close()

    async def _handle_client(
        self,
        connection_id: int,
        incoming_sock: socket.socket,
        incoming_remote_addr: tuple[str, int],
    ) -> None:
        try:
            if self.config.proxy_mode == "http_connect":
                await self.handle_http_connect(connection_id, incoming_sock, incoming_remote_addr)
            else:
                await self.handle_raw(connection_id, incoming_sock, incoming_remote_addr)
        finally:
            self._active_count -= 1
            self.metrics.gauge("active_connections", self._active_count)

    async def handle_raw(
        self,
        connection_id: int,
        incoming_sock: socket.socket,
        incoming_remote_addr: tuple[str, int],
    ) -> None:
        outgoing_sock: socket.socket | None = None
        try:
            LOGGER.info("[%s] Accepted raw client from %s:%s", connection_id, incoming_remote_addr[0], incoming_remote_addr[1])
            outgoing_sock = await self._open_spoofed_upstream(connection_id, incoming_sock)
            LOGGER.info("[%s] Fake ClientHello was acknowledged; starting raw relay", connection_id)
            self.metrics.increment("raw_tunnels_established")
            self.metrics.event("raw_tunnel_established", connection_id=connection_id)
            await self._relay_pair(connection_id, incoming_sock, outgoing_sock)
        except Exception as exc:
            LOGGER.warning(
                "[%s] Raw client %s:%s closed before relay: %s",
                connection_id,
                incoming_remote_addr[0],
                incoming_remote_addr[1],
                exc,
            )
        finally:
            self._close_socket(incoming_sock)
            if outgoing_sock is not None:
                self._close_socket(outgoing_sock)

    async def handle_http_connect(
        self,
        connection_id: int,
        incoming_sock: socket.socket,
        incoming_remote_addr: tuple[str, int],
    ) -> None:
        outgoing_sock: socket.socket | None = None
        try:
            LOGGER.info(
                "[%s] Accepted HTTP CONNECT client from %s:%s",
                connection_id,
                incoming_remote_addr[0],
                incoming_remote_addr[1],
            )
            request = await read_connect_request(
                incoming_sock,
                self.config.max_connect_header_bytes,
                self.config.connect_timeout,
                self.config.recv_buffer_size,
            )
            self.metrics.increment("connect_requests")
            if not is_proxy_authorized(request.headers, self.config.auth_token):
                raise HttpConnectError(407, "Proxy Authentication Required", "proxy authentication failed")
            self.policy.validate_connect(request.host, request.port)

            LOGGER.info("[%s] CONNECT %s accepted", connection_id, request.authority)
            outgoing_sock = await self._open_spoofed_upstream(connection_id, incoming_sock)

            loop = asyncio.get_running_loop()
            await loop.sock_sendall(incoming_sock, build_connect_established())
            LOGGER.info("[%s] Tunnel established for %s", connection_id, request.authority)
            self.metrics.increment("tunnels_established")
            self.metrics.event("tunnel_established", connection_id=connection_id, authority=request.authority)
            await self._relay_pair(connection_id, incoming_sock, outgoing_sock, request.leftover)
        except HttpConnectError as exc:
            LOGGER.warning(
                "[%s] CONNECT rejected from %s:%s: %s",
                connection_id,
                incoming_remote_addr[0],
                incoming_remote_addr[1],
                exc.detail,
            )
            self.metrics.increment("connect_rejected")
            self.metrics.event("connect_rejected", connection_id=connection_id, reason=exc.detail)
            await self._send_http_error(incoming_sock, exc)
        except Exception as exc:
            LOGGER.warning(
                "[%s] CONNECT client %s:%s closed before relay: %s",
                connection_id,
                incoming_remote_addr[0],
                incoming_remote_addr[1],
                exc,
            )
        finally:
            self._close_socket(incoming_sock)
            if outgoing_sock is not None:
                self._close_socket(outgoing_sock)

    async def _open_spoofed_upstream(self, connection_id: int, peer_sock: socket.socket) -> socket.socket:
        outgoing_sock: socket.socket | None = None
        connection: FakeInjectionConnection | None = None
        try:
            fake_data = ClientHelloMaker.get_client_hello_with(
                os.urandom(32),
                os.urandom(32),
                self.config.fake_sni_bytes,
                os.urandom(32),
            )

            outgoing_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            outgoing_sock.setblocking(False)
            configure_keepalive(outgoing_sock)
            outgoing_sock.bind((self.interface_ipv4, 0))
            src_port = outgoing_sock.getsockname()[1]
            connection = FakeInjectionConnection(
                outgoing_sock,
                self.interface_ipv4,
                self.config.connect_ip,
                src_port,
                self.config.connect_port,
                fake_data,
                self.config.bypass_method,
                peer_sock,
            )
            self.registry.add(connection)

            loop = asyncio.get_running_loop()
            LOGGER.info(
                "[%s] Opening upstream connection %s:%s -> %s:%s",
                connection_id,
                self.interface_ipv4,
                src_port,
                self.config.connect_ip,
                self.config.connect_port,
            )
            await asyncio.wait_for(
                loop.sock_connect(outgoing_sock, (self.config.connect_ip, self.config.connect_port)),
                timeout=self.config.connect_timeout,
            )
            await self._wait_for_fake_ack(connection)
            self.registry.remove(connection.id)
            connection.monitor = False
            self.metrics.increment("fake_ack_total")
            self.metrics.event(
                "fake_ack_received",
                connection_id=connection_id,
                upstream=f"{self.config.connect_ip}:{self.config.connect_port}",
            )
            return outgoing_sock
        except Exception as exc:
            self.metrics.increment("upstream_failures")
            self.metrics.event("upstream_failed", connection_id=connection_id, reason=str(exc))
            if connection is not None:
                connection.monitor = False
                self.registry.remove(connection.id)
            if outgoing_sock is not None:
                self._close_socket(outgoing_sock)
            raise

    async def _wait_for_fake_ack(self, connection: FakeInjectionConnection) -> None:
        try:
            await asyncio.wait_for(connection.t2a_event.wait(), self.config.handshake_timeout)
        except asyncio.TimeoutError as exc:
            raise TimeoutError("timed out while waiting for fake packet acknowledgement") from exc
        if connection.t2a_msg == "fake_data_ack_recv":
            return
        if connection.t2a_msg == "unexpected_close":
            raise ConnectionError("connection closed while waiting for fake packet acknowledgement")
        raise ConnectionError(f"unexpected injector message: {connection.t2a_msg!r}")

    async def _relay_pair(self, connection_id: int, left: socket.socket, right: socket.socket, left_prefix: bytes = b"") -> None:
        relay = RelaySession(self.config.recv_buffer_size, self.config.idle_timeout, self._record_relay_bytes)
        result = await relay.run(left, right, left_prefix)
        LOGGER.info(
            "[%s] Relay finished client_to_upstream=%s upstream_to_client=%s",
            connection_id,
            result.client_to_upstream,
            result.upstream_to_client,
        )
        self.metrics.increment("relay_finished")
        self.metrics.event(
            "relay_finished",
            connection_id=connection_id,
            client_to_upstream=result.client_to_upstream,
            upstream_to_client=result.upstream_to_client,
        )

    def _record_relay_bytes(self, direction: str, size: int) -> None:
        metric_name = {
            "client_to_upstream": "bytes_client_to_upstream",
            "upstream_to_client": "bytes_upstream_to_client",
        }[direction]
        self.metrics.add_bytes(metric_name, size)

    async def _send_http_error(self, sock: socket.socket, exc: HttpConnectError) -> None:
        loop = asyncio.get_running_loop()
        extra_headers = None
        if exc.status_code == 407:
            extra_headers = {"Proxy-Authenticate": 'Basic realm="SNI Spoofing Proxy", Bearer'}
        with suppress(OSError):
            await loop.sock_sendall(sock, build_response(exc.status_code, exc.reason, exc.detail, extra_headers))

    @staticmethod
    def _log_control_server_exit(task: asyncio.Task) -> None:
        if task.cancelled():
            return
        exc = task.exception()
        if exc is not None:
            LOGGER.error("Control server stopped unexpectedly: %s", exc)

    @staticmethod
    def _log_client_task_exit(task: asyncio.Task) -> None:
        if task.cancelled():
            return
        exc = task.exception()
        if exc is not None:
            LOGGER.error("Client task stopped unexpectedly: %s", exc)

    @staticmethod
    def _close_socket(sock: socket.socket) -> None:
        with suppress(OSError):
            sock.shutdown(socket.SHUT_RDWR)
        with suppress(OSError):
            sock.close()
