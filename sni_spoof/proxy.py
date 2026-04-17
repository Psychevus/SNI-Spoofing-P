from __future__ import annotations

import asyncio
import logging
import os
import socket
import threading
from contextlib import suppress

from .config import AppConfig, ConfigError
from .injector import ConnectionRegistry, FakeInjectionConnection, FakeTcpInjector
from .network import build_ipv4_filter, configure_keepalive, get_default_interface_ipv4
from .packets import ClientHelloMaker


LOGGER = logging.getLogger(__name__)


class SpoofingProxy:
    def __init__(self, config: AppConfig) -> None:
        self.config = config
        self.registry = ConnectionRegistry()
        self.interface_ipv4 = config.interface_ipv4 or get_default_interface_ipv4(config.connect_ip)
        if not self.interface_ipv4:
            raise ConfigError("could not detect the default IPv4 interface for the target")
        self.filter = build_ipv4_filter(self.interface_ipv4, config.connect_ip)
        self._injector_thread: threading.Thread | None = None

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
        listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listen_sock.setblocking(False)
        listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        configure_keepalive(listen_sock)
        listen_sock.bind((self.config.listen_host, self.config.listen_port))
        listen_sock.listen(self.config.backlog)

        LOGGER.info("Listening on %s:%s", self.config.listen_host, self.config.listen_port)
        LOGGER.info("Forwarding to %s:%s with fake SNI %s", self.config.connect_ip, self.config.connect_port, self.config.fake_sni)

        loop = asyncio.get_running_loop()
        try:
            while True:
                incoming_sock, remote_addr = await loop.sock_accept(listen_sock)
                incoming_sock.setblocking(False)
                configure_keepalive(incoming_sock)
                asyncio.create_task(self.handle(incoming_sock, remote_addr))
        finally:
            listen_sock.close()

    async def handle(self, incoming_sock: socket.socket, incoming_remote_addr: tuple[str, int]) -> None:
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
                incoming_sock,
            )
            self.registry.add(connection)

            loop = asyncio.get_running_loop()
            await loop.sock_connect(outgoing_sock, (self.config.connect_ip, self.config.connect_port))
            await self._wait_for_fake_ack(connection)
            self.registry.remove(connection.id)
            connection.monitor = False

            await self._relay_pair(incoming_sock, outgoing_sock)
        except Exception as exc:
            LOGGER.debug("Connection from %s closed during setup: %r", incoming_remote_addr, exc)
        finally:
            if connection is not None:
                connection.monitor = False
                self.registry.remove(connection.id)
            self._close_socket(incoming_sock)
            if outgoing_sock is not None:
                self._close_socket(outgoing_sock)

    async def _wait_for_fake_ack(self, connection: FakeInjectionConnection) -> None:
        await asyncio.wait_for(connection.t2a_event.wait(), self.config.handshake_timeout)
        if connection.t2a_msg == "fake_data_ack_recv":
            return
        if connection.t2a_msg == "unexpected_close":
            raise ConnectionError("connection closed while waiting for fake packet acknowledgement")
        raise ConnectionError(f"unexpected injector message: {connection.t2a_msg!r}")

    async def _relay_pair(self, left: socket.socket, right: socket.socket) -> None:
        left_to_right = asyncio.create_task(self._relay(left, right))
        right_to_left = asyncio.create_task(self._relay(right, left))
        done, pending = await asyncio.wait({left_to_right, right_to_left}, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        for task in done:
            with suppress(Exception):
                task.result()

    async def _relay(self, source: socket.socket, target: socket.socket) -> None:
        loop = asyncio.get_running_loop()
        while True:
            data = await loop.sock_recv(source, self.config.recv_buffer_size)
            if not data:
                return
            await loop.sock_sendall(target, data)

    @staticmethod
    def _close_socket(sock: socket.socket) -> None:
        with suppress(OSError):
            sock.shutdown(socket.SHUT_RDWR)
        with suppress(OSError):
            sock.close()
