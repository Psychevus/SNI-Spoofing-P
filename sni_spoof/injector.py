from __future__ import annotations

import asyncio
import logging
import socket
import sys
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

try:
    from pydivert import Packet, WinDivert
except ImportError:
    Packet = Any  # type: ignore[misc, assignment]
    WinDivert = None  # type: ignore[assignment]


LOGGER = logging.getLogger(__name__)


@dataclass
class MonitoredConnection:
    sock: socket.socket
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    monitor: bool = True
    syn_seq: int = -1
    syn_ack_seq: int = -1
    thread_lock: threading.Lock = field(default_factory=threading.Lock)

    @property
    def id(self) -> tuple[str, int, str, int]:
        return self.src_ip, self.src_port, self.dst_ip, self.dst_port


class FakeInjectionConnection(MonitoredConnection):
    def __init__(
        self,
        sock: socket.socket,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        fake_data: bytes,
        bypass_method: str,
        peer_sock: socket.socket,
    ) -> None:
        super().__init__(sock, src_ip, dst_ip, src_port, dst_port)
        self.fake_data = fake_data
        self.sch_fake_sent = False
        self.fake_sent = False
        self.t2a_event = asyncio.Event()
        self.t2a_msg = ""
        self.bypass_method = bypass_method
        self.peer_sock = peer_sock
        self.running_loop = asyncio.get_running_loop()


class ConnectionRegistry:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._connections: dict[tuple[str, int, str, int], FakeInjectionConnection] = {}

    def add(self, connection: FakeInjectionConnection) -> None:
        with self._lock:
            self._connections[connection.id] = connection

    def remove(self, connection_id: tuple[str, int, str, int]) -> None:
        with self._lock:
            self._connections.pop(connection_id, None)

    def get(self, connection_id: tuple[str, int, str, int]) -> FakeInjectionConnection | None:
        with self._lock:
            return self._connections.get(connection_id)

    def __len__(self) -> int:
        with self._lock:
            return len(self._connections)


class TcpInjector(ABC):
    def __init__(self, w_filter: str) -> None:
        if WinDivert is None:
            raise RuntimeError("pydivert is not installed. Install requirements and run with administrator privileges.")
        self.w = WinDivert(w_filter)

    @abstractmethod
    def inject(self, packet: Packet) -> None:
        raise NotImplementedError

    def run(self, ready_event: threading.Event | None = None, error_box: list[BaseException] | None = None) -> None:
        try:
            with self.w:
                LOGGER.info("WinDivert injector is running")
                if ready_event is not None:
                    ready_event.set()
                while True:
                    packet = self.w.recv(65575)
                    self.inject(packet)
        except BaseException as exc:
            if error_box is not None:
                error_box.append(exc)
            if ready_event is not None:
                ready_event.set()
            LOGGER.exception("WinDivert injector stopped unexpectedly")


class FakeTcpInjector(TcpInjector):
    def __init__(self, w_filter: str, connections: ConnectionRegistry | dict[tuple[str, int, str, int], FakeInjectionConnection]) -> None:
        super().__init__(w_filter)
        if isinstance(connections, ConnectionRegistry):
            self.connections = connections
        else:
            self.connections = ConnectionRegistry()
            for connection in connections.values():
                self.connections.add(connection)

    def fake_send_thread(self, packet: Packet, connection: FakeInjectionConnection) -> None:
        time.sleep(0.001)
        with connection.thread_lock:
            if not connection.monitor:
                return

            packet.tcp.psh = True
            packet.ip.packet_len = packet.ip.packet_len + len(connection.fake_data)
            packet.tcp.payload = connection.fake_data
            if packet.ipv4:
                packet.ipv4.ident = (packet.ipv4.ident + 1) & 0xffff

            if connection.bypass_method == "wrong_seq":
                packet.tcp.seq_num = (connection.syn_seq + 1 - len(packet.tcp.payload)) & 0xffffffff
                connection.fake_sent = True
                LOGGER.debug(
                    "Sending fake payload on %s:%s -> %s:%s with seq=%s payload_len=%s",
                    connection.src_ip,
                    connection.src_port,
                    connection.dst_ip,
                    connection.dst_port,
                    packet.tcp.seq_num,
                    len(packet.tcp.payload),
                )
                self.w.send(packet, True)
                return

            LOGGER.error("Unsupported bypass method: %s", connection.bypass_method)
            connection.monitor = False

    def on_unexpected_packet(self, packet: Packet, connection: FakeInjectionConnection, info_message: str) -> None:
        LOGGER.warning("%s: %s", info_message, packet)
        connection.sock.close()
        connection.peer_sock.close()
        connection.monitor = False
        connection.t2a_msg = "unexpected_close"
        connection.running_loop.call_soon_threadsafe(connection.t2a_event.set)
        self.w.send(packet, False)

    def on_inbound_packet(self, packet: Packet, connection: FakeInjectionConnection) -> None:
        if connection.syn_seq == -1:
            self.on_unexpected_packet(packet, connection, "unexpected inbound packet, no syn sent")
            return

        if packet.tcp.ack and packet.tcp.syn and not packet.tcp.rst and not packet.tcp.fin and len(packet.tcp.payload) == 0:
            seq_num = packet.tcp.seq_num
            ack_num = packet.tcp.ack_num
            if connection.syn_ack_seq != -1 and connection.syn_ack_seq != seq_num:
                self.on_unexpected_packet(packet, connection, f"unexpected inbound syn-ack packet, seq changed: {seq_num} != {connection.syn_ack_seq}")
                return
            if ack_num != ((connection.syn_seq + 1) & 0xffffffff):
                self.on_unexpected_packet(packet, connection, f"unexpected inbound syn-ack packet, ack mismatch: {ack_num} != {connection.syn_seq}")
                return
            connection.syn_ack_seq = seq_num
            LOGGER.debug("Captured inbound SYN-ACK for %s with seq=%s ack=%s", connection.id, seq_num, ack_num)
            self.w.send(packet, False)
            return

        if packet.tcp.ack and not packet.tcp.syn and not packet.tcp.rst and not packet.tcp.fin and len(packet.tcp.payload) == 0 and connection.fake_sent:
            seq_num = packet.tcp.seq_num
            ack_num = packet.tcp.ack_num
            if connection.syn_ack_seq == -1 or ((connection.syn_ack_seq + 1) & 0xffffffff) != seq_num:
                self.on_unexpected_packet(packet, connection, f"unexpected inbound ack packet, seq mismatch: {seq_num} != {connection.syn_ack_seq}")
                return
            if ack_num != ((connection.syn_seq + 1) & 0xffffffff):
                self.on_unexpected_packet(packet, connection, f"unexpected inbound ack packet, ack mismatch: {ack_num} != {connection.syn_seq}")
                return

            connection.monitor = False
            connection.t2a_msg = "fake_data_ack_recv"
            LOGGER.debug("Fake payload ACK received for %s", connection.id)
            connection.running_loop.call_soon_threadsafe(connection.t2a_event.set)
            return

        self.on_unexpected_packet(packet, connection, "unexpected inbound packet")

    def on_outbound_packet(self, packet: Packet, connection: FakeInjectionConnection) -> None:
        if connection.sch_fake_sent:
            self.on_unexpected_packet(packet, connection, "unexpected outbound packet after fake packet was scheduled")
            return

        if packet.tcp.syn and not packet.tcp.ack and not packet.tcp.rst and not packet.tcp.fin and len(packet.tcp.payload) == 0:
            seq_num = packet.tcp.seq_num
            ack_num = packet.tcp.ack_num
            if ack_num != 0:
                self.on_unexpected_packet(packet, connection, "unexpected outbound syn packet with non-zero ack")
                return
            if connection.syn_seq != -1 and connection.syn_seq != seq_num:
                self.on_unexpected_packet(packet, connection, f"unexpected outbound syn packet, seq mismatch: {seq_num} != {connection.syn_seq}")
                return
            connection.syn_seq = seq_num
            LOGGER.debug("Captured outbound SYN for %s with seq=%s", connection.id, seq_num)
            self.w.send(packet, False)
            return

        if packet.tcp.ack and not packet.tcp.syn and not packet.tcp.rst and not packet.tcp.fin and len(packet.tcp.payload) == 0:
            seq_num = packet.tcp.seq_num
            ack_num = packet.tcp.ack_num
            if connection.syn_seq == -1 or ((connection.syn_seq + 1) & 0xffffffff) != seq_num:
                self.on_unexpected_packet(packet, connection, f"unexpected outbound ack packet, seq mismatch: {seq_num} != {connection.syn_seq}")
                return
            if connection.syn_ack_seq == -1 or ack_num != ((connection.syn_ack_seq + 1) & 0xffffffff):
                self.on_unexpected_packet(packet, connection, f"unexpected outbound ack packet, ack mismatch: {ack_num} != {connection.syn_ack_seq}")
                return

            self.w.send(packet, False)
            connection.sch_fake_sent = True
            LOGGER.debug("Captured outbound ACK for %s; scheduling fake payload", connection.id)
            threading.Thread(target=self.fake_send_thread, args=(packet, connection), daemon=True).start()
            return

        self.on_unexpected_packet(packet, connection, "unexpected outbound packet")

    def inject(self, packet: Packet) -> None:
        if packet.is_inbound:
            connection_id = (packet.ip.dst_addr, packet.tcp.dst_port, packet.ip.src_addr, packet.tcp.src_port)
        elif packet.is_outbound:
            connection_id = (packet.ip.src_addr, packet.tcp.src_port, packet.ip.dst_addr, packet.tcp.dst_port)
        else:
            LOGGER.error("Packet has no direction: %s", packet)
            sys.exit("packet direction is unavailable")

        connection = self.connections.get(connection_id)
        if connection is None:
            self.w.send(packet, False)
            return

        with connection.thread_lock:
            if not connection.monitor:
                self.w.send(packet, False)
                return
            if packet.is_inbound:
                self.on_inbound_packet(packet, connection)
            else:
                self.on_outbound_packet(packet, connection)


FakeInjectiveConnection = FakeInjectionConnection
