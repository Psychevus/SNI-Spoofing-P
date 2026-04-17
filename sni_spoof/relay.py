from __future__ import annotations

import asyncio
import socket
from contextlib import suppress
from dataclasses import dataclass
from typing import Callable


ByteCounter = Callable[[str, int], None]


@dataclass(frozen=True)
class RelayResult:
    client_to_upstream: int
    upstream_to_client: int


class RelaySession:
    def __init__(
        self,
        recv_buffer_size: int,
        idle_timeout: float,
        on_bytes: ByteCounter | None = None,
    ) -> None:
        self.recv_buffer_size = recv_buffer_size
        self.idle_timeout = idle_timeout
        self.on_bytes = on_bytes
        self._totals = {
            "client_to_upstream": 0,
            "upstream_to_client": 0,
        }

    async def run(self, client: socket.socket, upstream: socket.socket, client_prefix: bytes = b"") -> RelayResult:
        if client_prefix:
            loop = asyncio.get_running_loop()
            await loop.sock_sendall(upstream, client_prefix)
            self._record("client_to_upstream", len(client_prefix))

        client_task = asyncio.create_task(self._relay(client, upstream, "client_to_upstream"))
        upstream_task = asyncio.create_task(self._relay(upstream, client, "upstream_to_client"))
        done, pending = await asyncio.wait({client_task, upstream_task}, return_when=asyncio.FIRST_COMPLETED)

        for task in pending:
            task.cancel()
        for task in pending:
            with suppress(asyncio.CancelledError):
                await task
        for task in done:
            with suppress(OSError, ConnectionError):
                task.result()

        return RelayResult(
            client_to_upstream=self._totals["client_to_upstream"],
            upstream_to_client=self._totals["upstream_to_client"],
        )

    async def _relay(self, source: socket.socket, target: socket.socket, direction: str) -> None:
        loop = asyncio.get_running_loop()
        while True:
            try:
                data = await asyncio.wait_for(loop.sock_recv(source, self.recv_buffer_size), timeout=self.idle_timeout)
            except asyncio.TimeoutError:
                return
            if not data:
                return
            await loop.sock_sendall(target, data)
            self._record(direction, len(data))

    def _record(self, direction: str, size: int) -> None:
        if size <= 0:
            return
        self._totals[direction] += size
        if self.on_bytes is not None:
            self.on_bytes(direction, size)
