import asyncio
import socket
import unittest

from sni_spoof.relay import RelaySession


class RelaySessionTests(unittest.TestCase):
    def test_relay_tracks_bytes(self):
        async def scenario():
            client, client_peer = socket.socketpair()
            upstream, upstream_peer = socket.socketpair()
            sockets = (client, client_peer, upstream, upstream_peer)
            for sock in sockets:
                sock.setblocking(False)

            seen = []
            relay = RelaySession(4096, 1.0, lambda direction, size: seen.append((direction, size)))
            task = asyncio.create_task(relay.run(client, upstream))
            loop = asyncio.get_running_loop()

            await loop.sock_sendall(client_peer, b"hello")
            data = await loop.sock_recv(upstream_peer, 5)
            client_peer.close()
            upstream_peer.close()
            result = await asyncio.wait_for(task, timeout=2.0)
            client.close()
            upstream.close()
            return data, result, seen

        data, result, seen = asyncio.run(scenario())

        self.assertEqual(data, b"hello")
        self.assertEqual(result.client_to_upstream, 5)
        self.assertIn(("client_to_upstream", 5), seen)


if __name__ == "__main__":
    unittest.main()
