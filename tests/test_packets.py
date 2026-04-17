import unittest

from sni_spoof.packets import ClientHelloMaker, PacketTemplateError


class ClientHelloTemplateTests(unittest.TestCase):
    def test_client_hello_round_trip(self):
        client_hello = ClientHelloMaker.get_client_hello_with(
            b"a" * 32,
            b"b" * 32,
            b"auth.vercel.com",
            b"c" * 32,
        )

        self.assertEqual(len(client_hello), 517)
        rnd, session_id, sni, key_share = ClientHelloMaker.parse_client_hello(client_hello)
        self.assertEqual(rnd, b"a" * 32)
        self.assertEqual(session_id, b"b" * 32)
        self.assertEqual(sni, "auth.vercel.com")
        self.assertEqual(key_share, b"c" * 32)

    def test_rejects_oversized_sni(self):
        with self.assertRaises(PacketTemplateError):
            ClientHelloMaker.get_client_hello_with(b"a" * 32, b"b" * 32, b"x" * 220, b"c" * 32)

    def test_rejects_bad_random_size(self):
        with self.assertRaises(PacketTemplateError):
            ClientHelloMaker.get_client_hello_with(b"a", b"b" * 32, b"example.com", b"c" * 32)


if __name__ == "__main__":
    unittest.main()
