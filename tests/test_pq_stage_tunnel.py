"""Handshake, mutual authentication, record integrity and replay tests."""

import importlib.util
from pathlib import Path
import socket
import threading
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "deploy" / "pq_stage_tunnel.py"
SPEC = importlib.util.spec_from_file_location("pq_stage_tunnel", SCRIPT)
tunnel = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tunnel)


class PqTunnelTests(unittest.TestCase):
    def handshake(self, wrong_server_key=False):
        c_pk, c_sk = tunnel.dsa.keygen()
        s_pk, s_sk = tunnel.dsa.keygen()
        x, y = socket.socketpair()
        result = {}

        def serve():
            try:
                result["server"] = tunnel.handshake_server(y, (s_pk, s_sk), c_pk)
            except Exception as exc:
                result["error"] = exc
            if "error" in result:
                y.close()

        worker = threading.Thread(target=serve)
        worker.start()
        x.settimeout(15)
        with self.assertRaises(Exception) if wrong_server_key else _no_exception():
            result["client"] = tunnel.handshake_client(
                x, (c_pk, c_sk), tunnel.dsa.keygen()[0] if wrong_server_key else s_pk)
        worker.join(timeout=15)
        self.assertFalse(worker.is_alive())
        return x, y, result

    def test_encrypted_roundtrip_and_counter_replay(self):
        x, y, state = self.handshake()
        self.assertNotIn("error", state)
        client, server = state["client"], state["server"]
        self.assertEqual(client.salt, server.salt)
        client.send(b"stage activation secret")
        self.assertEqual(server.receive(), b"stage activation secret")
        server.send(b"verified token")
        self.assertEqual(client.receive(), b"verified token")
        # Counter is implicit in each encrypted record. A duplicate record
        # made for the previous counter must fail authentication.
        old_counter = client.sent - 1
        nonce = client.send_direction + old_counter.to_bytes(8, "big")
        aad = tunnel.DOMAIN + client.salt + nonce
        key = client._key(client.send_key, client.send_direction, old_counter)
        replay = tunnel.ChaCha20Poly1305(key).encrypt(nonce, b"\x00replay", aad)
        tunnel.send_frame(x, replay, tunnel.MAX_RECORD)
        with self.assertRaises(Exception):
            server.receive()
        x.close()
        y.close()

    def test_wrong_pinned_server_identity_rejected(self):
        x, y, state = self.handshake(wrong_server_key=True)
        self.assertNotIn("client", state)
        x.close()
        y.close()

    def test_record_size_is_bounded(self):
        x, y, state = self.handshake()
        with self.assertRaises(ValueError):
            state["client"].send(b"A" * 16385)
        x.close()
        y.close()


class _no_exception:
    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


if __name__ == "__main__":
    unittest.main()
