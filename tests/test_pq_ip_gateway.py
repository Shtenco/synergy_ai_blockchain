import importlib.util
from pathlib import Path
import socket
import threading
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "deploy" / "pq_ip_gateway.py"
SPEC = importlib.util.spec_from_file_location("pq_ip_gateway", SCRIPT)
gateway = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gateway)


class PqIpGatewayTests(unittest.TestCase):
    def make_channels(self):
        from pqcrypto.sign import ml_dsa_87 as dsa
        client_pk, _ = dsa.keygen()
        server_pk, _ = dsa.keygen()
        transcript = gateway.sha256(b"test-transcript")
        shared = bytes(range(32))
        a = gateway.Channel(shared, client_pk, server_pk, transcript)
        b = gateway.Channel(shared, client_pk, server_pk, transcript)
        return a, b

    def test_tcp_roundtrip_over_pq_channel(self):
        a, b = self.make_channels()
        frame = a.seal(0, b"GET /secret HTTP/1.1")
        self.assertEqual(b.open(frame, 0), b"GET /secret HTTP/1.1")
        reply = b.seal(1, b"response:GET /secret HTTP/1.1")
        self.assertEqual(a.open(reply, 1), b"response:GET /secret HTTP/1.1")
        fin = a.seal(0, b"", fin=True)
        self.assertIsNone(b.open(fin, 0))

    def test_corrupted_record_is_rejected(self):
        a, b = self.make_channels()
        frame = bytearray(a.seal(0, b"payload"))
        frame[-1] ^= 0xFF
        with self.assertRaises(ValueError):
            b.open(bytes(frame), 0)

    def test_replay_is_rejected(self):
        a, b = self.make_channels()
        frame = a.seal(0, b"payload")
        self.assertEqual(b.open(frame, 0), b"payload")
        with self.assertRaises(ValueError):
            b.open(frame, 0)

    def test_wrong_direction_is_rejected(self):
        a, b = self.make_channels()
        frame = a.seal(0, b"payload")
        with self.assertRaises(ValueError):
            b.open(frame, 1)

    def test_empty_data_is_rejected(self):
        a, _ = self.make_channels()
        with self.assertRaises(ValueError):
            a.seal(0, b"")
        with self.assertRaises(ValueError):
            a.seal(0, b"x" * (gateway.RECORD_LIMIT + 1))

    def test_handshake_roundtrip_with_pinned_keys(self):
        from pqcrypto.sign import ml_dsa_87 as dsa
        client_pk, client_sk = dsa.keygen()
        server_pk, server_sk = dsa.keygen()
        left, right = socket.socketpair()
        left.settimeout(10)
        right.settimeout(10)
        result = {}

        def serve():
            try:
                result["server"] = gateway.handshake_server(right, (server_pk, server_sk), client_pk)
            except Exception as exc:
                result["error"] = exc
            finally:
                right.close()

        worker = threading.Thread(target=serve, daemon=True)
        worker.start()
        try:
            client = gateway.handshake_client(left, (client_pk, client_sk), server_pk)
        finally:
            worker.join(timeout=10)
        self.assertNotIn("error", result)
        server = result["server"]
        frame = client.seal(0, b"stage-bytes")
        self.assertEqual(server.open(frame, 0), b"stage-bytes")
        reply = server.seal(1, b"ack-stage-bytes")
        self.assertEqual(client.open(reply, 1), b"ack-stage-bytes")
        left.close()
        right.close()

    def test_handshake_rejects_wrong_server_key(self):
        from pqcrypto.sign import ml_dsa_87 as dsa
        client_pk, client_sk = dsa.keygen()
        server_pk, server_sk = dsa.keygen()
        wrong_pk, _ = dsa.keygen()
        left, right = socket.socketpair()
        left.settimeout(10)
        right.settimeout(10)
        result = {}

        def serve():
            try:
                result["server"] = gateway.handshake_server(right, (server_pk, server_sk), client_pk)
            except Exception as exc:
                result["error"] = exc
            finally:
                right.close()

        worker = threading.Thread(target=serve, daemon=True)
        worker.start()
        try:
            # Wrong pinned server identity must not complete: the server
            # rejects the mismatched transcript and closes the connection.
            with self.assertRaises((ValueError, EOFError)):
                gateway.handshake_client(left, (client_pk, client_sk), wrong_pk)
            self.assertIn("error", result)
        finally:
            worker.join(timeout=10)
            left.close()


if __name__ == "__main__":
    unittest.main()
