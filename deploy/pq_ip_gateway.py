#!/usr/bin/env python3
"""TCP/IP-over-PQ gateway without TUN.

Every gateway has an ML-DSA-87 identity. A TCP connection accepted by the
client-side gateway becomes one logical PQ connection through the existing
ML-KEM-1024 handshake implementation. Packets carry only encrypted TCP bytes;
applications connect to the local gateway port explicitly. There is no IP
promiscuous mode and no kernel traffic interception.

  generate --out node.json
  server --bind 0.0.0.0:44100 --target 127.0.0.1:7700 --identity node.json --peer-key client.pub
  client --listen 127.0.0.1:8080 --peer host:44100 --identity client.json --peer-key node.pub

Dependencies: pqcrypto==1.0.0, cryptography>=42.
"""

import argparse
import hashlib
import json
import os
import secrets
import socket
import struct
import threading
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from pqcrypto.kem import ml_kem_1024 as kem
from pqcrypto.sign import ml_dsa_87 as dsa

DOMAIN = b"SYNERGY/PQ-IP-GATEWAY/V1\0"
CONTEXT = DOMAIN
HANDSHAKE_LIMIT = 10240
RECORD_LIMIT = 16384
FIN = 0x01


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def kdf(secret: bytes, salt: bytes, info: bytes, size: int = 32) -> bytes:
    return HKDF(hashes.SHA256(), size, salt, DOMAIN + info).derive(secret)


def read_exact(sock: socket.socket, count: int) -> bytes:
    out = []
    while count:
        piece = sock.recv(count)
        if not piece:
            raise EOFError("closed")
        out.append(piece)
        count -= len(piece)
    return b"".join(out)


def write_frame(sock: socket.socket, data: bytes, limit: int) -> None:
    if not 0 < len(data) <= limit:
        raise ValueError("invalid frame")
    sock.sendall(struct.pack(">I", len(data)) + data)


def read_frame(sock: socket.socket, limit: int) -> bytes:
    (size,) = struct.unpack(">I", read_exact(sock, 4))
    if not 0 < size <= limit:
        raise ValueError("invalid frame")
    return read_exact(sock, size)


def sign(secret: bytes, message: bytes) -> bytes:
    return dsa.sign(secret, message, CONTEXT)


def verify(public: bytes, message: bytes, signature: bytes) -> None:
    try:
        dsa.verify(public, message, signature, CONTEXT)
    except Exception as exc:
        raise ValueError("invalid PQ signature") from exc


def generate(path) -> None:
    from pathlib import Path as _P
    path = _P(path)
    if path.exists():
        raise FileExistsError(path)
    public, secret = dsa.keygen()
    path.write_text(json.dumps({"public": public.hex(), "private": secret.hex()}) + "\n")
    path.chmod(0o600)
    path.with_suffix(".pub").write_text(public.hex() + "\n")
    print(f"generated {path}; fingerprint sha256:{sha256(public).hexdigest()}")


def load_identity(path):
    from pathlib import Path as _P
    data = json.loads(_P(path).read_text())
    public, secret = bytes.fromhex(data["public"]), bytes.fromhex(data["private"])
    if len(public) != dsa.PUBLIC_KEY_SIZE or len(secret) != dsa.SECRET_KEY_SIZE:
        raise ValueError("invalid identity")
    return public, secret


def load_peer(path):
    from pathlib import Path as _P
    public = bytes.fromhex(_P(path).read_text().strip())
    if len(public) != dsa.PUBLIC_KEY_SIZE:
        raise ValueError("invalid peer key")
    return public


REKEY_EVERY = 1000


class Channel:
    """Ordered AEAD record channel bound to one ML-KEM handshake.

    Direction 0 is initiator->responder, direction 1 is responder->initiator.
    Both peers construct the channel with the same ordered identities and
    transcript hash, so sequence numbers, epochs, nonces and keys stay in sync.
    """

    def __init__(self, shared_secret: bytes, initiator_pk: bytes, responder_pk: bytes, transcript_hash: bytes):
        if len(shared_secret) != 32:
            raise ValueError("invalid shared secret")
        if len(initiator_pk) != dsa.PUBLIC_KEY_SIZE or len(responder_pk) != dsa.PUBLIC_KEY_SIZE:
            raise ValueError("invalid peer public key")
        if len(transcript_hash) != 32 or transcript_hash == bytes(32):
            raise ValueError("invalid transcript hash")
        self.salt = sha256(DOMAIN + transcript_hash + initiator_pk + responder_pk)
        self.root = kdf(shared_secret, self.salt, b"root")
        self.chains = [
            {"chain": kdf(self.root, self.salt, b"chain0"), "epoch": 0, "lock": threading.Lock()},
            {"chain": kdf(self.root, self.salt, b"chain1"), "epoch": 0, "lock": threading.Lock()},
        ]
        self.send_seq = [0, 0]
        self.recv_seq = [0, 0]
        self.send_lock = threading.Lock()
        self.recv_lock = threading.Lock()

    def _key_for(self, direction: int, seq: int) -> bytes:
        if direction not in (0, 1) or seq < 0:
            raise ValueError("invalid direction or sequence")
        epoch, state = divmod(seq, REKEY_EVERY)[0], self.chains[direction]
        with state["lock"]:
            while state["epoch"] < divmod(seq, REKEY_EVERY)[0]:
                state["chain"] = sha256(state["chain"] + b"rekey")
                state["epoch"] += 1
            epoch = state["epoch"]
            chain = state["chain"]
        return kdf(chain, self.salt, b"record" + bytes([direction]) + epoch.to_bytes(8, "big"))

    @staticmethod
    def _nonce(direction: int, seq: int) -> bytes:
        return bytes([direction]) * 4 + seq.to_bytes(8, "big")

    def seal(self, direction: int, payload: bytes, fin: bool = False) -> bytes:
        if direction not in (0, 1):
            raise ValueError("invalid direction")
        if fin and payload:
            raise ValueError("fin record must be empty")
        if not fin and (not payload or len(payload) > RECORD_LIMIT):
            raise ValueError("invalid payload")
        with self.send_lock:
            seq = self.send_seq[direction]
            key = self._key_for(direction, seq)
            nonce = self._nonce(direction, seq)
            aad = sha256(DOMAIN + self.salt + nonce)
            body = (b"\x01" if fin else b"\x00") + payload
            ciphertext = ChaCha20Poly1305(key).encrypt(nonce, body, aad)
            frame = sha256(DOMAIN + self.salt + nonce + ciphertext) + ciphertext
            self.send_seq[direction] = seq + 1
        return frame

    def open(self, data: bytes, direction: int):
        if direction not in (0, 1):
            raise ValueError("invalid direction")
        if len(data) < 32:
            raise ValueError("short record")
        commitment, ciphertext = data[:32], data[32:]
        if not ciphertext or len(ciphertext) > RECORD_LIMIT + 17:
            raise ValueError("invalid record length")
        with self.recv_lock:
            seq = self.recv_seq[direction]
            key = self._key_for(direction, seq)
            nonce = self._nonce(direction, seq)
            if sha256(DOMAIN + self.salt + nonce + ciphertext) != commitment:
                raise ValueError("record commitment")
            aad = sha256(DOMAIN + self.salt + nonce)
            try:
                body = ChaCha20Poly1305(key).decrypt(nonce, ciphertext, aad)
            except Exception as exc:
                raise ValueError("AEAD authentication failed") from exc
            if not body or body[0] not in (0, 1):
                raise ValueError("invalid record body")
            if (body[0] == 1 and len(body) != 1) or (body[0] == 0 and len(body) == 1):
                raise ValueError("invalid record body")
            self.recv_seq[direction] = seq + 1
        return None if body[0] == 1 else body[1:]

    def send(self, sock: socket.socket, direction: int, payload: bytes, fin: bool = False):
        write_frame(sock, self.seal(direction, payload, fin=fin), 20000)

    def finish(self, sock: socket.socket, direction: int):
        self.send(sock, direction, b"", fin=True)

    def receive(self, data: bytes, direction: int):
        return self.open(data, direction)


def handshake_client(sock, identity, peer_public):
    public, secret = identity
    if len(public) != dsa.PUBLIC_KEY_SIZE or len(peer_public) != dsa.PUBLIC_KEY_SIZE:
        raise ValueError("invalid peer public key")
    eph_public, eph_secret = kem.keygen()
    if len(eph_public) != kem.PUBLIC_KEY_SIZE:
        raise ValueError("invalid ephemeral KEM key")
    nonce = os.urandom(32)
    transcript = DOMAIN + b"client" + public + peer_public + nonce + eph_public
    write_frame(sock, nonce + eph_public + sign(secret, transcript), HANDSHAKE_LIMIT)
    response = read_frame(sock, HANDSHAKE_LIMIT)
    if len(response) != 32 + kem.CIPHERTEXT_SIZE + dsa.SIGNATURE_SIZE:
        raise ValueError("invalid server hello")
    server_nonce, ciphertext, signature = response[:32], response[32:-dsa.SIGNATURE_SIZE], response[-dsa.SIGNATURE_SIZE:]
    full_transcript = transcript + server_nonce + ciphertext
    verify(peer_public, full_transcript, signature)
    shared = kem.decaps(eph_secret, ciphertext)
    if len(shared) != 32:
        raise ValueError("invalid shared secret")
    return Channel(shared, public, peer_public, sha256(full_transcript))


def handshake_server(sock, identity, peer_public):
    public, secret = identity
    if len(public) != dsa.PUBLIC_KEY_SIZE or len(peer_public) != dsa.PUBLIC_KEY_SIZE:
        raise ValueError("invalid peer public key")
    request = read_frame(sock, HANDSHAKE_LIMIT)
    if len(request) != 32 + kem.PUBLIC_KEY_SIZE + dsa.SIGNATURE_SIZE:
        raise ValueError("invalid client hello")
    nonce, eph_public, signature = request[:32], request[32:-dsa.SIGNATURE_SIZE], request[-dsa.SIGNATURE_SIZE:]
    transcript = DOMAIN + b"client" + peer_public + public + nonce + eph_public
    verify(peer_public, transcript, signature)
    ciphertext, shared = kem.encaps(eph_public)
    if len(ciphertext) != kem.CIPHERTEXT_SIZE or len(shared) != 32:
        raise ValueError("invalid encapsulation")
    server_nonce = os.urandom(32)
    full_transcript = transcript + server_nonce + ciphertext
    write_frame(sock, server_nonce + ciphertext + sign(secret, full_transcript), HANDSHAKE_LIMIT)
    return Channel(shared, peer_public, public, sha256(full_transcript))


def parse_address(value):
    host, port = value.rsplit(":", 1)
    return host, int(port)


def run_client(args):
    identity = load_identity(args.identity)
    peer = load_peer(args.peer_key)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(parse_address(args.listen))
    listener.listen(32)
    print(f"PQ-IP client {args.listen} -> {args.peer}", flush=True)

    def handle(local):
        try:
            remote = socket.create_connection(parse_address(args.peer), timeout=15)
            remote.settimeout(15)
            channel = handshake_client(remote, identity, peer)
            channel_key = channel.salt
            outgoing = {}
            stop = threading.Event()

            def outbound_pump():
                while not stop.is_set():
                    try:
                        data = local.recv(16384)
                        if not data:
                            break
                        channel.send(remote, 0, data)
                    except Exception:
                        break
                try:
                    channel.finish(remote, 0)
                except Exception:
                    pass

            def inbound_pump():
                while not stop.is_set():
                    try:
                        record = read_frame(remote, 20000)
                    except Exception:
                        break
                    payload = channel.receive(record, 1)
                    if payload:
                        try:
                            local.sendall(payload)
                        except OSError:
                            break
                    elif payload is None:
                        try:
                            local.shutdown(socket.SHUT_WR)
                        except OSError:
                            pass

            thread = threading.Thread(target=outbound_pump, daemon=True)
            thread.start()
            inbound_pump()
            thread.join(timeout=2)
            stop.set()
        except Exception as exc:
            print(f"PQ-IP client connection: {type(exc).__name__}: {exc}", flush=True)
        finally:
            for sock in (local,):
                try:
                    sock.close()
                except OSError:
                    pass

    while True:
        local, _ = listener.accept()
        threading.Thread(target=handle, args=(local,), daemon=True).start()


def run_server(args):
    identity = load_identity(args.identity)
    peer = load_peer(args.peer_key)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(parse_address(args.bind))
    listener.listen(32)
    print(f"PQ-IP server {args.bind} -> {args.target}", flush=True)

    def handle(client):
        try:
            channel = handshake_server(client, identity, peer)
            target = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            target.settimeout(15)
            target.connect(parse_address(args.target))
            stop = threading.Event()

            def inbound():
                while not stop.is_set():
                    try:
                        data = target.recv(16384)
                        if not data:
                            break
                        channel.send(client, 1, data)
                    except Exception:
                        break
                try:
                    channel.finish(client, 1)
                except Exception:
                    pass

            thread = threading.Thread(target=inbound, daemon=True)
            thread.start()
            while not stop.is_set():
                try:
                    record = read_frame(client, 20000)
                except Exception:
                    break
                payload = channel.receive(record, 0)
                if payload:
                    try:
                        target.sendall(payload)
                    except OSError:
                        break
                elif payload is None:
                    try:
                        target.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
            thread.join(timeout=2)
            stop.set()
        except Exception as exc:
            print(f"PQ-IP server connection: {type(exc).__name__}: {exc}", flush=True)
        finally:
            for sock in (client,):
                try:
                    sock.close()
                except OSError:
                    pass

    while True:
        client, _ = listener.accept()
        threading.Thread(target=handle, args=(client,), daemon=True).start()


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="mode", required=True)
    generated = sub.add_parser("generate")
    generated.add_argument("--out", type=argparse.FileType("w"), required=True)
    for name in ("client", "server"):
        item = sub.add_parser(name)
        item.add_argument("--identity", required=True)
        item.add_argument("--peer-key", required=True)
        item.add_argument("--peer" if name == "client" else "--target", required=True)
        if name == "client":
            item.add_argument("--listen", required=True)
        else:
            item.add_argument("--bind", required=True)
    args = parser.parse_args()
    if args.mode == "generate":
        generate(args.out)
    elif args.mode == "client":
        run_client(args)
    else:
        run_server(args)


if __name__ == "__main__":
    main()
