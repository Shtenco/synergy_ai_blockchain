#!/usr/bin/env python3
"""Pinned ML-DSA-87 authenticated ML-KEM-1024 TCP tunnel for Stage RPC.

Protects ONE application TCP stream at a time. It is not an IP/TUN tunnel.
The public signing keys must be copied/pinned out of band; never accept a
peer key received in the handshake as its own proof of identity.

  generate --out NODE.json
  server --bind 0.0.0.0:44100 --target 127.0.0.1:7700 \
         --identity SERVER.json --peer-key CLIENT.pub
  client --bind 127.0.0.1:17700 --peer HOST:44100 \
         --identity CLIENT.json --peer-key SERVER.pub

Dependencies: pqcrypto==1.0.0, cryptography>=42. Reference integration;
neither this composition nor the cryptography providers have been audited.
"""

import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path
import socket
import struct
import threading

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from pqcrypto.kem import ml_kem_1024 as kem
from pqcrypto.sign import ml_dsa_87 as dsa


DOMAIN = b"SYNERGY/STAGE-PQ-TCP/V1\0"
CONTEXT = b"SYNERGY/STAGE-PQ-TCP/V1"
MAX_HELLO = 8192
MAX_RECORD = 16384 + 17
MAX_COUNTER = 2**32
REKEY_RECORDS = 2**16


def derive(secret: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt,
                info=DOMAIN + info).derive(secret)


def read_exact(sock: socket.socket, size: int) -> bytes:
    chunks = []
    while size:
        piece = sock.recv(size)
        if not piece:
            raise EOFError("truncated frame")
        chunks.append(piece)
        size -= len(piece)
    return b"".join(chunks)


def send_frame(sock: socket.socket, data: bytes, maximum: int):
    if not 0 < len(data) <= maximum:
        raise ValueError("invalid frame size")
    sock.sendall(struct.pack(">I", len(data)) + data)


def read_frame(sock: socket.socket, maximum: int) -> bytes:
    (size,) = struct.unpack(">I", read_exact(sock, 4))
    if not 0 < size <= maximum:
        raise ValueError("invalid frame size")
    return read_exact(sock, size)


def generate(path: Path):
    if path.exists() or path.with_suffix(".pub").exists():
        raise FileExistsError("refusing to replace identity")
    pk, sk = dsa.keygen()
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="ascii") as stream:
            json.dump({"public": pk.hex(), "private": sk.hex()}, stream)
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    path.with_suffix(".pub").write_text(pk.hex() + "\n", encoding="ascii")
    print(f"identity generated; public fingerprint sha256:{hashlib.sha256(pk).hexdigest()}")


def load_identity(path: Path) -> tuple[bytes, bytes]:
    identity = json.loads(path.read_text(encoding="ascii"))
    pk, sk = bytes.fromhex(identity["public"]), bytes.fromhex(identity["private"])
    if len(pk) != dsa.PUBLIC_KEY_SIZE or len(sk) != dsa.SECRET_KEY_SIZE:
        raise ValueError("invalid identity length")
    return pk, sk


def load_peer(path: Path) -> bytes:
    pk = bytes.fromhex(path.read_text(encoding="ascii").strip())
    if len(pk) != dsa.PUBLIC_KEY_SIZE:
        raise ValueError("invalid pinned peer key")
    return pk


def sign(sk: bytes, message: bytes) -> bytes:
    return dsa.sign(sk, message, CONTEXT)


def verify(pk: bytes, message: bytes, signature: bytes):
    try:
        dsa.verify(pk, message, signature, CONTEXT)
    except Exception as exc:
        raise ValueError("peer PQ signature invalid") from exc


def handshake_client(sock: socket.socket, identity: tuple[bytes, bytes], server_pk: bytes):
    client_pk, client_sk = identity
    eph_pk, eph_sk = kem.keygen()
    client_nonce = os.urandom(32)
    request = DOMAIN + client_pk + server_pk + client_nonce + eph_pk
    send_frame(sock, client_nonce + eph_pk + sign(client_sk, request), MAX_HELLO)
    hello = read_frame(sock, MAX_HELLO)
    if len(hello) != 32 + kem.CIPHERTEXT_SIZE + dsa.SIGNATURE_SIZE:
        raise ValueError("server hello length")
    server_nonce, ciphertext, signature = hello[:32], hello[32:32 + kem.CIPHERTEXT_SIZE], hello[32 + kem.CIPHERTEXT_SIZE:]
    transcript = DOMAIN + client_pk + server_pk + client_nonce + eph_pk + server_nonce + ciphertext
    verify(server_pk, transcript, signature)
    secret = kem.decaps(eph_sk, ciphertext)
    salt = hashlib.sha256(transcript).digest()
    material = derive(secret, salt, b"handshake", 96)
    finish, c2s, s2c = material[:32], material[32:64], material[64:]
    send_frame(sock, hmac.digest(finish, b"client" + salt, "sha256"), MAX_HELLO)
    if not hmac.compare_digest(read_frame(sock, MAX_HELLO), hmac.digest(finish, b"server" + salt, "sha256")):
        raise ValueError("server finished invalid")
    return SecureStream(sock, salt, send_key=c2s, recv_key=s2c, send_direction=b"C2S\x00", recv_direction=b"S2C\x00")


def handshake_server(sock: socket.socket, identity: tuple[bytes, bytes], client_pk: bytes):
    server_pk, server_sk = identity
    hello = read_frame(sock, MAX_HELLO)
    if len(hello) != 32 + kem.PUBLIC_KEY_SIZE + dsa.SIGNATURE_SIZE:
        raise ValueError("client hello length")
    client_nonce, eph_pk, signature = hello[:32], hello[32:32 + kem.PUBLIC_KEY_SIZE], hello[32 + kem.PUBLIC_KEY_SIZE:]
    request = DOMAIN + client_pk + server_pk + client_nonce + eph_pk
    verify(client_pk, request, signature)
    ciphertext, secret = kem.encaps(eph_pk)
    server_nonce = os.urandom(32)
    transcript = request + server_nonce + ciphertext
    salt = hashlib.sha256(transcript).digest()
    material = derive(secret, salt, b"handshake", 96)
    finish, c2s, s2c = material[:32], material[32:64], material[64:]
    send_frame(sock, server_nonce + ciphertext + sign(server_sk, transcript), MAX_HELLO)
    if not hmac.compare_digest(read_frame(sock, MAX_HELLO), hmac.digest(finish, b"client" + salt, "sha256")):
        raise ValueError("client finished invalid")
    send_frame(sock, hmac.digest(finish, b"server" + salt, "sha256"), MAX_HELLO)
    return SecureStream(sock, salt, send_key=s2c, recv_key=c2s, send_direction=b"S2C\x00", recv_direction=b"C2S\x00")


class SecureStream:
    def __init__(self, sock, salt, send_key, recv_key, send_direction, recv_direction):
        self.sock, self.salt = sock, salt
        self.send_key, self.recv_key = send_key, recv_key
        self.send_direction, self.recv_direction = send_direction, recv_direction
        self.sent = self.received = 0

    def _key(self, seed: bytes, direction: bytes, counter: int):
        return derive(seed, self.salt, b"record" + direction + (counter // REKEY_RECORDS).to_bytes(8, "big"), 32)

    def send(self, data: bytes):
        if len(data) > 16384 or self.sent >= MAX_COUNTER:
            raise ValueError("record limit exceeded")
        counter = self.sent
        nonce = self.send_direction + counter.to_bytes(8, "big")
        aad = DOMAIN + self.salt + nonce
        ct = ChaCha20Poly1305(self._key(self.send_key, self.send_direction, counter)).encrypt(
            nonce, b"\x00" + data, aad)
        send_frame(self.sock, ct, MAX_RECORD)
        self.sent += 1

    def finish(self):
        if self.sent >= MAX_COUNTER:
            raise ValueError("record limit exceeded")
        counter = self.sent
        nonce = self.send_direction + counter.to_bytes(8, "big")
        aad = DOMAIN + self.salt + nonce
        ct = ChaCha20Poly1305(self._key(self.send_key, self.send_direction, counter)).encrypt(
            nonce, b"\x01", aad)
        send_frame(self.sock, ct, MAX_RECORD)
        self.sent += 1

    def receive(self) -> bytes | None:
        if self.received >= MAX_COUNTER:
            raise ValueError("record limit exceeded")
        counter = self.received
        ct = read_frame(self.sock, MAX_RECORD)
        nonce = self.recv_direction + counter.to_bytes(8, "big")
        aad = DOMAIN + self.salt + nonce
        pt = ChaCha20Poly1305(self._key(self.recv_key, self.recv_direction, counter)).decrypt(nonce, ct, aad)
        self.received += 1
        if pt == b"\x01":
            return None
        if not pt or pt[0] != 0:
            raise ValueError("invalid record type")
        return pt[1:]


def address(text):
    host, port = text.rsplit(":", 1)
    return host, int(port)


def relay(stream: SecureStream, local: socket.socket):
    errors = []

    def outbound():
        try:
            while True:
                data = local.recv(16384)
                if not data:
                    stream.finish()
                    break
                stream.send(data)
        except (OSError, ValueError) as exc:
            errors.append(exc)
            stream.sock.close()

    def inbound():
        try:
            while True:
                data = stream.receive()
                if data is None:
                    try:
                        local.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                    break
                local.sendall(data)
        except (OSError, ValueError, EOFError) as exc:
            errors.append(exc)
        finally:
            local.close()

    t = threading.Thread(target=outbound, daemon=True)
    t.start()
    inbound()
    t.join(timeout=2)
    if errors:
        raise errors[0]


def serve(args):
    identity, peer = load_identity(args.identity), load_peer(args.peer_key)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(address(args.bind))
    listener.listen(16)
    print(f"PQ {args.mode} listening on {args.bind}", flush=True)

    def handle(sock):
        with sock:
            sock.settimeout(30)
            try:
                if args.mode == "client":
                    with socket.create_connection(address(args.peer), timeout=20) as remote:
                        remote.settimeout(30)
                        stream = handshake_client(remote, identity, peer)
                        remote.settimeout(None)
                        sock.settimeout(None)
                        relay(stream, sock)
                else:
                    stream = handshake_server(sock, identity, peer)
                    with socket.create_connection(address(args.target), timeout=10) as target:
                        sock.settimeout(None)
                        target.settimeout(None)
                        relay(stream, target)
            except Exception as exc:
                print(f"PQ connection rejected/ended: {type(exc).__name__}: {exc}", flush=True)

    while True:
        sock, _ = listener.accept()
        threading.Thread(target=handle, args=(sock,), daemon=True).start()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    gen = sub.add_parser("generate")
    gen.add_argument("--out", type=Path, required=True)
    for mode in ("client", "server"):
        cmd = sub.add_parser(mode)
        cmd.add_argument("--bind", required=True)
        cmd.add_argument("--identity", type=Path, required=True)
        cmd.add_argument("--peer-key", type=Path, required=True)
        cmd.add_argument("--peer" if mode == "client" else "--target", required=True)
    args = parser.parse_args()
    if args.mode == "generate":
        generate(args.out)
    else:
        serve(args)


if __name__ == "__main__":
    main()
