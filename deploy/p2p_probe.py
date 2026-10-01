#!/usr/bin/env python3
"""Bounded loopback service used to prove remote initiation through the PQ mesh."""

import argparse
import hashlib
import json
import os
import socket
import struct
import threading
import time


DOMAIN = b"SYNERGY/P2P-PROBE/V1\0"
MAX_REQUEST = 1024


def address(text: str) -> tuple[str, int]:
    host, port = text.rsplit(":", 1)
    return host, int(port)


def read_exact(sock: socket.socket, size: int) -> bytes:
    result = bytearray()
    while len(result) < size:
        chunk = sock.recv(size - len(result))
        if not chunk:
            raise EOFError("truncated probe")
        result.extend(chunk)
    return bytes(result)


def read_frame(sock: socket.socket) -> bytes:
    size = struct.unpack(">I", read_exact(sock, 4))[0]
    if not 0 < size <= MAX_REQUEST:
        raise ValueError("invalid probe size")
    return read_exact(sock, size)


def send_frame(sock: socket.socket, value: bytes) -> None:
    if not 0 < len(value) <= MAX_REQUEST:
        raise ValueError("invalid probe size")
    sock.sendall(struct.pack(">I", len(value)) + value)


def serve(bind: str, node_id: str, max_active: int) -> None:
    host, port = address(bind)
    if host != "127.0.0.1":
        raise ValueError("probe server must bind to 127.0.0.1")
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((host, port))
    listener.listen(max_active)
    capacity = threading.BoundedSemaphore(max_active)
    print(f"P2P probe {node_id} listening on {bind}", flush=True)

    def handle(sock: socket.socket) -> None:
        try:
            sock.settimeout(10)
            challenge = read_frame(sock)
            response = {
                "node_id": node_id,
                "protocol": "synergy.p2p-probe/v1",
                "challenge_sha256": hashlib.sha256(DOMAIN + challenge).hexdigest(),
                "unix_time": int(time.time()),
            }
            send_frame(sock, json.dumps(response, sort_keys=True).encode("ascii"))
        except Exception as exc:
            print(f"probe rejected: {type(exc).__name__}: {exc}", flush=True)
        finally:
            sock.close()
            capacity.release()

    while True:
        sock, _ = listener.accept()
        if not capacity.acquire(blocking=False):
            sock.close()
            continue
        threading.Thread(target=handle, args=(sock,), daemon=True).start()


def probe(peer: str) -> None:
    challenge = os.urandom(32)
    with socket.create_connection(address(peer), timeout=20) as sock:
        sock.settimeout(20)
        send_frame(sock, challenge)
        response = json.loads(read_frame(sock))
    expected = hashlib.sha256(DOMAIN + challenge).hexdigest()
    if response.get("challenge_sha256") != expected:
        raise ValueError("probe challenge mismatch")
    print(json.dumps(response, sort_keys=True))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    server = sub.add_parser("server")
    server.add_argument("--bind", default="127.0.0.1:7791")
    server.add_argument("--node-id", default="home")
    server.add_argument("--max-active", type=int, default=8)
    client = sub.add_parser("client")
    client.add_argument("--peer", required=True)
    args = parser.parse_args()
    if args.mode == "server":
        serve(args.bind, args.node_id, args.max_active)
    else:
        probe(args.peer)


if __name__ == "__main__":
    main()
