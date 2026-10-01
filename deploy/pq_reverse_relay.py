#!/usr/bin/env python3
"""End-to-end post-quantum reverse TCP relay for a node behind NAT.

The home agent maintains a pool of outbound, mutually authenticated PQ
channels to a public relay. A requester connects to the relay ingress and
performs a second, end-to-end PQ handshake directly with the home identity.
The relay only handles ciphertext from that inner session.

Run one route per pinned requester identity. Targets are deliberately limited
to IPv4 loopback to prevent this process from becoming an open proxy.
"""

import argparse
import ipaddress
import queue
import random
import socket
import threading
import time
from pathlib import Path

from pq_stage_tunnel import (
    MAX_RECORD,
    SecureStream,
    address,
    handshake_client,
    handshake_server,
    load_identity,
    load_peer,
    relay,
)


START = b"SYNERGY/PQ-REVERSE/START/V1"
DEFAULT_HANDSHAKE_TIMEOUT = 20
MAX_POOL = 32


def configure_socket(sock: socket.socket) -> None:
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    for name, value in (("TCP_KEEPIDLE", 30), ("TCP_KEEPINTVL", 10), ("TCP_KEEPCNT", 3)):
        option = getattr(socket, name, None)
        if option is not None:
            try:
                sock.setsockopt(socket.IPPROTO_TCP, option, value)
            except OSError:
                pass


class SecureStreamSocket:
    """Expose an encrypted record stream as the socket API used by a nested handshake."""

    def __init__(self, stream: SecureStream):
        self.stream = stream
        self.buffer = bytearray()
        self.closed = False

    def sendall(self, data: bytes) -> None:
        if self.closed:
            raise OSError("secure stream socket is closed")
        view = memoryview(data)
        while view:
            chunk = bytes(view[:16384])
            self.stream.send(chunk)
            view = view[len(chunk):]

    def recv(self, size: int) -> bytes:
        if size <= 0:
            return b""
        while not self.buffer and not self.closed:
            data = self.stream.receive()
            if data is None:
                self.closed = True
                return b""
            self.buffer.extend(data)
        result = bytes(self.buffer[:size])
        del self.buffer[:size]
        return result

    def settimeout(self, timeout: float | None) -> None:
        self.stream.sock.settimeout(timeout)

    def shutdown(self, how: int) -> None:
        if how in (socket.SHUT_WR, socket.SHUT_RDWR) and not self.closed:
            self.stream.finish()

    def close(self) -> None:
        if not self.closed:
            self.closed = True
            try:
                self.stream.sock.close()
            except OSError:
                pass


def loopback_target(text: str) -> tuple[str, int]:
    host, port = address(text)
    if not ipaddress.ip_address(host).is_loopback:
        raise ValueError("agent target must be an IP loopback address")
    return host, port


def allowed_source(source: str, networks: tuple[ipaddress._BaseNetwork, ...]) -> bool:
    try:
        value = ipaddress.ip_address(source)
    except ValueError:
        return False
    return any(value in network for network in networks)


def parse_networks(values: list[str]) -> tuple[ipaddress._BaseNetwork, ...]:
    return tuple(ipaddress.ip_network(value, strict=False) for value in values)


def create_listener(bind: str, backlog: int) -> socket.socket:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(address(bind))
    listener.listen(backlog)
    return listener


def run_relay(args) -> None:
    if not 1 <= args.pool <= MAX_POOL:
        raise ValueError(f"pool must be between 1 and {MAX_POOL}")
    identity = load_identity(args.identity)
    home_key = load_peer(args.home_key)
    ingress_networks = parse_networks(args.ingress_allow)
    agent_networks = parse_networks(args.agent_allow)
    available: queue.Queue[tuple[SecureStream, socket.socket]] = queue.Queue(args.pool)
    active = threading.BoundedSemaphore(args.max_active)
    agent_listener = create_listener(args.agent_bind, args.pool * 2)
    ingress_listener = create_listener(args.ingress_bind, args.max_active)
    print(
        f"PQ reverse relay agent={args.agent_bind} ingress={args.ingress_bind} "
        f"pool={args.pool} max_active={args.max_active}",
        flush=True,
    )

    def accept_agent(sock: socket.socket, source: str) -> None:
        keep = False
        try:
            if not allowed_source(source, agent_networks):
                raise PermissionError("agent source is not allowed")
            configure_socket(sock)
            sock.settimeout(args.handshake_timeout)
            stream = handshake_server(sock, identity, home_key)
            sock.settimeout(None)
            available.put((stream, sock), timeout=2)
            keep = True
            print(f"authenticated home channel queued from {source}", flush=True)
        except Exception as exc:
            print(f"agent rejected: {type(exc).__name__}: {exc}", flush=True)
        finally:
            if not keep:
                sock.close()

    def accept_ingress(sock: socket.socket, source: str) -> None:
        channel_sock = None
        acquired = False
        try:
            if not allowed_source(source, ingress_networks):
                raise PermissionError("ingress source is not allowed")
            if not active.acquire(blocking=False):
                raise ConnectionError("route capacity reached")
            acquired = True
            sock.settimeout(args.handshake_timeout)
            while True:
                try:
                    stream, channel_sock = available.get(timeout=args.queue_timeout)
                except queue.Empty as exc:
                    raise ConnectionError("no authenticated home channel available") from exc
                try:
                    stream.send(START)
                    break
                except Exception:
                    channel_sock.close()
                    channel_sock = None
            sock.settimeout(None)
            relay(stream, sock)
        except Exception as exc:
            print(f"ingress ended: {type(exc).__name__}: {exc}", flush=True)
        finally:
            sock.close()
            if channel_sock is not None:
                channel_sock.close()
            if acquired:
                active.release()

    def agent_loop() -> None:
        while True:
            sock, peer = agent_listener.accept()
            threading.Thread(target=accept_agent, args=(sock, peer[0]), daemon=True).start()

    threading.Thread(target=agent_loop, daemon=True).start()
    while True:
        sock, peer = ingress_listener.accept()
        threading.Thread(target=accept_ingress, args=(sock, peer[0]), daemon=True).start()


def run_agent(args) -> None:
    if not 1 <= args.pool <= MAX_POOL:
        raise ValueError(f"pool must be between 1 and {MAX_POOL}")
    target = loopback_target(args.target)
    outer_identity = load_identity(args.identity)
    relay_key = load_peer(args.relay_key)
    inner_identity = load_identity(args.inner_identity)
    requester_key = load_peer(args.requester_key)
    print(
        f"PQ reverse agent relay={args.relay} target={args.target} pool={args.pool}",
        flush=True,
    )

    def worker(slot: int) -> None:
        failures = 0
        while True:
            outer_sock = None
            adapter = None
            try:
                outer_sock = socket.create_connection(address(args.relay), timeout=20)
                configure_socket(outer_sock)
                outer_sock.settimeout(args.handshake_timeout)
                outer = handshake_client(outer_sock, outer_identity, relay_key)
                outer_sock.settimeout(None)
                failures = 0
                command = outer.receive()
                if command != START:
                    raise ValueError("invalid relay command")
                adapter = SecureStreamSocket(outer)
                adapter.settimeout(args.handshake_timeout)
                inner = handshake_server(adapter, inner_identity, requester_key)
                adapter.settimeout(None)
                with socket.create_connection(target, timeout=10) as local:
                    local.settimeout(None)
                    relay(inner, local)
            except Exception as exc:
                failures += 1
                if failures == 1 or failures % 10 == 0:
                    print(f"agent slot {slot} reconnecting: {type(exc).__name__}: {exc}", flush=True)
            finally:
                if adapter is not None:
                    adapter.close()
                elif outer_sock is not None:
                    outer_sock.close()
            delay = min(args.max_backoff, args.min_backoff * (2 ** min(failures - 1, 6)))
            time.sleep(delay + random.uniform(0, min(1.0, delay / 4)))

    workers = []
    for slot in range(args.pool):
        thread = threading.Thread(target=worker, args=(slot,), daemon=False)
        thread.start()
        workers.append(thread)
        time.sleep(0.1)
    for thread in workers:
        thread.join()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    relay_parser = sub.add_parser("relay")
    relay_parser.add_argument("--agent-bind", required=True)
    relay_parser.add_argument("--ingress-bind", required=True)
    relay_parser.add_argument("--identity", type=Path, required=True)
    relay_parser.add_argument("--home-key", type=Path, required=True)
    relay_parser.add_argument("--agent-allow", action="append", required=True)
    relay_parser.add_argument("--ingress-allow", action="append", required=True)
    relay_parser.add_argument("--pool", type=int, default=4)
    relay_parser.add_argument("--max-active", type=int, default=4)
    relay_parser.add_argument("--queue-timeout", type=float, default=5)
    relay_parser.add_argument("--handshake-timeout", type=float, default=DEFAULT_HANDSHAKE_TIMEOUT)
    agent_parser = sub.add_parser("agent")
    agent_parser.add_argument("--relay", required=True)
    agent_parser.add_argument("--target", required=True)
    agent_parser.add_argument("--identity", type=Path, required=True)
    agent_parser.add_argument("--relay-key", type=Path, required=True)
    agent_parser.add_argument("--inner-identity", type=Path, required=True)
    agent_parser.add_argument("--requester-key", type=Path, required=True)
    agent_parser.add_argument("--pool", type=int, default=4)
    agent_parser.add_argument("--handshake-timeout", type=float, default=DEFAULT_HANDSHAKE_TIMEOUT)
    agent_parser.add_argument("--min-backoff", type=float, default=1)
    agent_parser.add_argument("--max-backoff", type=float, default=30)
    args = parser.parse_args()
    if args.mode == "relay":
        run_relay(args)
    else:
        run_agent(args)


if __name__ == "__main__":
    main()
