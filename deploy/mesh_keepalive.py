#!/usr/bin/env python3
"""Тестовый UDP keepalive/проверка достижимости узлов. НЕ PQ-транспорт.

Каждый узел слушает UDP и ДИАЛИТ пиров; NAT-маппинг держится keepalive
каждые ~20с с джиттером — обратные пакеты идут по открытому маппингу,
получается логический full mesh (каждая пара имеет живой двунаправленный
flow), хотя ни один домашний узел не имеет входящего порта.

Кадр SYD1 (спека src/datagram.rs): контрольная сумма SHA256 без ключа.
Нет ML-KEM handshake, аутентификации пиров или шифрования.
Никогда не передавайте через этот демон данные модели, RPC или секреты.
Наличие GOT/ACK подтверждает только UDP-достижимость, не PQ-защиту.

Использование:
  python3 mesh_keepalive.py <listen_port> <session_hex> <peer_ip:port> [...]
Лог: строки GOT (принят валидный кадр) и ACK (отвечен).
"""
import hashlib
import os
import random
import socket
import struct
import sys
import threading
import time

DOMAIN = b"SYNERGY/PQ-DATAGRAM/V1\0"
MAGIC = b"SYD1"
VERSION = 1
FRAME_BYTES = 1200  # фиксированный размер полезной нагрузки


def commitment(session, seq, ack_seq, ack_bits, payload):
    h = hashlib.sha256()
    h.update(DOMAIN)
    h.update(struct.pack(">H", VERSION))
    h.update(session)
    h.update(struct.pack(">Q", seq))
    h.update(struct.pack(">Q", ack_seq))
    h.update(struct.pack(">I", ack_bits))
    h.update(struct.pack(">Q", len(payload)))
    h.update(payload)
    return h.digest()


def encode(session, seq, ack_seq, ack_bits):
    payload = os.urandom(FRAME_BYTES)
    head = MAGIC + struct.pack(">HH", VERSION, 0) + session
    head += struct.pack(">QQI", seq, ack_seq, ack_bits)
    head += struct.pack(">I", len(payload)) + payload
    return head + commitment(session, seq, ack_seq, ack_bits, payload)


def decode(buf):
    if len(buf) < 64 + 32 or buf[:4] != MAGIC:
        return None
    ver, _ = struct.unpack(">HH", buf[4:8])
    if ver != VERSION:
        return None
    session, seq, ack_seq, ack_bits = buf[8:40], *struct.unpack(">QQI", buf[40:60])
    (plen,) = struct.unpack(">I", buf[60:64])
    if plen != FRAME_BYTES or len(buf) != 64 + plen + 32:
        return None
    payload = buf[64:64 + plen]
    if buf[64 + plen:] != commitment(bytes(session), seq, ack_seq, ack_bits, payload):
        return None
    return bytes(session), seq, ack_seq, ack_bits


def parse_peer(s):
    host, port = s.rsplit(":", 1)
    return host, int(port)


def main():
    port, session = int(sys.argv[1]), bytes.fromhex(sys.argv[2])
    peers = [parse_peer(p) for p in sys.argv[3:]]
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", port))
    sock.settimeout(1.0)
    seq = random.randrange(1, 1 << 31)
    lock = threading.Lock()

    def send(to, ack_seq=0, ack_bits=0):
        nonlocal seq
        with lock:
            seq += 1
            my = seq
        sock.sendto(encode(session, my, ack_seq, ack_bits), to)

    def keepalives():
        while True:
            time.sleep(20 + random.uniform(-2, 5))
            for peer in peers:
                try:
                    send(peer)
                except OSError:
                    pass

    threading.Thread(target=keepalives, daemon=True).start()
    for peer in peers:  # стартовый HELLO сразу, без ожидания keepalive
        try:
            send(peer)
        except OSError:
            pass
    print(f"MESH FLOW UP port={port} peers={len(peers)}", flush=True)
    while True:
        try:
            buf, addr = sock.recvfrom(2048)
        except socket.timeout:
            continue
        except ConnectionResetError:
            # Windows reports ICMP port-unreachable when a peer has not yet
            # started; keep the listener alive and retry on the next pulse.
            continue
        f = decode(buf)
        if not f or f[0] != session:
            continue
        _, rseq, ack_seq, _ = f
        if ack_seq:
            # ACK frames are terminal. ACKing an ACK creates an unbounded
            # amplification loop between peers (observed in deployed logs).
            continue
        print(f"GOT seq={rseq} from={addr[0]}:{addr[1]}", flush=True)
        try:
            send(addr, rseq)
            print(f"ACK seq={rseq} to={addr[0]}:{addr[1]}", flush=True)
        except OSError:
            pass


main()
