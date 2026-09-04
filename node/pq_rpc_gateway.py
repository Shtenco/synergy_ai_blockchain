#!/usr/bin/env python3
"""SINERGY L1 G0 post-quantum JSON-RPC admission gateway.

Public RPC forwards reads to a private EVM backend but rejects ordinary write
submission. Writes enter through `synergy_sendPqRawTransaction` and require an
ML-DSA-87 envelope; `hybrid_max`/`pq_only` additionally require
SLH-DSA-SHAKE-256s. G0 is an integration node, not native PQ consensus.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sqlite3
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from pqcrypto.sign import ml_dsa_87, slh_dsa_shake_256s

DOMAIN = b"SYNERGY-PQ-RPC/1"
CHAIN_ID = int(os.environ.get("SYNERGY_CHAIN_ID", "8453001"))
LISTEN_HOST = os.environ.get("SYNERGY_RPC_HOST", "127.0.0.1")
LISTEN_PORT = int(os.environ.get("SYNERGY_RPC_PORT", "9545"))
BACKEND_RPC = os.environ.get("SYNERGY_BACKEND_RPC", "http://127.0.0.1:9546")
MAX_ENVELOPE_TTL = int(os.environ.get("SYNERGY_MAX_ENVELOPE_TTL", "600"))
MAX_RAW_TX_BYTES = int(os.environ.get("SYNERGY_MAX_RAW_TX_BYTES", str(1024 * 1024)))
STATE_DIR = Path(os.environ.get("SYNERGY_STATE_DIR", str(Path.home() / ".synergy-l1")))
DB_PATH = STATE_DIR / "pq_gateway.sqlite3"

BLOCKED_METHODS = {
    "eth_sendRawTransaction",
    "eth_sendTransaction",
    "eth_sign",
    "eth_signTransaction",
    "eth_signTypedData",
    "eth_signTypedData_v4",
}
BLOCKED_PREFIXES = ("personal_", "engine_", "admin_", "miner_", "anvil_", "hardhat_", "evm_")
POLICY_TAGS = {"hybrid_online": 1, "hybrid_max": 2, "pq_only": 3}
_submission_lock = threading.Lock()


def rpc_error(req_id: Any, code: int, message: str, data: Any = None) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": req_id, "error": error}


def rpc_result(req_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def backend_call(method: str, params: Any = None, req_id: Any = 1) -> dict[str, Any]:
    payload = json.dumps(
        {"jsonrpc": "2.0", "id": req_id, "method": method, "params": [] if params is None else params},
        separators=(",", ":"),
    ).encode()
    request = urllib.request.Request(
        BACKEND_RPC,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")
        raise RuntimeError(f"backend HTTP {exc.code}: {body[:500]}") from exc
    except Exception as exc:
        raise RuntimeError(f"backend RPC unavailable: {exc}") from exc


def decode_b64(value: Any, field: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be non-empty base64")
    try:
        return base64.b64decode(value, validate=True)
    except Exception as exc:
        raise ValueError(f"{field} is not valid base64") from exc


def raw_tx_bytes(raw_tx: Any) -> bytes:
    if not isinstance(raw_tx, str) or not raw_tx.startswith("0x"):
        raise ValueError("raw_tx must be a 0x-prefixed EVM raw transaction")
    h = raw_tx[2:]
    if len(h) % 2:
        raise ValueError("raw_tx hex has odd length")
    try:
        raw = bytes.fromhex(h)
    except ValueError as exc:
        raise ValueError("raw_tx is not valid hex") from exc
    if not raw or len(raw) > MAX_RAW_TX_BYTES:
        raise ValueError("raw_tx size is outside configured bounds")
    return raw


def account_id(ml_public_key: bytes) -> bytes:
    return hashlib.sha256(b"SYNERGY-PQ-ACCOUNT/1" + ml_public_key).digest()


def signing_preimage(raw_tx: bytes, ml_public_key: bytes, nonce: int, expires_at: int, policy: str) -> bytes:
    if policy not in POLICY_TAGS:
        raise ValueError("unknown PQ policy")
    if nonce < 0 or nonce > (1 << 63) - 1:
        raise ValueError("nonce out of range")
    if expires_at < 0 or expires_at > (1 << 63) - 1:
        raise ValueError("expires_at out of range")
    return b"".join(
        (
            DOMAIN,
            CHAIN_ID.to_bytes(8, "big"),
            account_id(ml_public_key),
            nonce.to_bytes(8, "big"),
            expires_at.to_bytes(8, "big"),
            bytes((POLICY_TAGS[policy],)),
            hashlib.sha256(raw_tx).digest(),
        )
    )


def verify_signature(module: Any, public_key: bytes, message: bytes, signature: bytes) -> bool:
    """pqcrypto 1.0 verify() returns None on success and raises on failure."""
    try:
        module.verify(public_key, message, signature)
        return True
    except Exception:
        return False


def db_init() -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH) as db:
        db.execute(
            "CREATE TABLE IF NOT EXISTS account_nonce (account_id TEXT PRIMARY KEY,last_nonce INTEGER NOT NULL)"
        )
        db.execute(
            "CREATE TABLE IF NOT EXISTS accepted_tx (tx_hash TEXT PRIMARY KEY,account_id TEXT NOT NULL,pq_nonce INTEGER NOT NULL,accepted_at INTEGER NOT NULL)"
        )
        db.commit()


def last_nonce(account_hex: str) -> int:
    with sqlite3.connect(DB_PATH) as db:
        row = db.execute("SELECT last_nonce FROM account_nonce WHERE account_id=?", (account_hex,)).fetchone()
    return -1 if row is None else int(row[0])


def commit_nonce(account_hex: str, nonce: int, tx_hash: str) -> None:
    with sqlite3.connect(DB_PATH) as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("SELECT last_nonce FROM account_nonce WHERE account_id=?", (account_hex,)).fetchone()
        current = -1 if row is None else int(row[0])
        if nonce != current + 1:
            raise RuntimeError("PQ nonce changed concurrently")
        db.execute(
            "INSERT INTO account_nonce(account_id,last_nonce) VALUES(?,?) ON CONFLICT(account_id) DO UPDATE SET last_nonce=excluded.last_nonce",
            (account_hex, nonce),
        )
        db.execute(
            "INSERT INTO accepted_tx(tx_hash,account_id,pq_nonce,accepted_at) VALUES(?,?,?,?)",
            (tx_hash, account_hex, nonce, int(time.time())),
        )
        db.commit()


def validate_backend_chain() -> None:
    response = backend_call("eth_chainId")
    if "error" in response:
        raise RuntimeError(f"backend eth_chainId failed: {response['error']}")
    backend_chain = int(response["result"], 16)
    if backend_chain != CHAIN_ID:
        raise RuntimeError(f"backend chain id {backend_chain} != configured SINERGY chain id {CHAIN_ID}")


def build_preimage_rpc(req_id: Any, params: Any) -> dict[str, Any]:
    if not isinstance(params, list) or len(params) != 1 or not isinstance(params[0], dict):
        return rpc_error(req_id, -32602, "expected one envelope object")
    p = params[0]
    try:
        raw = raw_tx_bytes(p.get("raw_tx"))
        ml_pk = decode_b64(p.get("ml_dsa_87_public_key"), "ml_dsa_87_public_key")
        nonce = int(p.get("nonce"))
        expires_at = int(p.get("expires_at"))
        policy = str(p.get("policy"))
        preimage = signing_preimage(raw, ml_pk, nonce, expires_at, policy)
    except Exception as exc:
        return rpc_error(req_id, -32602, str(exc))
    return rpc_result(
        req_id,
        {
            "chain_id": CHAIN_ID,
            "account_id": "0x" + account_id(ml_pk).hex(),
            "preimage_base64": base64.b64encode(preimage).decode(),
            "preimage_sha256": "0x" + hashlib.sha256(preimage).hexdigest(),
        },
    )


def send_pq_raw_transaction(req_id: Any, params: Any) -> dict[str, Any]:
    if not isinstance(params, list) or len(params) != 1 or not isinstance(params[0], dict):
        return rpc_error(req_id, -32602, "expected one PQ envelope object")
    p = params[0]
    now = int(time.time())
    try:
        raw_tx_hex = p.get("raw_tx")
        raw = raw_tx_bytes(raw_tx_hex)
        policy = str(p.get("policy"))
        if policy not in POLICY_TAGS:
            raise ValueError("policy must be hybrid_online, hybrid_max, or pq_only")
        nonce = int(p.get("nonce"))
        expires_at = int(p.get("expires_at"))
        if expires_at < now:
            raise ValueError("PQ envelope expired")
        if expires_at > now + MAX_ENVELOPE_TTL:
            raise ValueError("PQ envelope expiry exceeds configured TTL")

        ml_pk = decode_b64(p.get("ml_dsa_87_public_key"), "ml_dsa_87_public_key")
        ml_sig = decode_b64(p.get("ml_dsa_87_signature"), "ml_dsa_87_signature")
        preimage = signing_preimage(raw, ml_pk, nonce, expires_at, policy)
        if not verify_signature(ml_dsa_87, ml_pk, preimage, ml_sig):
            raise ValueError("ML-DSA-87 verification failed")

        if policy in ("hybrid_max", "pq_only"):
            slh_pk = decode_b64(
                p.get("slh_dsa_shake_256s_public_key"), "slh_dsa_shake_256s_public_key"
            )
            slh_sig = decode_b64(
                p.get("slh_dsa_shake_256s_signature"), "slh_dsa_shake_256s_signature"
            )
            if not verify_signature(slh_dsa_shake_256s, slh_pk, preimage, slh_sig):
                raise ValueError("SLH-DSA-SHAKE-256s verification failed")
    except Exception as exc:
        return rpc_error(req_id, -32040, str(exc))

    account_hex = "0x" + account_id(ml_pk).hex()
    with _submission_lock:
        expected_nonce = last_nonce(account_hex) + 1
        if nonce != expected_nonce:
            return rpc_error(
                req_id,
                -32041,
                "invalid PQ replay nonce",
                {"expected": expected_nonce, "received": nonce, "account_id": account_hex},
            )
        try:
            backend = backend_call("eth_sendRawTransaction", [raw_tx_hex], req_id=req_id)
        except Exception as exc:
            return rpc_error(req_id, -32042, str(exc))
        if "error" in backend:
            return backend
        tx_hash = backend.get("result")
        if not isinstance(tx_hash, str) or not tx_hash.startswith("0x"):
            return rpc_error(req_id, -32043, "backend returned invalid transaction hash")
        try:
            commit_nonce(account_hex, nonce, tx_hash)
        except Exception as exc:
            return rpc_error(req_id, -32044, str(exc))

    return rpc_result(req_id, {"tx_hash": tx_hash, "account_id": account_hex, "pq_nonce": nonce, "policy": policy})


def handle_one(request: Any) -> dict[str, Any]:
    if not isinstance(request, dict):
        return rpc_error(None, -32600, "invalid request")
    req_id = request.get("id")
    if request.get("jsonrpc") != "2.0" or not isinstance(request.get("method"), str):
        return rpc_error(req_id, -32600, "invalid JSON-RPC 2.0 request")
    method = request["method"]
    params = request.get("params", [])

    if method == "synergy_health":
        try:
            chain = backend_call("eth_chainId").get("result")
            block = backend_call("eth_blockNumber").get("result")
            return rpc_result(
                req_id,
                {"ok": True, "profile": "SYNERGY-PQ-EVM-G0/1", "chain_id": CHAIN_ID, "backend_chain_id": chain, "block_number": block},
            )
        except Exception as exc:
            return rpc_error(req_id, -32001, str(exc))

    if method == "synergy_chainProfile":
        return rpc_result(
            req_id,
            {
                "profile": "SYNERGY-PQ-EVM-G0/1",
                "chain_id": CHAIN_ID,
                "public_rpc": f"http://{LISTEN_HOST}:{LISTEN_PORT}",
                "pq_policies": list(POLICY_TAGS),
                "ml_dsa": "ML-DSA-87 / FIPS 204",
                "slh_dsa": "SLH-DSA-SHAKE-256s / FIPS 205",
                "native_pq_precompiles": False,
                "warning": "G0 admission gateway; native revm/reth PQ precompiles are the G4 target",
            },
        )

    if method == "synergy_buildPqPreimage":
        return build_preimage_rpc(req_id, params)

    if method == "synergy_getPqNonce":
        if not isinstance(params, list) or len(params) != 1:
            return rpc_error(req_id, -32602, "expected ML-DSA-87 public key base64")
        try:
            ml_pk = decode_b64(params[0], "ml_dsa_87_public_key")
        except Exception as exc:
            return rpc_error(req_id, -32602, str(exc))
        account_hex = "0x" + account_id(ml_pk).hex()
        return rpc_result(req_id, {"account_id": account_hex, "next_nonce": last_nonce(account_hex) + 1})

    if method == "synergy_sendPqRawTransaction":
        return send_pq_raw_transaction(req_id, params)

    if method in BLOCKED_METHODS or method.startswith(BLOCKED_PREFIXES):
        return rpc_error(req_id, -32050, "state-changing/admin method blocked by SINERGY PQ admission gateway")

    try:
        return backend_call(method, params, req_id=req_id)
    except Exception as exc:
        return rpc_error(req_id, -32000, str(exc))


class RpcHandler(BaseHTTPRequestHandler):
    server_version = "SinergyPqRpc/0.2"

    def do_POST(self) -> None:  # noqa: N802
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 4 * 1024 * 1024:
                raise ValueError("invalid request size")
            request = json.loads(self.rfile.read(length).decode())
            if isinstance(request, list):
                response: Any = rpc_error(None, -32600, "empty batch") if not request else [handle_one(x) for x in request]
            else:
                response = handle_one(request)
            encoded = json.dumps(response, separators=(",", ":")).encode()
            self.send_response(200)
        except Exception as exc:
            encoded = json.dumps(rpc_error(None, -32700, str(exc))).encode()
            self.send_response(400)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, fmt: str, *args: Any) -> None:
        if os.environ.get("SYNERGY_RPC_QUIET", "0") != "1":
            super().log_message(fmt, *args)


def main() -> None:
    db_init()
    validate_backend_chain()
    server = ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), RpcHandler)
    print(
        f"SINERGY PQ RPC listening on http://{LISTEN_HOST}:{LISTEN_PORT}; backend={BACKEND_RPC}; chain_id={CHAIN_ID}",
        flush=True,
    )
    server.serve_forever()


if __name__ == "__main__":
    main()
