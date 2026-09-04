#!/usr/bin/env python3
"""Trusted Base Mainnet <-> SINERGY L1 message relayer.

Security model:
- watches only configured TrustedRelayerCrossDomainMessenger contracts;
- waits configurable source confirmations;
- derives replay/sourceEventId from source chain id + block hash + tx hash + log index;
- verifies the destination messenger is wired to this relayer account;
- Base -> SINERGY writes are submitted through the SINERGY hybrid-max PQ RPC envelope;
- SINERGY -> Base writes use a dedicated Base relayer ECDSA key;
- processed cursors are persisted in SQLite.

This is V1 trusted-relayer infrastructure. It is not a light-client proof bridge.
"""

from __future__ import annotations

import base64
import json
import os
import sqlite3
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import requests
from eth_account import Account
from pqcrypto.sign import ml_dsa_87

try:
    from pqcrypto.sign import slh_dsa_shake_256s as slh_dsa_256s
except ImportError:
    from pqcrypto.sign import sphincs_shake_256s_simple as slh_dsa_256s

from web3 import Web3
from web3.contract import Contract


BASE_CHAIN_ID = 8453
SINERGY_CHAIN_ID = 8_453_001

MESSENGER_ABI: list[dict[str, Any]] = [
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "internalType": "address", "name": "target", "type": "address"},
            {"indexed": False, "internalType": "address", "name": "sender", "type": "address"},
            {"indexed": False, "internalType": "bytes", "name": "message", "type": "bytes"},
            {"indexed": False, "internalType": "uint256", "name": "messageNonce", "type": "uint256"},
            {"indexed": False, "internalType": "uint32", "name": "minGasLimit", "type": "uint32"},
        ],
        "name": "SentMessage",
        "type": "event",
    },
    {
        "inputs": [
            {"internalType": "uint256", "name": "sourceChainId", "type": "uint256"},
            {"internalType": "uint256", "name": "sourceNonce", "type": "uint256"},
            {"internalType": "address", "name": "sourceSender", "type": "address"},
            {"internalType": "address", "name": "target", "type": "address"},
            {"internalType": "uint32", "name": "minGasLimit", "type": "uint32"},
            {"internalType": "bytes", "name": "message", "type": "bytes"},
            {"internalType": "bytes32", "name": "sourceEventId", "type": "bytes32"},
        ],
        "name": "relayMessage",
        "outputs": [{"internalType": "bytes", "name": "returnData", "type": "bytes"}],
        "stateMutability": "payable",
        "type": "function",
    },
    {
        "inputs": [{"internalType": "bytes32", "name": "", "type": "bytes32"}],
        "name": "successfulMessages",
        "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "trustedRelayer",
        "outputs": [{"internalType": "address", "name": "", "type": "address"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "REMOTE_CHAIN_ID",
        "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function",
    },
]


@dataclass(frozen=True)
class ChainSide:
    name: str
    chain_id: int
    w3: Web3
    messenger: Contract
    confirmations: int


class CursorDB:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        with sqlite3.connect(self.path) as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS cursor (lane TEXT PRIMARY KEY, next_block INTEGER NOT NULL)"
            )
            db.execute(
                "CREATE TABLE IF NOT EXISTS relayed (source_event_id TEXT PRIMARY KEY, lane TEXT NOT NULL, destination_tx TEXT NOT NULL, relayed_at INTEGER NOT NULL)"
            )
            db.commit()

    def get_cursor(self, lane: str, default: int) -> int:
        with sqlite3.connect(self.path) as db:
            row = db.execute("SELECT next_block FROM cursor WHERE lane=?", (lane,)).fetchone()
        return default if row is None else int(row[0])

    def set_cursor(self, lane: str, next_block: int) -> None:
        with sqlite3.connect(self.path) as db:
            db.execute(
                "INSERT INTO cursor(lane,next_block) VALUES(?,?) ON CONFLICT(lane) DO UPDATE SET next_block=excluded.next_block",
                (lane, next_block),
            )
            db.commit()

    def record(self, event_id: str, lane: str, destination_tx: str) -> None:
        with sqlite3.connect(self.path) as db:
            db.execute(
                "INSERT OR IGNORE INTO relayed(source_event_id,lane,destination_tx,relayed_at) VALUES(?,?,?,?)",
                (event_id, lane, destination_tx, int(time.time())),
            )
            db.commit()


def env_required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"missing required environment variable {name}")
    return value


def load_binary(path_env: str) -> bytes:
    path = Path(env_required(path_env)).expanduser()
    data = path.read_bytes()
    if not data:
        raise RuntimeError(f"empty key file from {path_env}")
    return data


def rpc_call(url: str, method: str, params: list[Any]) -> Any:
    response = requests.post(
        url,
        json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
        timeout=30,
    )
    response.raise_for_status()
    payload = response.json()
    if "error" in payload:
        raise RuntimeError(f"{method} failed: {payload['error']}")
    return payload.get("result")


def source_event_id(chain_id: int, log: Any) -> bytes:
    return Web3.solidity_keccak(
        ["uint256", "bytes32", "bytes32", "uint256"],
        [chain_id, bytes(log["blockHash"]), bytes(log["transactionHash"]), int(log["logIndex"])],
    )


def type2_fee_fields(w3: Web3) -> dict[str, int]:
    latest = w3.eth.get_block("latest")
    base_fee = int(latest.get("baseFeePerGas", 0) or 0)
    try:
        priority = int(w3.eth.max_priority_fee)
    except Exception:
        priority = max(int(w3.eth.gas_price) // 10, 1)
    if base_fee == 0:
        return {"gasPrice": int(w3.eth.gas_price)}
    return {
        "maxPriorityFeePerGas": priority,
        "maxFeePerGas": base_fee * 2 + priority,
        "type": 2,
    }


def build_relay_tx(
    destination: ChainSide,
    destination_from: str,
    source: ChainSide,
    log: Any,
    event_id: bytes,
) -> dict[str, Any]:
    args = log["args"]
    fn = destination.messenger.functions.relayMessage(
        source.chain_id,
        int(args["messageNonce"]),
        Web3.to_checksum_address(args["sender"]),
        Web3.to_checksum_address(args["target"]),
        int(args["minGasLimit"]),
        bytes(args["message"]),
        event_id,
    )
    nonce = destination.w3.eth.get_transaction_count(destination_from, "pending")
    estimate = fn.estimate_gas({"from": destination_from})
    tx: dict[str, Any] = fn.build_transaction(
        {
            "from": destination_from,
            "nonce": nonce,
            "chainId": destination.chain_id,
            "gas": max(int(estimate * 125 // 100), estimate + 25_000),
            "value": 0,
            **type2_fee_fields(destination.w3),
        }
    )
    return tx


def send_base_transaction(base: ChainSide, source: ChainSide, log: Any, event_id: bytes) -> str:
    key = env_required("BASE_RELAYER_PRIVATE_KEY")
    account = Account.from_key(key)
    expected = Web3.to_checksum_address(base.messenger.functions.trustedRelayer().call())
    if account.address != expected:
        raise RuntimeError(f"Base relayer account {account.address} != messenger trustedRelayer {expected}")

    tx = build_relay_tx(base, account.address, source, log, event_id)
    signed = Account.sign_transaction(tx, key)
    tx_hash = base.w3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = base.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=180)
    if int(receipt.status) != 1:
        raise RuntimeError(f"Base relay reverted: {tx_hash.hex()}")
    return tx_hash.hex()


def send_sinergy_pq_transaction(
    sinergy: ChainSide,
    source: ChainSide,
    log: Any,
    event_id: bytes,
    sinergy_rpc_url: str,
    ml_public: bytes,
    ml_secret: bytes,
    slh_public: bytes,
    slh_secret: bytes,
) -> str:
    ecdsa_key = env_required("SINERGY_RELAYER_ECDSA_PRIVATE_KEY")
    account = Account.from_key(ecdsa_key)
    expected = Web3.to_checksum_address(sinergy.messenger.functions.trustedRelayer().call())
    if account.address != expected:
        raise RuntimeError(
            f"SINERGY backend relayer account {account.address} != messenger trustedRelayer {expected}"
        )

    tx = build_relay_tx(sinergy, account.address, source, log, event_id)
    signed = Account.sign_transaction(tx, ecdsa_key)
    raw_hex = "0x" + signed.raw_transaction.hex()

    ml_public_b64 = base64.b64encode(ml_public).decode()
    next_nonce_payload = rpc_call(sinergy_rpc_url, "synergy_getPqNonce", [ml_public_b64])
    pq_nonce = int(next_nonce_payload["next_nonce"])
    expires_at = int(time.time()) + 120

    preimage_payload = rpc_call(
        sinergy_rpc_url,
        "synergy_buildPqPreimage",
        [
            {
                "raw_tx": raw_hex,
                "ml_dsa_87_public_key": ml_public_b64,
                "nonce": pq_nonce,
                "expires_at": expires_at,
                "policy": "hybrid_max",
            }
        ],
    )
    preimage = base64.b64decode(preimage_payload["preimage_base64"], validate=True)
    ml_signature = ml_dsa_87.sign(ml_secret, preimage)
    slh_signature = slh_dsa_256s.sign(slh_secret, preimage)

    result = rpc_call(
        sinergy_rpc_url,
        "synergy_sendPqRawTransaction",
        [
            {
                "raw_tx": raw_hex,
                "policy": "hybrid_max",
                "nonce": pq_nonce,
                "expires_at": expires_at,
                "ml_dsa_87_public_key": ml_public_b64,
                "ml_dsa_87_signature": base64.b64encode(ml_signature).decode(),
                "slh_dsa_shake_256s_public_key": base64.b64encode(slh_public).decode(),
                "slh_dsa_shake_256s_signature": base64.b64encode(slh_signature).decode(),
            }
        ],
    )
    tx_hash = str(result["tx_hash"])
    receipt = sinergy.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
    if int(receipt.status) != 1:
        raise RuntimeError(f"SINERGY relay reverted: {tx_hash}")
    return tx_hash


def verify_side(side: ChainSide, expected_remote: int) -> None:
    actual_chain = int(side.w3.eth.chain_id)
    if actual_chain != side.chain_id:
        raise RuntimeError(f"{side.name} RPC chain id {actual_chain} != {side.chain_id}")
    remote = int(side.messenger.functions.REMOTE_CHAIN_ID().call())
    if remote != expected_remote:
        raise RuntimeError(f"{side.name} messenger remote chain {remote} != {expected_remote}")


def relay_lane(
    source: ChainSide,
    destination: ChainSide,
    db: CursorDB,
    start_block_default: int,
    send_fn: Any,
) -> int:
    lane = f"{source.chain_id}->{destination.chain_id}"
    head = int(source.w3.eth.block_number)
    confirmed = head - source.confirmations
    if confirmed < 0:
        return 0

    cursor = db.get_cursor(lane, start_block_default)
    if cursor > confirmed:
        return 0

    batch_end = min(cursor + 499, confirmed)
    logs = source.messenger.events.SentMessage().get_logs(from_block=cursor, to_block=batch_end)
    relayed = 0

    for log in sorted(logs, key=lambda x: (int(x["blockNumber"]), int(x["logIndex"]))):
        event_id = source_event_id(source.chain_id, log)
        event_hex = Web3.to_hex(event_id)
        if bool(destination.messenger.functions.successfulMessages(event_id).call()):
            db.record(event_hex, lane, "already-successful-on-destination")
            continue
        tx_hash = send_fn(source, destination, log, event_id)
        db.record(event_hex, lane, tx_hash)
        relayed += 1
        print(f"relayed {lane} event={event_hex} tx={tx_hash}", flush=True)

    db.set_cursor(lane, batch_end + 1)
    return relayed


def main() -> None:
    base_rpc = env_required("BASE_RPC_URL")
    sinergy_rpc = os.environ.get("SINERGY_RPC_URL", "http://127.0.0.1:9545")
    base_messenger_address = Web3.to_checksum_address(env_required("BASE_SINERGY_MESSENGER"))
    sinergy_messenger_address = Web3.to_checksum_address(env_required("SINERGY_BASE_MESSENGER"))

    base_w3 = Web3(Web3.HTTPProvider(base_rpc, request_kwargs={"timeout": 30}))
    sinergy_w3 = Web3(Web3.HTTPProvider(sinergy_rpc, request_kwargs={"timeout": 30}))

    base = ChainSide(
        "base",
        BASE_CHAIN_ID,
        base_w3,
        base_w3.eth.contract(address=base_messenger_address, abi=MESSENGER_ABI),
        int(os.environ.get("BASE_CONFIRMATIONS", "20")),
    )
    sinergy = ChainSide(
        "sinergy",
        SINERGY_CHAIN_ID,
        sinergy_w3,
        sinergy_w3.eth.contract(address=sinergy_messenger_address, abi=MESSENGER_ABI),
        int(os.environ.get("SINERGY_CONFIRMATIONS", "2")),
    )

    verify_side(base, SINERGY_CHAIN_ID)
    verify_side(sinergy, BASE_CHAIN_ID)

    ml_public = load_binary("SINERGY_RELAYER_ML_DSA_87_PUBLIC_KEY_FILE")
    ml_secret = load_binary("SINERGY_RELAYER_ML_DSA_87_SECRET_KEY_FILE")
    slh_public = load_binary("SINERGY_RELAYER_SLH_DSA_PUBLIC_KEY_FILE")
    slh_secret = load_binary("SINERGY_RELAYER_SLH_DSA_SECRET_KEY_FILE")

    state_path = Path(
        os.environ.get("RELAYER_DB", str(Path.home() / ".synergy-l1" / "base_sinergy_relayer.sqlite3"))
    ).expanduser()
    db = CursorDB(state_path)

    base_start = int(os.environ.get("BASE_START_BLOCK", str(base_w3.eth.block_number)))
    sinergy_start = int(os.environ.get("SINERGY_START_BLOCK", "0"))
    poll_seconds = float(os.environ.get("RELAYER_POLL_SECONDS", "2.0"))

    def base_to_sinergy(source: ChainSide, destination: ChainSide, log: Any, event_id: bytes) -> str:
        return send_sinergy_pq_transaction(
            destination,
            source,
            log,
            event_id,
            sinergy_rpc,
            ml_public,
            ml_secret,
            slh_public,
            slh_secret,
        )

    def sinergy_to_base(source: ChainSide, destination: ChainSide, log: Any, event_id: bytes) -> str:
        return send_base_transaction(destination, source, log, event_id)

    print(
        f"relayer ready base={base_messenger_address} sinergy={sinergy_messenger_address} "
        f"base_confirmations={base.confirmations} sinergy_confirmations={sinergy.confirmations}",
        flush=True,
    )

    while True:
        try:
            n1 = relay_lane(base, sinergy, db, base_start, base_to_sinergy)
            n2 = relay_lane(sinergy, base, db, sinergy_start, sinergy_to_base)
            if n1 == 0 and n2 == 0:
                time.sleep(poll_seconds)
        except KeyboardInterrupt:
            return
        except Exception as exc:
            print(f"relayer error: {exc}", file=sys.stderr, flush=True)
            time.sleep(max(poll_seconds, 3.0))


if __name__ == "__main__":
    main()
