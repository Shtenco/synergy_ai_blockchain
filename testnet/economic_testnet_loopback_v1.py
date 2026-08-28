from __future__ import annotations

import importlib.util
import json
import multiprocessing as mp
import socket
import sys
from pathlib import Path
from queue import Empty
from typing import Any

NODE_COUNT = 3
CHECKPOINT_COUNT = 2


class EconomicTestnetLoopbackV1Error(RuntimeError):
    pass


def _load_protocol():
    path = Path(__file__).resolve().with_name("economic_testnet_v1.py")
    name = "economic_testnet_v1_loopback_runtime"
    existing = sys.modules.get(name)
    if existing is not None:
        return existing
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise EconomicTestnetLoopbackV1Error("cannot load economic_testnet_v1 protocol")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def canonical_roots(mod) -> list[dict[str, str]]:
    roots = [
        {
            "root_type": "ECONOMIC_CYCLE",
            "digest": mod.PINNED_ECONOMIC_CYCLE,
            "source_repository": "Shtenco/synergy_system",
            "schema_id": "synergy.economic-cycle/v1",
        },
        {
            "root_type": "ECONOMIC_BLOCKCHAIN_COMMITMENT",
            "digest": mod.PINNED_ECONOMIC_COMMITMENT,
            "source_repository": "Shtenco/synergy_ai_blockchain",
            "schema_id": "synergy.ai-blockchain-economic-evidence-commitment/v1",
        },
        {
            "root_type": "COMPUTE_TRUST_CONTEXT",
            "digest": mod.PINNED_COMPUTE_CONTEXT,
            "source_repository": "Shtenco/synergy_ai_blockchain",
            "schema_id": "synergy.ai-blockchain-node-preproduction-commitment/v3",
        },
    ]
    roots.sort(key=lambda x: (x["root_type"], x["source_repository"], x["schema_id"], x["digest"]))
    return roots


def _recv_json_line(conn: socket.socket) -> dict[str, Any]:
    data = b""
    while not data.endswith(b"\n"):
        chunk = conn.recv(65536)
        if not chunk:
            break
        data += chunk
    if not data:
        raise EconomicTestnetLoopbackV1Error("empty TCP message")
    value = json.loads(data.decode("utf-8").strip())
    if not isinstance(value, dict):
        raise EconomicTestnetLoopbackV1Error("TCP message must be object")
    return value


def _node_worker(node_id: str, ready_q, done_q) -> None:
    mod = _load_protocol()
    genesis = mod.load_genesis()
    ledger = mod.CheckpointLedgerV1(genesis)
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(CHECKPOINT_COUNT)
    port = server.getsockname()[1]
    ready_q.put({"node_id": node_id, "port": port})
    transcript: list[dict[str, Any]] = []
    try:
        for _ in range(CHECKPOINT_COUNT):
            conn, _addr = server.accept()
            with conn:
                message = _recv_json_line(conn)
                checkpoint = message.get("checkpoint")
                accepted = True
                error = None
                try:
                    head = ledger.append(checkpoint)
                except Exception as exc:  # evidence harness: return failure, never hide it
                    accepted = False
                    error = type(exc).__name__
                    head = ledger.head_digest
                ack = {
                    "node_id": node_id,
                    "sequence": checkpoint.get("sequence") if isinstance(checkpoint, dict) else None,
                    "accepted": accepted,
                    "checkpoint_digest": checkpoint.get("checkpoint_digest") if accepted and isinstance(checkpoint, dict) else None,
                    "head_digest": head,
                    "error": error,
                }
                transcript.append(ack)
                conn.sendall((json.dumps(ack, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8"))
    finally:
        server.close()
    done_q.put({"node_id": node_id, "head_digest": ledger.head_digest, "transcript": transcript})


def _send_checkpoint(port: int, checkpoint: dict[str, Any]) -> dict[str, Any]:
    with socket.create_connection(("127.0.0.1", port), timeout=5) as conn:
        conn.sendall((json.dumps({"checkpoint": checkpoint}, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8"))
        return _recv_json_line(conn)


def run_three_node_loopback_selftest() -> dict[str, Any]:
    mod = _load_protocol()
    genesis = mod.load_genesis()
    roots = canonical_roots(mod)
    ctx = mp.get_context("spawn")
    ready_q = ctx.Queue()
    done_q = ctx.Queue()
    processes = [ctx.Process(target=_node_worker, args=(f"node-{i + 1}", ready_q, done_q)) for i in range(NODE_COUNT)]
    for process in processes:
        process.start()

    ready: list[dict[str, Any]] = []
    try:
        for _ in range(NODE_COUNT):
            ready.append(ready_q.get(timeout=10))
        ready.sort(key=lambda x: x["node_id"])

        c1 = mod.build_checkpoint(
            genesis=genesis,
            sequence=1,
            previous_checkpoint_digest=genesis["genesis_digest"],
            evidence_roots=roots,
            observed_at="2026-08-28T10:20:00Z",
        )
        c2 = mod.build_checkpoint(
            genesis=genesis,
            sequence=2,
            previous_checkpoint_digest=c1["checkpoint_digest"],
            evidence_roots=roots,
            observed_at="2026-08-28T10:21:00Z",
        )

        acks: list[dict[str, Any]] = []
        for node in ready:
            for checkpoint in (c1, c2):
                acks.append(_send_checkpoint(node["port"], checkpoint))

        completed: list[dict[str, Any]] = []
        for _ in range(NODE_COUNT):
            completed.append(done_q.get(timeout=10))
        completed.sort(key=lambda x: x["node_id"])
        acks.sort(key=lambda x: (x["node_id"], x["sequence"]))

        if len(acks) != NODE_COUNT * CHECKPOINT_COUNT or not all(ack["accepted"] for ack in acks):
            raise EconomicTestnetLoopbackV1Error("not all checkpoint deliveries were accepted")
        final_heads = [item["head_digest"] for item in completed]
        if final_heads != [c2["checkpoint_digest"]] * NODE_COUNT:
            raise EconomicTestnetLoopbackV1Error("nodes did not converge to exact checkpoint #2 head")

        return {
            "node_count": NODE_COUNT,
            "checkpoint_count_per_node": CHECKPOINT_COUNT,
            "accepted_delivery_count": len(acks),
            "rejected_delivery_count": 0,
            "evidence_set_digest": mod.digest(roots),
            "checkpoint_digests": [c1["checkpoint_digest"], c2["checkpoint_digest"]],
            "final_head_digest": c2["checkpoint_digest"],
            "all_nodes_same_final_head": True,
            "transcript_digest": mod.digest(acks),
            "acks": acks,
        }
    except Empty as exc:
        raise EconomicTestnetLoopbackV1Error("loopback worker timed out") from exc
    finally:
        for process in processes:
            process.join(timeout=5)
            if process.is_alive():
                process.terminate()
                process.join(timeout=2)


if __name__ == "__main__":
    print(json.dumps(run_three_node_loopback_selftest(), indent=2, sort_keys=True))
