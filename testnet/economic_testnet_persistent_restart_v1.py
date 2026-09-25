from __future__ import annotations

import importlib.util
import json
import multiprocessing as mp
import os
import sys
import tempfile
from pathlib import Path
from queue import Empty
from typing import Any, Mapping

NODE_COUNT = 3
PARENT_LOOPBACK_EVIDENCE = "6f80d6cfdbce8eb0b2410c7e440f260eaf6199da8e5b64ce48c365c68be684d5"


class PersistentRestartV1Error(RuntimeError):
    pass


def _load_protocol():
    path = Path(__file__).resolve().with_name("economic_testnet_v1.py")
    name = "economic_testnet_v1_persistent_runtime"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise PersistentRestartV1Error("cannot load economic testnet protocol")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def canonical_roots(mod) -> list[dict[str, str]]:
    roots = [
        {"root_type": "ECONOMIC_CYCLE", "digest": mod.PINNED_ECONOMIC_CYCLE, "source_repository": "Shtenco/synergy_system", "schema_id": "synergy.economic-cycle/v1"},
        {"root_type": "ECONOMIC_BLOCKCHAIN_COMMITMENT", "digest": mod.PINNED_ECONOMIC_COMMITMENT, "source_repository": "Shtenco/synergy_ai_blockchain", "schema_id": "synergy.ai-blockchain-economic-evidence-commitment/v1"},
        {"root_type": "COMPUTE_TRUST_CONTEXT", "digest": mod.PINNED_COMPUTE_CONTEXT, "source_repository": "Shtenco/synergy_ai_blockchain", "schema_id": "synergy.ai-blockchain-node-preproduction-commitment/v3"},
    ]
    roots.sort(key=lambda x: (x["root_type"], x["source_repository"], x["schema_id"], x["digest"]))
    return roots


class PersistentCheckpointStoreV1:
    def __init__(self, state_path: Path):
        self.mod = _load_protocol()
        self.genesis = self.mod.load_genesis()
        self.state_path = Path(state_path)
        self._checkpoints: list[dict[str, Any]] = []
        if self.state_path.exists():
            self._recover()

    @property
    def head_digest(self) -> str:
        return self.genesis["genesis_digest"] if not self._checkpoints else self._checkpoints[-1]["checkpoint_digest"]

    @property
    def next_sequence(self) -> int:
        return len(self._checkpoints) + 1

    @property
    def checkpoint_count(self) -> int:
        return len(self._checkpoints)

    def _recover(self) -> None:
        raw = json.loads(self.state_path.read_text(encoding="utf-8"))
        if raw.get("schema") != "synergy.economic-testnet-local-store/v1":
            raise PersistentRestartV1Error("store schema mismatch")
        if raw.get("genesis_digest") != self.genesis["genesis_digest"]:
            raise PersistentRestartV1Error("store genesis mismatch")
        checkpoints = raw.get("checkpoints")
        if not isinstance(checkpoints, list):
            raise PersistentRestartV1Error("store checkpoints invalid")
        previous = self.genesis["genesis_digest"]
        recovered: list[dict[str, Any]] = []
        for sequence, checkpoint in enumerate(checkpoints, 1):
            verified = self.mod.verify_checkpoint(
                checkpoint,
                genesis=self.genesis,
                expected_sequence=sequence,
                expected_previous_digest=previous,
            )
            recovered.append(dict(verified))
            previous = verified["checkpoint_digest"]
        self._checkpoints = recovered

    def _persist(self) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        body = {
            "schema": "synergy.economic-testnet-local-store/v1",
            "genesis_digest": self.genesis["genesis_digest"],
            "checkpoints": self._checkpoints,
        }
        fd, tmp_name = tempfile.mkstemp(prefix=self.state_path.name + ".", suffix=".tmp", dir=str(self.state_path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(body, handle, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_name, self.state_path)
        finally:
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)

    def append(self, checkpoint: Mapping[str, Any]) -> str:
        verified = self.mod.verify_checkpoint(
            checkpoint,
            genesis=self.genesis,
            expected_sequence=self.next_sequence,
            expected_previous_digest=self.head_digest,
        )
        self._checkpoints.append(dict(verified))
        self._persist()
        return verified["checkpoint_digest"]


def _recover_worker(node_id: str, state_path: str, result_q) -> None:
    try:
        store = PersistentCheckpointStoreV1(Path(state_path))
        result_q.put({"node_id": node_id, "ok": True, "checkpoint_count": store.checkpoint_count, "head_digest": store.head_digest})
    except Exception as exc:
        result_q.put({"node_id": node_id, "ok": False, "error": type(exc).__name__})


def recover_fresh_processes(paths: list[Path]) -> list[dict[str, Any]]:
    ctx = mp.get_context("spawn")
    result_q = ctx.Queue()
    processes = [ctx.Process(target=_recover_worker, args=(f"node-{i+1}", str(path), result_q)) for i, path in enumerate(paths)]
    for process in processes:
        process.start()
    results: list[dict[str, Any]] = []
    try:
        for _ in processes:
            results.append(result_q.get(timeout=10))
    except Empty as exc:
        raise PersistentRestartV1Error("recovery worker timeout") from exc
    finally:
        for process in processes:
            process.join(timeout=5)
            if process.is_alive():
                process.terminate(); process.join(timeout=2)
    results.sort(key=lambda x: x["node_id"])
    if not all(item.get("ok") for item in results):
        raise PersistentRestartV1Error("fresh-process recovery failed")
    return results


def run_persistent_restart_selftest(root: Path | None = None) -> dict[str, Any]:
    mod = _load_protocol()
    genesis = mod.load_genesis()
    roots = canonical_roots(mod)
    base = Path(root) if root is not None else Path(tempfile.mkdtemp(prefix="synergy-economic-persistent-"))
    paths = [base / f"node-{i+1}.json" for i in range(NODE_COUNT)]
    stores = [PersistentCheckpointStoreV1(path) for path in paths]

    c1 = mod.build_checkpoint(genesis=genesis, sequence=1, previous_checkpoint_digest=genesis["genesis_digest"], evidence_roots=roots, observed_at="2026-08-28T10:20:00Z")
    c2 = mod.build_checkpoint(genesis=genesis, sequence=2, previous_checkpoint_digest=c1["checkpoint_digest"], evidence_roots=roots, observed_at="2026-08-28T10:21:00Z")
    c3 = mod.build_checkpoint(genesis=genesis, sequence=3, previous_checkpoint_digest=c2["checkpoint_digest"], evidence_roots=roots, observed_at="2026-08-28T10:22:00Z")

    transcript: list[dict[str, Any]] = []
    for i, store in enumerate(stores):
        store.append(c1)
        transcript.append({"phase": "BOOT_A", "node": f"node-{i+1}", "action": "APPEND", "sequence": 1, "accepted": True, "head": store.head_digest})
    for i in (0, 1):
        stores[i].append(c2)
        transcript.append({"phase": "PARTITION", "node": f"node-{i+1}", "action": "APPEND", "sequence": 2, "accepted": True, "head": stores[i].head_digest})
    transcript.append({"phase": "PARTITION", "node": "node-3", "action": "WITHHELD", "sequence": 2, "accepted": False, "head": stores[2].head_digest})

    first_recovery = recover_fresh_processes(paths)
    for item in first_recovery:
        transcript.append({"phase": "RESTART_1", "node": item["node_id"], "action": "RECOVER", "sequence": item["checkpoint_count"], "accepted": True, "head": item["head_digest"]})
    expected_first = [c2["checkpoint_digest"], c2["checkpoint_digest"], c1["checkpoint_digest"]]
    if [item["head_digest"] for item in first_recovery] != expected_first:
        raise PersistentRestartV1Error("first restart recovery heads mismatch")

    node1 = PersistentCheckpointStoreV1(paths[0])
    replay_rejected = False
    try:
        node1.append(c1)
    except Exception:
        replay_rejected = True
    if not replay_rejected:
        raise PersistentRestartV1Error("checkpoint replay unexpectedly accepted")
    transcript.append({"phase": "REPLAY_TEST", "node": "node-1", "action": "REPLAY", "sequence": 1, "accepted": False, "error": "POSITION_OR_SEQUENCE_REJECTED", "head": node1.head_digest})

    node3 = PersistentCheckpointStoreV1(paths[2]); node3.append(c2)
    transcript.append({"phase": "RECONNECT", "node": "node-3", "action": "CATCH_UP", "sequence": 2, "accepted": True, "head": node3.head_digest})

    stores = [PersistentCheckpointStoreV1(path) for path in paths]
    for i, store in enumerate(stores):
        store.append(c3)
        transcript.append({"phase": "CONTINUE", "node": f"node-{i+1}", "action": "APPEND", "sequence": 3, "accepted": True, "head": store.head_digest})

    second_recovery = recover_fresh_processes(paths)
    for item in second_recovery:
        transcript.append({"phase": "RESTART_2", "node": item["node_id"], "action": "RECOVER", "sequence": item["checkpoint_count"], "accepted": True, "head": item["head_digest"]})
    if [item["head_digest"] for item in second_recovery] != [c3["checkpoint_digest"]] * NODE_COUNT:
        raise PersistentRestartV1Error("second restart did not recover one common head")

    return {
        "parent_loopback_execution_evidence_digest": PARENT_LOOPBACK_EVIDENCE,
        "node_count": NODE_COUNT,
        "restart_count": 2,
        "checkpoint_digests": [c1["checkpoint_digest"], c2["checkpoint_digest"], c3["checkpoint_digest"]],
        "first_restart_heads": expected_first,
        "replay_rejected": True,
        "node3_catchup_verified": True,
        "second_restart_all_nodes_same_final_head": True,
        "final_head_digest": c3["checkpoint_digest"],
        "transcript_digest": mod.digest(transcript),
        "transcript": transcript,
    }


if __name__ == "__main__":
    print(json.dumps(run_persistent_restart_selftest(), indent=2, sort_keys=True))
