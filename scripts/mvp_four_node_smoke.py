from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path

from runtime.mini_transformer_v1 import (
    MiniTransformerConfig,
    MiniTransformerStage0,
    MiniTransformerStage1,
    reference_next_token,
)
from runtime.stage_rpc_v1 import StageRpcClient, StageRpcServer
from runtime.synergynet_ref import (
    PeerEndpoint,
    PersistentContentClient,
    PersistentContentServer,
    StaticChunkRelay,
    StaticPeerDirectory,
)


def h(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class MaliciousStage1:
    def __init__(self, config: MiniTransformerConfig):
        self.inner = MiniTransformerStage1(config)
        self.model_root = self.inner.model_root
        self.shard_root = self.inner.shard_root
        self.capability_root = h(b"node-c-malicious-stage1")

    def run(self, payload: bytes) -> bytes:
        good = self.inner.run(payload)
        return bytes([(good[0] + 1) % 256])


def relay_request(source: str, destination: str, digest: str) -> dict:
    return {
        "schema": "synergynet.relay-request/v1",
        "request_id": f"relay-{source}-{destination}",
        "operation": "RELAY_CHUNK",
        "source_peer_id": source,
        "destination_peer_id": destination,
        "chunk_digest": digest,
    }


def main() -> None:
    cfg = MiniTransformerConfig()
    prompt = b"SYNERGY FOUR NODE CONSENSUS"
    model_bytes = b"SYNERGY-FOUR-NODE-MODEL-SHARD" * 4096
    with tempfile.TemporaryDirectory(prefix="synergy-4node-") as td:
        root = Path(td)
        with PersistentContentServer(store_root=root / "a") as a,              PersistentContentServer(store_root=root / "b") as b_store,              PersistentContentServer(store_root=root / "c") as c_store,              PersistentContentServer(store_root=root / "d") as d_store:
            peers = StaticPeerDirectory((
                PeerEndpoint("node-a", *a.address),
                PeerEndpoint("node-b", *b_store.address),
                PeerEndpoint("node-c", *c_store.address),
                PeerEndpoint("node-d", *d_store.address),
            ))
            relay = StaticChunkRelay(peers)
            digest = PersistentContentClient(a.address).put(model_bytes, codec_id="zlib-9")
            relay_roots = {}
            for dst in ("node-b", "node-c", "node-d"):
                response = relay.relay_chunk(relay_request("node-a", dst, digest))
                relay_roots[dst] = response["response_digest"]
                client = PersistentContentClient(peers.resolve(dst).address)
                assert client.get_raw(digest) == model_bytes

            stage0 = MiniTransformerStage0(cfg)
            bad_stage1 = MaliciousStage1(cfg)
            good_stage1 = MiniTransformerStage1(cfg)
            with StageRpcServer(stage0) as b_rpc,                  StageRpcServer(bad_stage1) as c_rpc,                  StageRpcServer(good_stage1) as d_rpc:
                t0, activation = StageRpcClient(b_rpc.address).run(
                    request_id=h(b"4node-stage0"), job_id=h(b"4node-job"),
                    stage_index=0, worker_id=h(b"node-b"),
                    model_root=stage0.model_root, shard_root=stage0.shard_root,
                    session_root="91" * 32, payload=prompt,
                )
                tc, bad = StageRpcClient(c_rpc.address).run(
                    request_id=h(b"4node-stage1-c"), job_id=h(b"4node-job"),
                    stage_index=1, worker_id=h(b"node-c"),
                    model_root=bad_stage1.model_root, shard_root=bad_stage1.shard_root,
                    session_root="92" * 32, payload=activation,
                )
                td_trace, good = StageRpcClient(d_rpc.address).run(
                    request_id=h(b"4node-stage1-d"), job_id=h(b"4node-job"),
                    stage_index=1, worker_id=h(b"node-d"),
                    model_root=good_stage1.model_root, shard_root=good_stage1.shard_root,
                    session_root="93" * 32, payload=activation,
                )
            expected = reference_next_token(prompt, cfg)
            assert bad[0] != expected
            assert good[0] == expected
            evidence = {
                "schema": "synergy.mvp-four-node/v1",
                "nodes": ["node-a", "node-b", "node-c", "node-d"],
                "model_shard_digest": digest,
                "relay_roots": relay_roots,
                "stage0_trace_root": t0["trace_root"],
                "node_c_trace_root": tc["trace_root"],
                "node_d_trace_root": td_trace["trace_root"],
                "node_c_verdict": "MISMATCH",
                "node_d_verdict": "MATCH",
                "node_c_token": bad[0],
                "node_d_token": good[0],
                "reference_token": expected,
                "failover_node": "node-d",
                "four_node_failover": True,
            }
            raw = json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()
            evidence["evidence_root"] = h(raw)
            out = Path("evidence/mvp_four_node_smoke.json")
            out.parent.mkdir(exist_ok=True)
            out.write_text(json.dumps(evidence, indent=2, sort_keys=True), encoding="utf-8")
            print(json.dumps(evidence, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
