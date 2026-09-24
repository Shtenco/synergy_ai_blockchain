from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path

from runtime.synergynet_ref import (
    PersistentContentClient,
    PersistentContentServer,
    PeerEndpoint,
    StaticChunkRelay,
    StaticPeerDirectory,
)
from runtime.stage_rpc_v1 import HashReferenceBackend, StageRpcClient, StageRpcServer


def h(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="synergy-mvp-vertical-") as td:
        root = Path(td)
        model_bytes = b"SYNERGY-VERTICAL-MODEL-SHARD" * 2048
        prompt = b"hello post-quantum distributed ai"
        session_root = "77" * 32

        with PersistentContentServer(store_root=root / "provider") as provider,              PersistentContentServer(store_root=root / "worker") as worker_store:
            provider_client = PersistentContentClient(provider.address)
            worker_client = PersistentContentClient(worker_store.address)

            shard_digest = provider_client.put(model_bytes, codec_id="zlib-9")
            peers = StaticPeerDirectory((
                PeerEndpoint("node-a", *provider.address),
                PeerEndpoint("node-b", *worker_store.address),
            ))
            relay = StaticChunkRelay(peers)
            relay_response = relay.relay_chunk({
                "schema": "synergynet.relay-request/v1",
                "request_id": "relay-vertical-1",
                "operation": "RELAY_CHUNK",
                "source_peer_id": "node-a",
                "destination_peer_id": "node-b",
                "chunk_digest": shard_digest,
            })
            assert worker_client.get_raw(shard_digest) == model_bytes

            backend = HashReferenceBackend(
                model_root=h(b"model-root"),
                shard_root=shard_digest,
                capability_root=h(b"cpu-reference-capability"),
            )
            with StageRpcServer(backend) as worker_rpc:
                trace, output = StageRpcClient(worker_rpc.address).run(
                    request_id=h(b"request-1"),
                    job_id=h(b"job-1"),
                    stage_index=0,
                    worker_id=h(b"node-b"),
                    model_root=backend.model_root,
                    shard_root=backend.shard_root,
                    session_root=session_root,
                    payload=prompt,
                )

                expected = hashlib.sha256(b"SYNERGY/STAGE-REFERENCE/V1\0" + prompt).digest()
                verifier_match = output == expected
                if not verifier_match:
                    raise SystemExit("verifier mismatch in vertical smoke")

                verification = {
                    "verdict": "MATCH",
                    "challenged_output_commitment": trace["output_commitment"],
                    "recomputed_output_commitment": h(expected),
                    "trace_root": trace["trace_root"],
                }
                verification_root = h(canonical(verification))

                evidence = {
                    "schema": "synergy.mvp-vertical-slice-smoke/v1",
                    "model_shard_digest": shard_digest,
                    "relay_response_digest": relay_response["response_digest"],
                    "session_root": session_root,
                    "stage_trace_root": trace["trace_root"],
                    "stage_output_commitment": trace["output_commitment"],
                    "verification_root": verification_root,
                    "verifier_match": verifier_match,
                    "content_authority": relay_response["execution_authority"],
                    "stage_execution_authority": trace["execution_authority"],
                    "stage_payment_authority": trace["payment_authority"],
                }
                evidence["evidence_root"] = h(canonical(evidence))
                out = Path("evidence/mvp_vertical_slice_smoke.json")
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_text(json.dumps(evidence, indent=2, sort_keys=True), encoding="utf-8")
                print(json.dumps(evidence, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
