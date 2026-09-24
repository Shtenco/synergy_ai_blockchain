from __future__ import annotations

import hashlib
import json
from pathlib import Path

from runtime.mini_transformer_v1 import (
    MiniTransformerConfig,
    MiniTransformerStage0,
    MiniTransformerStage1,
    reference_next_token,
)
from runtime.stage_rpc_v1 import StageRpcClient, StageRpcServer


class MaliciousStage1:
    def __init__(self, config: MiniTransformerConfig):
        self.inner = MiniTransformerStage1(config)
        self.model_root = self.inner.model_root
        self.shard_root = self.inner.shard_root
        self.capability_root = hashlib.sha256(b"malicious-stage1-test-only").hexdigest()

    def run(self, payload: bytes) -> bytes:
        good = self.inner.run(payload)
        return bytes([(good[0] + 1) % 256])


def _h(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> None:
    cfg = MiniTransformerConfig()
    prompt = b"SYNERGY adversarial verification"
    stage0 = MiniTransformerStage0(cfg)
    malicious = MaliciousStage1(cfg)

    with StageRpcServer(stage0) as a, StageRpcServer(malicious) as b:
        t0, activation = StageRpcClient(a.address).run(
            request_id=_h(b"bad-req-0"),
            job_id=_h(b"bad-job"),
            stage_index=0,
            worker_id=_h(b"worker-b"),
            model_root=stage0.model_root,
            shard_root=stage0.shard_root,
            session_root="81" * 32,
            payload=prompt,
        )
        t1, bad_output = StageRpcClient(b.address).run(
            request_id=_h(b"bad-req-1"),
            job_id=_h(b"bad-job"),
            stage_index=1,
            worker_id=_h(b"worker-c-malicious"),
            model_root=malicious.model_root,
            shard_root=malicious.shard_root,
            session_root="82" * 32,
            payload=activation,
        )

    expected = reference_next_token(prompt, cfg)
    actual = bad_output[0]
    assert actual != expected

    evidence = {
        "schema": "synergy.mvp-adversarial-transformer-runtime/v1",
        "job_id": _h(b"bad-job"),
        "stage0_trace_root": t0["trace_root"],
        "malicious_stage1_trace_root": t1["trace_root"],
        "challenged_output_commitment": t1["output_commitment"],
        "expected_token": expected,
        "malicious_token": actual,
        "verdict": "MISMATCH",
        "worker_reward_allowed": False,
        "slash_required": True,
        "note": "Canonical slash consumption/finalization is enforced by tests/mvp_adversarial.rs",
    }
    raw = json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()
    evidence["evidence_root"] = _h(raw)
    out = Path("evidence/mvp_adversarial_transformer_runtime.json")
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(evidence, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(evidence, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
