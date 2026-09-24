from __future__ import annotations
import hashlib,json
from pathlib import Path
from runtime.mini_transformer_v1 import MiniTransformerConfig, MiniTransformerStage0, MiniTransformerStage1, reference_next_token
from runtime.stage_rpc_v1 import StageRpcClient, StageRpcServer

def main():
    cfg=MiniTransformerConfig()
    s0=MiniTransformerStage0(cfg); s1=MiniTransformerStage1(cfg)
    prompt="Привет, SYNERGY".encode("utf-8")
    with StageRpcServer(s0) as a, StageRpcServer(s1) as b:
        t0,activation=StageRpcClient(a.address).run(
            request_id=hashlib.sha256(b"mt-req-0").hexdigest(),
            job_id=hashlib.sha256(b"mt-job").hexdigest(),
            stage_index=0,worker_id=hashlib.sha256(b"node-b").hexdigest(),
            model_root=s0.model_root,shard_root=s0.shard_root,
            session_root="71"*32,payload=prompt,
        )
        t1,out=StageRpcClient(b.address).run(
            request_id=hashlib.sha256(b"mt-req-1").hexdigest(),
            job_id=hashlib.sha256(b"mt-job").hexdigest(),
            stage_index=1,worker_id=hashlib.sha256(b"node-c").hexdigest(),
            model_root=s1.model_root,shard_root=s1.shard_root,
            session_root="72"*32,payload=activation,
        )
    distributed_token=out[0]
    reference_token=reference_next_token(prompt,cfg)
    assert distributed_token==reference_token
    evidence={
        "schema":"synergy.real-transformer-two-stage-smoke/v1",
        "model_root":s0.model_root,
        "stage0_shard_root":s0.shard_root,
        "stage1_shard_root":s1.shard_root,
        "stage0_trace_root":t0["trace_root"],
        "stage1_trace_root":t1["trace_root"],
        "activation_bytes":len(activation),
        "next_token_id":distributed_token,
        "reference_next_token_id":reference_token,
        "exact_distributed_equivalence":True,
        "backend":"NUMPY_CAUSAL_TRANSFORMER_REFERENCE",
        "language_quality_claim":"NONE_UNTRAINED_REFERENCE_MODEL",
    }
    raw=json.dumps(evidence,sort_keys=True,separators=(",",":")).encode()
    evidence["evidence_root"]=hashlib.sha256(raw).hexdigest()
    p=Path("evidence/mvp_real_transformer_smoke.json"); p.parent.mkdir(exist_ok=True); p.write_text(json.dumps(evidence,indent=2,sort_keys=True),encoding="utf-8")
    print(json.dumps(evidence,indent=2,sort_keys=True))

if __name__=="__main__": main()
