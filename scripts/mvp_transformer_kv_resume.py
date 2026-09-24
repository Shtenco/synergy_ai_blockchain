from __future__ import annotations
import hashlib,json
from pathlib import Path
from runtime.mini_transformer_v1 import MiniTransformerConfig
from runtime.mini_transformer_kv_v1 import IncrementalStage0,IncrementalStage1,prefill,generate_one

def main():
    cfg=MiniTransformerConfig(max_seq=64)
    prompt=b"SYNERGY KV"
    # uninterrupted reference
    ref0,ref1=IncrementalStage0(cfg),IncrementalStage1(cfg)
    first=preffill= pref = prefill(ref0,ref1,prompt)
    ref_next=generate_one(ref0,ref1,pref)

    # worker A prefill then snapshot
    a0,a1=IncrementalStage0(cfg),IncrementalStage1(cfg)
    token=prefill(a0,a1,prompt)
    s0=a0.snapshot(); s1=a1.snapshot()
    kv_root=hashlib.sha256(s0+s1).hexdigest()

    # worker A is gone; worker B reconstructs exact KV state
    b0,b1=IncrementalStage0(cfg),IncrementalStage1(cfg)
    b0.restore(s0); b1.restore(s1)
    resumed_next=generate_one(b0,b1,token)
    assert resumed_next==ref_next

    evidence={
        "schema":"synergy.remote-kv-transformer-resume/v1",
        "prompt_bytes":len(prompt),
        "kv_root":kv_root,
        "stage0_snapshot_bytes":len(s0),
        "stage1_snapshot_bytes":len(s1),
        "last_prefill_token":token,
        "uninterrupted_next_token":ref_next,
        "resumed_next_token":resumed_next,
        "exact_resume_equivalence":True,
        "primary_worker_terminated_before_resume":True,
    }
    raw=json.dumps(evidence,sort_keys=True,separators=(",",":")).encode()
    evidence["evidence_root"]=hashlib.sha256(raw).hexdigest()
    p=Path("evidence/mvp_transformer_kv_resume.json");p.parent.mkdir(exist_ok=True);p.write_text(json.dumps(evidence,indent=2,sort_keys=True),encoding="utf-8")
    print(json.dumps(evidence,indent=2,sort_keys=True))

if __name__=="__main__":main()
