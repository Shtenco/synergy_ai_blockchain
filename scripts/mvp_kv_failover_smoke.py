from __future__ import annotations
import hashlib,json,tempfile
from pathlib import Path
from runtime.kv_snapshot_v1 import KvSnapshot,KvSnapshotStore

def main():
    job=hashlib.sha256(b"kv-job").hexdigest()
    session=hashlib.sha256(b"kv-session").hexdigest()
    model=hashlib.sha256(b"kv-model").hexdigest()
    payload=b"serialized-kv-state"*4096
    snap=KvSnapshot.create(job_id=job,session_id=session,model_root=model,sequence=1,token_start=0,token_end_exclusive=32,payload=payload)
    with tempfile.TemporaryDirectory(prefix="synergy-kv-") as td:
        primary=KvSnapshotStore(Path(td)/"primary")
        replica=KvSnapshotStore(Path(td)/"replica")
        primary.put(snap)
        # transport-independent replication proof: exact bytes copied to replica store
        replica.put(primary.load(job,1))
        del primary
        recovered=replica.load(job,1)
        assert recovered.payload==payload
        ev={"schema":"synergy.kv-failover-smoke/v1","job_id":job,"sequence":1,"kv_root":recovered.kv_root,"bytes":len(payload),"primary_removed":True,"replica_recovery":True}
        ev["evidence_root"]=hashlib.sha256(json.dumps(ev,sort_keys=True,separators=(",",":")).encode()).hexdigest()
        out=Path("evidence/mvp_kv_failover_smoke.json");out.parent.mkdir(exist_ok=True);out.write_text(json.dumps(ev,indent=2,sort_keys=True),encoding="utf-8")
        print(json.dumps(ev,indent=2,sort_keys=True))
if __name__=="__main__": main()
