from __future__ import annotations
import hashlib
from runtime.stage_rpc_v1 import HashReferenceBackend, StageRpcClient, StageRpcServer

def h(x: bytes)->str: return hashlib.sha256(x).hexdigest()

def run() -> dict:
    backend=HashReferenceBackend(model_root="11"*32,shard_root="22"*32,capability_root="33"*32)
    with StageRpcServer(backend) as server:
        trace,out=StageRpcClient(server.address).run(
            request_id="44"*32,job_id="55"*32,stage_index=0,worker_id="66"*32,
            model_root="11"*32,shard_root="22"*32,session_root="77"*32,payload=b"hello-mvp",
        )
        expected=hashlib.sha256(b"SYNERGY/STAGE-REFERENCE/V1\0"+b"hello-mvp").digest()
        assert out==expected
        assert trace["output_commitment"]==h(expected)
        assert trace["execution_authority"]=="NONE"
        assert trace["payment_authority"]=="NONE"
        return {"trace_root":trace["trace_root"],"output_commitment":trace["output_commitment"],"elapsed_micros":trace["elapsed_micros"]}
if __name__=="__main__": print(run())
