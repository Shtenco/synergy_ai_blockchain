from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path

class KvSnapshotError(ValueError):
    pass

@dataclass(frozen=True)
class KvSnapshot:
    job_id: str
    session_id: str
    model_root: str
    sequence: int
    token_start: int
    token_end_exclusive: int
    kv_root: str
    payload: bytes

    @classmethod
    def create(cls, *, job_id: str, session_id: str, model_root: str, sequence: int, token_start: int, token_end_exclusive: int, payload: bytes) -> "KvSnapshot":
        if sequence <= 0 or token_end_exclusive <= token_start:
            raise KvSnapshotError("invalid KV sequence/range")
        payload=bytes(payload)
        root=hashlib.sha256(payload).hexdigest()
        return cls(job_id,session_id,model_root,sequence,token_start,token_end_exclusive,root,payload)

    def manifest(self) -> dict:
        return {
            "schema":"synergy.kv-snapshot/v1",
            "job_id":self.job_id,
            "session_id":self.session_id,
            "model_root":self.model_root,
            "sequence":self.sequence,
            "token_start":self.token_start,
            "token_end_exclusive":self.token_end_exclusive,
            "kv_root":self.kv_root,
            "bytes":len(self.payload),
        }

    def verify(self) -> None:
        if hashlib.sha256(self.payload).hexdigest()!=self.kv_root:
            raise KvSnapshotError("KV payload/root mismatch")

class KvSnapshotStore:
    def __init__(self, root: str|Path):
        self.root=Path(root); self.root.mkdir(parents=True,exist_ok=True)

    def put(self,s:KvSnapshot)->Path:
        s.verify()
        p=self.root/f"{s.job_id}.{s.sequence}.kv"
        m=p.with_suffix(".json")
        p.write_bytes(s.payload)
        m.write_text(json.dumps(s.manifest(),sort_keys=True,separators=(",",":")),encoding="utf-8")
        return p

    def load(self,job_id:str,sequence:int)->KvSnapshot:
        p=self.root/f"{job_id}.{sequence}.kv"
        m=p.with_suffix(".json")
        meta=json.loads(m.read_text(encoding="utf-8"))
        payload=p.read_bytes()
        snap=KvSnapshot(
            meta["job_id"],meta["session_id"],meta["model_root"],int(meta["sequence"]),
            int(meta["token_start"]),int(meta["token_end_exclusive"]),meta["kv_root"],payload
        )
        snap.verify()
        return snap
