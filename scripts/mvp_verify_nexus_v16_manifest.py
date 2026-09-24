#!/usr/bin/env python3
from __future__ import annotations
import hashlib,json
from pathlib import Path

DOMAIN=b"SYNERGY/MVP-NEXUS-V16-MANIFEST/V1\0"

def canonical(obj):
    return json.dumps(obj,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()

def main():
    path=Path("models/nexus_v16/DISTRIBUTED_MODEL_MANIFEST.json")
    obj=json.loads(path.read_text(encoding="utf-8"))
    shards=obj["physical_shards"]
    if len(shards)!=5: raise SystemExit("expected exactly five V16 shards")
    seen=set()
    h=hashlib.sha256(); h.update(DOMAIN)
    for i,s in enumerate(shards):
        digest=s["sha256"]
        if len(digest)!=64 or any(c not in "0123456789abcdef" for c in digest): raise SystemExit("bad shard hash")
        if digest in seen: raise SystemExit("duplicate shard hash")
        seen.add(digest)
        h.update(i.to_bytes(4,"big")); h.update(bytes.fromhex(digest)); h.update(int(s["parameters"]).to_bytes(8,"big"))
    root=h.hexdigest()
    out={"format":"synergy.mvp-nexus-v16-import/v1","shard_count":len(shards),"ordered_shard_root":root,"source_manifest_sha256":hashlib.sha256(path.read_bytes()).hexdigest()}
    Path("models/nexus_v16/IMPORT_EVIDENCE.json").write_text(json.dumps(out,indent=2,sort_keys=True),encoding="utf-8")
    print(json.dumps(out,sort_keys=True))
if __name__=="__main__": main()
