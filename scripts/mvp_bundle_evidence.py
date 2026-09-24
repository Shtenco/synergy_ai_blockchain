from __future__ import annotations
import argparse,hashlib,json
from pathlib import Path

def sha(path:Path)->str:
    h=hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda:f.read(1024*1024),b""): h.update(chunk)
    return h.hexdigest()

def main():
    p=argparse.ArgumentParser();p.add_argument("--evidence-dir",default="evidence");p.add_argument("--out",default="evidence/MVP_EVIDENCE_BUNDLE.json");args=p.parse_args()
    root=Path(args.evidence_dir); out=Path(args.out)
    files=sorted(x for x in root.rglob("*") if x.is_file() and x.resolve()!=out.resolve())
    entries=[{"path":str(x.as_posix()),"sha256":sha(x),"bytes":x.stat().st_size} for x in files]
    payload={"schema":"synergy.mvp-evidence-bundle/v1","artifacts":entries}
    raw=json.dumps(payload,sort_keys=True,separators=(",",":")).encode()
    payload["bundle_root"]=hashlib.sha256(raw).hexdigest()
    out.parent.mkdir(parents=True,exist_ok=True);out.write_text(json.dumps(payload,indent=2,sort_keys=True),encoding="utf-8")
    print(json.dumps(payload,indent=2,sort_keys=True))
if __name__=="__main__":main()
