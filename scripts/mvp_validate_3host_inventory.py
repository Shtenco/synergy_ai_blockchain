from __future__ import annotations
import argparse,ipaddress,json
from pathlib import Path

def is_loopback(host:str)->bool:
    h=host.strip().lower()
    if h in {"localhost","localhost.localdomain","::1"}: return True
    try: return ipaddress.ip_address(h).is_loopback
    except ValueError: return False

def main():
    p=argparse.ArgumentParser();p.add_argument("inventory");args=p.parse_args()
    obj=json.loads(Path(args.inventory).read_text(encoding="utf-8"))
    if obj.get("schema")!="synergy.mvp-3host-inventory/v1": raise SystemExit("bad inventory schema")
    nodes=obj.get("nodes")
    if not isinstance(nodes,list) or len(nodes)!=3: raise SystemExit("exactly three nodes required")
    ids=[n.get("node_id") for n in nodes]; hosts=[n.get("host") for n in nodes]
    if any(not isinstance(x,str) or not x for x in ids+hosts): raise SystemExit("node ids/hosts required")
    if len(set(ids))!=3 or len(set(hosts))!=3: raise SystemExit("three unique node ids and hosts required")
    if any(is_loopback(h) for h in hosts): raise SystemExit("loopback host forbidden")
    roles={n.get("role") for n in nodes}
    required={"provider","stage0-worker","stage1-verifier"}
    if roles!=required: raise SystemExit(f"roles must equal {sorted(required)}")
    print(json.dumps({"status":"PASS","unique_hosts":3,"roles":sorted(roles)},sort_keys=True))
if __name__=="__main__":main()
