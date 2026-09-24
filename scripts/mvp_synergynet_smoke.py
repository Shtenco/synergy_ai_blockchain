from __future__ import annotations
import hashlib, tempfile
from pathlib import Path
from runtime.synergynet_ref import PersistentContentClient, PersistentContentServer, PeerEndpoint, StaticChunkRelay, StaticPeerDirectory

def run_smoke() -> dict:
    with tempfile.TemporaryDirectory(prefix="synergy-mvp-") as td:
        root=Path(td)
        raw=b"SYNERGY-MVP-MODEL-SHARD"*1024
        with PersistentContentServer(store_root=root/"a") as a, PersistentContentServer(store_root=root/"b") as b:
            ca=PersistentContentClient(a.address); cb=PersistentContentClient(b.address)
            digest=ca.put(raw,codec_id="zlib-9")
            directory=StaticPeerDirectory((PeerEndpoint("node-a",*a.address),PeerEndpoint("node-b",*b.address)))
            response=StaticChunkRelay(directory).relay_chunk({"schema":"synergynet.relay-request/v1","request_id":"mvp-smoke-1","operation":"RELAY_CHUNK","source_peer_id":"node-a","destination_peer_id":"node-b","chunk_digest":digest})
            assert cb.get_raw(digest)==raw
            return {"digest":digest,"expected":hashlib.sha256(raw).hexdigest(),"status":response["status"],"authority":response["execution_authority"]}
if __name__=="__main__":
    print(run_smoke())
