from __future__ import annotations
from dataclasses import dataclass
import hashlib,json
from typing import Any
from .persistent_service_v1 import PersistentContentClient

class RelayInvariantError(ValueError): pass

def _canonical(v:Any)->bytes: return json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
def _digest_payload(p:dict,digest_field=None):
    b=dict(p)
    if digest_field: b.pop(digest_field,None)
    return hashlib.sha256(_canonical(b)).hexdigest()

@dataclass(frozen=True)
class PeerEndpoint:
    peer_id:str; host:str; port:int
    def __post_init__(self):
        if not self.peer_id or not self.host or not (1<=self.port<=65535): raise RelayInvariantError("invalid peer endpoint")
    @property
    def address(self): return self.host,self.port

class StaticPeerDirectory:
    def __init__(self,endpoints:tuple[PeerEndpoint,...]):
        if not endpoints or len(endpoints)>256: raise RelayInvariantError("peer directory size out of bounds")
        self._peers={p.peer_id:p for p in endpoints}
        if len(self._peers)!=len(endpoints): raise RelayInvariantError("peer ids must be unique")
    def resolve(self,peer_id:str):
        try:return self._peers[peer_id]
        except KeyError as exc: raise RelayInvariantError("peer is not allowlisted") from exc

class StaticChunkRelay:
    def __init__(self,directory:StaticPeerDirectory,timeout:float=5.0): self.directory=directory; self.timeout=timeout
    def relay_chunk(self,request:dict)->dict:
        required={"schema","request_id","operation","source_peer_id","destination_peer_id","chunk_digest"}
        if set(request)!=required or request["schema"]!="synergynet.relay-request/v1" or request["operation"]!="RELAY_CHUNK": raise RelayInvariantError("unexpected relay request shape")
        source_id=request["source_peer_id"]; destination_id=request["destination_peer_id"]
        if source_id==destination_id: raise RelayInvariantError("source and destination peers must differ")
        source=self.directory.resolve(source_id); destination=self.directory.resolve(destination_id); digest=request["chunk_digest"]
        raw=PersistentContentClient(source.address,self.timeout).get_raw(digest)
        if hashlib.sha256(raw).hexdigest()!=digest: raise RelayInvariantError("source returned wrong content")
        dst=PersistentContentClient(destination.address,self.timeout)
        if dst.put(raw)!=digest or not dst.has(digest): raise RelayInvariantError("destination failed to commit relayed chunk")
        response={"schema":"synergynet.relay-response/v1","request_id":request["request_id"],"operation":"RELAY_CHUNK","request_digest":_digest_payload(request),"source_peer_id":source_id,"destination_peer_id":destination_id,"chunk_digest":digest,"raw_bytes":len(raw),"relay_scope":"STATIC_ALLOWLISTED_PEERS_ONLY","status":"RELAYED","payment_authority":"NONE","accounting_authority":"NONE","execution_authority":"NONE"}
        response["response_digest"]=_digest_payload(response); return response
