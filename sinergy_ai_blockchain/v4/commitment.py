from __future__ import annotations
from dataclasses import dataclass
from datetime import UTC,datetime
from typing import Any,Mapping
from ..v2.canonical_json import MAX_SAFE_JSON_INTEGER,CanonicalJsonV2Error,canonical_json_digest
from .schema_policy import POLICY_PROFILE,CommitmentPolicyV4Error,validate_commitment_schema_binding_v4

COMMITMENT_ENVELOPE_SCHEMA_V4="commitment.envelope/v4"
CANONICAL_JSON_PROFILE="sinergy.canonical-json/v1"
class CommitmentV4InvariantError(ValueError):pass

def _text(v,n):
 if not isinstance(v,str) or not v.strip():raise CommitmentV4InvariantError(f'{n} is required')
 return v.strip()
def _hex(v,n,nullable=False):
 if nullable and v is None:return None
 x=_text(v,n).lower()
 if len(x)!=64 or any(c not in '0123456789abcdef' for c in x):raise CommitmentV4InvariantError(f'{n} must be hex64')
 return x
def _seq(v):
 if isinstance(v,bool) or not isinstance(v,int) or v<0 or v>MAX_SAFE_JSON_INTEGER:raise CommitmentV4InvariantError('sequence must be non-negative safe integer')
 return v
def canonical_rfc3339_utc_v4(v):
 if not isinstance(v,datetime) or v.tzinfo is None or v.utcoffset() is None:raise CommitmentV4InvariantError('as_of must be timezone-aware')
 x=v.astimezone(UTC);return x.isoformat(timespec='microseconds' if x.microsecond else 'seconds').replace('+00:00','Z')

@dataclass(frozen=True)
class CommitmentEnvelopeV4:
 logical_domain:str;network_domain:str;verifier_id:str;payload_schema:str;subject_id:str;sequence:int;as_of:datetime;payload_digest:str;signer_policy:str;previous_commitment:str|None=None;metadata_digest:str|None=None;policy_profile:str=POLICY_PROFILE
 def __post_init__(self):
  if self.policy_profile!=POLICY_PROFILE:raise CommitmentV4InvariantError('unsupported policy_profile')
  try:b=validate_commitment_schema_binding_v4(self.logical_domain,self.payload_schema)
  except CommitmentPolicyV4Error as exc:raise CommitmentV4InvariantError(str(exc)) from exc
  object.__setattr__(self,'logical_domain',b.logical_domain);object.__setattr__(self,'payload_schema',b.payload_schema)
  object.__setattr__(self,'network_domain',_text(self.network_domain,'network_domain'));object.__setattr__(self,'verifier_id',_text(self.verifier_id,'verifier_id'));object.__setattr__(self,'subject_id',_text(self.subject_id,'subject_id'));object.__setattr__(self,'sequence',_seq(self.sequence));canonical_rfc3339_utc_v4(self.as_of);object.__setattr__(self,'payload_digest',_hex(self.payload_digest,'payload_digest'));object.__setattr__(self,'signer_policy',_text(self.signer_policy,'signer_policy'))
  if self.previous_commitment is not None:object.__setattr__(self,'previous_commitment',_hex(self.previous_commitment,'previous_commitment'))
  if self.metadata_digest is not None:object.__setattr__(self,'metadata_digest',_hex(self.metadata_digest,'metadata_digest'))
 @property
 def domain(self):return f'SINERGY:{self.logical_domain}'
 def to_canonical_dict(self):
  return {'schema_version':COMMITMENT_ENVELOPE_SCHEMA_V4,'canonical_profile':CANONICAL_JSON_PROFILE,'policy_profile':self.policy_profile,'domain':self.domain,'network_domain':self.network_domain,'verifier_id':self.verifier_id,'payload_schema':self.payload_schema,'subject_id':self.subject_id,'sequence':self.sequence,'as_of':canonical_rfc3339_utc_v4(self.as_of),'payload_digest':self.payload_digest,'previous_commitment':self.previous_commitment,'signer_policy':self.signer_policy,'metadata_digest':self.metadata_digest}
 @property
 def commitment_digest(self):
  try:return canonical_json_digest(self.to_canonical_dict())
  except CanonicalJsonV2Error as exc:raise CommitmentV4InvariantError(str(exc)) from exc
 def verify_payload(self,payload:Mapping[str,Any]):
  if not isinstance(payload,Mapping):raise CommitmentV4InvariantError('payload must be JSON object')
  if payload.get('schema')!=self.payload_schema:raise CommitmentV4InvariantError('payload schema mismatch')
  if self.logical_domain=='ECONOMIC_CYCLE_TRACE' and self.payload_schema=='economic.cycle-trace/v5' and payload.get('trust_finalization')!='EXTERNAL_COMMITMENT_REQUIRED':raise CommitmentV4InvariantError('Trace v5 must request external commitment finalization')
  try:d=canonical_json_digest(dict(payload))
  except CanonicalJsonV2Error as exc:raise CommitmentV4InvariantError(str(exc)) from exc
  if d!=self.payload_digest:raise CommitmentV4InvariantError(f'payload digest mismatch: expected={self.payload_digest} got={d}')
  return d
 @classmethod
 def from_payload(cls,*,logical_domain,network_domain,verifier_id,payload_schema,subject_id,sequence,as_of,payload,signer_policy,previous_commitment=None,metadata_digest=None,require_latest_schema=True):
  if not isinstance(payload,Mapping):raise CommitmentV4InvariantError('payload must be JSON object')
  if payload.get('schema')!=payload_schema:raise CommitmentV4InvariantError('payload schema mismatch')
  try:validate_commitment_schema_binding_v4(logical_domain,payload_schema,require_latest=require_latest_schema)
  except CommitmentPolicyV4Error as exc:raise CommitmentV4InvariantError(str(exc)) from exc
  if logical_domain.upper().strip()=='ECONOMIC_CYCLE_TRACE' and payload_schema=='economic.cycle-trace/v5' and payload.get('trust_finalization')!='EXTERNAL_COMMITMENT_REQUIRED':raise CommitmentV4InvariantError('Trace v5 must request external commitment finalization')
  try:d=canonical_json_digest(dict(payload))
  except CanonicalJsonV2Error as exc:raise CommitmentV4InvariantError(str(exc)) from exc
  env=cls(logical_domain,network_domain,verifier_id,payload_schema,subject_id,sequence,as_of,d,signer_policy,previous_commitment,metadata_digest)
  env.verify_payload(payload);return env
