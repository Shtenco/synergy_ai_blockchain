from __future__ import annotations
from dataclasses import dataclass

POLICY_PROFILE="sinergy.commitment-schema-policy/v4"
DOMAIN_SCHEMA_POLICY_V4={
 "FINANCIAL_SNAPSHOT":frozenset({"financial.snapshot/v2"}),
 "MATURITY_SNAPSHOT":frozenset({"maturity.snapshot/v1"}),
 "SETTLEMENT_RECEIPT":frozenset({"settlement.receipt/v1","settlement.receipt/v2"}),
 "LEDGER_EVENT":frozenset({"ledger.event/v1"}),
 "PROJECT_PROPOSAL":frozenset({"project.proposal/v2"}),
 "PROJECT_EVIDENCE":frozenset({"project.evidence/v1"}),
 "PROJECT_SCREENING":frozenset({"project.screening/v1"}),
 "CAPITAL_AUTHORIZATION":frozenset({"capital.authorization/v1","capital.authorization/v2"}),
 "REVENUE_RECOGNITION":frozenset({"revenue.recognition/v2"}),
 "ECONOMIC_CYCLE_TRACE":frozenset({"economic.cycle-trace/v1","economic.cycle-trace/v2","economic.cycle-trace/v3","economic.cycle-trace/v4","economic.cycle-trace/v5"}),
 "AI_POLICY_PROPOSAL":frozenset({"ai.policy-proposal/v2"}),
}
LATEST_SCHEMA_BY_DOMAIN={
 "FINANCIAL_SNAPSHOT":"financial.snapshot/v2","MATURITY_SNAPSHOT":"maturity.snapshot/v1",
 "SETTLEMENT_RECEIPT":"settlement.receipt/v2","LEDGER_EVENT":"ledger.event/v1",
 "PROJECT_PROPOSAL":"project.proposal/v2","PROJECT_EVIDENCE":"project.evidence/v1",
 "PROJECT_SCREENING":"project.screening/v1","CAPITAL_AUTHORIZATION":"capital.authorization/v2",
 "REVENUE_RECOGNITION":"revenue.recognition/v2","ECONOMIC_CYCLE_TRACE":"economic.cycle-trace/v5",
 "AI_POLICY_PROPOSAL":"ai.policy-proposal/v2",
}
class CommitmentPolicyV4Error(ValueError):pass
@dataclass(frozen=True)
class CommitmentSchemaBindingV4:
 logical_domain:str;payload_schema:str;policy_profile:str=POLICY_PROFILE
 def __post_init__(self):
  d=self.logical_domain.upper().strip();s=self.payload_schema.strip()
  if self.policy_profile!=POLICY_PROFILE:raise CommitmentPolicyV4Error('unsupported commitment policy profile')
  if d not in DOMAIN_SCHEMA_POLICY_V4:raise CommitmentPolicyV4Error(f'unsupported logical_domain: {d or "<empty>"}')
  if s not in DOMAIN_SCHEMA_POLICY_V4[d]:raise CommitmentPolicyV4Error(f'payload schema {s or "<empty>"} is not allowed for {d}')
  object.__setattr__(self,'logical_domain',d);object.__setattr__(self,'payload_schema',s)
 @property
 def latest_for_domain(self):return LATEST_SCHEMA_BY_DOMAIN[self.logical_domain]==self.payload_schema
def validate_commitment_schema_binding_v4(logical_domain,payload_schema,*,require_latest=False):
 b=CommitmentSchemaBindingV4(logical_domain,payload_schema)
 if require_latest and not b.latest_for_domain:raise CommitmentPolicyV4Error(f'{b.payload_schema} is provenance-compatible but not latest for {b.logical_domain}; latest={LATEST_SCHEMA_BY_DOMAIN[b.logical_domain]}')
 return b
def allowed_payload_schemas_v4(logical_domain):
 d=logical_domain.upper().strip()
 if d not in DOMAIN_SCHEMA_POLICY_V4:raise CommitmentPolicyV4Error(f'unsupported logical_domain: {d or "<empty>"}')
 return tuple(sorted(DOMAIN_SCHEMA_POLICY_V4[d]))
