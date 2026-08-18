from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import jsonschema
import pytest

from sinergy_ai_blockchain.v4 import (
    POLICY_PROFILE,
    CommitmentEnvelopeV4,
    CommitmentPolicyV4Error,
    CommitmentV4InvariantError,
    allowed_payload_schemas_v4,
    validate_commitment_schema_binding_v4,
)

ROOT=Path(__file__).resolve().parents[1]
TRACE=ROOT/'fixtures/conformance/economic_cycle_trace_v5_complete.json'
RECOG=ROOT/'fixtures/conformance/revenue_recognition_v2_canonical.json'
EVENT=ROOT/'fixtures/conformance/ledger_event_v1_recognized_revenue.json'
SCHEMA=ROOT/'schemas/commitment_envelope_v4.schema.json'

def load(path):return json.loads(path.read_text(encoding='utf-8'))

def envelope(domain,schema,payload,subject):
 return CommitmentEnvelopeV4.from_payload(logical_domain=domain,network_domain='offchain:reference',verifier_id='sinergy-federation-v4',payload_schema=schema,subject_id=subject,sequence=5,as_of=datetime(2026,8,19,12,0,tzinfo=UTC),payload=payload,signer_policy='research-no-signature-v4')

def test_v4_policy_latest_generations_are_explicit_and_old_traces_are_provenance_only():
 assert allowed_payload_schemas_v4('ECONOMIC_CYCLE_TRACE')[-1]=='economic.cycle-trace/v5'
 assert validate_commitment_schema_binding_v4('ECONOMIC_CYCLE_TRACE','economic.cycle-trace/v5',require_latest=True).latest_for_domain is True
 with pytest.raises(CommitmentPolicyV4Error):validate_commitment_schema_binding_v4('ECONOMIC_CYCLE_TRACE','economic.cycle-trace/v4',require_latest=True)

def test_trace_v5_is_finalized_externally_without_self_reference():
 payload=load(TRACE);env=envelope('ECONOMIC_CYCLE_TRACE','economic.cycle-trace/v5',payload,payload['cycle_id'])
 assert payload['trust_finalization']=='EXTERNAL_COMMITMENT_REQUIRED'
 assert 'TRUST_COMMITMENT' not in [r['phase'] for r in payload['references']]
 assert env.payload_digest=='67933a4e517d4a3fbdb42776dfd4183809db139046e35da6d348fa2a408c57a9'
 assert env.commitment_digest=='b8a1737da1bc6a8b435f7d3a05f34d997ea229561e33a9003f0c0ccac7c184c4'
 assert env.policy_profile==POLICY_PROFILE

def test_trace_v5_without_external_finalization_marker_is_rejected_even_with_new_hash():
 payload=load(TRACE);payload['trust_finalization']='NONE'
 with pytest.raises(CommitmentV4InvariantError,match='external commitment'):
  envelope('ECONOMIC_CYCLE_TRACE','economic.cycle-trace/v5',payload,payload['cycle_id'])

def test_revenue_recognition_and_ledger_event_are_typed_separately():
 recog=load(RECOG);event=load(EVENT)
 er=envelope('REVENUE_RECOGNITION','revenue.recognition/v2',recog,recog['recognition_id'])
 ee=envelope('LEDGER_EVENT','ledger.event/v1',event,event['event_id'])
 assert er.domain=='SINERGY:REVENUE_RECOGNITION';assert ee.domain=='SINERGY:LEDGER_EVENT'
 with pytest.raises(CommitmentPolicyV4Error):validate_commitment_schema_binding_v4('LEDGER_EVENT','revenue.recognition/v2')

def test_envelope_v4_schema_requires_policy_profile():
 payload=load(TRACE);env=envelope('ECONOMIC_CYCLE_TRACE','economic.cycle-trace/v5',payload,payload['cycle_id']);schema=load(SCHEMA)
 jsonschema.Draft202012Validator.check_schema(schema);jsonschema.Draft202012Validator(schema).validate(env.to_canonical_dict())
 broken=env.to_canonical_dict();broken.pop('policy_profile');assert list(jsonschema.Draft202012Validator(schema).iter_errors(broken))
