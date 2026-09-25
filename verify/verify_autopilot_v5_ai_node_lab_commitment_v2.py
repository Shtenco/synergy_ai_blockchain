from __future__ import annotations
import hashlib,json
from pathlib import Path

COMMITMENT="1b47ae40ae48848be1648da5cc1c443232a47dc59969e70a6dd033672e5397c0"
PREVIOUS="1d33a7c7da14cdb7543d4723a69e1b1842d215a43ba97fda4c25ff12cdb2d666"
REGISTRY="12bdca330d81b81ec0acb32cf974f12fb36c5e72e6a1fea8680dc5e8470b275d"
DEPLOYMENT_EVIDENCE="8e1b05dca7e349d57e1908dca717d2c1d451ca79adde5cfe539e9e46f83d052b"
DEPLOYMENT_RESULT="011c3ce24cfd33dc99fbdea0ea2f5dcd344deefd927f57c1b9c1fa3e3eaa3833"
class CommitmentError(ValueError): pass

def digest(v):
 b=dict(v);b.pop('commitment_digest',None);return hashlib.sha256(json.dumps(b,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def verify(v):
 if v.get('schema')!='synergy.ai-blockchain-node-deployment-commitment/v2' or digest(v)!=v.get('commitment_digest') or v.get('commitment_digest')!=COMMITMENT: raise CommitmentError('digest')
 if v.get('previous_node_commitment_digest')!=PREVIOUS or v.get('system_registry_v2_digest')!=REGISTRY: raise CommitmentError('lineage')
 if v.get('deployment_evidence_digest')!=DEPLOYMENT_EVIDENCE or v.get('deployment_result_digest')!=DEPLOYMENT_RESULT: raise CommitmentError('deployment')
 if v.get('lab_running_snapshot_status')!='RUNNING_VERIFIED' or v.get('final_state')!='STOPPED_AFTER_VERIFICATION' or v.get('current_running') is not False: raise CommitmentError('state')
 if v.get('production_status')!='NOT_RUNNING_NO_PERSISTENT_PRODUCTION_HOST': raise CommitmentError('production')
 if v.get('submission_status')!='NOT_SUBMITTED_CANDIDATE_ONLY' or v.get('signing_authority')!='NONE' or v.get('blockchain_submission_authority')!='NONE': raise CommitmentError('submission')
 for f in ('financial_authority','payment_authority','accounting_authority','execution_authority'):
  if v.get(f)!='NONE': raise CommitmentError(f)
 return v
if __name__=='__main__':
 p=Path(__file__).resolve().parents[1]/'registry/autopilot_v5_ai_node_lab_deployment_commitment_v2.json';verify(json.loads(p.read_text()));print('PASS',COMMITMENT)
