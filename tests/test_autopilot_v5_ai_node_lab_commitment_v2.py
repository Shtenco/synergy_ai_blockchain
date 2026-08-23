from __future__ import annotations
import copy,hashlib,importlib.util,json,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('verify_mod',ROOT/'verify/verify_autopilot_v5_ai_node_lab_commitment_v2.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
P=ROOT/'registry/autopilot_v5_ai_node_lab_deployment_commitment_v2.json'
def load(): return json.loads(P.read_text())
def fresh(v):
 b=dict(v);b.pop('commitment_digest',None);v['commitment_digest']=hashlib.sha256(json.dumps(b,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()).hexdigest();return v
class TestCommitment(unittest.TestCase):
 def test_canonical(self): self.assertEqual(m.verify(load())['commitment_digest'],m.COMMITMENT)
 def test_adversarial(self):
  cases=[('current_running',True),('production_status','RUNNING'),('submission_status','SUBMITTED'),('signing_authority','AI_AUTONOMOUS'),('blockchain_submission_authority','SIGN_AND_SUBMIT'),('deployment_evidence_digest','0'*64),('system_registry_v2_digest','0'*64),('financial_authority','TREASURY'),('execution_authority','ROOT')]
  for field,value in cases:
   with self.subTest(field=field):
    v=copy.deepcopy(load());v[field]=value;fresh(v)
    with self.assertRaises(m.CommitmentError): m.verify(v)
if __name__=='__main__': unittest.main()
