from __future__ import annotations
import hashlib, json
from pathlib import Path
from typing import Any

EXPECTED_DIGEST = "608b0ca91e905cb0345d345af9e1246489236a8e672a07fb60ea4cfb8691d397"
EXPECTED = {'schema': 'synergy.ai-blockchain-node-preproduction-commitment/v3', 'commitment_id': 'SYNERGY_AUTOPILOT_V5_AI_NODE_PREPRODUCTION_COMMITMENT_V3_20260824', 'node_id': 'synergy-autopilot-v5-ai-node', 'previous_commitment_digest': '1b47ae40ae48848be1648da5cc1c443232a47dc59969e70a6dd033672e5397c0', 'source_repository': 'Shtenco/agi_autopilot', 'source_commit': 'c39f6f0ee0e37c08366a63ec160c580b9ae954ba', 'integration_manifest_digest': 'a793250aaa2299fdaf1661e985423c2b62687a19395ceabcc7bb63c005defe54', 'nexus_artifact_sha256': 'e87d00809ff976c76655b892166ec1cf1f13a893927ead156295b6814fcd9325', 'synergynet_artifact_sha256': '7f22e68d80a7df879af71ebccdb45f8edb10cae3698bf07faa7076ce76fd0ef7', 'synergynet_location_evidence_v3_digest': 'b1ca1c1f5849deac30a0aac14748c21b8a74a26776ba2134a448c9427a839220', 'synergynet_transport_binding_v2_digest': '0c58185ea0af4a8abc7ce215c0b7ff077cea9357e831b9d197ec730a34ed6c7e', 'meta_os_profile_v3_digest': '96ea31f50ff61b478390d682e88cca89c806e88dbaef1c4fc53b109724ca8222', 'meta_os_admission_v3_digest': 'b1c151d4d5095278006d338c65f3a56b4853c3b3aa70a429205bea84fc5770e8', 'production_bootstrap_v4_digest': '39d262d4d6b28ceba3f6ffacadebd79d023e214ba63db6dbef6f5a3ad15547c6', 'federation_registry_v3_digest': 'af24fe8c4b3ddfd8832f7e5ac6d92b2d4d69761cb9ab869407cd4d085e475526', 'preproduction_rc4_digest': 'a7239ebf88b07f41b390120e3b3e23448e28548b3b9d981eb80a1fc014325803', 'historical_lab_deployment_evidence_digest': '8e1b05dca7e349d57e1908dca717d2c1d451ca79adde5cfe539e9e46f83d052b', 'historical_lab_deployment_result_digest': '011c3ce24cfd33dc99fbdea0ea2f5dcd344deefd927f57c1b9c1fa3e3eaa3833', 'artifact_resolution_status': 'RESOLVED_CURRENT_GITHUB_GIT_CARRIER', 'federation_alignment_status': 'LOCATION_V3_TRANSPORT_V2_META_V3_REGISTRY_V3_RC4_BOOTSTRAP_V4_BOUND', 'deployment_stage': 'PREPRODUCTION_NOT_RUNNING', 'current_running': False, 'submission_status': 'NOT_SUBMITTED_CANDIDATE_ONLY', 'signing_authority': 'NONE', 'blockchain_submission_authority': 'NONE', 'financial_authority': 'NONE', 'payment_authority': 'NONE', 'accounting_authority': 'NONE', 'host_execution_authority': 'NONE', 'execution_authority': 'NONE'}

class CommitmentV3Error(ValueError):
    pass

def canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()

def verify(value: dict[str, Any]) -> str:
    if not isinstance(value, dict):
        raise CommitmentV3Error("commitment must be object")
    payload = dict(value)
    claimed = payload.pop("commitment_digest", None)
    actual = hashlib.sha256(canonical(payload)).hexdigest()
    if claimed != EXPECTED_DIGEST or actual != EXPECTED_DIGEST:
        raise CommitmentV3Error("commitment digest mismatch")
    if payload != EXPECTED:
        raise CommitmentV3Error("commitment identity/state/authority mismatch")
    return actual

def main() -> int:
    root = Path(__file__).resolve().parents[1]
    p = root / "registry" / "autopilot_v5_ai_node_preproduction_commitment_v3.json"
    d = verify(json.loads(p.read_text(encoding="utf-8")))
    print(json.dumps({"status":"PASS","commitment_digest":d}, sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
