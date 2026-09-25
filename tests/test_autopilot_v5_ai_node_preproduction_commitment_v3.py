import copy, hashlib, json, unittest
from pathlib import Path
from verify.verify_autopilot_v5_ai_node_preproduction_commitment_v3 import verify, CommitmentV3Error, canonical

ROOT = Path(__file__).resolve().parents[1]

class CommitmentV3Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.value = json.loads((ROOT/"registry"/"autopilot_v5_ai_node_preproduction_commitment_v3.json").read_text(encoding="utf-8"))

    def test_canonical(self):
        self.assertEqual(verify(self.value), "608b0ca91e905cb0345d345af9e1246489236a8e672a07fb60ea4cfb8691d397")

    def test_reject_lineage_substitution_even_with_fresh_hash(self):
        fields = (
            "synergynet_location_evidence_v3_digest",
            "synergynet_transport_binding_v2_digest",
            "meta_os_profile_v3_digest",
            "meta_os_admission_v3_digest",
            "production_bootstrap_v4_digest",
            "federation_registry_v3_digest",
            "preproduction_rc4_digest",
        )
        for field in fields:
            candidate = copy.deepcopy(self.value)
            candidate[field] = "0"*64
            p = dict(candidate); p.pop("commitment_digest", None)
            candidate["commitment_digest"] = hashlib.sha256(canonical(p)).hexdigest()
            with self.subTest(field=field), self.assertRaises(CommitmentV3Error):
                verify(candidate)

    def test_reject_state_or_authority_escalation(self):
        for field, value in (
            ("current_running", True),
            ("submission_status", "SUBMITTED"),
            ("signing_authority", "ROOT"),
            ("blockchain_submission_authority", "ROOT"),
            ("financial_authority", "ROOT"),
            ("payment_authority", "ROOT"),
            ("accounting_authority", "ROOT"),
            ("host_execution_authority", "ROOT"),
            ("execution_authority", "ROOT"),
        ):
            candidate = copy.deepcopy(self.value)
            candidate[field] = value
            p = dict(candidate); p.pop("commitment_digest", None)
            candidate["commitment_digest"] = hashlib.sha256(canonical(p)).hexdigest()
            with self.subTest(field=field), self.assertRaises(CommitmentV3Error):
                verify(candidate)

if __name__ == "__main__":
    unittest.main()
