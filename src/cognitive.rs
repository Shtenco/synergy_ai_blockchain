//! Bonded cognitive-service node primitives for the SYNERGY economic network.
//!
//! A CognitiveNode is not a consensus validator by default. It performs useful
//! AI/symbolic/retrieval/verifier work off-consensus and commits evidence/results
//! that deterministic policy or proofs can verify before payment.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CognitiveRole {
    OperatorProposer,
    LogicVerifier,
    CyberCausal,
    LanguageBinder,
    WorldModel,
    KnowledgeOrgan,
    Critic,
    RetrievalMemory,
    DomainSpecialist,
    TrustGovernor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceKind {
    Answer,
    Proof,
    Counterexample,
    Simulation,
    Retrieval,
    CausalTrace,
    Program,
    Verification,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CognitiveNodeManifest {
    pub node_id: [u8; 32],
    pub owner_account: [u8; 32],
    pub pq_identity_commitment: [u8; 32],
    pub software_commitment: [u8; 32],
    pub model_root: [u8; 32],
    pub policy_root: [u8; 32],
    pub role: CognitiveRole,
    pub trust_tier: u8,
    pub bond: u128,
    pub max_unit_price: u128,
    pub valid_from_epoch: u64,
    pub valid_until_epoch: u64,
}

impl CognitiveNodeManifest {
    pub fn validate(&self, epoch: u64) -> Result<(), &'static str> {
        if self.node_id == [0; 32]
            || self.owner_account == [0; 32]
            || self.pq_identity_commitment == [0; 32]
            || self.software_commitment == [0; 32]
            || self.model_root == [0; 32]
            || self.policy_root == [0; 32]
        {
            return Err("node commitments required");
        }
        if self.bond == 0 {
            return Err("cognitive node bond required");
        }
        if epoch < self.valid_from_epoch || epoch > self.valid_until_epoch {
            return Err("node manifest inactive");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CognitiveWorkRequest {
    pub request_id: [u8; 32],
    pub requester: [u8; 32],
    pub input_commitment: [u8; 32],
    pub required_role: CognitiveRole,
    pub max_price: u128,
    pub deadline_epoch: u64,
    pub verification_policy_root: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CognitiveEvidence {
    pub request_id: [u8; 32],
    pub node_id: [u8; 32],
    pub model_root: [u8; 32],
    pub evidence_kind: EvidenceKind,
    pub input_commitment: [u8; 32],
    pub output_commitment: [u8; 32],
    pub trace_commitment: [u8; 32],
    pub proof_commitment: [u8; 32],
    pub confidence_micros: u32,
    pub uncertainty_micros: u32,
    pub compute_units: u64,
    pub quoted_price: u128,
}

impl CognitiveEvidence {
    pub fn validate_against(
        &self,
        request: &CognitiveWorkRequest,
        node: &CognitiveNodeManifest,
        epoch: u64,
    ) -> Result<(), &'static str> {
        node.validate(epoch)?;
        if self.request_id != request.request_id || self.node_id != node.node_id {
            return Err("request/node mismatch");
        }
        if node.role != request.required_role {
            return Err("wrong cognitive role");
        }
        if self.input_commitment != request.input_commitment {
            return Err("input commitment mismatch");
        }
        if self.model_root != node.model_root {
            return Err("model root mismatch");
        }
        if self.output_commitment == [0; 32] {
            return Err("output commitment required");
        }
        if self.confidence_micros > 1_000_000 || self.uncertainty_micros > 1_000_000 {
            return Err("invalid calibration value");
        }
        if self.quoted_price > request.max_price || self.quoted_price > node.max_unit_price {
            return Err("price exceeds policy");
        }
        if epoch > request.deadline_epoch {
            return Err("work request expired");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkVerdict {
    Accepted,
    Rejected,
    Abstained,
    Disputed,
}

/// Payment/reputation may use only a deterministic verification receipt, never
/// the node's self-reported confidence alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CognitiveWorkReceipt {
    pub request_id: [u8; 32],
    pub node_id: [u8; 32],
    pub evidence_commitment: [u8; 32],
    pub verifier_commitment: [u8; 32],
    pub authority_commitment: [u8; 32],
    pub verdict: WorkVerdict,
    pub paid_amount: u128,
    pub slash_amount: u128,
    pub realized_utility_micros: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node() -> CognitiveNodeManifest {
        CognitiveNodeManifest {
            node_id: [1; 32],
            owner_account: [2; 32],
            pq_identity_commitment: [3; 32],
            software_commitment: [4; 32],
            model_root: [5; 32],
            policy_root: [6; 32],
            role: CognitiveRole::LogicVerifier,
            trust_tier: 1,
            bond: 100,
            max_unit_price: 10,
            valid_from_epoch: 1,
            valid_until_epoch: 100,
        }
    }

    #[test]
    fn rejects_self_priced_work_above_request_cap() {
        let node = node();
        let request = CognitiveWorkRequest {
            request_id: [7; 32],
            requester: [8; 32],
            input_commitment: [9; 32],
            required_role: CognitiveRole::LogicVerifier,
            max_price: 5,
            deadline_epoch: 50,
            verification_policy_root: [10; 32],
        };
        let evidence = CognitiveEvidence {
            request_id: request.request_id,
            node_id: node.node_id,
            model_root: node.model_root,
            evidence_kind: EvidenceKind::Verification,
            input_commitment: request.input_commitment,
            output_commitment: [11; 32],
            trace_commitment: [12; 32],
            proof_commitment: [13; 32],
            confidence_micros: 900_000,
            uncertainty_micros: 100_000,
            compute_units: 10,
            quoted_price: 6,
        };
        assert!(evidence.validate_against(&request, &node, 10).is_err());
    }
}
