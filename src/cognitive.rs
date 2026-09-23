//! Bonded cognitive-service node primitives for the SYNERGY economic network.
//!
//! A CognitiveNode is not a consensus validator by default. It performs useful
//! AI/symbolic/retrieval/verifier work off-consensus and commits evidence/results
//! that deterministic policy or proofs can verify before payment.

use sha2::{Digest, Sha256};

use crate::pq::{
    verify_envelope_authorization, AuthPolicy, AuthorizationDomain, AuthorizationEnvelope,
    AuthorizationValidationContext, ContextSignatureVerifier, HybridAuthorization,
};

const COGNITIVE_EVIDENCE_DOMAIN: &[u8] = b"SYNERGY/COGNITIVE-EVIDENCE/V1\0";


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

impl CognitiveRole {
    pub const fn protocol_code(self) -> u8 {
        match self {
            Self::OperatorProposer => 1,
            Self::LogicVerifier => 2,
            Self::CyberCausal => 3,
            Self::LanguageBinder => 4,
            Self::WorldModel => 5,
            Self::KnowledgeOrgan => 6,
            Self::Critic => 7,
            Self::RetrievalMemory => 8,
            Self::DomainSpecialist => 9,
            Self::TrustGovernor => 10,
        }
    }
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

impl EvidenceKind {
    pub const fn protocol_code(self) -> u8 {
        match self {
            Self::Answer => 1,
            Self::Proof => 2,
            Self::Counterexample => 3,
            Self::Simulation => 4,
            Self::Retrieval => 5,
            Self::CausalTrace => 6,
            Self::Program => 7,
            Self::Verification => 8,
        }
    }
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


impl CognitiveEvidence {
    pub fn authorization_commitment(
        &self,
        request: &CognitiveWorkRequest,
        node: &CognitiveNodeManifest,
        epoch: u64,
    ) -> Option<[u8; 32]> {
        self.validate_against(request, node, epoch).ok()?;

        let mut hasher = Sha256::new();
        hasher.update(COGNITIVE_EVIDENCE_DOMAIN);
        hasher.update(self.request_id);
        hasher.update(self.node_id);
        hasher.update(self.model_root);
        hasher.update([self.evidence_kind.protocol_code()]);
        hasher.update(self.input_commitment);
        hasher.update(self.output_commitment);
        hasher.update(self.trace_commitment);
        hasher.update(self.proof_commitment);
        hasher.update(self.confidence_micros.to_be_bytes());
        hasher.update(self.uncertainty_micros.to_be_bytes());
        hasher.update(self.compute_units.to_be_bytes());
        hasher.update(self.quoted_price.to_be_bytes());

        hasher.update(request.requester);
        hasher.update([request.required_role.protocol_code()]);
        hasher.update(request.max_price.to_be_bytes());
        hasher.update(request.deadline_epoch.to_be_bytes());
        hasher.update(request.verification_policy_root);

        hasher.update(node.pq_identity_commitment);
        hasher.update(node.software_commitment);
        hasher.update(node.policy_root);
        Some(hasher.finalize().into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CognitiveEvidenceAuthorization {
    pub chain_id: [u8; 32],
    pub epoch: u64,
    pub nonce: u64,
    pub expires_at: u64,
    pub evidence: CognitiveEvidence,
    pub authorization: HybridAuthorization,
}

impl CognitiveEvidenceAuthorization {
    pub fn envelope(
        &self,
        request: &CognitiveWorkRequest,
        node: &CognitiveNodeManifest,
    ) -> Option<AuthorizationEnvelope> {
        Some(AuthorizationEnvelope {
            chain_id: self.chain_id,
            domain: AuthorizationDomain::CognitiveEvidence,
            epoch: self.epoch,
            nonce: self.nonce,
            expires_at: self.expires_at,
            payload_commitment: self
                .evidence
                .authorization_commitment(request, node, self.epoch)?,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CognitiveEvidenceValidationContext {
    pub expected_chain_id: [u8; 32],
    pub expected_epoch: u64,
    pub expected_nonce: u64,
    pub expected_node_id: [u8; 32],
    pub now: u64,
    pub max_future_seconds: u64,
}

pub fn verify_cognitive_evidence<V: ContextSignatureVerifier>(
    verifier: &V,
    request: &CognitiveWorkRequest,
    node: &CognitiveNodeManifest,
    authorized: &CognitiveEvidenceAuthorization,
    validation: &CognitiveEvidenceValidationContext,
) -> bool {
    if authorized.authorization.policy != AuthPolicy::PqOnly
        || node.node_id != validation.expected_node_id
        || node.pq_identity_commitment == [0u8; 32]
        || authorized.authorization.keyset_commitment() != Some(node.pq_identity_commitment)
        || authorized
            .evidence
            .validate_against(request, node, validation.expected_epoch)
            .is_err()
    {
        return false;
    }

    let envelope = match authorized.envelope(request, node) {
        Some(envelope) => envelope,
        None => return false,
    };

    let auth_validation = AuthorizationValidationContext {
        expected_chain_id: validation.expected_chain_id,
        expected_domain: AuthorizationDomain::CognitiveEvidence,
        expected_policy: AuthPolicy::PqOnly,
        expected_epoch: validation.expected_epoch,
        expected_nonce: validation.expected_nonce,
        now: validation.now,
        max_future_seconds: validation.max_future_seconds,
    };

    verify_envelope_authorization(
        verifier,
        &authorized.authorization,
        &envelope,
        &auth_validation,
    )
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
    use crate::pq::{
        AuthScheme, ContextSignatureVerifier, SignatureEvidence, ML_DSA_87_PUBLIC_KEY_BYTES,
        ML_DSA_87_SIGNATURE_BYTES, SLH_DSA_SHAKE_256S_PUBLIC_KEY_BYTES,
        SLH_DSA_SHAKE_256S_SIGNATURE_BYTES,
    };

    #[derive(Clone)]
    struct ExpectedVerifier {
        message: Vec<u8>,
        context: Vec<u8>,
    }

    impl ContextSignatureVerifier for ExpectedVerifier {
        fn verify_with_context(
            &self,
            _scheme: AuthScheme,
            _public_key: &[u8],
            message: &[u8],
            context: &[u8],
            _signature: &[u8],
        ) -> bool {
            message == self.message && context == self.context
        }
    }

    fn pq_only_authorization() -> HybridAuthorization {
        HybridAuthorization {
            policy: AuthPolicy::PqOnly,
            evidence: vec![
                SignatureEvidence {
                    scheme: AuthScheme::MlDsa87,
                    public_key: vec![0x51; ML_DSA_87_PUBLIC_KEY_BYTES],
                    signature: vec![0x52; ML_DSA_87_SIGNATURE_BYTES],
                },
                SignatureEvidence {
                    scheme: AuthScheme::SlhDsaShake256s,
                    public_key: vec![0x53; SLH_DSA_SHAKE_256S_PUBLIC_KEY_BYTES],
                    signature: vec![0x54; SLH_DSA_SHAKE_256S_SIGNATURE_BYTES],
                },
            ],
        }
    }

    fn node() -> CognitiveNodeManifest {
        let pq_identity_commitment = pq_only_authorization()
            .keyset_commitment()
            .expect("node keyset commitment");
        CognitiveNodeManifest {
            node_id: [1; 32],
            owner_account: [2; 32],
            pq_identity_commitment,
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
    fn cognitive_evidence_requires_registered_node_keyset() {
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
            quoted_price: 5,
        };
        let authorized = CognitiveEvidenceAuthorization {
            chain_id: [0xF1; 32],
            epoch: 10,
            nonce: 11,
            expires_at: 100,
            evidence,
            authorization: pq_only_authorization(),
        };
        let envelope = authorized
            .envelope(&request, &node)
            .expect("cognitive envelope");
        let verifier = ExpectedVerifier {
            message: envelope
                .canonical_message(AuthPolicy::PqOnly)
                .expect("message"),
            context: envelope
                .fips_signature_context(AuthPolicy::PqOnly)
                .expect("context"),
        };
        let validation = CognitiveEvidenceValidationContext {
            expected_chain_id: [0xF1; 32],
            expected_epoch: 10,
            expected_nonce: 11,
            expected_node_id: node.node_id,
            now: 20,
            max_future_seconds: 100,
        };

        assert!(verify_cognitive_evidence(
            &verifier,
            &request,
            &node,
            &authorized,
            &validation,
        ));

        let mut wrong_node = node.clone();
        wrong_node.pq_identity_commitment[0] ^= 1;
        assert!(!verify_cognitive_evidence(
            &verifier,
            &request,
            &wrong_node,
            &authorized,
            &validation,
        ));
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
