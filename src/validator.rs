use crate::pq::{AuthScheme, SignatureVerifier};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValidatorPolicy {
    /// Migration mode: require both the legacy validator signature and ML-DSA.
    HybridTransition,
    /// Native post-quantum validator mode.
    PqOnly,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatorIdentity {
    pub validator_id: [u8; 32],
    pub legacy_public_key: Vec<u8>,
    pub ml_dsa87_public_key: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatorVoteProof {
    pub legacy_signature: Vec<u8>,
    pub ml_dsa87_signature: Vec<u8>,
}

/// Verify block/vote authorization with no OR downgrade. During migration both
/// classical and PQ signatures are required. After the PQ-only fork, only the
/// independently generated ML-DSA validator key is authoritative.
pub fn verify_validator_vote<V: SignatureVerifier>(
    verifier: &V,
    policy: ValidatorPolicy,
    legacy_scheme: AuthScheme,
    identity: &ValidatorIdentity,
    vote_message: &[u8],
    proof: &ValidatorVoteProof,
) -> bool {
    let pq_ok = verifier.verify(
        AuthScheme::MlDsa87,
        &identity.ml_dsa87_public_key,
        vote_message,
        &proof.ml_dsa87_signature,
    );
    if !pq_ok {
        return false;
    }
    match policy {
        ValidatorPolicy::PqOnly => true,
        ValidatorPolicy::HybridTransition => verifier.verify(
            legacy_scheme,
            &identity.legacy_public_key,
            vote_message,
            &proof.legacy_signature,
        ),
    }
}
