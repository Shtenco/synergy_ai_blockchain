#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LegacyChain {
    Bitcoin,
    Ethereum,
    Solana,
    Other(u32),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegacyIdentityBinding {
    pub source_chain: LegacyChain,
    /// Canonical raw address/public-key encoding for the source chain.
    pub legacy_identifier: Vec<u8>,
    /// Independent PQ public key. It MUST NOT be derived from the legacy private key.
    pub pq_public_key: Vec<u8>,
    pub synergy_account_id: [u8; 32],
    pub nonce: u64,
    pub expires_at: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MigrationError {
    EmptyLegacyIdentifier,
    EmptyPqKey,
    Expired,
    InvalidLegacyProof,
    InvalidPqProof,
}

pub trait LegacyProofVerifier {
    fn verify_legacy_ownership(&self, binding: &LegacyIdentityBinding, proof: &[u8]) -> bool;
}

pub trait PqBindingVerifier {
    fn verify_pq_possession(&self, binding: &LegacyIdentityBinding, proof: &[u8]) -> bool;
}

/// Require proof from BOTH sides of the binding. A legacy ECC/EdDSA private key is
/// only evidence of old-chain ownership; it is never used as entropy for the PQ key.
pub fn verify_binding<L: LegacyProofVerifier, P: PqBindingVerifier>(
    now: u64,
    binding: &LegacyIdentityBinding,
    legacy_proof: &[u8],
    pq_proof: &[u8],
    legacy: &L,
    pq: &P,
) -> Result<(), MigrationError> {
    if binding.legacy_identifier.is_empty() { return Err(MigrationError::EmptyLegacyIdentifier); }
    if binding.pq_public_key.is_empty() { return Err(MigrationError::EmptyPqKey); }
    if now > binding.expires_at { return Err(MigrationError::Expired); }
    if !legacy.verify_legacy_ownership(binding, legacy_proof) {
        return Err(MigrationError::InvalidLegacyProof);
    }
    if !pq.verify_pq_possession(binding, pq_proof) {
        return Err(MigrationError::InvalidPqProof);
    }
    Ok(())
}
