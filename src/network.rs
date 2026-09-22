#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportPolicy {
    Hybrid,
    PqOnly,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportPeerIdentity {
    pub node_id: [u8; 32],
    pub ml_kem1024_public_key: Vec<u8>,
    pub legacy_kex_public_key: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HybridSharedSecret {
    pub pq_shared: Vec<u8>,
    pub classical_shared: Vec<u8>,
    pub transcript_hash: [u8; 32],
}

/// Provider boundary for a reviewed ML-KEM-1024 implementation.
pub trait MlKem1024Provider {
    type SecretHandle;

    fn encapsulate(&self, public_key: &[u8]) -> Option<(Vec<u8>, Vec<u8>)>;
    fn decapsulate(
        &self,
        secret_key_handle: &Self::SecretHandle,
        ciphertext: &[u8],
    ) -> Option<Vec<u8>>;
}

/// Consensus code does not implement a transport cipher here. The networking
/// stack feeds the resulting hybrid secret into its reviewed transcript-bound KDF.
pub fn validate_shared_secret(policy: TransportPolicy, secret: &HybridSharedSecret) -> bool {
    if secret.pq_shared.len() < 32 {
        return false;
    }
    match policy {
        TransportPolicy::PqOnly => true,
        TransportPolicy::Hybrid => secret.classical_shared.len() >= 32,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RekeyPolicy {
    pub max_messages: u64,
    pub max_seconds: u64,
}

impl Default for RekeyPolicy {
    fn default() -> Self {
        Self { max_messages: 1 << 20, max_seconds: 300 }
    }
}
