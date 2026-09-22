use core::fmt;
use zeroize::Zeroize;

pub const ML_KEM_1024_PUBLIC_KEY_BYTES: usize = 1568;
pub const ML_KEM_1024_CIPHERTEXT_BYTES: usize = 1568;
pub const ML_KEM_SHARED_SECRET_BYTES: usize = 32;

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

impl TransportPeerIdentity {
    pub fn validate_for_policy(&self, policy: TransportPolicy) -> Result<(), &'static str> {
        if self.node_id == [0u8; 32] {
            return Err("transport node id required");
        }
        if self.ml_kem1024_public_key.len() != ML_KEM_1024_PUBLIC_KEY_BYTES {
            return Err("ML-KEM-1024 public key length mismatch");
        }
        if matches!(policy, TransportPolicy::Hybrid) && self.legacy_kex_public_key.is_empty() {
            return Err("hybrid transport requires legacy KEX public key");
        }
        Ok(())
    }
}

#[derive(PartialEq, Eq)]
pub struct HybridSharedSecret {
    pub pq_shared: Vec<u8>,
    pub classical_shared: Vec<u8>,
    pub transcript_hash: [u8; 32],
}

impl fmt::Debug for HybridSharedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HybridSharedSecret")
            .field("pq_shared", &"<redacted>")
            .field("classical_shared", &"<redacted>")
            .field("transcript_hash", &self.transcript_hash)
            .finish()
    }
}

impl Drop for HybridSharedSecret {
    fn drop(&mut self) {
        self.pq_shared.zeroize();
        self.classical_shared.zeroize();
    }
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
    if secret.pq_shared.len() != ML_KEM_SHARED_SECRET_BYTES
        || secret.transcript_hash == [0u8; 32]
    {
        return false;
    }
    match policy {
        TransportPolicy::PqOnly => true,
        TransportPolicy::Hybrid => secret.classical_shared.len() >= 32,
    }
}

pub const MAX_REKEY_MESSAGES: u64 = 1 << 20;
pub const MAX_REKEY_SECONDS: u64 = 300;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RekeyPolicy {
    pub max_messages: u64,
    pub max_seconds: u64,
}

impl RekeyPolicy {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.max_messages == 0 || self.max_seconds == 0 {
            return Err("rekey limits must be nonzero");
        }
        if self.max_messages > MAX_REKEY_MESSAGES {
            return Err("rekey message limit exceeds protocol maximum");
        }
        if self.max_seconds > MAX_REKEY_SECONDS {
            return Err("rekey time limit exceeds protocol maximum");
        }
        Ok(())
    }

    pub fn should_rekey(&self, messages_since_rekey: u64, seconds_since_rekey: u64) -> bool {
        self.validate().is_err()
            || messages_since_rekey >= self.max_messages
            || seconds_since_rekey >= self.max_seconds
    }
}

impl Default for RekeyPolicy {
    fn default() -> Self {
        Self {
            max_messages: MAX_REKEY_MESSAGES,
            max_seconds: MAX_REKEY_SECONDS,
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rekey_policy_is_bounded_and_fail_closed() {
        let policy = RekeyPolicy::default();
        assert_eq!(policy.validate(), Ok(()));
        assert!(!policy.should_rekey(MAX_REKEY_MESSAGES - 1, MAX_REKEY_SECONDS - 1));
        assert!(policy.should_rekey(MAX_REKEY_MESSAGES, 0));
        assert!(policy.should_rekey(0, MAX_REKEY_SECONDS));

        let disabled_by_zero = RekeyPolicy {
            max_messages: 0,
            max_seconds: MAX_REKEY_SECONDS,
        };
        assert!(disabled_by_zero.validate().is_err());
        assert!(disabled_by_zero.should_rekey(0, 0));

        let too_weak = RekeyPolicy {
            max_messages: MAX_REKEY_MESSAGES + 1,
            max_seconds: MAX_REKEY_SECONDS,
        };
        assert!(too_weak.validate().is_err());
        assert!(too_weak.should_rekey(0, 0));
    }

    #[test]
    fn peer_identity_enforces_ml_kem_size_and_hybrid_classical_key() {
        let mut peer = TransportPeerIdentity {
            node_id: [1u8; 32],
            ml_kem1024_public_key: vec![2u8; ML_KEM_1024_PUBLIC_KEY_BYTES],
            legacy_kex_public_key: vec![3u8; 33],
        };

        assert_eq!(peer.validate_for_policy(TransportPolicy::Hybrid), Ok(()));

        peer.ml_kem1024_public_key.pop();
        assert!(peer.validate_for_policy(TransportPolicy::PqOnly).is_err());

        peer.ml_kem1024_public_key = vec![2u8; ML_KEM_1024_PUBLIC_KEY_BYTES];
        peer.legacy_kex_public_key.clear();
        assert!(peer.validate_for_policy(TransportPolicy::Hybrid).is_err());
        assert_eq!(peer.validate_for_policy(TransportPolicy::PqOnly), Ok(()));
    }

    fn valid_secret() -> HybridSharedSecret {
        HybridSharedSecret {
            pq_shared: vec![1u8; ML_KEM_SHARED_SECRET_BYTES],
            classical_shared: vec![2u8; 32],
            transcript_hash: [3u8; 32],
        }
    }

    #[test]
    fn shared_secret_requires_exact_pq_size_and_nonzero_transcript() {
        let valid = valid_secret();
        assert!(validate_shared_secret(TransportPolicy::Hybrid, &valid));
        assert!(validate_shared_secret(TransportPolicy::PqOnly, &valid));

        let mut bad = valid_secret();
        bad.pq_shared.push(0);
        assert!(!validate_shared_secret(TransportPolicy::PqOnly, &bad));

        let mut bad = valid_secret();
        bad.transcript_hash = [0u8; 32];
        assert!(!validate_shared_secret(TransportPolicy::PqOnly, &bad));

        let mut bad = valid_secret();
        bad.classical_shared.clear();
        assert!(!validate_shared_secret(TransportPolicy::Hybrid, &bad));
        assert!(validate_shared_secret(TransportPolicy::PqOnly, &bad));
    }

    #[test]
    fn shared_secret_debug_redacts_key_material() {
        let secret = valid_secret();
        let debug = format!("{secret:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("1, 1, 1"));
        assert!(!debug.contains("2, 2, 2"));
    }
}
