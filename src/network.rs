use core::fmt;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

pub const ML_KEM_1024_PROTOCOL_CODE: u8 = 1;
pub const ML_KEM_1024_PUBLIC_KEY_BYTES: usize = 1568;
pub const ML_KEM_1024_CIPHERTEXT_BYTES: usize = 1568;
pub const ML_KEM_SHARED_SECRET_BYTES: usize = 32;
pub const X25519_PUBLIC_KEY_BYTES: usize = 32;
pub const SECP256K1_KEX_PUBLIC_KEY_BYTES: usize = 33;
pub const CLASSICAL_SHARED_SECRET_BYTES: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportPolicy {
    Hybrid,
    PqOnly,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportRole {
    Initiator,
    Responder,
}

impl TransportRole {
    pub const fn protocol_code(self) -> u8 {
        match self {
            Self::Initiator => 1,
            Self::Responder => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClassicalKexScheme {
    X25519,
    Secp256k1,
}

impl ClassicalKexScheme {
    pub const fn protocol_code(self) -> u8 {
        match self {
            Self::X25519 => 1,
            Self::Secp256k1 => 2,
        }
    }

    pub const fn expected_public_key_bytes(self) -> usize {
        match self {
            Self::X25519 => X25519_PUBLIC_KEY_BYTES,
            Self::Secp256k1 => SECP256K1_KEX_PUBLIC_KEY_BYTES,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportPeerIdentity {
    pub node_id: [u8; 32],
    pub ml_kem1024_public_key: Vec<u8>,
    pub legacy_kex_scheme: Option<ClassicalKexScheme>,
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
        if self.ml_kem1024_public_key.iter().all(|byte| *byte == 0) {
            return Err("ML-KEM-1024 public key must not be all-zero");
        }
        match policy {
            TransportPolicy::PqOnly => {
                if self.legacy_kex_scheme.is_some() || !self.legacy_kex_public_key.is_empty() {
                    return Err("PQ-only transport forbids classical KEX material");
                }
            }
            TransportPolicy::Hybrid => {
                let scheme = self
                    .legacy_kex_scheme
                    .ok_or("hybrid transport requires classical KEX scheme")?;
                if self.legacy_kex_public_key.len() != scheme.expected_public_key_bytes() {
                    return Err("classical KEX public key length mismatch");
                }
                if self.legacy_kex_public_key.iter().all(|byte| *byte == 0) {
                    return Err("classical KEX public key must not be all-zero");
                }
                if scheme == ClassicalKexScheme::Secp256k1
                    && !matches!(self.legacy_kex_public_key.first(), Some(0x02 | 0x03))
                {
                    return Err("secp256k1 KEX public key must use compressed encoding");
                }
            }
        }
        Ok(())
    }
}

pub struct MlKemSharedSecret([u8; ML_KEM_SHARED_SECRET_BYTES]);

impl MlKemSharedSecret {
    pub fn try_from_slice(bytes: &[u8]) -> Option<Self> {
        let bytes: [u8; ML_KEM_SHARED_SECRET_BYTES] = bytes.try_into().ok()?;
        Some(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; ML_KEM_SHARED_SECRET_BYTES] {
        &self.0
    }
}

impl fmt::Debug for MlKemSharedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MlKemSharedSecret(<redacted>)")
    }
}

impl Drop for MlKemSharedSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Option<Self> {
        (bytes.len() == CLASSICAL_SHARED_SECRET_BYTES).then_some(Self(bytes))
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBytes(<redacted>)")
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub const TRANSPORT_TRANSCRIPT_DOMAIN: &[u8] = b"SYNERGY/PQ-TRANSPORT\0";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportTranscript {
    pub initiator: TransportPeerIdentity,
    pub responder: TransportPeerIdentity,
    pub policy: TransportPolicy,
    pub rekey_policy: RekeyPolicy,
    pub ml_kem_recipient: TransportRole,
    pub ml_kem_ciphertext: Vec<u8>,
    pub classical_transcript_hash: Option<[u8; 32]>,
}

impl TransportTranscript {
    pub fn validate(&self) -> Result<(), &'static str> {
        self.initiator.validate_for_policy(self.policy)?;
        self.responder.validate_for_policy(self.policy)?;
        self.rekey_policy.validate()?;

        if self.initiator.node_id == self.responder.node_id {
            return Err("transport peers must be distinct");
        }
        if self.initiator.ml_kem1024_public_key == self.responder.ml_kem1024_public_key {
            return Err("transport peers must use distinct ML-KEM public keys");
        }
        if matches!(self.policy, TransportPolicy::Hybrid) {
            if self.initiator.legacy_kex_scheme != self.responder.legacy_kex_scheme {
                return Err("hybrid transport peers must agree on classical KEX scheme");
            }
            if self.initiator.legacy_kex_public_key == self.responder.legacy_kex_public_key {
                return Err("hybrid transport peers must use distinct classical KEX public keys");
            }
        }
        if self.ml_kem_ciphertext.len() != ML_KEM_1024_CIPHERTEXT_BYTES {
            return Err("ML-KEM-1024 ciphertext length mismatch");
        }

        match self.policy {
            TransportPolicy::PqOnly => {
                if self.classical_transcript_hash.is_some() {
                    return Err("PQ-only transcript must not include classical transcript hash");
                }
            }
            TransportPolicy::Hybrid => {
                let classical = self
                    .classical_transcript_hash
                    .ok_or("hybrid transcript requires classical transcript hash")?;
                if classical == [0u8; 32] {
                    return Err("classical transcript hash must be nonzero");
                }
            }
        }

        Ok(())
    }

    pub fn commitment(&self) -> Option<[u8; 32]> {
        self.validate().ok()?;

        fn put_len_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
            hasher.update((bytes.len() as u64).to_be_bytes());
            hasher.update(bytes);
        }

        let mut hasher = Sha256::new();
        hasher.update(TRANSPORT_TRANSCRIPT_DOMAIN);
        hasher.update(crate::pq::CRYPTO_PROFILE_VERSION.to_be_bytes());
        hasher.update([ML_KEM_1024_PROTOCOL_CODE]);
        hasher.update([match self.policy {
            TransportPolicy::Hybrid => 1,
            TransportPolicy::PqOnly => 2,
        }]);
        hasher.update(self.rekey_policy.max_messages.to_be_bytes());
        hasher.update(self.rekey_policy.max_seconds.to_be_bytes());
        hasher.update([self.ml_kem_recipient.protocol_code()]);

        // Role order is canonical: initiator first, responder second.
        for peer in [&self.initiator, &self.responder] {
            hasher.update(peer.node_id);
            put_len_prefixed(&mut hasher, &peer.ml_kem1024_public_key);
            match peer.legacy_kex_scheme {
                Some(scheme) => {
                    hasher.update([1, scheme.protocol_code()]);
                    put_len_prefixed(&mut hasher, &peer.legacy_kex_public_key);
                }
                None => {
                    hasher.update([0, 0]);
                    put_len_prefixed(&mut hasher, &[]);
                }
            }
        }

        put_len_prefixed(&mut hasher, &self.ml_kem_ciphertext);
        match self.classical_transcript_hash {
            Some(hash) => {
                hasher.update([1]);
                hasher.update(hash);
            }
            None => hasher.update([0]),
        }

        Some(hasher.finalize().into())
    }
}

pub struct HybridSharedSecret {
    policy: TransportPolicy,
    rekey_policy: RekeyPolicy,
    pq_shared: MlKemSharedSecret,
    classical_shared: Option<SecretBytes>,
    transcript_hash: [u8; 32],
}

impl HybridSharedSecret {
    pub fn from_transcript(
        pq_shared: MlKemSharedSecret,
        classical_shared: Option<SecretBytes>,
        transcript: &TransportTranscript,
    ) -> Option<Self> {
        let transcript_hash = transcript.commitment()?;
        if transcript_hash == [0u8; 32] {
            return None;
        }

        match transcript.policy {
            TransportPolicy::PqOnly if classical_shared.is_some() => return None,
            TransportPolicy::Hybrid
                if classical_shared
                    .as_ref()
                    .map(|secret| {
                        secret.len() != CLASSICAL_SHARED_SECRET_BYTES
                    })
                    .unwrap_or(true) =>
            {
                return None;
            }
            _ => {}
        }

        Some(Self {
            policy: transcript.policy,
            rekey_policy: transcript.rekey_policy,
            pq_shared,
            classical_shared,
            transcript_hash,
        })
    }

    pub fn policy(&self) -> TransportPolicy {
        self.policy
    }

    pub fn rekey_policy(&self) -> RekeyPolicy {
        self.rekey_policy
    }

    pub fn should_rekey(&self, messages_since_rekey: u64, seconds_since_rekey: u64) -> bool {
        self.rekey_policy
            .should_rekey(messages_since_rekey, seconds_since_rekey)
    }

    pub fn pq_shared(&self) -> &MlKemSharedSecret {
        &self.pq_shared
    }

    pub fn classical_shared(&self) -> Option<&SecretBytes> {
        self.classical_shared.as_ref()
    }

    pub fn transcript_hash(&self) -> &[u8; 32] {
        &self.transcript_hash
    }
}

impl fmt::Debug for HybridSharedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HybridSharedSecret")
            .field("policy", &self.policy)
            .field("rekey_policy", &self.rekey_policy)
            .field("pq_shared", &"<redacted>")
            .field("classical_shared", &"<redacted>")
            .field("transcript_hash", &self.transcript_hash)
            .finish()
    }
}

/// Provider boundary for a reviewed ML-KEM-1024 implementation.
pub trait MlKem1024Provider {
    type SecretHandle;

    fn encapsulate(&self, public_key: &[u8]) -> Option<(Vec<u8>, MlKemSharedSecret)>;
    fn decapsulate(
        &self,
        secret_key_handle: &Self::SecretHandle,
        ciphertext: &[u8],
    ) -> Option<MlKemSharedSecret>;
}

/// Consensus code does not implement a transport cipher here. The networking
/// stack feeds the resulting hybrid secret into its reviewed transcript-bound KDF.
pub fn validate_shared_secret(policy: TransportPolicy, secret: &HybridSharedSecret) -> bool {
    if secret.policy() != policy
        || secret.transcript_hash() == &[0u8; 32]
        || secret.rekey_policy().validate().is_err()
    {
        return false;
    }
    match policy {
        TransportPolicy::PqOnly => true,
        TransportPolicy::Hybrid => secret
            .classical_shared()
            .map(|shared| {
                shared.len() == CLASSICAL_SHARED_SECRET_BYTES
            })
            .unwrap_or(false),
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
    fn transport_algorithm_registry_codes_are_nonzero_and_unique() {
        assert_ne!(ML_KEM_1024_PROTOCOL_CODE, 0);
        let kex = [
            ClassicalKexScheme::X25519.protocol_code(),
            ClassicalKexScheme::Secp256k1.protocol_code(),
        ];
        assert!(kex.iter().all(|code| *code != 0));
        assert_ne!(kex[0], kex[1]);
    }

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
            legacy_kex_scheme: Some(ClassicalKexScheme::Secp256k1),
            legacy_kex_public_key: {
                let mut key = vec![3u8; SECP256K1_KEX_PUBLIC_KEY_BYTES];
                key[0] = 0x02;
                key
            },
        };

        assert_eq!(peer.validate_for_policy(TransportPolicy::Hybrid), Ok(()));

        peer.ml_kem1024_public_key.pop();
        assert!(peer.validate_for_policy(TransportPolicy::PqOnly).is_err());

        peer.ml_kem1024_public_key = vec![2u8; ML_KEM_1024_PUBLIC_KEY_BYTES];
        peer.legacy_kex_public_key.pop();
        assert!(peer.validate_for_policy(TransportPolicy::Hybrid).is_err());

        peer.legacy_kex_scheme = None;
        peer.legacy_kex_public_key.clear();
        assert_eq!(peer.validate_for_policy(TransportPolicy::PqOnly), Ok(()));
        assert!(peer.validate_for_policy(TransportPolicy::Hybrid).is_err());
    }

    fn test_peer(node: u8) -> TransportPeerIdentity {
        TransportPeerIdentity {
            node_id: [node; 32],
            ml_kem1024_public_key: vec![node; ML_KEM_1024_PUBLIC_KEY_BYTES],
            legacy_kex_scheme: Some(ClassicalKexScheme::Secp256k1),
            legacy_kex_public_key: {
                let mut key = vec![node; SECP256K1_KEX_PUBLIC_KEY_BYTES];
                key[0] = 0x02;
                key
            },
        }
    }

    fn valid_transcript(policy: TransportPolicy) -> TransportTranscript {
        let mut initiator = test_peer(1);
        let mut responder = test_peer(2);
        if matches!(policy, TransportPolicy::PqOnly) {
            initiator.legacy_kex_scheme = None;
            initiator.legacy_kex_public_key.clear();
            responder.legacy_kex_scheme = None;
            responder.legacy_kex_public_key.clear();
        }

        TransportTranscript {
            initiator,
            responder,
            policy,
            rekey_policy: RekeyPolicy::default(),
            ml_kem_recipient: TransportRole::Responder,
            ml_kem_ciphertext: vec![3u8; ML_KEM_1024_CIPHERTEXT_BYTES],
            classical_transcript_hash: matches!(policy, TransportPolicy::Hybrid)
                .then_some([4u8; 32]),
        }
    }

    fn valid_secret() -> HybridSharedSecret {
        HybridSharedSecret::from_transcript(
            MlKemSharedSecret::try_from_slice(&[1u8; ML_KEM_SHARED_SECRET_BYTES])
                .expect("fixed ML-KEM shared secret"),
            SecretBytes::new(vec![2u8; 32]),
            &valid_transcript(TransportPolicy::Hybrid),
        )
        .expect("valid hybrid shared secret")
    }

    #[test]
    fn peer_identity_rejects_zero_and_noncanonical_kex_keys() {
        let mut peer = test_peer(7);
        peer.ml_kem1024_public_key.fill(0);
        assert!(peer.validate_for_policy(TransportPolicy::Hybrid).is_err());

        let mut peer = test_peer(7);
        peer.legacy_kex_public_key.fill(0);
        assert!(peer.validate_for_policy(TransportPolicy::Hybrid).is_err());

        let mut peer = test_peer(7);
        peer.legacy_kex_public_key[0] = 0x04;
        assert!(peer.validate_for_policy(TransportPolicy::Hybrid).is_err());

        let peer = TransportPeerIdentity {
            node_id: [8u8; 32],
            ml_kem1024_public_key: vec![8u8; ML_KEM_1024_PUBLIC_KEY_BYTES],
            legacy_kex_scheme: Some(ClassicalKexScheme::X25519),
            legacy_kex_public_key: vec![9u8; X25519_PUBLIC_KEY_BYTES],
        };
        assert_eq!(peer.validate_for_policy(TransportPolicy::Hybrid), Ok(()));
    }

    #[test]
    fn transport_classical_material_is_bounded() {
        assert!(SecretBytes::new(vec![1u8; CLASSICAL_SHARED_SECRET_BYTES]).is_some());
        assert!(SecretBytes::new(vec![1u8; CLASSICAL_SHARED_SECRET_BYTES + 1]).is_none());

        let peer = TransportPeerIdentity {
            node_id: [1u8; 32],
            ml_kem1024_public_key: vec![2u8; ML_KEM_1024_PUBLIC_KEY_BYTES],
            legacy_kex_scheme: Some(ClassicalKexScheme::X25519),
            legacy_kex_public_key: vec![3u8; X25519_PUBLIC_KEY_BYTES + 1],
        };
        assert!(peer.validate_for_policy(TransportPolicy::Hybrid).is_err());
        assert!(peer.validate_for_policy(TransportPolicy::PqOnly).is_err());
    }

    #[test]
    fn established_secret_uses_transcript_bound_rekey_policy() {
        let secret = valid_secret();
        let policy = secret.rekey_policy();
        assert!(!secret.should_rekey(policy.max_messages - 1, policy.max_seconds - 1));
        assert!(secret.should_rekey(policy.max_messages, 0));
        assert!(secret.should_rekey(0, policy.max_seconds));
    }

    #[test]
    fn shared_secret_requires_exact_pq_size_and_nonzero_transcript() {
        assert!(MlKemSharedSecret::try_from_slice(
            &[1u8; ML_KEM_SHARED_SECRET_BYTES - 1]
        )
        .is_none());
        assert!(MlKemSharedSecret::try_from_slice(
            &[1u8; ML_KEM_SHARED_SECRET_BYTES + 1]
        )
        .is_none());

        let valid = valid_secret();
        assert!(validate_shared_secret(TransportPolicy::Hybrid, &valid));
        assert!(!validate_shared_secret(TransportPolicy::PqOnly, &valid));

        assert_ne!(valid.transcript_hash(), &[0u8; 32]);

        let pq_only = HybridSharedSecret::from_transcript(
            MlKemSharedSecret::try_from_slice(&[1u8; ML_KEM_SHARED_SECRET_BYTES])
                .expect("fixed ML-KEM shared secret"),
            None,
            &valid_transcript(TransportPolicy::PqOnly),
        )
        .expect("valid PQ-only shared secret");
        assert!(!validate_shared_secret(TransportPolicy::Hybrid, &pq_only));
        assert!(validate_shared_secret(TransportPolicy::PqOnly, &pq_only));
    }

    #[test]
    fn hybrid_secret_rejects_oversized_classical_secret() {
        let secret = HybridSharedSecret::from_transcript(
            MlKemSharedSecret::try_from_slice(&[1u8; ML_KEM_SHARED_SECRET_BYTES])
                .expect("fixed ML-KEM shared secret"),
            SecretBytes::new(vec![2u8; CLASSICAL_SHARED_SECRET_BYTES + 1]),
            &valid_transcript(TransportPolicy::Hybrid),
        );
        assert!(secret.is_none());
    }

    #[test]
    fn hybrid_transcript_rejects_kex_algorithm_mismatch_and_key_reuse() {
        let mut mismatch = valid_transcript(TransportPolicy::Hybrid);
        mismatch.initiator.legacy_kex_scheme = Some(ClassicalKexScheme::X25519);
        mismatch.initiator.legacy_kex_public_key = vec![7u8; X25519_PUBLIC_KEY_BYTES];
        assert!(mismatch.commitment().is_none());

        let mut same_kem = valid_transcript(TransportPolicy::Hybrid);
        same_kem.responder.ml_kem1024_public_key =
            same_kem.initiator.ml_kem1024_public_key.clone();
        assert!(same_kem.commitment().is_none());

        let mut same_classical = valid_transcript(TransportPolicy::Hybrid);
        same_classical.responder.legacy_kex_public_key =
            same_classical.initiator.legacy_kex_public_key.clone();
        assert!(same_classical.commitment().is_none());
    }

    #[test]
    fn transcript_commitment_binds_ml_kem_recipient_role() {
        let base = valid_transcript(TransportPolicy::Hybrid);
        let commitment = base.commitment().expect("commitment");

        let mut changed = base;
        changed.ml_kem_recipient = TransportRole::Initiator;
        assert_ne!(commitment, changed.commitment().expect("changed commitment"));
    }

    #[test]
    fn transcript_commitment_binds_rekey_policy() {
        let base = valid_transcript(TransportPolicy::Hybrid);
        let commitment = base.commitment().expect("commitment");

        let mut changed = base.clone();
        changed.rekey_policy.max_messages -= 1;
        assert_ne!(commitment, changed.commitment().expect("changed commitment"));

        let mut invalid = base;
        invalid.rekey_policy.max_seconds = 0;
        assert!(invalid.commitment().is_none());
    }

    #[test]
    fn transcript_commitment_binds_roles_policy_keys_and_ciphertext() {
        let base = valid_transcript(TransportPolicy::Hybrid);
        let commitment = base.commitment().expect("commitment");

        let mut changed = base.clone();
        changed.initiator.node_id = [9u8; 32];
        assert_ne!(commitment, changed.commitment().expect("changed commitment"));

        let mut changed = base.clone();
        changed.ml_kem_ciphertext[0] ^= 1;
        assert_ne!(commitment, changed.commitment().expect("changed commitment"));

        let pq_only = valid_transcript(TransportPolicy::PqOnly);
        assert_ne!(commitment, pq_only.commitment().expect("PQ-only commitment"));

        let mut invalid = base;
        invalid.classical_transcript_hash = Some([0u8; 32]);
        assert!(invalid.commitment().is_none());
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
