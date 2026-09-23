use core::fmt;
use std::collections::BTreeSet;
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::pq::{
    verify_envelope_authorization, AuthPolicy, AuthorizationDomain, AuthorizationEnvelope,
    AuthorizationReplayState, AuthorizationValidationContext, ContextSignatureVerifier,
    HybridAuthorization,
};

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
pub struct TransportValidationContext {
    pub expected_network_id: [u8; 32],
    pub expected_epoch: u64,
    pub expected_session_id: [u8; 32],
}

pub trait TransportReplayGuard {
    fn consume_session(
        &mut self,
        network_id: &[u8; 32],
        epoch: u64,
        session_id: &[u8; 32],
        transcript_hash: &[u8; 32],
    ) -> bool;
}

pub const MAX_TRANSPORT_SESSIONS_PER_EPOCH: usize = 65_536;

#[derive(Clone)]
pub struct InMemoryTransportReplayGuard {
    network_id: [u8; 32],
    epoch: u64,
    consumed: BTreeSet<[u8; 32]>,
}

impl InMemoryTransportReplayGuard {
    pub fn new(network_id: [u8; 32], epoch: u64) -> Option<Self> {
        if network_id == [0u8; 32] {
            return None;
        }
        Some(Self {
            network_id,
            epoch,
            consumed: BTreeSet::new(),
        })
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn consumed_sessions(&self) -> usize {
        self.consumed.len()
    }

    pub fn rotate_epoch(&mut self, new_epoch: u64) -> bool {
        if new_epoch <= self.epoch {
            return false;
        }
        self.epoch = new_epoch;
        self.consumed.clear();
        true
    }
}

impl TransportReplayGuard for InMemoryTransportReplayGuard {
    fn consume_session(
        &mut self,
        network_id: &[u8; 32],
        epoch: u64,
        session_id: &[u8; 32],
        transcript_hash: &[u8; 32],
    ) -> bool {
        if network_id != &self.network_id
            || epoch != self.epoch
            || session_id == &[0u8; 32]
            || transcript_hash == &[0u8; 32]
            || self.consumed.len() >= MAX_TRANSPORT_SESSIONS_PER_EPOCH
        {
            return false;
        }

        self.consumed.insert(*session_id)
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

const TRANSPORT_HANDSHAKE_AUTH_DOMAIN: &[u8] = b"SYNERGY/PQ-TRANSPORT/AUTH/V1\0";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportPeerAuthorization {
    pub role: TransportRole,
    pub nonce: u64,
    pub expires_at: u64,
    pub authorization: HybridAuthorization,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransportPeerAuthorizationValidationContext {
    pub expected_node_id: [u8; 32],
    pub expected_keyset_commitment: [u8; 32],
    pub now: u64,
    pub max_future_seconds: u64,
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
pub const TRANSPORT_KDF_DOMAIN: &[u8] = b"SYNERGY/PQ-TRANSPORT/KDF\0";
pub const TRANSPORT_KDF_PROTOCOL_CODE: u8 = 1; // HKDF-SHA256
pub const TRANSPORT_SESSION_KEY_BYTES: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportTranscript {
    pub network_id: [u8; 32],
    pub epoch: u64,
    pub session_id: [u8; 32],
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
        if self.network_id == [0u8; 32] {
            return Err("transport network id required");
        }
        if self.session_id == [0u8; 32] {
            return Err("transport session id required");
        }
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

    pub fn validate_in_context(
        &self,
        context: &TransportValidationContext,
    ) -> Result<(), &'static str> {
        self.validate()?;
        if self.network_id != context.expected_network_id {
            return Err("transport network mismatch");
        }
        if self.epoch != context.expected_epoch {
            return Err("transport epoch mismatch");
        }
        if self.session_id != context.expected_session_id {
            return Err("transport session mismatch");
        }
        Ok(())
    }

    pub fn commitment_in_context(
        &self,
        context: &TransportValidationContext,
    ) -> Option<[u8; 32]> {
        self.validate_in_context(context).ok()?;
        self.commitment()
    }

    pub fn commitment(&self) -> Option<[u8; 32]> {
        self.validate().ok()?;

        fn put_len_prefixed(hasher: &mut Sha256, bytes: &[u8]) -> Option<()> {
            let len = u64::try_from(bytes.len()).ok()?;
            hasher.update(len.to_be_bytes());
            hasher.update(bytes);
            Some(())
        }

        let mut hasher = Sha256::new();
        hasher.update(TRANSPORT_TRANSCRIPT_DOMAIN);
        hasher.update(crate::pq::CRYPTO_PROFILE_VERSION.to_be_bytes());
        hasher.update([ML_KEM_1024_PROTOCOL_CODE]);
        hasher.update([TRANSPORT_KDF_PROTOCOL_CODE]);
        hasher.update(self.network_id);
        hasher.update(self.epoch.to_be_bytes());
        hasher.update(self.session_id);
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
            put_len_prefixed(&mut hasher, &peer.ml_kem1024_public_key)?;
            match peer.legacy_kex_scheme {
                Some(scheme) => {
                    hasher.update([1, scheme.protocol_code()]);
                    put_len_prefixed(&mut hasher, &peer.legacy_kex_public_key)?;
                }
                None => {
                    hasher.update([0, 0]);
                    put_len_prefixed(&mut hasher, &[])?;
                }
            }
        }

        put_len_prefixed(&mut hasher, &self.ml_kem_ciphertext)?;
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


impl TransportPeerAuthorization {
    fn peer_for_role<'a>(
        &self,
        transcript: &'a TransportTranscript,
    ) -> &'a TransportPeerIdentity {
        match self.role {
            TransportRole::Initiator => &transcript.initiator,
            TransportRole::Responder => &transcript.responder,
        }
    }

    pub fn envelope(&self, transcript: &TransportTranscript) -> Option<AuthorizationEnvelope> {
        let transcript_commitment = transcript.commitment()?;
        let peer = self.peer_for_role(transcript);

        let mut hasher = Sha256::new();
        hasher.update(TRANSPORT_HANDSHAKE_AUTH_DOMAIN);
        hasher.update(transcript_commitment);
        hasher.update([self.role.protocol_code()]);
        hasher.update(peer.node_id);
        let payload_commitment: [u8; 32] = hasher.finalize().into();

        Some(AuthorizationEnvelope {
            chain_id: transcript.network_id,
            domain: AuthorizationDomain::TransportHandshake,
            epoch: transcript.epoch,
            nonce: self.nonce,
            expires_at: self.expires_at,
            payload_commitment,
        })
    }
}

fn verify_transport_peer_authorization<V: ContextSignatureVerifier>(
    verifier: &V,
    transcript: &TransportTranscript,
    expected_role: TransportRole,
    authorized: &TransportPeerAuthorization,
    validation: &TransportPeerAuthorizationValidationContext,
) -> bool {
    if authorized.role != expected_role
        || authorized.authorization.policy != AuthPolicy::PqOnly
    {
        return false;
    }

    let peer = authorized.peer_for_role(transcript);
    if peer.node_id != validation.expected_node_id
        || authorized.authorization.keyset_commitment()
            != Some(validation.expected_keyset_commitment)
    {
        return false;
    }

    let envelope = match authorized.envelope(transcript) {
        Some(envelope) => envelope,
        None => return false,
    };
    let auth_validation = AuthorizationValidationContext {
        expected_chain_id: transcript.network_id,
        expected_domain: AuthorizationDomain::TransportHandshake,
        expected_policy: AuthPolicy::PqOnly,
        expected_epoch: transcript.epoch,
        expected_nonce: authorized.nonce,
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

pub struct HybridSharedSecret {
    policy: TransportPolicy,
    rekey_policy: RekeyPolicy,
    pq_shared: MlKemSharedSecret,
    classical_shared: Option<SecretBytes>,
    transcript_hash: [u8; 32],
}

impl HybridSharedSecret {
    pub(crate) fn from_transcript(
        pq_shared: MlKemSharedSecret,
        classical_shared: Option<SecretBytes>,
        transcript: &TransportTranscript,
        validation: &TransportValidationContext,
    ) -> Option<Self> {
        let transcript_hash = transcript.commitment_in_context(validation)?;
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

pub(crate) fn establish_shared_secret<G: TransportReplayGuard>(
    replay_guard: &mut G,
    pq_shared: MlKemSharedSecret,
    classical_shared: Option<SecretBytes>,
    transcript: &TransportTranscript,
    validation: &TransportValidationContext,
) -> Option<HybridSharedSecret> {
    // Validate transcript and secret material before consuming replay state.
    // Otherwise malformed local input could burn an otherwise valid session ID.
    let secret = HybridSharedSecret::from_transcript(
        pq_shared,
        classical_shared,
        transcript,
        validation,
    )?;
    let transcript_hash = *secret.transcript_hash();

    if !replay_guard.consume_session(
        &transcript.network_id,
        transcript.epoch,
        &transcript.session_id,
        &transcript_hash,
    ) {
        return None;
    }

    Some(secret)
}

pub fn establish_authenticated_shared_secret<G: TransportReplayGuard, V: ContextSignatureVerifier>(
    replay_guard: &mut G,
    initiator_replay: &mut AuthorizationReplayState,
    responder_replay: &mut AuthorizationReplayState,
    verifier: &V,
    pq_shared: MlKemSharedSecret,
    classical_shared: Option<SecretBytes>,
    transcript: &TransportTranscript,
    transport_validation: &TransportValidationContext,
    initiator_authorization: &TransportPeerAuthorization,
    initiator_validation: &TransportPeerAuthorizationValidationContext,
    responder_authorization: &TransportPeerAuthorization,
    responder_validation: &TransportPeerAuthorizationValidationContext,
) -> Option<HybridSharedSecret> {
    if initiator_validation.expected_node_id != transcript.initiator.node_id
        || responder_validation.expected_node_id != transcript.responder.node_id
        || initiator_validation.expected_keyset_commitment == [0u8; 32]
        || responder_validation.expected_keyset_commitment == [0u8; 32]
        || initiator_validation.expected_keyset_commitment
            == responder_validation.expected_keyset_commitment
        || !verify_transport_peer_authorization(
            verifier,
            transcript,
            TransportRole::Initiator,
            initiator_authorization,
            initiator_validation,
        )
        || !verify_transport_peer_authorization(
            verifier,
            transcript,
            TransportRole::Responder,
            responder_authorization,
            responder_validation,
        )
    {
        return None;
    }

    let initiator_envelope = initiator_authorization.envelope(transcript)?;
    let responder_envelope = responder_authorization.envelope(transcript)?;

    // Consume peer authorization on clones first. Real replay state is committed
    // only after the transport session itself is accepted, avoiding partial nonce burn.
    let mut next_initiator = initiator_replay.clone();
    let mut next_responder = responder_replay.clone();
    if !next_initiator.consume_verified_for_subject(
        &initiator_authorization.authorization,
        &initiator_envelope,
        transcript.initiator.node_id,
    ) || !next_responder.consume_verified_for_subject(
        &responder_authorization.authorization,
        &responder_envelope,
        transcript.responder.node_id,
    ) {
        return None;
    }

    let secret = establish_shared_secret(
        replay_guard,
        pq_shared,
        classical_shared,
        transcript,
        transport_validation,
    )?;

    *initiator_replay = next_initiator;
    *responder_replay = next_responder;
    Some(secret)
}

pub struct TransportSessionKey([u8; TRANSPORT_SESSION_KEY_BYTES]);

impl TransportSessionKey {
    pub fn as_bytes(&self) -> &[u8; TRANSPORT_SESSION_KEY_BYTES] {
        &self.0
    }
}

impl fmt::Debug for TransportSessionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TransportSessionKey(<redacted>)")
    }
}

impl Drop for TransportSessionKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub fn derive_transport_session_key(
    secret: &HybridSharedSecret,
) -> Option<TransportSessionKey> {
    if !validate_shared_secret(secret.policy(), secret) {
        return None;
    }

    let mut ikm = Vec::with_capacity(
        2 + ML_KEM_SHARED_SECRET_BYTES + CLASSICAL_SHARED_SECRET_BYTES,
    );
    ikm.push(1); // PQ component present.
    ikm.extend_from_slice(secret.pq_shared().as_bytes());

    match secret.classical_shared() {
        Some(classical) => {
            ikm.push(1);
            ikm.extend_from_slice(classical.as_bytes());
        }
        None => ikm.push(0),
    }

    let hkdf = Hkdf::<Sha256>::new(Some(secret.transcript_hash()), &ikm);
    ikm.zeroize();

    let mut info = Vec::with_capacity(
        TRANSPORT_KDF_DOMAIN.len() + 2 + 2 + 32,
    );
    info.extend_from_slice(TRANSPORT_KDF_DOMAIN);
    info.extend_from_slice(&crate::pq::CRYPTO_PROFILE_VERSION.to_be_bytes());
    info.push(match secret.policy() {
        TransportPolicy::Hybrid => 1,
        TransportPolicy::PqOnly => 2,
    });
    info.push(ML_KEM_1024_PROTOCOL_CODE);
    info.push(TRANSPORT_KDF_PROTOCOL_CODE);
    info.extend_from_slice(secret.transcript_hash());

    let mut output = [0u8; TRANSPORT_SESSION_KEY_BYTES];
    let expand_result = hkdf.expand(&info, &mut output);
    // RustCrypto hkdf 0.12.4/0.13.0 do not expose zeroize-on-drop for
    // internal PRK/HMAC state. Keep the object strictly local and drop it
    // immediately after the single expand operation.
    drop(hkdf);

    if expand_result.is_err() {
        info.zeroize();
        output.zeroize();
        return None;
    }
    info.zeroize();

    Some(TransportSessionKey(output))
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
    use crate::pq::{
        AuthScheme, SignatureEvidence, ML_DSA_87_PUBLIC_KEY_BYTES, ML_DSA_87_SIGNATURE_BYTES,
        SLH_DSA_SHAKE_256S_PUBLIC_KEY_BYTES, SLH_DSA_SHAKE_256S_SIGNATURE_BYTES,
    };

    #[derive(Clone)]
    struct HandshakeVerifier {
        accepted: Vec<(Vec<u8>, Vec<u8>)>,
    }

    impl ContextSignatureVerifier for HandshakeVerifier {
        fn verify_with_context(
            &self,
            _scheme: AuthScheme,
            _public_key: &[u8],
            message: &[u8],
            context: &[u8],
            _signature: &[u8],
        ) -> bool {
            self.accepted.iter().any(|(expected_message, expected_context)| {
                message == expected_message && context == expected_context
            })
        }
    }

    fn pq_only_authorization(seed: u8) -> HybridAuthorization {
        HybridAuthorization {
            policy: AuthPolicy::PqOnly,
            evidence: vec![
                SignatureEvidence {
                    scheme: AuthScheme::MlDsa87,
                    public_key: vec![seed; ML_DSA_87_PUBLIC_KEY_BYTES],
                    signature: vec![seed.wrapping_add(1); ML_DSA_87_SIGNATURE_BYTES],
                },
                SignatureEvidence {
                    scheme: AuthScheme::SlhDsaShake256s,
                    public_key: vec![seed.wrapping_add(2); SLH_DSA_SHAKE_256S_PUBLIC_KEY_BYTES],
                    signature: vec![seed.wrapping_add(3); SLH_DSA_SHAKE_256S_SIGNATURE_BYTES],
                },
            ],
        }
    }

    fn peer_authorization(
        transcript: &TransportTranscript,
        role: TransportRole,
        nonce: u64,
        seed: u8,
    ) -> (
        TransportPeerAuthorization,
        TransportPeerAuthorizationValidationContext,
    ) {
        let authorization = pq_only_authorization(seed);
        let peer = match role {
            TransportRole::Initiator => &transcript.initiator,
            TransportRole::Responder => &transcript.responder,
        };
        let validation = TransportPeerAuthorizationValidationContext {
            expected_node_id: peer.node_id,
            expected_keyset_commitment: authorization
                .keyset_commitment()
                .expect("transport peer keyset"),
            now: 900,
            max_future_seconds: 200,
        };
        (
            TransportPeerAuthorization {
                role,
                nonce,
                expires_at: 1_000,
                authorization,
            },
            validation,
        )
    }

    fn handshake_verifier(
        transcript: &TransportTranscript,
        initiator: &TransportPeerAuthorization,
        responder: &TransportPeerAuthorization,
    ) -> HandshakeVerifier {
        let accepted = [initiator, responder]
            .iter()
            .map(|authorized| {
                let envelope = authorized.envelope(transcript).expect("handshake envelope");
                (
                    envelope
                        .canonical_message(AuthPolicy::PqOnly)
                        .expect("handshake message"),
                    envelope
                        .fips_signature_context(AuthPolicy::PqOnly)
                        .expect("handshake context"),
                )
            })
            .collect();
        HandshakeVerifier { accepted }
    }

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
            network_id: [0xA0; 32],
            epoch: 7,
            session_id: [0xA1; 32],
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

    fn validation_for(transcript: &TransportTranscript) -> TransportValidationContext {
        TransportValidationContext {
            expected_network_id: transcript.network_id,
            expected_epoch: transcript.epoch,
            expected_session_id: transcript.session_id,
        }
    }

    #[test]
    fn in_memory_replay_guard_is_bounded_and_epoch_monotonic() {
        let network_id = [0xC1; 32];
        let mut guard = InMemoryTransportReplayGuard::new(network_id, 7)
            .expect("valid replay guard");
        let session = [0xC2; 32];
        let transcript = [0xC3; 32];

        assert!(guard.consume_session(&network_id, 7, &session, &transcript));
        assert!(!guard.consume_session(&network_id, 7, &session, &transcript));
        assert!(!guard.consume_session(
            &network_id,
            7,
            &session,
            &[0xC6; 32],
        ));
        assert!(!guard.consume_session(&[0xC4; 32], 7, &[0xC5; 32], &transcript));
        assert!(!guard.consume_session(&network_id, 8, &[0xC5; 32], &transcript));

        assert!(!guard.rotate_epoch(7));
        assert!(!guard.rotate_epoch(6));
        assert!(guard.rotate_epoch(8));
        assert_eq!(guard.epoch(), 8);
        assert_eq!(guard.consumed_sessions(), 0);
        assert!(guard.consume_session(&network_id, 8, &session, &transcript));
    }

    #[test]
    fn in_memory_replay_guard_rejects_zero_capabilities() {
        let network_id = [0xD1; 32];
        let mut guard = InMemoryTransportReplayGuard::new(network_id, 1)
            .expect("valid replay guard");
        assert!(!guard.consume_session(&network_id, 1, &[0u8; 32], &[1u8; 32]));
        assert!(!guard.consume_session(&network_id, 1, &[1u8; 32], &[0u8; 32]));
        assert!(InMemoryTransportReplayGuard::new([0u8; 32], 1).is_none());
    }

    #[derive(Default)]
    struct OneShotReplayGuard {
        used: std::collections::BTreeSet<([u8; 32], u64, [u8; 32], [u8; 32])>,
    }

    impl TransportReplayGuard for OneShotReplayGuard {
        fn consume_session(
            &mut self,
            network_id: &[u8; 32],
            epoch: u64,
            session_id: &[u8; 32],
            transcript_hash: &[u8; 32],
        ) -> bool {
            self.used
                .insert((*network_id, epoch, *session_id, *transcript_hash))
        }
    }

    fn valid_secret() -> HybridSharedSecret {
        let transcript = valid_transcript(TransportPolicy::Hybrid);
        let validation = validation_for(&transcript);
        let mut replay_guard = OneShotReplayGuard::default();
        establish_shared_secret(
            &mut replay_guard,
            MlKemSharedSecret::try_from_slice(&[1u8; ML_KEM_SHARED_SECRET_BYTES])
                .expect("fixed ML-KEM shared secret"),
            SecretBytes::new(vec![2u8; 32]),
            &transcript,
            &validation,
        )
        .expect("valid hybrid shared secret")
    }

    #[test]
    fn authenticated_transport_binds_both_peer_identities_and_consumes_once() {
        let transcript = valid_transcript(TransportPolicy::Hybrid);
        let transport_validation = validation_for(&transcript);
        let (initiator_auth, initiator_validation) =
            peer_authorization(&transcript, TransportRole::Initiator, 11, 0x21);
        let (responder_auth, responder_validation) =
            peer_authorization(&transcript, TransportRole::Responder, 12, 0x31);
        let verifier = handshake_verifier(&transcript, &initiator_auth, &responder_auth);

        let mut initiator_replay = AuthorizationReplayState::new_for_subject(
            transcript.network_id,
            AuthorizationDomain::TransportHandshake,
            AuthPolicy::PqOnly,
            transcript.initiator.node_id,
            transcript.epoch,
            initiator_auth.nonce,
        )
        .expect("initiator replay");
        let mut responder_replay = AuthorizationReplayState::new_for_subject(
            transcript.network_id,
            AuthorizationDomain::TransportHandshake,
            AuthPolicy::PqOnly,
            transcript.responder.node_id,
            transcript.epoch,
            responder_auth.nonce,
        )
        .expect("responder replay");
        let mut session_replay = OneShotReplayGuard::default();

        assert!(establish_authenticated_shared_secret(
            &mut session_replay,
            &mut initiator_replay,
            &mut responder_replay,
            &verifier,
            MlKemSharedSecret::try_from_slice(&[1u8; ML_KEM_SHARED_SECRET_BYTES])
                .expect("PQ secret"),
            SecretBytes::new(vec![2u8; CLASSICAL_SHARED_SECRET_BYTES]),
            &transcript,
            &transport_validation,
            &initiator_auth,
            &initiator_validation,
            &responder_auth,
            &responder_validation,
        )
        .is_some());
        assert_eq!(initiator_replay.next_nonce(), 12);
        assert_eq!(responder_replay.next_nonce(), 13);

        assert!(establish_authenticated_shared_secret(
            &mut session_replay,
            &mut initiator_replay,
            &mut responder_replay,
            &verifier,
            MlKemSharedSecret::try_from_slice(&[3u8; ML_KEM_SHARED_SECRET_BYTES])
                .expect("replay PQ secret"),
            SecretBytes::new(vec![4u8; CLASSICAL_SHARED_SECRET_BYTES]),
            &transcript,
            &transport_validation,
            &initiator_auth,
            &initiator_validation,
            &responder_auth,
            &responder_validation,
        )
        .is_none());
        assert_eq!(initiator_replay.next_nonce(), 12);
        assert_eq!(responder_replay.next_nonce(), 13);
    }

    #[test]
    fn transport_handshake_rejects_shared_authentication_keyset_between_peers() {
        let transcript = valid_transcript(TransportPolicy::Hybrid);
        let transport_validation = validation_for(&transcript);
        let (initiator_auth, initiator_validation) =
            peer_authorization(&transcript, TransportRole::Initiator, 11, 0x21);
        let (responder_auth, mut responder_validation) =
            peer_authorization(&transcript, TransportRole::Responder, 12, 0x31);
        responder_validation.expected_keyset_commitment =
            initiator_validation.expected_keyset_commitment;
        let verifier = handshake_verifier(&transcript, &initiator_auth, &responder_auth);

        let mut initiator_replay = AuthorizationReplayState::new_for_subject(
            transcript.network_id,
            AuthorizationDomain::TransportHandshake,
            AuthPolicy::PqOnly,
            transcript.initiator.node_id,
            transcript.epoch,
            11,
        )
        .expect("initiator replay");
        let mut responder_replay = AuthorizationReplayState::new_for_subject(
            transcript.network_id,
            AuthorizationDomain::TransportHandshake,
            AuthPolicy::PqOnly,
            transcript.responder.node_id,
            transcript.epoch,
            12,
        )
        .expect("responder replay");
        let mut session_replay = OneShotReplayGuard::default();

        assert!(establish_authenticated_shared_secret(
            &mut session_replay,
            &mut initiator_replay,
            &mut responder_replay,
            &verifier,
            MlKemSharedSecret::try_from_slice(&[1u8; ML_KEM_SHARED_SECRET_BYTES])
                .expect("PQ secret"),
            SecretBytes::new(vec![2u8; CLASSICAL_SHARED_SECRET_BYTES]),
            &transcript,
            &transport_validation,
            &initiator_auth,
            &initiator_validation,
            &responder_auth,
            &responder_validation,
        )
        .is_none());
        assert_eq!(initiator_replay.next_nonce(), 11);
        assert_eq!(responder_replay.next_nonce(), 12);
    }

    #[test]
    fn transport_handshake_rejects_role_swap() {
        let transcript = valid_transcript(TransportPolicy::Hybrid);
        let transport_validation = validation_for(&transcript);
        let (mut initiator_auth, initiator_validation) =
            peer_authorization(&transcript, TransportRole::Initiator, 11, 0x21);
        let (responder_auth, responder_validation) =
            peer_authorization(&transcript, TransportRole::Responder, 12, 0x31);
        let verifier = handshake_verifier(&transcript, &initiator_auth, &responder_auth);
        initiator_auth.role = TransportRole::Responder;

        let mut initiator_replay = AuthorizationReplayState::new_for_subject(
            transcript.network_id,
            AuthorizationDomain::TransportHandshake,
            AuthPolicy::PqOnly,
            transcript.initiator.node_id,
            transcript.epoch,
            11,
        )
        .expect("initiator replay");
        let mut responder_replay = AuthorizationReplayState::new_for_subject(
            transcript.network_id,
            AuthorizationDomain::TransportHandshake,
            AuthPolicy::PqOnly,
            transcript.responder.node_id,
            transcript.epoch,
            12,
        )
        .expect("responder replay");
        let mut session_replay = OneShotReplayGuard::default();

        assert!(establish_authenticated_shared_secret(
            &mut session_replay,
            &mut initiator_replay,
            &mut responder_replay,
            &verifier,
            MlKemSharedSecret::try_from_slice(&[1u8; ML_KEM_SHARED_SECRET_BYTES])
                .expect("PQ secret"),
            SecretBytes::new(vec![2u8; CLASSICAL_SHARED_SECRET_BYTES]),
            &transcript,
            &transport_validation,
            &initiator_auth,
            &initiator_validation,
            &responder_auth,
            &responder_validation,
        )
        .is_none());
        assert_eq!(initiator_replay.next_nonce(), 11);
        assert_eq!(responder_replay.next_nonce(), 12);
    }

    #[test]
    fn transport_session_replay_failure_does_not_burn_peer_auth_nonces() {
        let transcript = valid_transcript(TransportPolicy::Hybrid);
        let transport_validation = validation_for(&transcript);
        let (initiator_auth, initiator_validation) =
            peer_authorization(&transcript, TransportRole::Initiator, 11, 0x21);
        let (responder_auth, responder_validation) =
            peer_authorization(&transcript, TransportRole::Responder, 12, 0x31);
        let verifier = handshake_verifier(&transcript, &initiator_auth, &responder_auth);

        let mut initiator_replay = AuthorizationReplayState::new_for_subject(
            transcript.network_id,
            AuthorizationDomain::TransportHandshake,
            AuthPolicy::PqOnly,
            transcript.initiator.node_id,
            transcript.epoch,
            11,
        )
        .expect("initiator replay");
        let mut responder_replay = AuthorizationReplayState::new_for_subject(
            transcript.network_id,
            AuthorizationDomain::TransportHandshake,
            AuthPolicy::PqOnly,
            transcript.responder.node_id,
            transcript.epoch,
            12,
        )
        .expect("responder replay");
        let mut session_replay = OneShotReplayGuard::default();
        let transcript_hash = transcript.commitment().expect("transcript hash");
        assert!(session_replay.consume_session(
            &transcript.network_id,
            transcript.epoch,
            &transcript.session_id,
            &transcript_hash,
        ));

        assert!(establish_authenticated_shared_secret(
            &mut session_replay,
            &mut initiator_replay,
            &mut responder_replay,
            &verifier,
            MlKemSharedSecret::try_from_slice(&[1u8; ML_KEM_SHARED_SECRET_BYTES])
                .expect("PQ secret"),
            SecretBytes::new(vec![2u8; CLASSICAL_SHARED_SECRET_BYTES]),
            &transcript,
            &transport_validation,
            &initiator_auth,
            &initiator_validation,
            &responder_auth,
            &responder_validation,
        )
        .is_none());
        assert_eq!(initiator_replay.next_nonce(), 11);
        assert_eq!(responder_replay.next_nonce(), 12);
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

        let pq_transcript = valid_transcript(TransportPolicy::PqOnly);
        let pq_validation = validation_for(&pq_transcript);
        let mut replay_guard = OneShotReplayGuard::default();
        let pq_only = establish_shared_secret(
            &mut replay_guard,
            MlKemSharedSecret::try_from_slice(&[1u8; ML_KEM_SHARED_SECRET_BYTES])
                .expect("fixed ML-KEM shared secret"),
            None,
            &pq_transcript,
            &pq_validation,
        )
        .expect("valid PQ-only shared secret");
        assert!(!validate_shared_secret(TransportPolicy::Hybrid, &pq_only));
        assert!(validate_shared_secret(TransportPolicy::PqOnly, &pq_only));
    }

    #[test]
    fn hybrid_secret_rejects_oversized_classical_secret() {
        let transcript = valid_transcript(TransportPolicy::Hybrid);
        let validation = validation_for(&transcript);
        let mut replay_guard = OneShotReplayGuard::default();
        let secret = establish_shared_secret(
            &mut replay_guard,
            MlKemSharedSecret::try_from_slice(&[1u8; ML_KEM_SHARED_SECRET_BYTES])
                .expect("fixed ML-KEM shared secret"),
            SecretBytes::new(vec![2u8; CLASSICAL_SHARED_SECRET_BYTES + 1]),
            &transcript,
            &validation,
        );
        assert!(secret.is_none());
    }

    #[test]
    fn invalid_secret_material_does_not_burn_session_id() {
        let transcript = valid_transcript(TransportPolicy::Hybrid);
        let validation = validation_for(&transcript);
        let mut replay_guard = OneShotReplayGuard::default();

        let invalid = establish_shared_secret(
            &mut replay_guard,
            MlKemSharedSecret::try_from_slice(&[1u8; ML_KEM_SHARED_SECRET_BYTES])
                .expect("invalid-attempt ML-KEM shared secret"),
            None,
            &transcript,
            &validation,
        );
        assert!(invalid.is_none());

        let valid = establish_shared_secret(
            &mut replay_guard,
            MlKemSharedSecret::try_from_slice(&[2u8; ML_KEM_SHARED_SECRET_BYTES])
                .expect("valid-attempt ML-KEM shared secret"),
            SecretBytes::new(vec![3u8; CLASSICAL_SHARED_SECRET_BYTES]),
            &transcript,
            &validation,
        );
        assert!(valid.is_some());
    }

    #[test]
    fn shared_secret_establishment_consumes_session_exactly_once() {
        let transcript = valid_transcript(TransportPolicy::Hybrid);
        let validation = validation_for(&transcript);
        let mut replay_guard = OneShotReplayGuard::default();

        let first = establish_shared_secret(
            &mut replay_guard,
            MlKemSharedSecret::try_from_slice(&[1u8; ML_KEM_SHARED_SECRET_BYTES])
                .expect("first ML-KEM shared secret"),
            SecretBytes::new(vec![2u8; CLASSICAL_SHARED_SECRET_BYTES]),
            &transcript,
            &validation,
        );
        assert!(first.is_some());

        let second = establish_shared_secret(
            &mut replay_guard,
            MlKemSharedSecret::try_from_slice(&[3u8; ML_KEM_SHARED_SECRET_BYTES])
                .expect("second ML-KEM shared secret"),
            SecretBytes::new(vec![4u8; CLASSICAL_SHARED_SECRET_BYTES]),
            &transcript,
            &validation,
        );
        assert!(second.is_none());
    }

    #[test]
    fn transport_context_rejects_cross_network_epoch_and_session_replay() {
        let transcript = valid_transcript(TransportPolicy::Hybrid);
        let ok = validation_for(&transcript);
        assert!(transcript.validate_in_context(&ok).is_ok());

        let mut wrong = ok;
        wrong.expected_network_id = [0xB0; 32];
        assert!(transcript.validate_in_context(&wrong).is_err());

        let mut wrong = ok;
        wrong.expected_epoch += 1;
        assert!(transcript.validate_in_context(&wrong).is_err());

        let mut wrong = ok;
        wrong.expected_session_id = [0xB1; 32];
        assert!(transcript.validate_in_context(&wrong).is_err());
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
    fn transport_transcript_and_hkdf_match_independent_known_answer() {
        let transcript = valid_transcript(TransportPolicy::Hybrid);
        let commitment = transcript.commitment().expect("transcript commitment");
        assert_eq!(
            hex::encode(commitment),
            "7cedd002de19f032b45bdde3d99eef89eb9b12b30bbfbcf9e66740c060b297e8"
        );

        let validation = validation_for(&transcript);
        let mut replay_guard = OneShotReplayGuard::default();
        let secret = establish_shared_secret(
            &mut replay_guard,
            MlKemSharedSecret::try_from_slice(&[1u8; ML_KEM_SHARED_SECRET_BYTES])
                .expect("KAT PQ secret"),
            SecretBytes::new(vec![2u8; CLASSICAL_SHARED_SECRET_BYTES]),
            &transcript,
            &validation,
        )
        .expect("KAT hybrid secret");

        let session = derive_transport_session_key(&secret).expect("KAT session key");
        assert_eq!(
            hex::encode(session.as_bytes()),
            "c1bfa4aaaf544e95235f01fbdb40f392eb8d4869183f221713d05f2da8568890"
        );
    }

    #[test]
    fn transport_kdf_algorithm_code_is_nonzero_and_transcript_bound() {
        assert_ne!(TRANSPORT_KDF_PROTOCOL_CODE, 0);

        let base = valid_transcript(TransportPolicy::Hybrid);
        let commitment = base.commitment().expect("commitment");

        let mut hasher = Sha256::new();
        hasher.update(TRANSPORT_TRANSCRIPT_DOMAIN);
        hasher.update(crate::pq::CRYPTO_PROFILE_VERSION.to_be_bytes());
        hasher.update([ML_KEM_1024_PROTOCOL_CODE]);
        hasher.update([TRANSPORT_KDF_PROTOCOL_CODE.wrapping_add(1)]);
        hasher.update(base.network_id);
        let changed_prefix: [u8; 32] = hasher.finalize().into();

        assert_ne!(commitment, changed_prefix);
    }

    #[test]
    fn transport_kdf_is_transcript_and_policy_bound() {
        let hybrid = valid_secret();
        let hybrid_key = derive_transport_session_key(&hybrid).expect("hybrid session key");
        assert_eq!(hybrid_key.as_bytes().len(), TRANSPORT_SESSION_KEY_BYTES);

        let pq_transcript = valid_transcript(TransportPolicy::PqOnly);
        let pq_validation = validation_for(&pq_transcript);
        let mut replay_guard = OneShotReplayGuard::default();
        let pq_secret = establish_shared_secret(
            &mut replay_guard,
            MlKemSharedSecret::try_from_slice(&[1u8; ML_KEM_SHARED_SECRET_BYTES])
                .expect("PQ-only ML-KEM shared secret"),
            None,
            &pq_transcript,
            &pq_validation,
        )
        .expect("PQ-only shared secret");
        let pq_key = derive_transport_session_key(&pq_secret).expect("PQ-only session key");

        assert_ne!(hybrid_key.as_bytes(), pq_key.as_bytes());
    }

    #[test]
    fn transport_session_key_debug_is_redacted() {
        let key = derive_transport_session_key(&valid_secret()).expect("session key");
        assert_eq!(format!("{key:?}"), "TransportSessionKey(<redacted>)");
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
