//! Phase 2 — gossip dissemination for link-state advertisements.
//!
//! `MeshLinkAdvertisement`s (see `mesh_routing.rs`) flood via deterministic
//! fanout with duplicate suppression and TTL. Payloads stay opaque roots;
//! relay validity rules from the mesh layer still apply on delivery.

use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

use crate::pq::{
    verify_envelope_authorization, AuthPolicy, AuthorizationDomain, AuthorizationEnvelope,
    AuthorizationValidationContext, ContextSignatureVerifier, HybridAuthorization,
};

pub const GOSSIP_DOMAIN: &[u8] = b"SYNERGY/PQ-GOSSIP/V1\0";
pub const MAX_GOSSIP_PAYLOAD_BYTES: usize = 64 * 1024;
pub const MAX_GOSSIP_TTL: u8 = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GossipMessage {
    pub origin: [u8; 32],
    pub epoch: u64,
    pub ttl: u8,
    pub payload: Vec<u8>,
}

impl GossipMessage {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.origin == [0; 32] {
            return Err("gossip origin required");
        }
        if self.epoch == 0 {
            return Err("gossip epoch required");
        }
        if self.ttl == 0 || self.ttl > MAX_GOSSIP_TTL {
            return Err("gossip ttl out of range");
        }
        if self.payload.is_empty() || self.payload.len() > MAX_GOSSIP_PAYLOAD_BYTES {
            return Err("gossip payload length out of range");
        }
        Ok(())
    }

    pub fn msg_id(&self) -> Option<[u8; 32]> {
        self.validate().ok()?;
        let mut h = Sha256::new();
        h.update(GOSSIP_DOMAIN);
        h.update(crate::pq::CRYPTO_PROFILE_VERSION.to_be_bytes());
        h.update(self.origin);
        h.update(self.epoch.to_be_bytes());
        h.update((self.payload.len() as u64).to_be_bytes());
        h.update(&self.payload);
        Some(h.finalize().into())
    }

    /// Forward copy with decremented TTL (None at expiry — fail-closed).
    pub fn forward(&self) -> Option<Self> {
        self.validate().ok()?;
        if self.ttl <= 1 {
            return None;
        }
        Some(Self {
            origin: self.origin,
            epoch: self.epoch,
            ttl: self.ttl - 1,
            payload: self.payload.clone(),
        })
    }
}

/// Duplicate suppression with bounded memory (fail-closed when full).
#[derive(Debug, Default)]
pub struct GossipSeenCache {
    seen: HashSet<[u8; 32]>,
    max_entries: usize,
}

impl GossipSeenCache {
    pub fn new(max_entries: usize) -> Self {
        Self {
            seen: HashSet::new(),
            max_entries: if max_entries == 0 { 8192 } else { max_entries },
        }
    }

    /// Returns true on first sight (should forward), false on duplicate.
    pub fn observe(&mut self, msg: &GossipMessage) -> Result<bool, &'static str> {
        let id = msg.msg_id().ok_or("gossip message invalid")?;
        if self.seen.contains(&id) {
            return Ok(false);
        }
        if self.seen.len() >= self.max_entries {
            return Err("gossip seen-cache full (fail-closed)");
        }
        self.seen.insert(id);
        Ok(true)
    }
}

/// Deterministic fanout: sort candidates, take `fanout` excluding origin/self.
pub fn select_fanout(
    candidates: &[[u8; 32]],
    origin: &[u8; 32],
    self_node: &[u8; 32],
    msg_id: &[u8; 32],
    fanout: usize,
) -> Vec<[u8; 32]> {
    let mut scored: Vec<([u8; 32], [u8; 32])> = Vec::new();
    for c in candidates {
        if c == origin || c == self_node || c == &[0; 32] {
            continue;
        }
        let mut h = Sha256::new();
        h.update(msg_id);
        h.update(c);
        let score: [u8; 32] = h.finalize().into();
        scored.push((*c, score));
    }
    scored.sort_by(|a, b| a.1.cmp(&b.1).then(a.0.cmp(&b.0)));
    scored.into_iter().take(fanout).map(|(c, _)| c).collect()
}

/// Compatibility shim: advertisements are keyed by payload roots.
#[derive(Debug, Default)]
pub struct LinkAdvertisementIndex {
    by_root: HashMap<[u8; 32], GossipMessage>,
}
impl LinkAdvertisementIndex {
    pub fn insert(&mut self, msg: GossipMessage) -> Result<bool, &'static str> {
        let id = msg.msg_id().ok_or("gossip message invalid")?;
        if self.by_root.contains_key(&id) {
            return Ok(false);
        }
        self.by_root.insert(id, msg);
        Ok(true)
    }

    pub fn len(&self) -> usize {
        self.by_root.len()
    }
}

/// PQ-signed gossip envelope (Phase: close the unsigned-gossip gap).
///
/// Every relayed advertisement must arrive inside this envelope carrying a
/// `PqOnly` dual-signature authorization (ML-DSA-87 + SLH-DSA-SHAKE-256s)
/// over the gossip `msg_id`. Relays verify before forwarding; unsigned
/// gossip is dropped, never relayed.
pub const GOSSIP_ENVELOPE_DOMAIN: &[u8] = b"SYNERGY/PQ-GOSSIP/ENVELOPE/V1\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedGossipEnvelope {
    pub message: GossipMessage,
    pub authorization: HybridAuthorization,
    pub nonce: u64,
    pub expires_at: u64,
}

impl SignedGossipEnvelope {
    pub fn envelope(&self, network_id: [u8; 32]) -> Option<AuthorizationEnvelope> {
        let msg_id = self.message.msg_id()?;
        let mut hasher = Sha256::new();
        hasher.update(GOSSIP_ENVELOPE_DOMAIN);
        hasher.update(crate::pq::CRYPTO_PROFILE_VERSION.to_be_bytes());
        hasher.update(msg_id);
        hasher.update(self.message.origin);
        let payload_commitment: [u8; 32] = hasher.finalize().into();
        Some(AuthorizationEnvelope {
            chain_id: network_id,
            domain: AuthorizationDomain::GossipAdvertisement,
            epoch: self.message.epoch,
            nonce: self.nonce,
            expires_at: self.expires_at,
            payload_commitment,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignedGossipValidationContext {
    pub expected_network_id: [u8; 32],
    pub expected_origin: [u8; 32],
    pub expected_keyset_commitment: [u8; 32],
    pub now: u64,
    pub max_future_seconds: u64,
}

/// Verify a signed gossip envelope. Fail-closed on: non-PqOnly policy,
/// origin mismatch, keyset mismatch, bad/expired envelope, bad signatures.
pub fn verify_signed_gossip<V: ContextSignatureVerifier>(
    verifier: &V,
    signed: &SignedGossipEnvelope,
    validation: &SignedGossipValidationContext,
) -> bool {
    if signed.authorization.policy != AuthPolicy::PqOnly {
        return false;
    }
    if signed.message.origin != validation.expected_origin {
        return false;
    }
    if signed.authorization.keyset_commitment()
        != Some(validation.expected_keyset_commitment)
    {
        return false;
    }
    let envelope = match signed.envelope(validation.expected_network_id) {
        Some(envelope) => envelope,
        None => return false,
    };
    let auth_validation = AuthorizationValidationContext {
        expected_chain_id: validation.expected_network_id,
        expected_domain: AuthorizationDomain::GossipAdvertisement,
        expected_policy: AuthPolicy::PqOnly,
        expected_epoch: signed.message.epoch,
        expected_nonce: signed.nonce,
        now: validation.now,
        max_future_seconds: validation.max_future_seconds,
    };
    verify_envelope_authorization(verifier, &signed.authorization, &envelope, &auth_validation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pq::{AuthScheme, SignatureEvidence};
    use crate::pq::{
        ML_DSA_87_PUBLIC_KEY_BYTES, ML_DSA_87_SIGNATURE_BYTES,
        SLH_DSA_SHAKE_256S_PUBLIC_KEY_BYTES, SLH_DSA_SHAKE_256S_SIGNATURE_BYTES,
    };

    fn msg(ttl: u8) -> GossipMessage {
        GossipMessage {
            origin: [1; 32],
            epoch: 3,
            ttl,
            payload: vec![9, 9],
        }
    }

    #[test]
    fn gossip_dedup_and_ttl() {
        let m = msg(4);
        let mut cache = GossipSeenCache::new(8);
        assert_eq!(cache.observe(&m).unwrap(), true);
        assert_eq!(cache.observe(&m).unwrap(), false);
        let f = m.forward().unwrap();
        assert_eq!(f.ttl, 3);
        assert!(msg(1).forward().is_none());
    }

    #[test]
    fn gossip_fanout_deterministic_and_excludes() {
        let m = msg(8);
        let id = m.msg_id().unwrap();
        let peers = [[2; 32], [3; 32], [4; 32], [1; 32]];
        let a = select_fanout(&peers, &[1; 32], &[9; 32], &id, 2);
        let b = select_fanout(&peers, &[1; 32], &[9; 32], &id, 2);
        assert_eq!(a, b);
        assert_eq!(a.len(), 2);
        assert!(!a.contains(&[1; 32]));
    }

    #[test]
    fn gossip_rejects_bad_ttl_and_empty() {
        assert!(msg(0).validate().is_err());
        let mut m = msg(4);
        m.payload.clear();
        assert!(m.validate().is_err());
    }

    #[derive(Clone)]
    struct EnvelopeVerifier {
        accepted: Vec<(Vec<u8>, Vec<u8>)>,
    }

    impl ContextSignatureVerifier for EnvelopeVerifier {
        fn verify_with_context(
            &self,
            _scheme: AuthScheme,
            _public_key: &[u8],
            message: &[u8],
            context: &[u8],
            _signature: &[u8],
        ) -> bool {
            self.accepted
                .iter()
                .any(|(em, ec)| message == em && context == ec)
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

    fn signed_envelope() -> (SignedGossipEnvelope, SignedGossipValidationContext, EnvelopeVerifier) {
        let authorization = pq_only_authorization(11);
        let keyset = authorization.keyset_commitment().expect("keyset");
        let signed = SignedGossipEnvelope {
            message: msg(8),
            authorization,
            nonce: 7,
            expires_at: 1_000,
        };
        let network_id = [5; 32];
        let envelope = signed.envelope(network_id).expect("envelope");
        let verifier = EnvelopeVerifier {
            accepted: vec![(
                envelope
                    .canonical_message(AuthPolicy::PqOnly)
                    .expect("message"),
                envelope
                    .fips_signature_context(AuthPolicy::PqOnly)
                    .expect("context"),
            )],
        };
        let validation = SignedGossipValidationContext {
            expected_network_id: network_id,
            expected_origin: [1; 32],
            expected_keyset_commitment: keyset,
            now: 900,
            max_future_seconds: 200,
        };
        (signed, validation, verifier)
    }

    #[test]
    fn signed_gossip_verifies_and_binds_origin_keyset_policy() {
        let (signed, validation, verifier) = signed_envelope();
        assert!(verify_signed_gossip(&verifier, &signed, &validation));

        // Wrong origin.
        let mut bad = validation;
        bad.expected_origin = [9; 32];
        assert!(!verify_signed_gossip(&verifier, &signed, &bad));

        // Wrong keyset.
        let mut bad = validation;
        bad.expected_keyset_commitment = [9; 32];
        assert!(!verify_signed_gossip(&verifier, &signed, &bad));

        // Non-PQ policy.
        let mut bad_signed = signed.clone();
        bad_signed.authorization.policy = AuthPolicy::Max;
        assert!(!verify_signed_gossip(&verifier, &bad_signed, &validation));

        // Tampered payload: envelope binds a different msg_id.
        let mut tampered = signed.clone();
        tampered.message.payload = vec![8, 8];
        assert!(!verify_signed_gossip(&verifier, &tampered, &validation));

        // Expired envelope.
        let mut expired = validation;
        expired.now = 5_000;
        assert!(!verify_signed_gossip(&verifier, &signed, &expired));
    }
}
