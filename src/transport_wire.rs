//! Canonical wire-level handshake commitments for the MVP PQ transport.
//!
//! This module does not weaken the M2 dual-PQ authorization policy. It defines
//! the deterministic hello/transcript contract that a keystore/HSM signer signs
//! through the existing `TransportPeerAuthorization` path.

use sha2::{Digest, Sha256};

use crate::network::{
    RekeyPolicy, TransportPeerIdentity, TransportPolicy, TransportRole, TransportTranscript,
    ML_KEM_1024_CIPHERTEXT_BYTES,
};

pub const TRANSPORT_HELLO_DOMAIN: &[u8] = b"SYNERGY/PQ-TRANSPORT-HELLO/V1\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitiatorHello {
    pub network_id: [u8; 32],
    pub epoch: u64,
    pub session_id: [u8; 32],
    pub initiator: TransportPeerIdentity,
    pub endpoint_root: [u8; 32],
    pub rekey_policy: RekeyPolicy,
}

impl InitiatorHello {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.network_id == [0; 32]
            || self.epoch == 0
            || self.session_id == [0; 32]
            || self.endpoint_root == [0; 32]
        {
            return Err("initiator hello commitments required");
        }
        self.initiator
            .validate_for_policy(TransportPolicy::PqOnly)?;
        self.rekey_policy.validate()
    }

    pub fn commitment(&self) -> Option<[u8; 32]> {
        self.validate().ok()?;
        let mut h = Sha256::new();
        h.update(TRANSPORT_HELLO_DOMAIN);
        h.update(crate::pq::CRYPTO_PROFILE_VERSION.to_be_bytes());
        h.update([1]);
        h.update(self.network_id);
        h.update(self.epoch.to_be_bytes());
        h.update(self.session_id);
        h.update(self.initiator.node_id);
        h.update((self.initiator.ml_kem1024_public_key.len() as u64).to_be_bytes());
        h.update(&self.initiator.ml_kem1024_public_key);
        h.update(self.endpoint_root);
        h.update(self.rekey_policy.max_messages.to_be_bytes());
        h.update(self.rekey_policy.max_seconds.to_be_bytes());
        Some(h.finalize().into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponderHello {
    pub initiator_hello_root: [u8; 32],
    pub responder: TransportPeerIdentity,
    pub endpoint_root: [u8; 32],
    pub ml_kem_ciphertext: Vec<u8>,
}

impl ResponderHello {
    pub fn validate_against(&self, initiator: &InitiatorHello) -> Result<(), &'static str> {
        initiator.validate()?;
        if self.initiator_hello_root
            != initiator.commitment().ok_or("initiator root unavailable")?
        {
            return Err("responder hello not bound to initiator hello");
        }
        self.responder
            .validate_for_policy(TransportPolicy::PqOnly)?;
        if self.responder.node_id == initiator.initiator.node_id {
            return Err("transport peers must be distinct");
        }
        if self.responder.ml_kem1024_public_key == initiator.initiator.ml_kem1024_public_key {
            return Err("transport peers must use distinct ML-KEM keys");
        }
        if self.endpoint_root == [0; 32] {
            return Err("responder endpoint root required");
        }
        if self.ml_kem_ciphertext.len() != ML_KEM_1024_CIPHERTEXT_BYTES {
            return Err("ML-KEM ciphertext length mismatch");
        }
        Ok(())
    }

    pub fn commitment(&self, initiator: &InitiatorHello) -> Option<[u8; 32]> {
        self.validate_against(initiator).ok()?;
        let mut h = Sha256::new();
        h.update(TRANSPORT_HELLO_DOMAIN);
        h.update(crate::pq::CRYPTO_PROFILE_VERSION.to_be_bytes());
        h.update([2]);
        h.update(self.initiator_hello_root);
        h.update(self.responder.node_id);
        h.update((self.responder.ml_kem1024_public_key.len() as u64).to_be_bytes());
        h.update(&self.responder.ml_kem1024_public_key);
        h.update(self.endpoint_root);
        h.update((self.ml_kem_ciphertext.len() as u64).to_be_bytes());
        h.update(&self.ml_kem_ciphertext);
        Some(h.finalize().into())
    }

    pub fn transcript(&self, initiator: &InitiatorHello) -> Option<TransportTranscript> {
        self.validate_against(initiator).ok()?;
        let transcript = TransportTranscript {
            network_id: initiator.network_id,
            epoch: initiator.epoch,
            session_id: initiator.session_id,
            initiator: initiator.initiator.clone(),
            responder: self.responder.clone(),
            policy: TransportPolicy::PqOnly,
            rekey_policy: initiator.rekey_policy,
            ml_kem_recipient: TransportRole::Responder,
            ml_kem_ciphertext: self.ml_kem_ciphertext.clone(),
        };
        transcript.validate().ok()?;
        Some(transcript)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::{TransportPeerIdentity, ML_KEM_1024_PUBLIC_KEY_BYTES};

    fn peer(id: u8, key: u8) -> TransportPeerIdentity {
        TransportPeerIdentity {
            node_id: [id; 32],
            ml_kem1024_public_key: vec![key; ML_KEM_1024_PUBLIC_KEY_BYTES],
        }
    }

    #[test]
    fn hello_pair_builds_exact_pq_only_transcript() {
        let init = InitiatorHello {
            network_id: [1; 32],
            epoch: 1,
            session_id: [2; 32],
            initiator: peer(3, 4),
            endpoint_root: [5; 32],
            rekey_policy: RekeyPolicy {
                max_messages: 100,
                max_seconds: 60,
            },
        };
        let resp = ResponderHello {
            initiator_hello_root: init.commitment().unwrap(),
            responder: peer(6, 7),
            endpoint_root: [8; 32],
            ml_kem_ciphertext: vec![9; ML_KEM_1024_CIPHERTEXT_BYTES],
        };
        let transcript = resp.transcript(&init).expect("transcript");
        assert_eq!(transcript.policy, TransportPolicy::PqOnly);
        assert_eq!(transcript.initiator.node_id, [3; 32]);
        assert_eq!(transcript.responder.node_id, [6; 32]);
    }

    #[test]
    fn responder_cannot_switch_initiator_hello() {
        let a = InitiatorHello {
            network_id: [1; 32],
            epoch: 1,
            session_id: [2; 32],
            initiator: peer(3, 4),
            endpoint_root: [5; 32],
            rekey_policy: RekeyPolicy {
                max_messages: 100,
                max_seconds: 60,
            },
        };
        let mut b = a.clone();
        b.session_id = [10; 32];
        let resp = ResponderHello {
            initiator_hello_root: a.commitment().unwrap(),
            responder: peer(6, 7),
            endpoint_root: [8; 32],
            ml_kem_ciphertext: vec![9; ML_KEM_1024_CIPHERTEXT_BYTES],
        };
        assert!(resp.transcript(&b).is_none());
    }
}
