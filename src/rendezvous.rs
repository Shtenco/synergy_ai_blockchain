//! Phase 1 — NAT-traversal rendezvous via mesh relays (hole-punch cookies).
//!
//! Both peers behind NAT cannot dial each other directly. They agree on a
//! relay from the signed `PeerDirectory`, exchange punch cookies through it,
//! and then send simultaneous UDP datagrams (see `datagram.rs`). The relay
//! never learns session keys — it only forwards opaque cookie envelopes.
//!
//! Flow: `A -> relay: PunchOffer(cookie_a_root)` + `B -> relay:
//! PunchOffer(cookie_b_root)` -> relay fans both offers out ->
//! `A <-> B` direct datagrams carrying `punch_id` proof.

use sha2::{Digest, Sha256};

pub const RENDEZVOUS_DOMAIN: &[u8] = b"SYNERGY/PQ-RENDEZVOUS/V1\0";
pub const PUNCH_DOMAIN: &[u8] = b"SYNERGY/PQ-PUNCH/V1\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RendezvousIntent {
    pub network_id: [u8; 32],
    pub epoch: u64,
    pub initiator_node: [u8; 32],
    pub responder_node: [u8; 32],
    pub relay_node: [u8; 32],
    pub nonce: [u8; 32],
}

impl RendezvousIntent {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.network_id == [0; 32] || self.nonce == [0; 32] {
            return Err("rendezvous commitments required");
        }
        if self.epoch == 0 {
            return Err("rendezvous epoch required");
        }
        if self.initiator_node == [0; 32]
            || self.responder_node == [0; 32]
            || self.relay_node == [0; 32]
        {
            return Err("rendezvous nodes required");
        }
        if self.initiator_node == self.responder_node {
            return Err("rendezvous peers must be distinct");
        }
        if self.relay_node == self.initiator_node || self.relay_node == self.responder_node {
            return Err("rendezvous relay must be third party");
        }
        Ok(())
    }

    pub fn intent_root(&self) -> Option<[u8; 32]> {
        self.validate().ok()?;
        let mut h = Sha256::new();
        h.update(RENDEZVOUS_DOMAIN);
        h.update(crate::pq::CRYPTO_PROFILE_VERSION.to_be_bytes());
        h.update(self.network_id);
        h.update(self.epoch.to_be_bytes());
        h.update(self.initiator_node);
        h.update(self.responder_node);
        h.update(self.relay_node);
        h.update(self.nonce);
        Some(h.finalize().into())
    }
}

/// Opaque cookie offer forwarded by the relay (relay checks only roots).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PunchOffer {
    pub intent_root: [u8; 32],
    pub sender_node: [u8; 32],
    pub cookie_root: [u8; 32],
}

impl PunchOffer {
    pub fn validate(&self, intent: &RendezvousIntent) -> Result<(), &'static str> {
        intent.validate()?;
        if self.intent_root != intent.intent_root().ok_or("intent root unavailable")? {
            return Err("punch offer not bound to intent");
        }
        if self.sender_node != intent.initiator_node && self.sender_node != intent.responder_node {
            return Err("punch offer sender not part of intent");
        }
        if self.cookie_root == [0; 32] {
            return Err("punch cookie root required");
        }
        Ok(())
    }
}

/// Both cookies combined into the direct-path proof. Order-independent:
/// cookies are sorted so A and B derive the same `punch_id`.
pub fn derive_punch_id(
    intent: &RendezvousIntent,
    cookie_a: &[u8; 32],
    cookie_b: &[u8; 32],
) -> Option<[u8; 32]> {
    let root = intent.intent_root()?;
    if cookie_a == &[0; 32] || cookie_b == &[0; 32] {
        return None;
    }
    let (first, second) = if cookie_a <= cookie_b {
        (cookie_a, cookie_b)
    } else {
        (cookie_b, cookie_a)
    };
    let mut h = Sha256::new();
    h.update(PUNCH_DOMAIN);
    h.update(root);
    h.update(first);
    h.update(second);
    Some(h.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn intent() -> RendezvousIntent {
        RendezvousIntent {
            network_id: [1; 32],
            epoch: 4,
            initiator_node: [2; 32],
            responder_node: [3; 32],
            relay_node: [4; 32],
            nonce: [5; 32],
        }
    }

    #[test]
    fn rendezvous_intent_stable_and_third_party_relay() {
        let i = intent();
        assert_eq!(i.intent_root(), i.intent_root());
        let mut bad = i.clone();
        bad.relay_node = bad.initiator_node;
        assert!(bad.validate().is_err());
    }

    #[test]
    fn punch_id_order_independent() {
        let i = intent();
        let a = [11; 32];
        let b = [22; 32];
        assert_eq!(derive_punch_id(&i, &a, &b), derive_punch_id(&i, &b, &a));
    }

    #[test]
    fn punch_offer_bound_to_intent() {
        let i = intent();
        let root = i.intent_root().unwrap();
        let ok = PunchOffer {
            intent_root: root,
            sender_node: i.initiator_node,
            cookie_root: [9; 32],
        };
        assert!(ok.validate(&i).is_ok());
        let bad = PunchOffer {
            intent_root: [0; 32],
            sender_node: i.initiator_node,
            cookie_root: [9; 32],
        };
        assert!(bad.validate(&i).is_err());
    }
}
