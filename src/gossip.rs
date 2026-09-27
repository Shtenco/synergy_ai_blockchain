//! Phase 2 — gossip dissemination for link-state advertisements.
//!
//! `MeshLinkAdvertisement`s (see `mesh_routing.rs`) flood via deterministic
//! fanout with duplicate suppression and TTL. Payloads stay opaque roots;
//! relay validity rules from the mesh layer still apply on delivery.

use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

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

#[cfg(test)]
mod tests {
    use super::*;

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
}
