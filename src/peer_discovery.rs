//! Deterministic peer discovery records for the bounded MVP mesh.

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const NODE_RECORD_DOMAIN: &[u8] = b"SYNERGY/NODE-RECORD/V1\0";
pub const NODE_SET_DOMAIN: &[u8] = b"SYNERGY/NODE-SET/V1\0";
pub const MAX_MVP_PEERS: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeRecord {
    pub node_id: [u8; 32],
    pub endpoint_root: [u8; 32],
    pub transport_keyset_root: [u8; 32],
    pub pq_identity_commitment: [u8; 32],
    pub capability_root: [u8; 32],
    pub epoch: u64,
    pub sequence: u64,
    pub expires_at: u64,
}

impl NodeRecord {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.node_id == [0; 32]
            || self.endpoint_root == [0; 32]
            || self.transport_keyset_root == [0; 32]
            || self.pq_identity_commitment == [0; 32]
            || self.capability_root == [0; 32]
        {
            return Err("node record commitments required");
        }
        if self.epoch == 0 || self.sequence == 0 || self.expires_at == 0 {
            return Err("node record epoch/sequence/expiry required");
        }
        Ok(())
    }
    pub fn commitment(&self) -> Option<[u8; 32]> {
        self.validate().ok()?;
        let mut h = Sha256::new();
        h.update(NODE_RECORD_DOMAIN);
        h.update(crate::pq::CRYPTO_PROFILE_VERSION.to_be_bytes());
        h.update(self.node_id);
        h.update(self.endpoint_root);
        h.update(self.transport_keyset_root);
        h.update(self.pq_identity_commitment);
        h.update(self.capability_root);
        h.update(self.epoch.to_be_bytes());
        h.update(self.sequence.to_be_bytes());
        h.update(self.expires_at.to_be_bytes());
        Some(h.finalize().into())
    }
    pub fn live(&self, now: u64) -> bool {
        now > 0 && now <= self.expires_at && self.validate().is_ok()
    }
}

#[derive(Debug, Clone, Default)]
pub struct PeerDirectory {
    records: BTreeMap<[u8; 32], NodeRecord>,
}

impl PeerDirectory {
    pub fn upsert(&mut self, r: NodeRecord, now: u64) -> Result<(), &'static str> {
        r.validate()?;
        if !r.live(now) {
            return Err("stale node record");
        }
        if self.records.values().any(|existing| {
            existing.node_id != r.node_id
                && existing.live(now)
                && existing.pq_identity_commitment == r.pq_identity_commitment
        }) {
            return Err("PQ identity commitment already registered to another node");
        }
        match self.records.get(&r.node_id) {
            Some(old)
                if r.epoch < old.epoch
                    || (r.epoch == old.epoch && r.sequence <= old.sequence) =>
            {
                return Err("node record replay or downgrade");
            }
            Some(_) => {}
            None if self.records.len() >= MAX_MVP_PEERS => {
                return Err("peer directory capacity exceeded");
            }
            None => {}
        }
        self.records.insert(r.node_id, r);
        Ok(())
    }
    pub fn get(&self, id: &[u8; 32], now: u64) -> Option<&NodeRecord> {
        self.records.get(id).filter(|r| r.live(now))
    }
    pub fn live_nodes(&self, now: u64) -> Vec<&NodeRecord> {
        self.records.values().filter(|r| r.live(now)).collect()
    }
    pub fn commitment(&self, now: u64) -> Option<[u8; 32]> {
        let live = self.live_nodes(now);
        let count = u64::try_from(live.len()).ok()?;
        let mut h = Sha256::new();
        h.update(NODE_SET_DOMAIN);
        h.update(crate::pq::CRYPTO_PROFILE_VERSION.to_be_bytes());
        h.update(count.to_be_bytes());
        for r in live {
            h.update(r.commitment()?);
        }
        Some(h.finalize().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn r(seq: u64) -> NodeRecord {
        NodeRecord {
            node_id: [1; 32],
            endpoint_root: [2; 32],
            transport_keyset_root: [3; 32],
            pq_identity_commitment: [4; 32],
            capability_root: [5; 32],
            epoch: 1,
            sequence: seq,
            expires_at: 100,
        }
    }
    #[test]
    fn node_commitment_binds_pq_signing_identity_separately_from_transport() {
        let record = r(1);
        let root = record.commitment().unwrap();

        let mut changed = record.clone();
        changed.pq_identity_commitment[0] ^= 1;
        assert_ne!(changed.commitment().unwrap(), root);

        let mut changed_transport = record;
        changed_transport.transport_keyset_root[0] ^= 1;
        assert_ne!(changed_transport.commitment().unwrap(), root);
    }

    #[test]
    fn rejects_same_pq_identity_under_different_node_ids() {
        let mut d = PeerDirectory::default();
        let first = r(1);
        d.upsert(first.clone(), 1).unwrap();

        let mut second = r(1);
        second.node_id = [9; 32];
        second.endpoint_root = [8; 32];
        second.transport_keyset_root = [7; 32];
        second.capability_root = [6; 32];

        assert_eq!(
            d.upsert(second, 1),
            Err("PQ identity commitment already registered to another node")
        );
        assert_eq!(d.records.len(), 1);
    }

    #[test]
    fn rejects_replay() {
        let mut d = PeerDirectory::default();
        assert!(d.upsert(r(1), 10).is_ok());
        assert!(d.upsert(r(1), 10).is_err());
        assert!(d.upsert(r(2), 10).is_ok());
    }
}
