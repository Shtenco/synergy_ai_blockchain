//! Phase 2 — Kademlia-style routing over PQ mesh addresses.
//!
//! Carries the exact signed `NodeRecord`s from `peer_discovery.rs`
//! (see `discovery.rs`: "future Kademlia may carry these exact records").
//! Distance is XOR over the 256-bit `MeshAddress`; contacts live in
//! 256 k-buckets (`K=20`). Eviction is fail-closed and deterministic:
//! a full bucket only replaces its oldest entry when the newcomer is
//! strictly fresher.

use std::collections::HashMap;

pub const DHT_KEY_BYTES: usize = 32;
pub const DHT_K: usize = 20;
pub const DHT_BUCKETS: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DhtNode {
    pub address: [u8; 32],
    pub last_seen_ms: u64,
}

impl DhtNode {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.address == [0; 32] {
            return Err("dht address required");
        }
        Ok(())
    }
}

pub fn xor_distance(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = a[i] ^ b[i];
    }
    out
}

/// Bucket index = position of the highest differing bit (0 = closest).
/// Identical keys have no bucket.
pub fn bucket_index(self_id: &[u8; 32], other: &[u8; 32]) -> Option<usize> {
    for (i, (x, y)) in self_id.iter().zip(other.iter()).enumerate() {
        let d = x ^ y;
        if d != 0 {
            let leading = d.leading_zeros() as usize; // 0..7
            return Some((31 - i) * 8 + (7 - leading));
        }
    }
    None
}

#[derive(Debug, Default)]
pub struct RoutingTable {
    self_id: [u8; 32],
    buckets: HashMap<usize, Vec<DhtNode>>,
}

impl RoutingTable {
    pub fn new(self_id: [u8; 32]) -> Self {
        Self {
            self_id,
            buckets: HashMap::new(),
        }
    }

    /// Insert or refresh. Returns true if the table changed.
    pub fn insert(&mut self, node: DhtNode) -> Result<bool, &'static str> {
        node.validate()?;
        if node.address == self.self_id {
            return Err("dht cannot insert self");
        }
        let bucket = bucket_index(&self.self_id, &node.address).ok_or("no bucket for self")?;
        let entries = self.buckets.entry(bucket).or_default();
        if let Some(pos) = entries.iter().position(|n| n.address == node.address) {
            if node.last_seen_ms > entries[pos].last_seen_ms {
                entries[pos].last_seen_ms = node.last_seen_ms;
                return Ok(true);
            }
            return Ok(false);
        }
        if entries.len() < DHT_K {
            entries.push(node);
            return Ok(true);
        }
        // Full bucket: replace oldest only if newcomer is strictly fresher
        // (deterministic, no silent drops of fresher contacts).
        let mut oldest = 0;
        for i in 1..entries.len() {
            if entries[i].last_seen_ms < entries[oldest].last_seen_ms {
                oldest = i;
            }
        }
        if node.last_seen_ms > entries[oldest].last_seen_ms {
            entries[oldest] = node;
            return Ok(true);
        }
        Ok(false)
    }

    /// `n` closest known nodes to `target` by XOR distance.
    pub fn closest(&self, target: &[u8; 32], n: usize) -> Vec<DhtNode> {
        let mut all: Vec<(DhtNode, [u8; 32])> = Vec::new();
        for entries in self.buckets.values() {
            for node in entries {
                all.push((node.clone(), xor_distance(&node.address, target)));
            }
        }
        all.sort_by(|a, b| a.1.cmp(&b.1).then(a.0.address.cmp(&b.0.address)));
        all.into_iter().take(n).map(|(node, _)| node).collect()
    }

    pub fn len(&self) -> usize {
        self.buckets.values().map(|v| v.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dht_bucket_ordering() {
        let self_id = [0; 32];
        // Differ in last byte low bit -> bucket 0; differ in first byte high bit -> bucket 255.
        let near = {
            let mut a = [0; 32];
            a[31] = 1;
            a
        };
        let far = {
            let mut a = [0; 32];
            a[0] = 0x80;
            a
        };
        assert_eq!(bucket_index(&self_id, &near), Some(0));
        assert_eq!(bucket_index(&self_id, &far), Some(255));
        assert_eq!(bucket_index(&self_id, &self_id), None);
    }

    #[test]
    fn dht_insert_refresh_and_closest() {
        let mut t = RoutingTable::new([0xFF; 32]);
        let mut a = [0; 32];
        a[0] = 1;
        let mut b = [0; 32];
        b[0] = 2;
        assert!(t
            .insert(DhtNode {
                address: a,
                last_seen_ms: 10
            })
            .unwrap());
        assert!(t
            .insert(DhtNode {
                address: b,
                last_seen_ms: 20
            })
            .unwrap());
        // Refresh same node with newer timestamp changes table.
        assert!(t
            .insert(DhtNode {
                address: a,
                last_seen_ms: 30
            })
            .unwrap());
        // Stale refresh does not.
        assert!(!t
            .insert(DhtNode {
                address: a,
                last_seen_ms: 5
            })
            .unwrap());
        let mut target = [0; 32];
        target[0] = 1;
        let closest = t.closest(&target, 1);
        assert_eq!(closest.len(), 1);
        assert_eq!(closest[0].address, a);
        assert_eq!(t.len(), 2);
    }

    #[test]
    fn dht_rejects_self_and_zero() {
        let mut t = RoutingTable::new([7; 32]);
        assert!(t
            .insert(DhtNode {
                address: [7; 32],
                last_seen_ms: 1
            })
            .is_err());
        assert!(t
            .insert(DhtNode {
                address: [0; 32],
                last_seen_ms: 1
            })
            .is_err());
    }
}
