//! Phase 2 — PQ-DNS: signed name -> mesh-address records.
//!
//! Names resolve to `MeshAddress`es (hashes of PQ identities) through
//! signed records carried over gossip/DHT. Signatures themselves stay in
//! the existing `AuthorizationEnvelope` path (ML-DSA-87 + SLH-DSA); this
//! module owns deterministic namehashing, record canonicalization, and
//! monotonic registry semantics (sequence per epoch, expiry enforced).

use sha2::{Digest, Sha256};
use std::collections::HashMap;

pub const PQ_DNS_DOMAIN: &[u8] = b"SYNERGY/PQ-DNS/V1\0";
pub const MAX_PQ_DNS_NAME_BYTES: usize = 253;

pub fn pq_namehash(name: &str) -> Option<[u8; 32]> {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_PQ_DNS_NAME_BYTES {
        return None;
    }
    let lower = name.to_ascii_lowercase();
    // Fail-closed: only printable ASCII, no leading/trailing dots, no empties.
    if lower
        .bytes()
        .any(|b| !(0x20..=0x7E).contains(&b) || b == b' ' || b == b'\0')
    {
        return None;
    }
    if lower.starts_with('.') || lower.ends_with('.') || lower.contains("..") {
        return None;
    }
    let mut h = Sha256::new();
    h.update(PQ_DNS_DOMAIN);
    h.update(crate::pq::CRYPTO_PROFILE_VERSION.to_be_bytes());
    h.update((lower.len() as u64).to_be_bytes());
    h.update(lower.as_bytes());
    Some(h.finalize().into())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqDnsRecord {
    pub name_hash: [u8; 32],
    pub address: [u8; 32],
    pub identity_root: [u8; 32],
    pub epoch: u64,
    pub sequence: u64,
    pub expires_at_ms: u64,
}

impl PqDnsRecord {
    pub fn validate(&self, now_ms: u64) -> Result<(), &'static str> {
        if self.name_hash == [0; 32] || self.address == [0; 32] {
            return Err("pq-dns record commitments required");
        }
        if self.identity_root == [0; 32] {
            return Err("pq-dns identity root required");
        }
        if self.epoch == 0 {
            return Err("pq-dns epoch required");
        }
        if now_ms > self.expires_at_ms {
            return Err("pq-dns record expired");
        }
        Ok(())
    }

    pub fn record_root(&self) -> Option<[u8; 32]> {
        self.validate(self.expires_at_ms.saturating_sub(1)).ok()?;
        let mut h = Sha256::new();
        h.update(PQ_DNS_DOMAIN);
        h.update(crate::pq::CRYPTO_PROFILE_VERSION.to_be_bytes());
        h.update(self.name_hash);
        h.update(self.address);
        h.update(self.identity_root);
        h.update(self.epoch.to_be_bytes());
        h.update(self.sequence.to_be_bytes());
        h.update(self.expires_at_ms.to_be_bytes());
        Some(h.finalize().into())
    }
}

/// Registry with monotonic `(epoch, sequence)` per name (replay-safe).
#[derive(Debug, Default)]
pub struct PqDnsRegistry {
    records: HashMap<[u8; 32], PqDnsRecord>,
}

impl PqDnsRegistry {
    pub fn upsert(&mut self, record: PqDnsRecord, now_ms: u64) -> Result<bool, &'static str> {
        record.validate(now_ms)?;
        match self.records.get(&record.name_hash) {
            Some(cur) => {
                if (record.epoch, record.sequence) <= (cur.epoch, cur.sequence) {
                    return Ok(false); // stale or duplicate: ignore, not an error
                }
                self.records.insert(record.name_hash, record);
                Ok(true)
            }
            None => {
                self.records.insert(record.name_hash, record);
                Ok(true)
            }
        }
    }

    pub fn resolve(&self, name_hash: &[u8; 32], now_ms: u64) -> Option<[u8; 32]> {
        let r = self.records.get(name_hash)?;
        r.validate(now_ms).ok()?;
        Some(r.address)
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pq_dns_namehash_case_insensitive_and_stable() {
        let a = pq_namehash("Node.Example").unwrap();
        let b = pq_namehash("node.example").unwrap();
        assert_eq!(a, b);
        assert!(pq_namehash("").is_none());
        assert!(pq_namehash(".bad").is_none());
        assert!(pq_namehash("bad..name").is_none());
    }

    #[test]
    fn pq_dns_registry_monotonic_and_expiry() {
        let name = pq_namehash("relay.mesh").unwrap();
        let mut reg = PqDnsRegistry::default();
        let r1 = PqDnsRecord {
            name_hash: name,
            address: [2; 32],
            identity_root: [3; 32],
            epoch: 1,
            sequence: 1,
            expires_at_ms: 5000,
        };
        assert!(reg.upsert(r1.clone(), 1000).unwrap());
        assert_eq!(reg.resolve(&name, 2000), Some([2; 32]));
        // Stale sequence ignored.
        let mut stale = r1.clone();
        stale.sequence = 0;
        assert!(!reg.upsert(stale, 2000).unwrap());
        // Newer wins.
        let mut r2 = r1.clone();
        r2.sequence = 2;
        r2.address = [9; 32];
        assert!(reg.upsert(r2, 2000).unwrap());
        assert_eq!(reg.resolve(&name, 2000), Some([9; 32]));
        // Expired: unresolvable.
        assert_eq!(reg.resolve(&name, 6000), None);
    }
}
