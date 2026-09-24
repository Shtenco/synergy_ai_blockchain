//! Deterministic bootstrap/provider discovery primitives for the MVP.
//!
//! This is deliberately transport-agnostic. A future Kademlia implementation may
//! carry these exact records without changing their consensus commitments.

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const PROVIDER_RECORD_DOMAIN: &[u8] = b"SYNERGY/PROVIDER-RECORD/V1\0";
pub const PROVIDER_SET_DOMAIN: &[u8] = b"SYNERGY/PROVIDER-SET/V1\0";
pub const MAX_PROVIDER_RECORDS: usize = 16_384;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderRecord {
    pub provider_id: [u8; 32],
    pub model_root: [u8; 32],
    pub shard_root: [u8; 32],
    pub endpoint_root: [u8; 32],
    pub capability_root: [u8; 32],
    pub epoch: u64,
    pub sequence: u64,
    pub expires_at: u64,
    /// Commitment to the externally verified node authorization/signature.
    pub authorization_root: [u8; 32],
}

impl ProviderRecord {
    pub fn validate(&self) -> Result<(), &'static str> {
        for value in [
            self.provider_id,
            self.model_root,
            self.shard_root,
            self.endpoint_root,
            self.capability_root,
            self.authorization_root,
        ] {
            if value == [0; 32] {
                return Err("provider commitments required");
            }
        }
        if self.epoch == 0 || self.sequence == 0 || self.expires_at == 0 {
            return Err("provider epoch/sequence/expiry required");
        }
        Ok(())
    }

    pub fn commitment(&self) -> Option<[u8; 32]> {
        self.validate().ok()?;
        let mut h = Sha256::new();
        h.update(PROVIDER_RECORD_DOMAIN);
        h.update(crate::pq::CRYPTO_PROFILE_VERSION.to_be_bytes());
        h.update(self.provider_id);
        h.update(self.model_root);
        h.update(self.shard_root);
        h.update(self.endpoint_root);
        h.update(self.capability_root);
        h.update(self.epoch.to_be_bytes());
        h.update(self.sequence.to_be_bytes());
        h.update(self.expires_at.to_be_bytes());
        h.update(self.authorization_root);
        Some(h.finalize().into())
    }

    pub fn is_live_at(&self, now: u64) -> bool {
        self.validate().is_ok() && now > 0 && now <= self.expires_at
    }
}

#[derive(Debug, Clone, Default)]
pub struct ProviderRegistry {
    records: BTreeMap<([u8; 32], [u8; 32], [u8; 32]), ProviderRecord>,
}

impl ProviderRegistry {
    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn upsert(&mut self, record: ProviderRecord, now: u64) -> Result<(), &'static str> {
        record.validate()?;
        if !record.is_live_at(now) {
            return Err("stale provider record");
        }
        let key = (record.model_root, record.shard_root, record.provider_id);
        if let Some(existing) = self.records.get(&key) {
            if record.epoch < existing.epoch
                || (record.epoch == existing.epoch && record.sequence <= existing.sequence)
            {
                return Err("provider record replay or downgrade");
            }
        } else if self.records.len() >= MAX_PROVIDER_RECORDS {
            return Err("provider registry capacity exceeded");
        }
        self.records.insert(key, record);
        Ok(())
    }

    pub fn providers_for(
        &self,
        model_root: [u8; 32],
        shard_root: [u8; 32],
        now: u64,
    ) -> Vec<&ProviderRecord> {
        self.records
            .values()
            .filter(|record| {
                record.model_root == model_root
                    && record.shard_root == shard_root
                    && record.is_live_at(now)
            })
            .collect()
    }

    pub fn prune_expired(&mut self, now: u64) -> usize {
        let before = self.records.len();
        self.records.retain(|_, record| record.is_live_at(now));
        before - self.records.len()
    }

    pub fn commitment(&self, now: u64) -> Option<[u8; 32]> {
        if now == 0 {
            return None;
        }
        let live: Vec<_> = self.records.values().filter(|r| r.is_live_at(now)).collect();
        let count = u64::try_from(live.len()).ok()?;
        let mut h = Sha256::new();
        h.update(PROVIDER_SET_DOMAIN);
        h.update(crate::pq::CRYPTO_PROFILE_VERSION.to_be_bytes());
        h.update(count.to_be_bytes());
        for record in live {
            h.update(record.commitment()?);
        }
        Some(h.finalize().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(provider: u8, sequence: u64, expires_at: u64) -> ProviderRecord {
        ProviderRecord {
            provider_id: [provider; 32],
            model_root: [2; 32],
            shard_root: [3; 32],
            endpoint_root: [4; 32],
            capability_root: [5; 32],
            epoch: 7,
            sequence,
            expires_at,
            authorization_root: [6; 32],
        }
    }

    #[test]
    fn registry_rejects_stale_and_replayed_records() {
        let mut registry = ProviderRegistry::default();
        assert!(registry.upsert(record(1, 1, 100), 10).is_ok());
        assert!(registry.upsert(record(1, 1, 100), 10).is_err());
        assert!(registry.upsert(record(2, 1, 5), 10).is_err());
    }

    #[test]
    fn fresh_lookup_returns_only_live_matching_provider() {
        let mut registry = ProviderRegistry::default();
        registry.upsert(record(1, 1, 100), 10).unwrap();
        let mut other = record(2, 1, 100);
        other.shard_root = [9; 32];
        registry.upsert(other, 10).unwrap();

        let found = registry.providers_for([2; 32], [3; 32], 20);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].provider_id, [1; 32]);
    }

    #[test]
    fn provider_set_commitment_changes_on_new_generation() {
        let mut registry = ProviderRegistry::default();
        registry.upsert(record(1, 1, 100), 10).unwrap();
        let a = registry.commitment(10).unwrap();
        registry.upsert(record(1, 2, 100), 10).unwrap();
        let b = registry.commitment(10).unwrap();
        assert_ne!(a, b);
    }
}
