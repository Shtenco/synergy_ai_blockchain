//! Distributed KV-cache commitment and lease primitives.
//!
//! Raw KV tensors never enter consensus state. The chain/service plane commits
//! ownership, sequence/range identity, replicas and expiry.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KvCacheLease {
    pub lease_id: [u8; 32],
    pub job_id: [u8; 32],
    pub session_id: [u8; 32],
    pub model_root: [u8; 32],
    pub sequence_commitment: [u8; 32],
    pub token_start: u64,
    pub token_end_exclusive: u64,
    pub primary_worker: [u8; 32],
    pub replica_workers: Vec<[u8; 32]>,
    pub kv_root: [u8; 32],
    pub expires_at: u64,
}

impl KvCacheLease {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.lease_id == [0; 32]
            || self.job_id == [0; 32]
            || self.session_id == [0; 32]
            || self.model_root == [0; 32]
            || self.sequence_commitment == [0; 32]
            || self.primary_worker == [0; 32]
            || self.kv_root == [0; 32]
        {
            return Err("kv lease commitments required");
        }
        if self.token_end_exclusive <= self.token_start {
            return Err("empty kv token range");
        }
        for (i, replica) in self.replica_workers.iter().enumerate() {
            if *replica == [0; 32] || *replica == self.primary_worker {
                return Err("invalid kv replica worker");
            }
            if self.replica_workers[..i].contains(replica) {
                return Err("duplicate kv replica worker");
            }
        }
        Ok(())
    }

    pub fn failover_candidates(&self) -> usize {
        self.replica_workers.len()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KvReplicaReceipt {
    pub lease_id: [u8; 32],
    pub worker_id: [u8; 32],
    pub kv_root: [u8; 32],
    pub stored_bytes: u64,
    pub signature_commitment: [u8; 32],
    pub valid_until: u64,
}

impl KvReplicaReceipt {
    pub fn validate_against(&self, lease: &KvCacheLease) -> Result<(), &'static str> {
        if self.lease_id != lease.lease_id || self.kv_root != lease.kv_root {
            return Err("kv replica/lease mismatch");
        }
        if self.worker_id != lease.primary_worker && !lease.replica_workers.contains(&self.worker_id) {
            return Err("worker is not authorized for kv lease");
        }
        if self.stored_bytes == 0 || self.signature_commitment == [0; 32] {
            return Err("kv replica evidence required");
        }
        if self.valid_until > lease.expires_at {
            return Err("replica outlives kv lease");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lease() -> KvCacheLease {
        KvCacheLease {
            lease_id: [1; 32],
            job_id: [2; 32],
            session_id: [3; 32],
            model_root: [4; 32],
            sequence_commitment: [5; 32],
            token_start: 0,
            token_end_exclusive: 100,
            primary_worker: [6; 32],
            replica_workers: vec![[7; 32], [8; 32]],
            kv_root: [9; 32],
            expires_at: 50,
        }
    }

    #[test]
    fn replicas_must_be_distinct_from_primary() {
        let mut l = lease();
        assert_eq!(l.validate(), Ok(()));
        l.replica_workers.push(l.primary_worker);
        assert!(l.validate().is_err());
    }

    #[test]
    fn unauthorized_worker_cannot_claim_replica() {
        let l = lease();
        let r = KvReplicaReceipt {
            lease_id: l.lease_id,
            worker_id: [99; 32],
            kv_root: l.kv_root,
            stored_bytes: 100,
            signature_commitment: [10; 32],
            valid_until: 40,
        };
        assert!(r.validate_against(&l).is_err());
    }
}
