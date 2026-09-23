//! Distributed KV-cache commitment and lease primitives.
//!
//! Raw KV tensors never enter consensus state. The chain/service plane commits
//! ownership, sequence/range identity, replicas and expiry.

use sha2::{Digest, Sha256};

use crate::pq::{
    verify_envelope_authorization, AuthPolicy, AuthorizationDomain, AuthorizationEnvelope,
    AuthorizationReplayState, AuthorizationValidationContext, ContextSignatureVerifier,
    HybridAuthorization,
};

const KV_REPLICA_RECEIPT_DOMAIN: &[u8] = b"SYNERGY/KV-REPLICA-RECEIPT/V1\0";
pub const MAX_KV_REPLICAS: usize = 32;

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
        if self.expires_at == 0 {
            return Err("kv lease expiry required");
        }
        if self.replica_workers.len() > MAX_KV_REPLICAS {
            return Err("too many kv replica workers");
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

    pub fn commitment(&self) -> Option<[u8; 32]> {
        self.validate().ok()?;

        const DOMAIN: &[u8] = b"SYNERGY/KV-CACHE-LEASE/V1\0";
        let replica_count = u64::try_from(self.replica_workers.len()).ok()?;

        let mut hasher = Sha256::new();
        hasher.update(DOMAIN);
        hasher.update(self.lease_id);
        hasher.update(self.job_id);
        hasher.update(self.session_id);
        hasher.update(self.model_root);
        hasher.update(self.sequence_commitment);
        hasher.update(self.token_start.to_be_bytes());
        hasher.update(self.token_end_exclusive.to_be_bytes());
        hasher.update(self.primary_worker);
        hasher.update(replica_count.to_be_bytes());
        for worker in &self.replica_workers {
            hasher.update(worker);
        }
        hasher.update(self.kv_root);
        hasher.update(self.expires_at.to_be_bytes());
        Some(hasher.finalize().into())
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
        lease.validate()?;
        if self.lease_id != lease.lease_id || self.kv_root != lease.kv_root {
            return Err("kv replica/lease mismatch");
        }
        if self.worker_id != lease.primary_worker && !lease.replica_workers.contains(&self.worker_id) {
            return Err("worker is not authorized for kv lease");
        }
        if self.stored_bytes == 0 || self.signature_commitment == [0; 32] {
            return Err("kv replica evidence required");
        }
        if self.valid_until == 0 || self.valid_until > lease.expires_at {
            return Err("replica outlives kv lease");
        }
        Ok(())
    }

    pub fn authorization_commitment(&self, lease: &KvCacheLease) -> Option<[u8; 32]> {
        self.validate_against(lease).ok()?;
        let lease_commitment = lease.commitment()?;

        let mut hasher = Sha256::new();
        hasher.update(KV_REPLICA_RECEIPT_DOMAIN);
        hasher.update(lease_commitment);
        hasher.update(self.lease_id);
        hasher.update(self.worker_id);
        hasher.update(self.kv_root);
        hasher.update(self.stored_bytes.to_be_bytes());
        hasher.update(self.signature_commitment);
        hasher.update(self.valid_until.to_be_bytes());
        Some(hasher.finalize().into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KvReplicaReceiptAuthorization {
    pub chain_id: [u8; 32],
    pub epoch: u64,
    pub nonce: u64,
    pub receipt: KvReplicaReceipt,
    pub authorization: HybridAuthorization,
}

impl KvReplicaReceiptAuthorization {
    pub fn envelope(&self, lease: &KvCacheLease) -> Option<AuthorizationEnvelope> {
        Some(AuthorizationEnvelope {
            chain_id: self.chain_id,
            domain: AuthorizationDomain::KvReplicaReceipt,
            epoch: self.epoch,
            nonce: self.nonce,
            expires_at: self.receipt.valid_until,
            payload_commitment: self.receipt.authorization_commitment(lease)?,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KvReplicaReceiptValidationContext {
    pub expected_chain_id: [u8; 32],
    pub expected_epoch: u64,
    pub expected_nonce: u64,
    pub expected_worker_id: [u8; 32],
    pub expected_worker_keyset_commitment: [u8; 32],
    pub now: u64,
    pub max_future_seconds: u64,
}

pub(crate) fn verify_kv_replica_receipt<V: ContextSignatureVerifier>(
    verifier: &V,
    lease: &KvCacheLease,
    authorized: &KvReplicaReceiptAuthorization,
    validation: &KvReplicaReceiptValidationContext,
) -> bool {
    if authorized.authorization.policy != AuthPolicy::PqOnly
        || authorized.receipt.worker_id != validation.expected_worker_id
        || authorized.authorization.keyset_commitment()
            != Some(validation.expected_worker_keyset_commitment)
        || authorized.receipt.validate_against(lease).is_err()
    {
        return false;
    }

    let envelope = match authorized.envelope(lease) {
        Some(envelope) => envelope,
        None => return false,
    };
    let auth_validation = AuthorizationValidationContext {
        expected_chain_id: validation.expected_chain_id,
        expected_domain: AuthorizationDomain::KvReplicaReceipt,
        expected_policy: AuthPolicy::PqOnly,
        expected_epoch: validation.expected_epoch,
        expected_nonce: validation.expected_nonce,
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

pub fn verify_kv_replica_receipt_and_consume<V: ContextSignatureVerifier>(
    verifier: &V,
    lease: &KvCacheLease,
    authorized: &KvReplicaReceiptAuthorization,
    validation: &KvReplicaReceiptValidationContext,
    replay: &mut AuthorizationReplayState,
) -> bool {
    if !verify_kv_replica_receipt(verifier, lease, authorized, validation) {
        return false;
    }
    let envelope = match authorized.envelope(lease) {
        Some(envelope) => envelope,
        None => return false,
    };
    replay.consume_verified_for_subject(
        &authorized.authorization,
        &envelope,
        validation.expected_worker_keyset_commitment,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pq::{
        AuthScheme, ContextSignatureVerifier, SignatureEvidence, ML_DSA_87_PUBLIC_KEY_BYTES,
        ML_DSA_87_SIGNATURE_BYTES, SLH_DSA_SHAKE_256S_PUBLIC_KEY_BYTES,
        SLH_DSA_SHAKE_256S_SIGNATURE_BYTES,
    };

    #[derive(Clone)]
    struct ExpectedVerifier {
        message: Vec<u8>,
        context: Vec<u8>,
    }

    impl ContextSignatureVerifier for ExpectedVerifier {
        fn verify_with_context(
            &self,
            _scheme: AuthScheme,
            _public_key: &[u8],
            message: &[u8],
            context: &[u8],
            _signature: &[u8],
        ) -> bool {
            message == self.message && context == self.context
        }
    }

    fn pq_only_authorization() -> HybridAuthorization {
        HybridAuthorization {
            policy: AuthPolicy::PqOnly,
            evidence: vec![
                SignatureEvidence {
                    scheme: AuthScheme::MlDsa87,
                    public_key: vec![0x71; ML_DSA_87_PUBLIC_KEY_BYTES],
                    signature: vec![0x72; ML_DSA_87_SIGNATURE_BYTES],
                },
                SignatureEvidence {
                    scheme: AuthScheme::SlhDsaShake256s,
                    public_key: vec![0x73; SLH_DSA_SHAKE_256S_PUBLIC_KEY_BYTES],
                    signature: vec![0x74; SLH_DSA_SHAKE_256S_SIGNATURE_BYTES],
                },
            ],
        }
    }

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
    fn kv_lease_requires_nonzero_expiry() {
        let mut l = lease();
        l.expires_at = 0;
        assert!(l.validate().is_err());
    }

    #[test]
    fn replicas_must_be_distinct_from_primary() {
        let mut l = lease();
        assert_eq!(l.validate(), Ok(()));
        l.replica_workers.push(l.primary_worker);
        assert!(l.validate().is_err());
    }

    #[test]
    fn kv_replica_receipt_requires_registered_worker_and_consumes_nonce() {
        let mut l = lease();
        let authorization = pq_only_authorization();
        let worker_keyset = authorization
            .keyset_commitment()
            .expect("worker keyset");
        let worker_id = [7; 32];
        l.replica_workers = vec![worker_id];

        let authorized = KvReplicaReceiptAuthorization {
            chain_id: [0x75; 32],
            epoch: 4,
            nonce: 5,
            receipt: KvReplicaReceipt {
                lease_id: l.lease_id,
                worker_id,
                kv_root: l.kv_root,
                stored_bytes: 100,
                signature_commitment: [10; 32],
                valid_until: 40,
            },
            authorization,
        };
        let envelope = authorized.envelope(&l).expect("kv envelope");
        let verifier = ExpectedVerifier {
            message: envelope
                .canonical_message(AuthPolicy::PqOnly)
                .expect("message"),
            context: envelope
                .fips_signature_context(AuthPolicy::PqOnly)
                .expect("context"),
        };
        let validation = KvReplicaReceiptValidationContext {
            expected_chain_id: [0x75; 32],
            expected_epoch: 4,
            expected_nonce: 5,
            expected_worker_id: worker_id,
            expected_worker_keyset_commitment: worker_keyset,
            now: 20,
            max_future_seconds: 30,
        };
        let mut replay = AuthorizationReplayState::new(
            [0x75; 32],
            AuthorizationDomain::KvReplicaReceipt,
            AuthPolicy::PqOnly,
            4,
            5,
        )
        .expect("replay state");

        assert!(verify_kv_replica_receipt_and_consume(
            &verifier,
            &l,
            &authorized,
            &validation,
            &mut replay,
        ));
        assert_eq!(replay.next_nonce(), 6);
        assert!(!verify_kv_replica_receipt_and_consume(
            &verifier,
            &l,
            &authorized,
            &validation,
            &mut replay,
        ));
    }

    #[test]
    fn kv_lease_rejects_replica_fanout_above_protocol_cap() {
        let mut l = lease();
        l.replica_workers = (0..=MAX_KV_REPLICAS)
            .map(|i| {
                let mut id = [0u8; 32];
                id[0] = u8::try_from(i + 1).expect("small replica index");
                id
            })
            .collect();
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
