//! Content-addressed archival storage primitives.
//!
//! Compression ratios are evidence, never protocol constants. The chain records
//! exact raw/archive byte counts, scoped dedup evidence and erasure placement
//! commitments so storage savings can be derived rather than advertised.

use sha2::{Digest, Sha256};

use crate::pq::{
    verify_envelope_authorization, AuthPolicy, AuthorizationDomain, AuthorizationEnvelope,
    AuthorizationReplayState, AuthorizationValidationContext, ContextSignatureVerifier, HybridAuthorization,
};

const STORAGE_PROOF_DOMAIN: &[u8] = b"SYNERGY/STORAGE-PROOF/V1\0";


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageClass {
    Hot,
    Warm,
    Archive,
    DeepArchive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DedupScope {
    /// Global deduplication is allowed only for public/explicitly opted-in data.
    Public,
    /// Private deduplication is domain separated; unrelated tenants cannot probe
    /// whether the same private chunk exists in another tenant domain.
    TenantPrivate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveReceipt {
    pub object_id: [u8; 32],
    pub raw_sha256: [u8; 32],
    pub archive_sha256: [u8; 32],
    pub codec_id: [u8; 16],
    pub codec_version_commitment: [u8; 32],
    pub raw_bytes: u64,
    pub archive_bytes: u64,
    pub chunk_root: [u8; 32],
    pub replicas: u16,
    pub erasure_k: u16,
    pub erasure_n: u16,
    pub storage_class: StorageClass,
    pub random_access_amplification_milli: u32,
    pub expires_at_epoch: u64,
}

impl ArchiveReceipt {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.object_id == [0; 32]
            || self.raw_sha256 == [0; 32]
            || self.archive_sha256 == [0; 32]
            || self.codec_id == [0; 16]
            || self.codec_version_commitment == [0; 32]
            || self.chunk_root == [0; 32]
        {
            return Err("content commitments required");
        }
        if self.raw_bytes == 0 || self.archive_bytes == 0 {
            return Err("byte lengths must be positive");
        }
        if self.replicas == 0 {
            return Err("at least one replica required");
        }
        if self.random_access_amplification_milli == 0 || self.expires_at_epoch == 0 {
            return Err("archive access/expiry policy required");
        }
        if self.erasure_k == 0 || self.erasure_n < self.erasure_k {
            return Err("invalid erasure parameters");
        }
        Ok(())
    }

    /// Archive/raw ratio in basis points: 10000 = same size, 1000 = 10x smaller.
    pub fn archive_to_raw_bps(&self) -> Option<u64> {
        let raw = u128::from(self.raw_bytes);
        if raw == 0 {
            return None;
        }
        let numerator = u128::from(self.archive_bytes).checked_mul(10_000)?;
        let ratio = numerator.checked_div(raw)?;
        u64::try_from(ratio).ok()
    }

    /// Compression-only storage saving in basis points. Returns `None` for an
    /// invalid zero-length raw object instead of panicking.
    pub fn saving_bps(&self) -> Option<u64> {
        Some(10_000u64.saturating_sub(self.archive_to_raw_bps()?))
    }
}

/// Incremental dedup evidence for one already-compressed object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DedupReceipt {
    pub object_id: [u8; 32],
    pub archive_sha256: [u8; 32],
    pub scope: DedupScope,
    pub dedup_domain_commitment: [u8; 32],
    pub catalog_root_before: [u8; 32],
    pub catalog_root_after: [u8; 32],
    pub logical_archive_bytes: u64,
    pub newly_stored_unique_bytes: u64,
    pub reused_bytes: u64,
}

impl DedupReceipt {
    pub fn validate_against(&self, archive: &ArchiveReceipt) -> Result<(), &'static str> {
        if self.object_id != archive.object_id || self.archive_sha256 != archive.archive_sha256 {
            return Err("dedup receipt archive mismatch");
        }
        if self.dedup_domain_commitment == [0; 32]
            || self.catalog_root_before == [0; 32]
            || self.catalog_root_after == [0; 32]
        {
            return Err("dedup commitments required");
        }
        if self.logical_archive_bytes != archive.archive_bytes {
            return Err("dedup logical bytes differ from archive bytes");
        }
        if self.newly_stored_unique_bytes > 0
            && self.catalog_root_before == self.catalog_root_after
        {
            return Err("dedup catalog root must change when unique bytes are stored");
        }
        let total = self
            .newly_stored_unique_bytes
            .checked_add(self.reused_bytes)
            .ok_or("dedup byte accounting overflow")?;
        if total != self.logical_archive_bytes {
            return Err("dedup byte accounting mismatch");
        }
        Ok(())
    }

    /// Incremental unique/archive ratio: 0 means all bytes reused, 10000 means
    /// no dedup saving for this object.
    pub fn unique_to_logical_bps(&self) -> Option<u64> {
        let logical = u128::from(self.logical_archive_bytes);
        if logical == 0 {
            return None;
        }
        let numerator = u128::from(self.newly_stored_unique_bytes).checked_mul(10_000)?;
        let ratio = numerator.checked_div(logical)?;
        u64::try_from(ratio).ok()
    }
}

/// Evidence for the physical bytes placed after erasure coding the incremental
/// unique compressed bytes. This separates logical savings from durability cost.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErasurePlacementReceipt {
    pub object_id: [u8; 32],
    pub dedup_catalog_root: [u8; 32],
    pub provider_set_root: [u8; 32],
    pub unique_archive_bytes: u64,
    pub erasure_k: u16,
    pub erasure_n: u16,
    pub physical_stored_bytes: u64,
    pub availability_policy_root: [u8; 32],
}

impl ErasurePlacementReceipt {
    pub fn minimum_physical_bytes(&self) -> Result<u64, &'static str> {
        if self.erasure_k == 0 || self.erasure_n < self.erasure_k {
            return Err("invalid erasure parameters");
        }
        let numerator = u128::from(self.unique_archive_bytes)
            .checked_mul(u128::from(self.erasure_n))
            .ok_or("erasure size overflow")?;
        let k = u128::from(self.erasure_k);
        let ceil = numerator
            .checked_add(k - 1)
            .ok_or("erasure rounding overflow")?
            / k;
        u64::try_from(ceil).map_err(|_| "erasure size exceeds u64")
    }

    pub fn validate_against(
        &self,
        archive: &ArchiveReceipt,
        dedup: &DedupReceipt,
    ) -> Result<(), &'static str> {
        archive.validate()?;
        dedup.validate_against(archive)?;

        if self.object_id != archive.object_id || self.object_id != dedup.object_id {
            return Err("erasure receipt object mismatch");
        }
        if self.dedup_catalog_root != dedup.catalog_root_after {
            return Err("dedup catalog root mismatch");
        }
        if self.provider_set_root == [0; 32] || self.availability_policy_root == [0; 32] {
            return Err("placement commitments required");
        }
        if self.unique_archive_bytes != dedup.newly_stored_unique_bytes {
            return Err("unique byte count mismatch");
        }
        if self.erasure_k != archive.erasure_k || self.erasure_n != archive.erasure_n {
            return Err("erasure placement policy differs from archive metadata");
        }
        if self.physical_stored_bytes < self.minimum_physical_bytes()? {
            return Err("physical placement below erasure minimum");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageBid {
    pub provider_id: [u8; 32],
    pub object_id: [u8; 32],
    pub price_per_gib_epoch: u128,
    pub max_epochs: u64,
    pub availability_commitment: [u8; 32],
    pub codec_supported: [u8; 16],
}

impl StorageBid {
    pub fn validate_against(&self, archive: &ArchiveReceipt) -> Result<(), &'static str> {
        archive.validate()?;
        if self.provider_id == [0u8; 32] || self.object_id == [0u8; 32] {
            return Err("storage bid provider/object required");
        }
        if self.object_id != archive.object_id {
            return Err("storage bid object mismatch");
        }
        if self.price_per_gib_epoch == 0 || self.max_epochs == 0 {
            return Err("storage bid price/term required");
        }
        if self.availability_commitment == [0u8; 32] {
            return Err("storage bid availability commitment required");
        }
        if self.codec_supported == [0u8; 16] || self.codec_supported != archive.codec_id {
            return Err("storage bid codec mismatch");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofOfStorageReceipt {
    pub object_id: [u8; 32],
    pub provider_id: [u8; 32],
    pub epoch: u64,
    pub challenge_commitment: [u8; 32],
    pub proof_commitment: [u8; 32],
    pub served_bytes: u64,
}


impl ProofOfStorageReceipt {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.object_id == [0u8; 32]
            || self.provider_id == [0u8; 32]
            || self.challenge_commitment == [0u8; 32]
            || self.proof_commitment == [0u8; 32]
        {
            return Err("storage proof commitments required");
        }
        if self.epoch == 0 || self.served_bytes == 0 {
            return Err("storage proof epoch/served bytes required");
        }
        Ok(())
    }

    pub fn authorization_commitment(&self) -> Option<[u8; 32]> {
        self.validate().ok()?;
        let mut hasher = Sha256::new();
        hasher.update(STORAGE_PROOF_DOMAIN);
        hasher.update(self.object_id);
        hasher.update(self.provider_id);
        hasher.update(self.epoch.to_be_bytes());
        hasher.update(self.challenge_commitment);
        hasher.update(self.proof_commitment);
        hasher.update(self.served_bytes.to_be_bytes());
        Some(hasher.finalize().into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageProofAuthorization {
    pub chain_id: [u8; 32],
    pub nonce: u64,
    pub expires_at: u64,
    pub receipt: ProofOfStorageReceipt,
    pub authorization: HybridAuthorization,
}

impl StorageProofAuthorization {
    pub fn envelope(&self) -> Option<AuthorizationEnvelope> {
        Some(AuthorizationEnvelope {
            chain_id: self.chain_id,
            domain: AuthorizationDomain::StorageProof,
            epoch: self.receipt.epoch,
            nonce: self.nonce,
            expires_at: self.expires_at,
            payload_commitment: self.receipt.authorization_commitment()?,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StorageProofValidationContext {
    pub expected_chain_id: [u8; 32],
    pub expected_nonce: u64,
    pub expected_epoch: u64,
    pub expected_object_id: [u8; 32],
    pub expected_provider_id: [u8; 32],
    pub expected_provider_keyset_commitment: [u8; 32],
    pub now: u64,
    pub max_future_seconds: u64,
}

pub(crate) fn verify_storage_proof<V: ContextSignatureVerifier>(
    verifier: &V,
    authorized: &StorageProofAuthorization,
    validation: &StorageProofValidationContext,
) -> bool {
    if authorized.authorization.policy != AuthPolicy::PqOnly
        || authorized.receipt.object_id != validation.expected_object_id
        || authorized.receipt.provider_id != validation.expected_provider_id
        || authorized.receipt.epoch != validation.expected_epoch
        || authorized.authorization.keyset_commitment()
            != Some(validation.expected_provider_keyset_commitment)
        || authorized.receipt.validate().is_err()
    {
        return false;
    }

    let envelope = match authorized.envelope() {
        Some(envelope) => envelope,
        None => return false,
    };

    let auth_validation = AuthorizationValidationContext {
        expected_chain_id: validation.expected_chain_id,
        expected_domain: AuthorizationDomain::StorageProof,
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


pub fn verify_storage_proof_and_consume<V: ContextSignatureVerifier>(
    verifier: &V,
    authorized: &StorageProofAuthorization,
    validation: &StorageProofValidationContext,
    replay: &mut AuthorizationReplayState,
) -> bool {
    if !verify_storage_proof(verifier, authorized, validation) {
        return false;
    }
    let envelope = match authorized.envelope() {
        Some(envelope) => envelope,
        None => return false,
    };
    replay.consume_verified_for_subject(
        &authorized.authorization,
        &envelope,
        validation.expected_provider_keyset_commitment,
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
                    public_key: vec![0x31; ML_DSA_87_PUBLIC_KEY_BYTES],
                    signature: vec![0x32; ML_DSA_87_SIGNATURE_BYTES],
                },
                SignatureEvidence {
                    scheme: AuthScheme::SlhDsaShake256s,
                    public_key: vec![0x33; SLH_DSA_SHAKE_256S_PUBLIC_KEY_BYTES],
                    signature: vec![0x34; SLH_DSA_SHAKE_256S_SIGNATURE_BYTES],
                },
            ],
        }
    }

    fn archive() -> ArchiveReceipt {
        ArchiveReceipt {
            object_id: [1; 32],
            raw_sha256: [2; 32],
            archive_sha256: [3; 32],
            codec_id: [4; 16],
            codec_version_commitment: [5; 32],
            raw_bytes: 1_000_000,
            archive_bytes: 250_000,
            chunk_root: [6; 32],
            replicas: 3,
            erasure_k: 4,
            erasure_n: 6,
            storage_class: StorageClass::Archive,
            random_access_amplification_milli: 1200,
            expires_at_epoch: 100,
        }
    }

    #[test]
    fn storage_proof_requires_registered_provider_keyset() {
        let authorization = pq_only_authorization();
        let provider_keyset = authorization
            .keyset_commitment()
            .expect("provider keyset");
        let authorized = StorageProofAuthorization {
            chain_id: [0xE1; 32],
            nonce: 9,
            expires_at: 200,
            receipt: ProofOfStorageReceipt {
                object_id: [0x41; 32],
                provider_id: [0x42; 32],
                epoch: 7,
                challenge_commitment: [0x43; 32],
                proof_commitment: [0x44; 32],
                served_bytes: 4096,
            },
            authorization,
        };
        let envelope = authorized.envelope().expect("storage envelope");
        let verifier = ExpectedVerifier {
            message: envelope
                .canonical_message(AuthPolicy::PqOnly)
                .expect("message"),
            context: envelope
                .fips_signature_context(AuthPolicy::PqOnly)
                .expect("context"),
        };
        let validation = StorageProofValidationContext {
            expected_chain_id: [0xE1; 32],
            expected_nonce: 9,
            expected_epoch: 7,
            expected_object_id: [0x41; 32],
            expected_provider_id: [0x42; 32],
            expected_provider_keyset_commitment: provider_keyset,
            now: 100,
            max_future_seconds: 200,
        };

        assert!(verify_storage_proof(
            &verifier,
            &authorized,
            &validation,
        ));

        let mut wrong = validation;
        wrong.expected_provider_keyset_commitment[0] ^= 1;
        assert!(!verify_storage_proof(
            &verifier,
            &authorized,
            &wrong,
        ));
    }

    #[test]
    fn archive_requires_codec_version_access_and_expiry_metadata() {
        let mut a = archive();
        assert_eq!(a.validate(), Ok(()));

        a.codec_id = [0; 16];
        assert!(a.validate().is_err());
        a = archive();
        a.codec_version_commitment = [0; 32];
        assert!(a.validate().is_err());
        a = archive();
        a.expires_at_epoch = 0;
        assert!(a.validate().is_err());
    }

    #[test]
    fn storage_bid_is_bound_to_exact_archive_and_codec() {
        let a = archive();
        let mut bid = StorageBid {
            provider_id: [0x21; 32],
            object_id: a.object_id,
            price_per_gib_epoch: 10,
            max_epochs: 30,
            availability_commitment: [0x22; 32],
            codec_supported: a.codec_id,
        };
        assert_eq!(bid.validate_against(&a), Ok(()));

        bid.object_id[0] ^= 1;
        assert!(bid.validate_against(&a).is_err());
        bid = StorageBid {
            provider_id: [0x21; 32],
            object_id: a.object_id,
            price_per_gib_epoch: 10,
            max_epochs: 30,
            availability_commitment: [0x22; 32],
            codec_supported: [0xFF; 16],
        };
        assert!(bid.validate_against(&a).is_err());
    }

    #[test]
    fn ratio_is_measured_not_assumed() {
        let r = archive();
        assert_eq!(r.archive_to_raw_bps(), Some(2500));
        assert_eq!(r.saving_bps(), Some(7500));
    }

    #[test]
    fn archive_ratio_fails_closed_on_zero_raw_bytes() {
        let mut r = archive();
        r.raw_bytes = 0;
        assert_eq!(r.archive_to_raw_bps(), None);
        assert_eq!(r.saving_bps(), None);
    }

    #[test]
    fn dedup_bytes_must_close_exactly() {
        let a = archive();
        let d = DedupReceipt {
            object_id: a.object_id,
            archive_sha256: a.archive_sha256,
            scope: DedupScope::TenantPrivate,
            dedup_domain_commitment: [7; 32],
            catalog_root_before: [8; 32],
            catalog_root_after: [9; 32],
            logical_archive_bytes: 250_000,
            newly_stored_unique_bytes: 50_000,
            reused_bytes: 200_000,
        };
        assert_eq!(d.validate_against(&a), Ok(()));
        assert_eq!(d.unique_to_logical_bps(), Some(2000));
    }

    #[test]
    fn dedup_ratio_fails_closed_on_zero_or_unrepresentable_ratio() {
        let a = archive();
        let mut d = DedupReceipt {
            object_id: a.object_id,
            archive_sha256: a.archive_sha256,
            scope: DedupScope::Public,
            dedup_domain_commitment: [7; 32],
            catalog_root_before: [8; 32],
            catalog_root_after: [9; 32],
            logical_archive_bytes: 0,
            newly_stored_unique_bytes: 1,
            reused_bytes: 0,
        };
        assert_eq!(d.unique_to_logical_bps(), None);

        d.logical_archive_bytes = 1;
        d.newly_stored_unique_bytes = u64::MAX;
        assert_eq!(d.unique_to_logical_bps(), None);
    }

    #[test]
    fn dedup_catalog_root_must_advance_when_unique_bytes_are_added() {
        let a = archive();
        let d = DedupReceipt {
            object_id: a.object_id,
            archive_sha256: a.archive_sha256,
            scope: DedupScope::Public,
            dedup_domain_commitment: [7; 32],
            catalog_root_before: [8; 32],
            catalog_root_after: [8; 32],
            logical_archive_bytes: a.archive_bytes,
            newly_stored_unique_bytes: 1,
            reused_bytes: a.archive_bytes - 1,
        };
        assert_eq!(
            d.validate_against(&a),
            Err("dedup catalog root must change when unique bytes are stored")
        );
    }

    #[test]
    fn erasure_placement_must_match_archive_erasure_policy() {
        let a = archive();
        let d = DedupReceipt {
            object_id: a.object_id,
            archive_sha256: a.archive_sha256,
            scope: DedupScope::Public,
            dedup_domain_commitment: [7; 32],
            catalog_root_before: [8; 32],
            catalog_root_after: [9; 32],
            logical_archive_bytes: a.archive_bytes,
            newly_stored_unique_bytes: 50_000,
            reused_bytes: a.archive_bytes - 50_000,
        };
        let mut p = ErasurePlacementReceipt {
            object_id: a.object_id,
            dedup_catalog_root: d.catalog_root_after,
            provider_set_root: [10; 32],
            unique_archive_bytes: 50_000,
            erasure_k: a.erasure_k,
            erasure_n: a.erasure_n,
            physical_stored_bytes: 100_000,
            availability_policy_root: [11; 32],
        };
        assert_eq!(p.validate_against(&a, &d), Ok(()));

        p.erasure_n = p.erasure_n.checked_add(1).expect("test erasure_n");
        assert_eq!(
            p.validate_against(&a, &d),
            Err("erasure placement policy differs from archive metadata")
        );
    }

    #[test]
    fn erasure_placement_cannot_claim_fewer_than_minimum_physical_bytes() {
        let a = archive();
        let d = DedupReceipt {
            object_id: a.object_id,
            archive_sha256: a.archive_sha256,
            scope: DedupScope::Public,
            dedup_domain_commitment: [7; 32],
            catalog_root_before: [8; 32],
            catalog_root_after: [9; 32],
            logical_archive_bytes: 250_000,
            newly_stored_unique_bytes: 50_000,
            reused_bytes: 200_000,
        };
        let p = ErasurePlacementReceipt {
            object_id: a.object_id,
            dedup_catalog_root: d.catalog_root_after,
            provider_set_root: [10; 32],
            unique_archive_bytes: 50_000,
            erasure_k: 10,
            erasure_n: 15,
            physical_stored_bytes: 74_999,
            availability_policy_root: [11; 32],
        };
        assert_eq!(p.minimum_physical_bytes(), Ok(75_000));
        assert!(p.validate_against(&a, &d).is_err());
    }
}
