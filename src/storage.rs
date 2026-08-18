//! Content-addressed archival storage primitives.
//!
//! Compression ratios are evidence, never protocol constants. The chain records
//! exact raw/archive byte counts, scoped dedup evidence and erasure placement
//! commitments so storage savings can be derived rather than advertised.

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
        if self.erasure_k == 0 || self.erasure_n < self.erasure_k {
            return Err("invalid erasure parameters");
        }
        Ok(())
    }

    /// Archive/raw ratio in basis points: 10000 = same size, 1000 = 10x smaller.
    pub fn archive_to_raw_bps(&self) -> u64 {
        ((self.archive_bytes as u128) * 10_000u128 / (self.raw_bytes as u128)) as u64
    }

    /// Compression-only storage saving in basis points. Saturates at zero when
    /// the lossless archive is larger than the source.
    pub fn saving_bps(&self) -> u64 {
        10_000u64.saturating_sub(self.archive_to_raw_bps())
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
    pub fn unique_to_logical_bps(&self) -> u64 {
        if self.logical_archive_bytes == 0 {
            return 0;
        }
        ((self.newly_stored_unique_bytes as u128) * 10_000u128
            / (self.logical_archive_bytes as u128)) as u64
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
        let numerator = (self.unique_archive_bytes as u128)
            .checked_mul(self.erasure_n as u128)
            .ok_or("erasure size overflow")?;
        let k = self.erasure_k as u128;
        let ceil = numerator
            .checked_add(k - 1)
            .ok_or("erasure rounding overflow")?
            / k;
        u64::try_from(ceil).map_err(|_| "erasure size exceeds u64")
    }

    pub fn validate_against(&self, dedup: &DedupReceipt) -> Result<(), &'static str> {
        if self.object_id != dedup.object_id {
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofOfStorageReceipt {
    pub object_id: [u8; 32],
    pub provider_id: [u8; 32],
    pub epoch: u64,
    pub challenge_commitment: [u8; 32],
    pub proof_commitment: [u8; 32],
    pub served_bytes: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn ratio_is_measured_not_assumed() {
        let r = archive();
        assert_eq!(r.archive_to_raw_bps(), 2500);
        assert_eq!(r.saving_bps(), 7500);
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
        assert_eq!(d.unique_to_logical_bps(), 2000);
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
        assert!(p.validate_against(&d).is_err());
    }
}
