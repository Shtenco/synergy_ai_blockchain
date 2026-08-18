//! Content-addressed archival storage primitives.
//!
//! Compression ratios are evidence, never protocol constants. The chain records
//! the exact raw/archive byte counts and codec commitment for every object.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageClass {
    Hot,
    Warm,
    Archive,
    DeepArchive,
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

    /// Compression ratio in basis points: 10000 = 1.0x, 1000 = 10x smaller.
    pub fn archive_to_raw_bps(&self) -> u64 {
        ((self.archive_bytes as u128) * 10_000u128 / (self.raw_bytes as u128)) as u64
    }

    /// Storage saving in basis points. Saturates at zero if the archive expands.
    pub fn saving_bps(&self) -> u64 {
        10_000u64.saturating_sub(self.archive_to_raw_bps())
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

    #[test]
    fn ratio_is_measured_not_assumed() {
        let r = ArchiveReceipt {
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
        };
        assert_eq!(r.archive_to_raw_bps(), 2500);
        assert_eq!(r.saving_bps(), 7500);
    }
}
