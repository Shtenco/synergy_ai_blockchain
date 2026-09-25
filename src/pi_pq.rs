//! Experimental SYNERGY PI-PQ evidence lane.
//!
//! This module deliberately does NOT implement or invent the historical PI-based
//! primitive. It records recovered provenance and deterministic evidence while
//! remaining non-authoritative until the exact algorithm is recovered and audited.

use sha2::{Digest, Sha256};

pub const PI_PQ_EVIDENCE_DOMAIN: &[u8] = b"SYNERGY/PI-PQ-EVIDENCE/V1\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PiPqEvidence {
    pub algorithm_source_hash: [u8; 32],
    pub specification_hash: [u8; 32],
    pub test_vector_root: [u8; 32],
    pub input_commitment: [u8; 32],
    pub output_commitment: [u8; 32],
    pub version: u32,
}

impl PiPqEvidence {
    pub fn validate_non_authoritative(&self) -> Result<(), &'static str> {
        if self.algorithm_source_hash == [0; 32]
            || self.specification_hash == [0; 32]
            || self.test_vector_root == [0; 32]
            || self.input_commitment == [0; 32]
            || self.output_commitment == [0; 32]
            || self.version == 0
        {
            return Err("PI-PQ evidence fields required");
        }
        Ok(())
    }

    pub fn evidence_root(&self) -> Option<[u8; 32]> {
        self.validate_non_authoritative().ok()?;
        let mut h = Sha256::new();
        h.update(PI_PQ_EVIDENCE_DOMAIN);
        h.update(crate::pq::CRYPTO_PROFILE_VERSION.to_be_bytes());
        h.update(self.algorithm_source_hash);
        h.update(self.specification_hash);
        h.update(self.test_vector_root);
        h.update(self.input_commitment);
        h.update(self.output_commitment);
        h.update(self.version.to_be_bytes());
        Some(h.finalize().into())
    }

    pub const fn may_authorize_consensus(&self) -> bool { false }
    pub const fn may_authorize_assets(&self) -> bool { false }
    pub const fn may_authorize_syna_mint(&self) -> bool { false }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pi_lane_is_fail_closed_and_non_authoritative() {
        let e = PiPqEvidence {
            algorithm_source_hash: [1; 32],
            specification_hash: [2; 32],
            test_vector_root: [3; 32],
            input_commitment: [4; 32],
            output_commitment: [5; 32],
            version: 1,
        };
        assert!(e.evidence_root().is_some());
        assert!(!e.may_authorize_consensus());
        assert!(!e.may_authorize_assets());
        assert!(!e.may_authorize_syna_mint());
    }

    #[test]
    fn missing_recovered_provenance_is_rejected() {
        let e = PiPqEvidence {
            algorithm_source_hash: [0; 32],
            specification_hash: [2; 32],
            test_vector_root: [3; 32],
            input_commitment: [4; 32],
            output_commitment: [5; 32],
            version: 1,
        };
        assert!(e.evidence_root().is_none());
    }
}
