//! Domain-separated commitment for authoritative SYNERGY cross-repository artifacts.
//!
//! This module deliberately does NOT interpret accounting/trading/science payloads.
//! The producer authority owns meaning; blockchain owns commitment/finality.

use sha2::{Digest, Sha256};

pub const DOMAIN_ARTIFACT_COMMITMENT_V1: &[u8] =
    b"SYNERGY/DOMAIN-ARTIFACT-COMMITMENT/V1\0";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DomainArtifactCommitment {
    pub source_contract_id: String,
    pub source_event_id: String,
    pub authority: String,
    pub schema_version: u32,
    pub payload_sha256: [u8; 32],
}

fn put_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) -> Option<()> {
    let len = u64::try_from(bytes.len()).ok()?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Some(())
}

impl DomainArtifactCommitment {
    pub fn new(
        source_contract_id: impl Into<String>,
        source_event_id: impl Into<String>,
        authority: impl Into<String>,
        schema_version: u32,
        payload_sha256: [u8; 32],
    ) -> Option<Self> {
        let source_contract_id = source_contract_id.into();
        let source_event_id = source_event_id.into();
        let authority = authority.into();
        if source_contract_id.is_empty()
            || source_event_id.is_empty()
            || authority.is_empty()
            || schema_version == 0
            || payload_sha256 == [0; 32]
        {
            return None;
        }
        Some(Self {
            source_contract_id,
            source_event_id,
            authority,
            schema_version,
            payload_sha256,
        })
    }

    pub fn canonical_preimage(&self) -> Option<Vec<u8>> {
        let mut out = Vec::with_capacity(192);
        put_len_prefixed(&mut out, DOMAIN_ARTIFACT_COMMITMENT_V1)?;
        put_len_prefixed(&mut out, self.source_contract_id.as_bytes())?;
        put_len_prefixed(&mut out, self.source_event_id.as_bytes())?;
        put_len_prefixed(&mut out, self.authority.as_bytes())?;
        out.extend_from_slice(&self.schema_version.to_be_bytes());
        out.extend_from_slice(&self.payload_sha256);
        Some(out)
    }

    pub fn commitment_id(&self) -> Option<[u8; 32]> {
        Some(Sha256::digest(self.canonical_preimage()?).into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn accounting() -> DomainArtifactCommitment {
        DomainArtifactCommitment::new(
            "synergy.accounting.recognition/v1",
            "77777777-7777-4777-8777-777777777777",
            "canonical_accounting",
            1,
            [0x42; 32],
        )
        .expect("valid accounting commitment")
    }

    #[test]
    fn accounting_bytes_are_committed_without_reinterpretation() {
        let c = accounting();
        let id = c.commitment_id().expect("commitment");
        assert_ne!(id, [0; 32]);
        assert_eq!(c.source_contract_id, "synergy.accounting.recognition/v1");
        assert_eq!(c.authority, "canonical_accounting");
    }

    #[test]
    fn domain_fields_change_commitment() {
        let a = accounting();
        let mut b = accounting();
        b.authority = "blockchain_trust".to_owned();
        assert_ne!(a.commitment_id(), b.commitment_id());
    }

    #[test]
    fn zero_payload_hash_is_rejected() {
        assert!(DomainArtifactCommitment::new(
            "synergy.accounting.recognition/v1",
            "event",
            "canonical_accounting",
            1,
            [0; 32],
        )
        .is_none());
    }
}
