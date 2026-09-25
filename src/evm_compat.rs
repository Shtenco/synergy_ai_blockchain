//! Ethereum/EVM interoperability profile for SYNERGY PQ-EVM.
//!
//! This module describes compatibility and bridge-proof requirements. It does
//! not treat an RPC response as bridge finality.

use sha2::{Digest, Sha256};

pub const EVM_COMPAT_DOMAIN: &[u8] = b"SYNERGY/EVM-COMPAT/V1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvmNetworkClass {
    EthereumL1,
    OptimisticRollup,
    ZkRollup,
    Validium,
    Sidechain,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvmCompatibilityEvidence {
    pub transaction_vectors_root: [u8; 32],
    pub receipts_logs_vectors_root: [u8; 32],
    pub gas_vectors_root: [u8; 32],
    pub json_rpc_vectors_root: [u8; 32],
    pub abi_vectors_root: [u8; 32],
    pub precompile_registry_root: [u8; 32],
    pub client_matrix_root: [u8; 32],
    pub version: u32,
}

impl EvmCompatibilityEvidence {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.version == 0 {
            return Err("EVM compatibility evidence version required");
        }
        for root in [
            self.transaction_vectors_root,
            self.receipts_logs_vectors_root,
            self.gas_vectors_root,
            self.json_rpc_vectors_root,
            self.abi_vectors_root,
            self.precompile_registry_root,
            self.client_matrix_root,
        ] {
            if root == [0; 32] {
                return Err("all EVM compatibility evidence roots required");
            }
        }
        Ok(())
    }

    pub fn verified_commitment(
        &self,
        evidence: &EvmCompatibilityEvidence,
    ) -> Option<[u8; 32]> {
        let profile_root = self.commitment()?;
        let evidence_root = evidence.commitment()?;
        let mut h = Sha256::new();
        h.update(EVM_COMPAT_DOMAIN);
        h.update(b"VERIFIED\0");
        h.update(profile_root);
        h.update(evidence_root);
        Some(h.finalize().into())
    }

    pub fn commitment(&self) -> Option<[u8; 32]> {
        self.validate().ok()?;
        let mut h = Sha256::new();
        h.update(EVM_COMPAT_EVIDENCE_DOMAIN);
        h.update(self.version.to_be_bytes());
        h.update(self.transaction_vectors_root);
        h.update(self.receipts_logs_vectors_root);
        h.update(self.gas_vectors_root);
        h.update(self.json_rpc_vectors_root);
        h.update(self.abi_vectors_root);
        h.update(self.precompile_registry_root);
        h.update(self.client_matrix_root);
        Some(h.finalize().into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvmCompatibilityProfile {
    pub chain_id: u64,
    pub network_class: EvmNetworkClass,
    pub settlement_chain_id: u64,
    pub bridge_contract: [u8; 20],
    pub min_finality_blocks: u64,
    pub max_reorg_blocks: u64,
    pub json_rpc_compatible: bool,
    pub abi_compatible: bool,
    pub receipts_logs_compatible: bool,
    pub pq_authorization_additive: bool,
    pub legacy_downgrade_for_pq_only: bool,
}

impl EvmCompatibilityProfile {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.chain_id == 0
            || self.settlement_chain_id == 0
            || self.bridge_contract == [0; 20]
            || self.min_finality_blocks == 0
            || !self.json_rpc_compatible
            || !self.abi_compatible
            || !self.receipts_logs_compatible
            || !self.pq_authorization_additive
            || self.legacy_downgrade_for_pq_only
        {
            return Err("EVM compatibility profile violates SYNERGY requirements");
        }
        if self.network_class == EvmNetworkClass::EthereumL1
            && self.chain_id != self.settlement_chain_id
        {
            return Err("Ethereum L1 must settle to itself");
        }
        Ok(())
    }

    pub fn commitment(&self) -> Option<[u8; 32]> {
        self.validate().ok()?;
        let mut h = Sha256::new();
        h.update(EVM_COMPAT_DOMAIN);
        h.update(self.chain_id.to_be_bytes());
        h.update([self.network_class as u8]);
        h.update(self.settlement_chain_id.to_be_bytes());
        h.update(self.bridge_contract);
        h.update(self.min_finality_blocks.to_be_bytes());
        h.update(self.max_reorg_blocks.to_be_bytes());
        h.update([
            self.json_rpc_compatible as u8,
            self.abi_compatible as u8,
            self.receipts_logs_compatible as u8,
            self.pq_authorization_additive as u8,
            self.legacy_downgrade_for_pq_only as u8,
        ]);
        Some(h.finalize().into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvmBridgeProofReceipt {
    pub source_chain_id: u64,
    pub destination_chain_id: u64,
    pub source_block_hash: [u8; 32],
    pub source_block_number: u64,
    pub event_or_state_root: [u8; 32],
    pub proof_root: [u8; 32],
    pub deposit_or_withdrawal_id: [u8; 32],
    pub finalized: bool,
}

impl EvmBridgeProofReceipt {
    pub fn validate(&self, source: &EvmCompatibilityProfile) -> Result<(), &'static str> {
        source.validate()?;
        if self.source_chain_id != source.chain_id
            || self.destination_chain_id == 0
            || self.destination_chain_id == self.source_chain_id
            || self.source_block_hash == [0; 32]
            || self.source_block_number == 0
            || self.event_or_state_root == [0; 32]
            || self.proof_root == [0; 32]
            || self.deposit_or_withdrawal_id == [0; 32]
            || !self.finalized
        {
            return Err("invalid EVM bridge proof receipt");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eth() -> EvmCompatibilityProfile {
        EvmCompatibilityProfile {
            chain_id: 1,
            network_class: EvmNetworkClass::EthereumL1,
            settlement_chain_id: 1,
            bridge_contract: [1; 20],
            min_finality_blocks: 2,
            max_reorg_blocks: 2,
            json_rpc_compatible: true,
            abi_compatible: true,
            receipts_logs_compatible: true,
            pq_authorization_additive: true,
            legacy_downgrade_for_pq_only: false,
        }
    }

    #[test]
    fn pq_only_downgrade_is_never_compatible() {
        let mut p = eth();
        assert!(p.validate().is_ok());
        p.legacy_downgrade_for_pq_only = true;
        assert!(p.validate().is_err());
    }

    #[test]
    fn compatibility_claim_requires_hash_pinned_evidence() {
        let p = eth();
        let e = EvmCompatibilityEvidence {
            transaction_vectors_root: [11; 32],
            receipts_logs_vectors_root: [12; 32],
            gas_vectors_root: [13; 32],
            json_rpc_vectors_root: [14; 32],
            abi_vectors_root: [15; 32],
            precompile_registry_root: [16; 32],
            client_matrix_root: [17; 32],
            version: 1,
        };
        assert!(p.verified_commitment(&e).is_some());

        let mut missing = e.clone();
        missing.gas_vectors_root = [0; 32];
        assert!(p.verified_commitment(&missing).is_none());
    }

    #[test]
    fn rpc_without_finalized_proof_is_not_bridge_finality() {
        let p = eth();
        let r = EvmBridgeProofReceipt {
            source_chain_id: 1,
            destination_chain_id: 8453,
            source_block_hash: [2; 32],
            source_block_number: 10,
            event_or_state_root: [3; 32],
            proof_root: [4; 32],
            deposit_or_withdrawal_id: [5; 32],
            finalized: false,
        };
        assert!(r.validate(&p).is_err());
    }
}
