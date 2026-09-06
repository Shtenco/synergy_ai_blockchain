pub mod pq_event_signing;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FinancialCommitmentArtifact {
    pub close_id: String,
    pub snapshot_hash: String,
    pub merkle_root: String,
    pub hardnav: f64,
    pub liquid_nav: f64,
    pub liabilities: f64,
    pub accounting_period_end: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FinalityStatus {
    PENDING,
    FINAL,
    REORGED,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ChainCommitmentReceipt {
    pub close_id: String,
    pub chain_id: String,
    pub block_height: u64,
    pub tx_hash: String,
    pub commitment_hash: String,
    pub finality_status: FinalityStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContractError {
    InvalidSnapshotHash,
    InvalidMerkleRoot,
    NegativeLiabilities,
    MissingChainId,
    MissingTxHash,
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

pub fn validate_financial_commitment(
    artifact: &FinancialCommitmentArtifact,
) -> Result<(), ContractError> {
    if !is_sha256_hex(&artifact.snapshot_hash) {
        return Err(ContractError::InvalidSnapshotHash);
    }
    if !is_sha256_hex(&artifact.merkle_root) {
        return Err(ContractError::InvalidMerkleRoot);
    }
    if artifact.liabilities < 0.0 {
        return Err(ContractError::NegativeLiabilities);
    }
    Ok(())
}

pub fn make_chain_receipt(
    artifact: &FinancialCommitmentArtifact,
    chain_id: impl Into<String>,
    block_height: u64,
    tx_hash: impl Into<String>,
    finality_status: FinalityStatus,
) -> Result<ChainCommitmentReceipt, ContractError> {
    validate_financial_commitment(artifact)?;
    let chain_id = chain_id.into();
    let tx_hash = tx_hash.into();
    if chain_id.is_empty() {
        return Err(ContractError::MissingChainId);
    }
    if tx_hash.is_empty() {
        return Err(ContractError::MissingTxHash);
    }
    Ok(ChainCommitmentReceipt {
        close_id: artifact.close_id.clone(),
        chain_id,
        block_height,
        tx_hash,
        commitment_hash: artifact.snapshot_hash.clone(),
        finality_status,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn artifact() -> FinancialCommitmentArtifact {
        FinancialCommitmentArtifact {
            close_id: "close-1".into(),
            snapshot_hash: "a".repeat(64),
            merkle_root: "b".repeat(64),
            hardnav: 1_000_000.0,
            liquid_nav: 800_000.0,
            liabilities: 100_000.0,
            accounting_period_end: "2026-09-06T10:00:00Z".into(),
        }
    }

    #[test]
    fn chain_commits_snapshot_hash_without_repricing_financial_state() {
        let source = artifact();
        let receipt = make_chain_receipt(
            &source,
            "synergy-testnet",
            42,
            "0xabc",
            FinalityStatus::FINAL,
        )
        .unwrap();
        assert_eq!(receipt.commitment_hash, source.snapshot_hash);
        assert_eq!(receipt.close_id, source.close_id);
    }

    #[test]
    fn invalid_hash_is_rejected() {
        let mut source = artifact();
        source.snapshot_hash = "not-a-hash".into();
        assert_eq!(
            validate_financial_commitment(&source),
            Err(ContractError::InvalidSnapshotHash),
        );
    }
}
