//! Narrow MVP compute-market settlement.
//!
//! This does not replace MetaPay. It creates one deterministic reward/slash root
//! for an already funded inference job.

use crate::verification::{VerificationAggregate, VerificationChallenge, VerificationVerdict};
use sha2::{Digest, Sha256};

pub const COMPUTE_SETTLEMENT_DOMAIN: &[u8] = b"SYNERGY/COMPUTE-SETTLEMENT/V1\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComputeSettlement {
    pub job_id: [u8; 32],
    pub funding_root: [u8; 32],
    pub worker_id: [u8; 32],
    pub storage_provider_id: [u8; 32],
    pub verifier_set_root: [u8; 32],
    pub worker_reward: u128,
    pub storage_reward: u128,
    pub verifier_reward: u128,
    pub protocol_fee: u128,
    pub slash_root: Option<[u8; 32]>,
    pub refund_amount: u128,
}

impl ComputeSettlement {
    pub fn total_debit(&self) -> Option<u128> {
        self.worker_reward
            .checked_add(self.storage_reward)?
            .checked_add(self.verifier_reward)?
            .checked_add(self.protocol_fee)?
            .checked_add(self.refund_amount)
    }

    pub fn validate(
        &self,
        challenge: &VerificationChallenge,
        aggregate: &VerificationAggregate,
        funded_amount: u128,
    ) -> Result<(), &'static str> {
        challenge.validate()?;
        aggregate.validate(challenge)?;
        if self.job_id != challenge.job_id
            || self.funding_root == [0; 32]
            || self.worker_id == [0; 32]
            || self.storage_provider_id == [0; 32]
            || self.verifier_set_root != aggregate.receipt_root
        {
            return Err("compute settlement binding mismatch");
        }
        if self.total_debit() != Some(funded_amount) {
            return Err("compute settlement must exactly conserve funded amount");
        }
        match aggregate.final_verdict() {
            VerificationVerdict::Match => {
                if self.slash_root.is_some() || self.worker_reward == 0 {
                    return Err("valid worker must be rewarded and not slashed");
                }
            }
            VerificationVerdict::Mismatch => {
                if self.slash_root.is_none() || self.worker_reward != 0 {
                    return Err("invalid worker must be slashed and receive no worker reward");
                }
            }
            VerificationVerdict::Inconclusive => {
                if self.worker_reward != 0 || self.slash_root.is_some() {
                    return Err("inconclusive result cannot reward or slash worker");
                }
            }
        }
        Ok(())
    }

    pub fn canonical_root(
        &self,
        challenge: &VerificationChallenge,
        aggregate: &VerificationAggregate,
        funded_amount: u128,
    ) -> Option<[u8; 32]> {
        self.validate(challenge, aggregate, funded_amount).ok()?;
        let mut h = Sha256::new();
        h.update(COMPUTE_SETTLEMENT_DOMAIN);
        h.update(crate::pq::CRYPTO_PROFILE_VERSION.to_be_bytes());
        h.update(self.job_id);
        h.update(self.funding_root);
        h.update(self.worker_id);
        h.update(self.storage_provider_id);
        h.update(self.verifier_set_root);
        h.update(self.worker_reward.to_be_bytes());
        h.update(self.storage_reward.to_be_bytes());
        h.update(self.verifier_reward.to_be_bytes());
        h.update(self.protocol_fee.to_be_bytes());
        match self.slash_root {
            Some(root) => {
                h.update([1]);
                h.update(root);
            }
            None => h.update([0]),
        }
        h.update(self.refund_amount.to_be_bytes());
        h.update(funded_amount.to_be_bytes());
        Some(h.finalize().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn c() -> VerificationChallenge {
        VerificationChallenge {
            challenge_id: [1; 32],
            job_id: [2; 32],
            challenged_output_commitment: [3; 32],
            sample_seed_commitment: [4; 32],
            required_replications: 2,
            opened_at: 1,
            closes_at: 10,
        }
    }
    fn a_match() -> VerificationAggregate {
        VerificationAggregate {
            challenge_id: [1; 32],
            receipt_root: [5; 32],
            distinct_verifiers: 2,
            matches: 2,
            mismatches: 0,
            inconclusive: 0,
        }
    }
    #[test]
    fn matching_job_conserves_funding() {
        let s = ComputeSettlement {
            job_id: [2; 32],
            funding_root: [6; 32],
            worker_id: [7; 32],
            storage_provider_id: [8; 32],
            verifier_set_root: [5; 32],
            worker_reward: 60,
            storage_reward: 10,
            verifier_reward: 20,
            protocol_fee: 10,
            slash_root: None,
            refund_amount: 0,
        };
        assert!(s.canonical_root(&c(), &a_match(), 100).is_some());
    }
    #[test]
    fn cannot_overpay() {
        let s = ComputeSettlement {
            job_id: [2; 32],
            funding_root: [6; 32],
            worker_id: [7; 32],
            storage_provider_id: [8; 32],
            verifier_set_root: [5; 32],
            worker_reward: 90,
            storage_reward: 10,
            verifier_reward: 20,
            protocol_fee: 10,
            slash_root: None,
            refund_amount: 0,
        };
        assert!(s.canonical_root(&c(), &a_match(), 100).is_none());
    }
}
