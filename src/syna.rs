//! SYNA Proof-of-Useful-Inference reward authorization.
//!
//! Mining in this lane means useful, independently verified AI inference.
//! A worker can receive an issuance authorization only from the exact finalized
//! inference/verification/settlement checkpoint. No MATCH -> no worker mint.

use std::collections::{BTreeMap, BTreeSet};

use sha2::{Digest, Sha256};

use crate::{
    ComputeSettlement, MvpCheckpoint, VerificationAggregate, VerificationChallenge,
    VerificationVerdict,
};

pub const SYNA_REWARD_CLAIM_DOMAIN: &[u8] = b"SYNERGY/SYNA-INFERENCE-REWARD/V1\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SynaRewardPolicy {
    pub version: u32,
    pub reward_per_useful_unit: u128,
    pub max_reward_per_job: u128,
    pub max_reward_per_epoch: u128,
    pub max_total_supply: u128,
    pub min_distinct_verifiers: u16,
}

impl SynaRewardPolicy {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.version == 0
            || self.reward_per_useful_unit == 0
            || self.max_reward_per_job == 0
            || self.max_reward_per_epoch == 0
            || self.max_total_supply == 0
            || self.min_distinct_verifiers < 2
        {
            return Err("invalid SYNA reward policy");
        }
        if self.max_reward_per_job > self.max_reward_per_epoch
            || self.max_reward_per_epoch > self.max_total_supply
        {
            return Err("inconsistent SYNA emission caps");
        }
        Ok(())
    }

    pub fn reward_for(&self, useful_work_units: u64) -> Option<u128> {
        self.validate().ok()?;
        if useful_work_units == 0 {
            return None;
        }
        let raw = self
            .reward_per_useful_unit
            .checked_mul(u128::from(useful_work_units))?;
        Some(raw.min(self.max_reward_per_job))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SynaInferenceClaim {
    pub chain_id: [u8; 32],
    pub epoch: u64,
    pub job_id: [u8; 32],
    pub model_root: [u8; 32],
    pub inference_root: [u8; 32],
    pub verifier_set_root: [u8; 32],
    pub settlement_root: [u8; 32],
    pub checkpoint_root: [u8; 32],
    pub worker_id: [u8; 32],
    pub useful_work_units: u64,
    pub reward_policy_version: u32,
    pub reward_nonce: u64,
}

impl SynaInferenceClaim {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.chain_id == [0; 32]
            || self.epoch == 0
            || self.job_id == [0; 32]
            || self.model_root == [0; 32]
            || self.inference_root == [0; 32]
            || self.verifier_set_root == [0; 32]
            || self.settlement_root == [0; 32]
            || self.checkpoint_root == [0; 32]
            || self.worker_id == [0; 32]
            || self.useful_work_units == 0
            || self.reward_policy_version == 0
            || self.reward_nonce == 0
        {
            return Err("incomplete SYNA inference claim");
        }
        Ok(())
    }

    pub fn claim_id(&self) -> Option<[u8; 32]> {
        self.validate().ok()?;
        let mut h = Sha256::new();
        h.update(SYNA_REWARD_CLAIM_DOMAIN);
        h.update(crate::pq::CRYPTO_PROFILE_VERSION.to_be_bytes());
        h.update(self.chain_id);
        h.update(self.epoch.to_be_bytes());
        h.update(self.job_id);
        h.update(self.model_root);
        h.update(self.inference_root);
        h.update(self.verifier_set_root);
        h.update(self.settlement_root);
        h.update(self.checkpoint_root);
        h.update(self.worker_id);
        h.update(self.useful_work_units.to_be_bytes());
        h.update(self.reward_policy_version.to_be_bytes());
        h.update(self.reward_nonce.to_be_bytes());
        Some(h.finalize().into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SynaMintAuthorization {
    pub claim_id: [u8; 32],
    pub worker_id: [u8; 32],
    pub amount: u128,
    pub epoch: u64,
    pub checkpoint_root: [u8; 32],
}

#[derive(Debug, Default, Clone)]
pub struct SynaClaimState {
    consumed_claims: BTreeSet<[u8; 32]>,
    minted_by_epoch: BTreeMap<u64, u128>,
    total_minted: u128,
}

impl SynaClaimState {
    pub fn total_minted(&self) -> u128 {
        self.total_minted
    }

    pub fn minted_in_epoch(&self, epoch: u64) -> u128 {
        self.minted_by_epoch.get(&epoch).copied().unwrap_or(0)
    }

    pub fn is_consumed(&self, claim_id: &[u8; 32]) -> bool {
        self.consumed_claims.contains(claim_id)
    }
}

pub fn authorize_syna_inference_mint_and_consume(
    claim: &SynaInferenceClaim,
    policy: &SynaRewardPolicy,
    checkpoint: &MvpCheckpoint,
    challenge: &VerificationChallenge,
    aggregate: &VerificationAggregate,
    settlement: &ComputeSettlement,
    state: &mut SynaClaimState,
) -> Result<SynaMintAuthorization, &'static str> {
    claim.validate()?;
    policy.validate()?;
    checkpoint.validate()?;
    challenge.validate()?;
    aggregate.validate(challenge)?;

    if aggregate.final_verdict() != VerificationVerdict::Match {
        return Err("SYNA inference mint requires MATCH verdict");
    }
    if aggregate.distinct_verifiers < policy.min_distinct_verifiers {
        return Err("insufficient verifier quorum for SYNA mint");
    }

    let checkpoint_root = checkpoint.commitment().ok_or("invalid checkpoint")?;
    if claim.checkpoint_root != checkpoint_root
        || claim.chain_id != checkpoint.chain_id
        || claim.epoch != checkpoint.epoch
        || claim.model_root != checkpoint.model_root
        || claim.inference_root != checkpoint.inference_root
        || claim.verifier_set_root != checkpoint.verification_root
        || claim.settlement_root != checkpoint.settlement_root
        || claim.job_id != challenge.job_id
        || settlement.job_id != claim.job_id
        || settlement.worker_id != claim.worker_id
        || settlement.verifier_set_root != claim.verifier_set_root
        || settlement.worker_reward == 0
        || settlement.slash_root.is_some()
    {
        return Err("SYNA claim does not match finalized inference state");
    }

    let funded_amount = settlement
        .total_debit()
        .ok_or("compute settlement debit overflow")?;
    let settlement_root = settlement
        .canonical_root(challenge, aggregate, funded_amount)
        .ok_or("invalid compute settlement for SYNA mint")?;
    if settlement_root != claim.settlement_root {
        return Err("SYNA settlement root mismatch");
    }

    if claim.reward_policy_version != policy.version {
        return Err("SYNA reward policy version mismatch");
    }

    let amount = policy
        .reward_for(claim.useful_work_units)
        .ok_or("invalid useful-work reward")?;
    let claim_id = claim.claim_id().ok_or("invalid SYNA claim id")?;
    if state.is_consumed(&claim_id) {
        return Err("SYNA reward claim already consumed");
    }

    let epoch_total = state
        .minted_in_epoch(claim.epoch)
        .checked_add(amount)
        .ok_or("SYNA epoch mint overflow")?;
    if epoch_total > policy.max_reward_per_epoch {
        return Err("SYNA epoch emission cap exceeded");
    }

    let total_minted = state
        .total_minted
        .checked_add(amount)
        .ok_or("SYNA total supply overflow")?;
    if total_minted > policy.max_total_supply {
        return Err("SYNA total supply cap exceeded");
    }

    state.consumed_claims.insert(claim_id);
    state.minted_by_epoch.insert(claim.epoch, epoch_total);
    state.total_minted = total_minted;

    Ok(SynaMintAuthorization {
        claim_id,
        worker_id: claim.worker_id,
        amount,
        epoch: claim.epoch,
        checkpoint_root,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{aggregate_verifier_receipts, VerifierReceipt};

    fn challenge() -> VerificationChallenge {
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

    fn receipt(id: u8, verdict: VerificationVerdict, output: [u8; 32]) -> VerifierReceipt {
        VerifierReceipt {
            challenge_id: [1; 32],
            verifier_id: [id; 32],
            recomputed_output_commitment: output,
            trace_commitment: [10 + id; 32],
            signature_commitment: [20 + id; 32],
            verdict,
            completed_at: 5,
        }
    }

    #[test]
    fn mismatch_is_never_mint_eligible() {
        let c = challenge();
        let receipts = vec![
            receipt(5, VerificationVerdict::Match, c.challenged_output_commitment),
            receipt(6, VerificationVerdict::Mismatch, [99; 32]),
        ];
        let a = aggregate_verifier_receipts(&c, &receipts).unwrap();
        assert_eq!(a.final_verdict(), VerificationVerdict::Mismatch);
    }

    #[test]
    fn policy_caps_are_consistent() {
        let p = SynaRewardPolicy {
            version: 1,
            reward_per_useful_unit: 10,
            max_reward_per_job: 1_000,
            max_reward_per_epoch: 10_000,
            max_total_supply: 1_000_000,
            min_distinct_verifiers: 2,
        };
        assert_eq!(p.reward_for(5), Some(50));
    }
}
