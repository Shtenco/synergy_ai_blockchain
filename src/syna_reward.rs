//! SYNA Proof-of-Useful-Inference reward authorization.
//!
//! Monetary authorization is recomputed from the exact canonical verifier
//! receipt set. Callers cannot mint SYNA by supplying counters alone.

use std::collections::BTreeSet;

use sha2::{Digest, Sha256};

use crate::{
    aggregate_verifier_receipts, ComputeSettlement, MvpCheckpoint, SynaEmissionPolicy,
    SynaSupplyState, VerificationChallenge, VerificationVerdict, VerifierReceipt,
};

pub const SYNA_REWARD_DOMAIN: &[u8] = b"SYNERGY/SYNA-USEFUL-INFERENCE/V2\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SynaRewardClaim {
    pub claim_id: [u8; 32],
    pub chain_id: [u8; 32],
    pub epoch: u64,
    pub job_id: [u8; 32],
    pub worker_id: [u8; 32],
    pub model_root: [u8; 32],
    pub inference_root: [u8; 32],
    pub verifier_set_root: [u8; 32],
    pub settlement_root: [u8; 32],
    pub checkpoint_root: [u8; 32],
    pub useful_work_units: u128,
    pub reward_amount: u128,
    pub reward_policy_version: u32,
}

impl SynaRewardClaim {
    pub fn validate_fields(&self) -> Result<(), &'static str> {
        if self.claim_id == [0; 32]
            || self.chain_id == [0; 32]
            || self.epoch == 0
            || self.job_id == [0; 32]
            || self.worker_id == [0; 32]
            || self.model_root == [0; 32]
            || self.inference_root == [0; 32]
            || self.verifier_set_root == [0; 32]
            || self.settlement_root == [0; 32]
            || self.checkpoint_root == [0; 32]
            || self.useful_work_units == 0
            || self.reward_amount == 0
            || self.reward_policy_version == 0
        {
            return Err("SYNA reward claim fields required");
        }
        Ok(())
    }

    pub fn canonical_root(&self) -> Option<[u8; 32]> {
        self.validate_fields().ok()?;
        let mut h = Sha256::new();
        h.update(SYNA_REWARD_DOMAIN);
        h.update(crate::pq::CRYPTO_PROFILE_VERSION.to_be_bytes());
        h.update(self.claim_id);
        h.update(self.chain_id);
        h.update(self.epoch.to_be_bytes());
        h.update(self.job_id);
        h.update(self.worker_id);
        h.update(self.model_root);
        h.update(self.inference_root);
        h.update(self.verifier_set_root);
        h.update(self.settlement_root);
        h.update(self.checkpoint_root);
        h.update(self.useful_work_units.to_be_bytes());
        h.update(self.reward_amount.to_be_bytes());
        h.update(self.reward_policy_version.to_be_bytes());
        Some(h.finalize().into())
    }
}

#[derive(Debug, Default, Clone)]
pub struct SynaRewardState {
    consumed_claims: BTreeSet<[u8; 32]>,
}

impl SynaRewardState {
    pub fn is_consumed(&self, claim_id: &[u8; 32]) -> bool {
        self.consumed_claims.contains(claim_id)
    }

    fn consume(&mut self, claim_id: [u8; 32]) -> Result<(), &'static str> {
        if !self.consumed_claims.insert(claim_id) {
            return Err("SYNA reward claim already consumed");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SynaMintAuthorization {
    pub claim_root: [u8; 32],
    pub claim_id: [u8; 32],
    pub worker_id: [u8; 32],
    pub amount: u128,
    pub epoch: u64,
    pub checkpoint_root: [u8; 32],
    pub verifier_set_root: [u8; 32],
    pub settlement_root: [u8; 32],
    pub supply_state_root: [u8; 32],
}

pub fn authorize_verified_inference_reward_and_mint(
    claim: &SynaRewardClaim,
    checkpoint: &MvpCheckpoint,
    settlement: &ComputeSettlement,
    challenge: &VerificationChallenge,
    receipts: &[VerifierReceipt],
    policy: &SynaEmissionPolicy,
    reward_state: &mut SynaRewardState,
    supply_state: &mut SynaSupplyState,
) -> Result<SynaMintAuthorization, &'static str> {
    claim.validate_fields()?;
    checkpoint.validate()?;
    challenge.validate()?;
    policy.validate()?;

    let aggregate = aggregate_verifier_receipts(challenge, receipts)?;
    if aggregate.final_verdict() != VerificationVerdict::Match {
        return Err("SYNA worker reward requires canonical MATCH verdict");
    }

    let checkpoint_root = checkpoint.commitment().ok_or("invalid checkpoint")?;
    if claim.checkpoint_root != checkpoint_root
        || claim.chain_id != checkpoint.chain_id
        || claim.epoch != checkpoint.epoch
        || claim.model_root != checkpoint.model_root
        || claim.inference_root != checkpoint.inference_root
        || claim.verifier_set_root != aggregate.receipt_root
        || checkpoint.verification_root != aggregate.receipt_root
        || claim.job_id != challenge.job_id
        || settlement.job_id != challenge.job_id
        || settlement.worker_id != claim.worker_id
        || settlement.verifier_set_root != aggregate.receipt_root
        || settlement.worker_reward == 0
        || settlement.slash_root.is_some()
    {
        return Err("SYNA reward claim binding mismatch");
    }

    let funded_amount = settlement
        .total_debit()
        .ok_or("compute settlement debit overflow")?;
    let settlement_root = settlement
        .canonical_root(challenge, &aggregate, funded_amount)
        .ok_or("invalid compute settlement")?;

    if claim.settlement_root != settlement_root
        || checkpoint.settlement_root != settlement_root
    {
        return Err("SYNA settlement root mismatch");
    }

    if claim.reward_policy_version != policy.version {
        return Err("SYNA reward policy version mismatch");
    }

    let expected_reward = policy
        .reward_for_useful_work(claim.useful_work_units)
        .ok_or("useful work below reward threshold")?;
    if claim.reward_amount != expected_reward {
        return Err("SYNA reward amount is not policy-derived");
    }

    if reward_state.is_consumed(&claim.claim_id) {
        return Err("SYNA reward claim already consumed");
    }

    // Transactional preflight: mutate clones first so failure cannot partially
    // consume the one-shot claim or partially advance supply accounting.
    let mut next_supply = supply_state.clone();
    next_supply.mint_bounded(policy, claim.epoch, expected_reward)?;

    let claim_root = claim.canonical_root().ok_or("invalid SYNA claim root")?;
    let mut next_rewards = reward_state.clone();
    next_rewards.consume(claim.claim_id)?;

    let supply_state_root = next_supply
        .commitment()
        .ok_or("invalid post-mint SYNA supply state")?;

    *supply_state = next_supply;
    *reward_state = next_rewards;

    Ok(SynaMintAuthorization {
        claim_root,
        claim_id: claim.claim_id,
        worker_id: claim.worker_id,
        amount: expected_reward,
        epoch: claim.epoch,
        checkpoint_root,
        verifier_set_root: aggregate.receipt_root,
        settlement_root,
        supply_state_root,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SynaEmissionPolicy, SynaSupplyState, VerificationVerdict};

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

    fn receipt(
        verifier: u8,
        verdict: VerificationVerdict,
        recomputed: [u8; 32],
    ) -> VerifierReceipt {
        VerifierReceipt {
            challenge_id: [1; 32],
            verifier_id: [verifier; 32],
            recomputed_output_commitment: recomputed,
            trace_commitment: [10 + verifier; 32],
            signature_commitment: [20 + verifier; 32],
            verdict,
            completed_at: 5,
        }
    }

    fn policy() -> SynaEmissionPolicy {
        SynaEmissionPolicy {
            version: 1,
            max_reward_per_job: 100,
            max_emission_per_epoch: 1_000,
            max_supply: Some(10_000),
            min_useful_work_units: 10,
        }
    }

    fn fixture() -> (
        VerificationChallenge,
        Vec<VerifierReceipt>,
        ComputeSettlement,
        MvpCheckpoint,
        SynaRewardClaim,
    ) {
        let c = challenge();
        let receipts = vec![
            receipt(
                5,
                VerificationVerdict::Match,
                c.challenged_output_commitment,
            ),
            receipt(
                6,
                VerificationVerdict::Match,
                c.challenged_output_commitment,
            ),
        ];
        let a = aggregate_verifier_receipts(&c, &receipts).unwrap();
        let settlement = ComputeSettlement {
            job_id: c.job_id,
            funding_root: [6; 32],
            worker_id: [7; 32],
            storage_provider_id: [8; 32],
            verifier_set_root: a.receipt_root,
            worker_reward: 60,
            storage_reward: 10,
            verifier_reward: 20,
            protocol_fee: 10,
            slash_root: None,
            refund_amount: 0,
        };
        let settlement_root = settlement.canonical_root(&c, &a, 100).unwrap();
        let cp = MvpCheckpoint {
            chain_id: [10; 32],
            epoch: 1,
            sequence: 1,
            previous_checkpoint: [0; 32],
            model_root: [11; 32],
            network_root: [12; 32],
            provider_root: [13; 32],
            inference_root: [14; 32],
            verification_root: a.receipt_root,
            kv_root: [16; 32],
            storage_root: [17; 32],
            settlement_root,
            scheduler_root: [19; 32],
            node_set_root: [20; 32],
        };
        let claim = SynaRewardClaim {
            claim_id: [21; 32],
            chain_id: cp.chain_id,
            epoch: cp.epoch,
            job_id: c.job_id,
            worker_id: settlement.worker_id,
            model_root: cp.model_root,
            inference_root: cp.inference_root,
            verifier_set_root: a.receipt_root,
            settlement_root,
            checkpoint_root: cp.commitment().unwrap(),
            useful_work_units: 100,
            reward_amount: 10,
            reward_policy_version: 1,
        };
        (c, receipts, settlement, cp, claim)
    }

    #[test]
    fn verified_inference_mints_once_and_updates_supply() {
        let (c, receipts, settlement, cp, claim) = fixture();
        let mut rewards = SynaRewardState::default();
        let mut supply = SynaSupplyState {
            policy_version: 1,
            current_epoch: 1,
            total_supply: 0,
            epoch_emission: 0,
        };
        let auth = authorize_verified_inference_reward_and_mint(
            &claim,
            &cp,
            &settlement,
            &c,
            &receipts,
            &policy(),
            &mut rewards,
            &mut supply,
        )
        .unwrap();
        assert_eq!(auth.amount, 10);
        assert_eq!(supply.total_supply, 10);
        assert_eq!(auth.supply_state_root, supply.commitment().unwrap());
        assert!(authorize_verified_inference_reward_and_mint(
            &claim,
            &cp,
            &settlement,
            &c,
            &receipts,
            &policy(),
            &mut rewards,
            &mut supply,
        )
        .is_err());
    }

    #[test]
    fn mismatch_receipt_blocks_mint() {
        let (c, mut receipts, settlement, cp, claim) = fixture();
        receipts[1].verdict = VerificationVerdict::Mismatch;
        receipts[1].recomputed_output_commitment = [99; 32];
        let mut rewards = SynaRewardState::default();
        let mut supply = SynaSupplyState {
            policy_version: 1,
            current_epoch: 1,
            total_supply: 0,
            epoch_emission: 0,
        };
        assert!(authorize_verified_inference_reward_and_mint(
            &claim,
            &cp,
            &settlement,
            &c,
            &receipts,
            &policy(),
            &mut rewards,
            &mut supply,
        )
        .is_err());
        assert_eq!(supply.total_supply, 0);
    }

    #[test]
    fn model_cannot_self_choose_reward_amount() {
        let (c, receipts, settlement, cp, mut claim) = fixture();
        claim.reward_amount = 99;
        let mut rewards = SynaRewardState::default();
        let mut supply = SynaSupplyState {
            policy_version: 1,
            current_epoch: 1,
            total_supply: 0,
            epoch_emission: 0,
        };
        assert!(authorize_verified_inference_reward_and_mint(
            &claim,
            &cp,
            &settlement,
            &c,
            &receipts,
            &policy(),
            &mut rewards,
            &mut supply,
        )
        .is_err());
    }
}
