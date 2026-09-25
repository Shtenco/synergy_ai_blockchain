//! SYNA Proof-of-Useful-Inference reward authorization.
//!
//! A SYNA inference reward is authorized only from a finalized checkpoint
//! whose verification and settlement roots correspond to a MATCH verdict.

use std::collections::BTreeSet;
use sha2::{Digest, Sha256};

use crate::{ComputeSettlement, MvpCheckpoint, VerificationAggregate, VerificationVerdict};

pub const SYNA_REWARD_DOMAIN: &[u8] = b"SYNERGY/SYNA-USEFUL-INFERENCE/V1\0";

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
    pub fn validate(
        &self,
        checkpoint: &MvpCheckpoint,
        settlement: &ComputeSettlement,
        aggregate: &VerificationAggregate,
    ) -> Result<(), &'static str> {
        if aggregate.final_verdict() != VerificationVerdict::Match {
            return Err("SYNA worker reward requires MATCH verdict");
        }
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
        let cp_root = checkpoint.commitment().ok_or("invalid checkpoint")?;
        if self.checkpoint_root != cp_root
            || self.chain_id != checkpoint.chain_id
            || self.epoch != checkpoint.epoch
            || self.model_root != checkpoint.model_root
            || self.inference_root != checkpoint.inference_root
            || self.verifier_set_root != checkpoint.verification_root
            || self.settlement_root != checkpoint.settlement_root
            || self.job_id != settlement.job_id
            || self.worker_id != settlement.worker_id
            || settlement.worker_reward == 0
            || settlement.slash_root.is_some()
        {
            return Err("SYNA reward claim binding mismatch");
        }
        Ok(())
    }

    pub fn canonical_root(
        &self,
        checkpoint: &MvpCheckpoint,
        settlement: &ComputeSettlement,
        aggregate: &VerificationAggregate,
    ) -> Option<[u8; 32]> {
        self.validate(checkpoint, settlement, aggregate).ok()?;
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

#[derive(Debug, Default)]
pub struct SynaRewardState {
    consumed_claims: BTreeSet<[u8; 32]>,
}

impl SynaRewardState {
    pub fn consume_once(
        &mut self,
        claim: &SynaRewardClaim,
        checkpoint: &MvpCheckpoint,
        settlement: &ComputeSettlement,
        aggregate: &VerificationAggregate,
    ) -> Result<[u8; 32], &'static str> {
        let root = claim
            .canonical_root(checkpoint, settlement, aggregate)
            .ok_or("invalid SYNA reward claim")?;
        if self.consumed_claims.contains(&claim.claim_id) {
            return Err("SYNA reward claim already consumed");
        }
        self.consumed_claims.insert(claim.claim_id);
        Ok(root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::VerificationAggregate;

    fn aggregate_match() -> VerificationAggregate {
        VerificationAggregate {
            challenge_id: [1; 32],
            receipt_root: [5; 32],
            distinct_verifiers: 2,
            matches: 2,
            mismatches: 0,
            inconclusive: 0,
        }
    }

    fn checkpoint() -> MvpCheckpoint {
        MvpCheckpoint {
            chain_id: [10; 32],
            epoch: 1,
            sequence: 1,
            previous_checkpoint: [0; 32],
            model_root: [11; 32],
            network_root: [12; 32],
            provider_root: [13; 32],
            inference_root: [14; 32],
            verification_root: [5; 32],
            kv_root: [16; 32],
            storage_root: [17; 32],
            settlement_root: [18; 32],
            scheduler_root: [19; 32],
            node_set_root: [20; 32],
        }
    }

    fn settlement() -> ComputeSettlement {
        ComputeSettlement {
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
        }
    }

    fn claim(cp: &MvpCheckpoint) -> SynaRewardClaim {
        SynaRewardClaim {
            claim_id: [21; 32],
            chain_id: cp.chain_id,
            epoch: cp.epoch,
            job_id: [2; 32],
            worker_id: [7; 32],
            model_root: cp.model_root,
            inference_root: cp.inference_root,
            verifier_set_root: cp.verification_root,
            settlement_root: cp.settlement_root,
            checkpoint_root: cp.commitment().unwrap(),
            useful_work_units: 1000,
            reward_amount: 25,
            reward_policy_version: 1,
        }
    }

    #[test]
    fn verified_inference_reward_is_one_shot() {
        let cp = checkpoint();
        let s = settlement();
        let a = aggregate_match();
        let c = claim(&cp);
        let mut state = SynaRewardState::default();
        assert!(state.consume_once(&c, &cp, &s, &a).is_ok());
        assert!(state.consume_once(&c, &cp, &s, &a).is_err());
    }

    #[test]
    fn mismatch_cannot_mint_worker_reward() {
        let cp = checkpoint();
        let s = settlement();
        let mut a = aggregate_match();
        a.matches = 1;
        a.mismatches = 1;
        let c = claim(&cp);
        let mut state = SynaRewardState::default();
        assert!(state.consume_once(&c, &cp, &s, &a).is_err());
    }
}
