//! One-shot worker slashing bound to canonical verification evidence.

use crate::verification::{VerificationAggregate, VerificationChallenge, VerificationVerdict};
use sha2::{Digest, Sha256};

pub const WORKER_SLASH_DOMAIN: &[u8] = b"SYNERGY/WORKER-SLASH/V1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlashState {
    Open,
    Consumed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerSlash {
    pub slash_id: [u8; 32],
    pub job_id: [u8; 32],
    pub worker_id: [u8; 32],
    pub challenged_output_commitment: [u8; 32],
    pub verification_receipt_root: [u8; 32],
    pub amount: u128,
    pub epoch: u64,
    pub state: SlashState,
}

impl WorkerSlash {
    pub fn validate_against(
        &self,
        challenge: &VerificationChallenge,
        aggregate: &VerificationAggregate,
    ) -> Result<(), &'static str> {
        challenge.validate()?;
        aggregate.validate(challenge)?;
        if aggregate.final_verdict() != VerificationVerdict::Mismatch {
            return Err("worker slash requires confirmed mismatch");
        }
        if self.state != SlashState::Open {
            return Err("worker slash already consumed");
        }
        if self.slash_id == [0; 32]
            || self.worker_id == [0; 32]
            || self.amount == 0
            || self.epoch == 0
        {
            return Err("worker slash fields required");
        }
        if self.job_id != challenge.job_id
            || self.challenged_output_commitment != challenge.challenged_output_commitment
            || self.verification_receipt_root != aggregate.receipt_root
        {
            return Err("worker slash verification binding mismatch");
        }
        Ok(())
    }

    pub fn canonical_root(
        &self,
        challenge: &VerificationChallenge,
        aggregate: &VerificationAggregate,
    ) -> Option<[u8; 32]> {
        self.validate_against(challenge, aggregate).ok()?;
        let mut h = Sha256::new();
        h.update(WORKER_SLASH_DOMAIN);
        h.update(crate::pq::CRYPTO_PROFILE_VERSION.to_be_bytes());
        h.update(self.slash_id);
        h.update(self.job_id);
        h.update(self.worker_id);
        h.update(self.challenged_output_commitment);
        h.update(self.verification_receipt_root);
        h.update(self.amount.to_be_bytes());
        h.update(self.epoch.to_be_bytes());
        Some(h.finalize().into())
    }

    pub fn consume_once(
        &mut self,
        challenge: &VerificationChallenge,
        aggregate: &VerificationAggregate,
    ) -> Result<[u8; 32], &'static str> {
        let root = self
            .canonical_root(challenge, aggregate)
            .ok_or("invalid worker slash")?;
        self.state = SlashState::Consumed;
        Ok(root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verification::{VerificationAggregate, VerificationChallenge};

    fn challenge() -> VerificationChallenge {
        VerificationChallenge {
            challenge_id: [1; 32],
            job_id: [2; 32],
            challenged_output_commitment: [3; 32],
            sample_seed_commitment: [4; 32],
            required_replications: 2,
            opened_at: 10,
            closes_at: 20,
        }
    }

    fn mismatch() -> VerificationAggregate {
        VerificationAggregate {
            challenge_id: [1; 32],
            receipt_root: [5; 32],
            distinct_verifiers: 2,
            matches: 1,
            mismatches: 1,
            inconclusive: 0,
        }
    }

    fn slash() -> WorkerSlash {
        WorkerSlash {
            slash_id: [6; 32],
            job_id: [2; 32],
            worker_id: [7; 32],
            challenged_output_commitment: [3; 32],
            verification_receipt_root: [5; 32],
            amount: 100,
            epoch: 1,
            state: SlashState::Open,
        }
    }

    #[test]
    fn confirmed_mismatch_can_be_slashed_once() {
        let c = challenge();
        let a = mismatch();
        let mut s = slash();
        assert!(s.consume_once(&c, &a).is_ok());
        assert!(s.consume_once(&c, &a).is_err());
    }

    #[test]
    fn all_match_cannot_be_slashed() {
        let c = challenge();
        let a = VerificationAggregate {
            challenge_id: [1; 32],
            receipt_root: [5; 32],
            distinct_verifiers: 2,
            matches: 2,
            mismatches: 0,
            inconclusive: 0,
        };
        assert!(slash().canonical_root(&c, &a).is_none());
    }
}
