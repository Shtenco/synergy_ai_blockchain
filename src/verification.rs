//! Replication-first proof-of-inference primitives.
//!
//! V1 deliberately does not pretend that a hash is a proof of correct inference.
//! Finalization requires independently assigned verifier evidence over the same
//! committed execution outcome. More expensive TEE/zk proof lanes can be added later.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationVerdict {
    Match,
    Mismatch,
    Inconclusive,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationChallenge {
    pub challenge_id: [u8; 32],
    pub job_id: [u8; 32],
    pub challenged_output_commitment: [u8; 32],
    pub sample_seed_commitment: [u8; 32],
    pub required_replications: u16,
    pub opened_at: u64,
    pub closes_at: u64,
}

impl VerificationChallenge {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.challenge_id == [0; 32]
            || self.job_id == [0; 32]
            || self.challenged_output_commitment == [0; 32]
            || self.sample_seed_commitment == [0; 32]
        {
            return Err("verification challenge commitments required");
        }
        if self.required_replications < 2 {
            return Err("at least two independent replications required");
        }
        if self.closes_at <= self.opened_at {
            return Err("invalid challenge window");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifierReceipt {
    pub challenge_id: [u8; 32],
    pub verifier_id: [u8; 32],
    pub recomputed_output_commitment: [u8; 32],
    pub trace_commitment: [u8; 32],
    pub signature_commitment: [u8; 32],
    pub verdict: VerificationVerdict,
    pub completed_at: u64,
}

impl VerifierReceipt {
    pub fn validate_against(&self, challenge: &VerificationChallenge) -> Result<(), &'static str> {
        if self.challenge_id != challenge.challenge_id {
            return Err("receipt/challenge mismatch");
        }
        if self.verifier_id == [0; 32]
            || self.recomputed_output_commitment == [0; 32]
            || self.trace_commitment == [0; 32]
            || self.signature_commitment == [0; 32]
        {
            return Err("verifier receipt commitments required");
        }
        if self.completed_at < challenge.opened_at || self.completed_at > challenge.closes_at {
            return Err("verifier receipt outside challenge window");
        }
        let expected = if self.recomputed_output_commitment == challenge.challenged_output_commitment {
            VerificationVerdict::Match
        } else {
            VerificationVerdict::Mismatch
        };
        if self.verdict != expected {
            return Err("verdict/output commitment inconsistency");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationAggregate {
    pub challenge_id: [u8; 32],
    pub receipt_root: [u8; 32],
    pub distinct_verifiers: u16,
    pub matches: u16,
    pub mismatches: u16,
    pub inconclusive: u16,
}

impl VerificationAggregate {
    pub fn validate(&self, challenge: &VerificationChallenge) -> Result<(), &'static str> {
        if self.challenge_id != challenge.challenge_id || self.receipt_root == [0; 32] {
            return Err("verification aggregate mismatch");
        }
        let total = self.matches as u32 + self.mismatches as u32 + self.inconclusive as u32;
        if total != self.distinct_verifiers as u32 {
            return Err("verification receipt accounting mismatch");
        }
        if self.distinct_verifiers < challenge.required_replications {
            return Err("insufficient independent verifier receipts");
        }
        Ok(())
    }

    pub fn final_verdict(&self) -> VerificationVerdict {
        if self.mismatches > 0 {
            VerificationVerdict::Mismatch
        } else if self.matches == self.distinct_verifiers && self.inconclusive == 0 {
            VerificationVerdict::Match
        } else {
            VerificationVerdict::Inconclusive
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn a_mismatch_cannot_be_reported_as_match() {
        let c = challenge();
        let r = VerifierReceipt {
            challenge_id: c.challenge_id,
            verifier_id: [5; 32],
            recomputed_output_commitment: [9; 32],
            trace_commitment: [6; 32],
            signature_commitment: [7; 32],
            verdict: VerificationVerdict::Match,
            completed_at: 15,
        };
        assert!(r.validate_against(&c).is_err());
    }

    #[test]
    fn any_confirmed_mismatch_blocks_match_finalization() {
        let c = challenge();
        let a = VerificationAggregate {
            challenge_id: c.challenge_id,
            receipt_root: [8; 32],
            distinct_verifiers: 2,
            matches: 1,
            mismatches: 1,
            inconclusive: 0,
        };
        assert_eq!(a.validate(&c), Ok(()));
        assert_eq!(a.final_verdict(), VerificationVerdict::Mismatch);
    }
}
