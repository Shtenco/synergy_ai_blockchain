use sha2::{Digest, Sha256};

//! Replication-first proof-of-inference primitives.
//!
//! V1 deliberately does not pretend that a hash is a proof of correct inference.
//! Finalization requires independently assigned verifier evidence over the same
//! committed execution outcome. More expensive TEE/zk proof lanes can be added later.

const VERIFICATION_RECEIPT_SET_DOMAIN: &[u8] = b"SYNERGY/VERIFICATION-RECEIPTS/V1\0";

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
    /// Zero is allowed only for an inconclusive verifier that could not complete
    /// deterministic recomputation before the challenge deadline.
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
            || self.trace_commitment == [0; 32]
            || self.signature_commitment == [0; 32]
        {
            return Err("verifier receipt commitments required");
        }
        if self.completed_at < challenge.opened_at || self.completed_at > challenge.closes_at {
            return Err("verifier receipt outside challenge window");
        }

        match self.verdict {
            VerificationVerdict::Inconclusive => {
                if self.recomputed_output_commitment != [0; 32] {
                    return Err("inconclusive receipt must not claim a recomputed output");
                }
            }
            VerificationVerdict::Match => {
                if self.recomputed_output_commitment == [0; 32]
                    || self.recomputed_output_commitment != challenge.challenged_output_commitment
                {
                    return Err("match verdict/output commitment inconsistency");
                }
            }
            VerificationVerdict::Mismatch => {
                if self.recomputed_output_commitment == [0; 32]
                    || self.recomputed_output_commitment == challenge.challenged_output_commitment
                {
                    return Err("mismatch verdict/output commitment inconsistency");
                }
            }
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

fn canonical_receipt_set(
    challenge: &VerificationChallenge,
    receipts: &[VerifierReceipt],
) -> Result<([u8; 32], u16, u16, u16), &'static str> {
    challenge.validate()?;
    let count = u16::try_from(receipts.len()).map_err(|_| "too many verifier receipts")?;

    let mut hasher = Sha256::new();
    hasher.update(VERIFICATION_RECEIPT_SET_DOMAIN);
    hasher.update(challenge.challenge_id);
    hasher.update((receipts.len() as u64).to_be_bytes());

    let mut previous_verifier: Option<[u8; 32]> = None;
    let mut matches = 0u16;
    let mut mismatches = 0u16;
    let mut inconclusive = 0u16;

    for receipt in receipts {
        receipt.validate_against(challenge)?;

        if let Some(previous) = previous_verifier {
            if receipt.verifier_id <= previous {
                return Err("verifier receipts must be strictly ordered and unique");
            }
        }
        previous_verifier = Some(receipt.verifier_id);

        match receipt.verdict {
            VerificationVerdict::Match => {
                matches = matches.checked_add(1).ok_or("match count overflow")?;
            }
            VerificationVerdict::Mismatch => {
                mismatches = mismatches.checked_add(1).ok_or("mismatch count overflow")?;
            }
            VerificationVerdict::Inconclusive => {
                inconclusive = inconclusive
                    .checked_add(1)
                    .ok_or("inconclusive count overflow")?;
            }
        }

        hasher.update(receipt.challenge_id);
        hasher.update(receipt.verifier_id);
        hasher.update(receipt.recomputed_output_commitment);
        hasher.update(receipt.trace_commitment);
        hasher.update(receipt.signature_commitment);
        hasher.update([match receipt.verdict {
            VerificationVerdict::Match => 1,
            VerificationVerdict::Mismatch => 2,
            VerificationVerdict::Inconclusive => 3,
        }]);
        hasher.update(receipt.completed_at.to_be_bytes());
    }

    let root: [u8; 32] = hasher.finalize().into();
    if count == 0 {
        return Err("verification receipt set must not be empty");
    }

    Ok((root, matches, mismatches, inconclusive))
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

    pub fn validate_receipts(
        &self,
        challenge: &VerificationChallenge,
        receipts: &[VerifierReceipt],
    ) -> Result<(), &'static str> {
        self.validate(challenge)?;

        let (root, matches, mismatches, inconclusive) =
            canonical_receipt_set(challenge, receipts)?;

        if receipts.len() != self.distinct_verifiers as usize
            || root != self.receipt_root
            || matches != self.matches
            || mismatches != self.mismatches
            || inconclusive != self.inconclusive
        {
            return Err("verification aggregate does not match canonical receipt set");
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

    fn receipt(
        verifier: u8,
        verdict: VerificationVerdict,
        recomputed: [u8; 32],
    ) -> VerifierReceipt {
        VerifierReceipt {
            challenge_id: [1; 32],
            verifier_id: [verifier; 32],
            recomputed_output_commitment: recomputed,
            trace_commitment: [6 + verifier; 32],
            signature_commitment: [20 + verifier; 32],
            verdict,
            completed_at: 15,
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
    fn inconclusive_cannot_smuggle_an_output_commitment() {
        let c = challenge();
        let r = VerifierReceipt {
            challenge_id: c.challenge_id,
            verifier_id: [5; 32],
            recomputed_output_commitment: [9; 32],
            trace_commitment: [6; 32],
            signature_commitment: [7; 32],
            verdict: VerificationVerdict::Inconclusive,
            completed_at: 15,
        };
        assert!(r.validate_against(&c).is_err());
    }

    #[test]
    fn valid_inconclusive_has_no_output_commitment() {
        let c = challenge();
        let r = VerifierReceipt {
            challenge_id: c.challenge_id,
            verifier_id: [5; 32],
            recomputed_output_commitment: [0; 32],
            trace_commitment: [6; 32],
            signature_commitment: [7; 32],
            verdict: VerificationVerdict::Inconclusive,
            completed_at: 15,
        };
        assert_eq!(r.validate_against(&c), Ok(()));
    }

    #[test]
    fn aggregate_must_match_canonical_unique_receipt_set() {
        let challenge = challenge();
        let receipts = vec![
            receipt(5, VerificationVerdict::Match, challenge.challenged_output_commitment),
            receipt(6, VerificationVerdict::Match, challenge.challenged_output_commitment),
        ];
        let (root, matches, mismatches, inconclusive) =
            canonical_receipt_set(&challenge, &receipts).expect("receipt set");

        let aggregate = VerificationAggregate {
            challenge_id: challenge.challenge_id,
            receipt_root: root,
            distinct_verifiers: 2,
            matches,
            mismatches,
            inconclusive,
        };
        assert_eq!(aggregate.validate_receipts(&challenge, &receipts), Ok(()));

        let mut forged = aggregate.clone();
        forged.matches = 1;
        forged.inconclusive = 1;
        assert!(forged.validate_receipts(&challenge, &receipts).is_err());
    }

    #[test]
    fn duplicate_or_reordered_verifiers_are_rejected() {
        let challenge = challenge();
        let duplicate = vec![
            receipt(5, VerificationVerdict::Match, challenge.challenged_output_commitment),
            receipt(5, VerificationVerdict::Match, challenge.challenged_output_commitment),
        ];
        assert!(canonical_receipt_set(&challenge, &duplicate).is_err());

        let reordered = vec![
            receipt(6, VerificationVerdict::Match, challenge.challenged_output_commitment),
            receipt(5, VerificationVerdict::Match, challenge.challenged_output_commitment),
        ];
        assert!(canonical_receipt_set(&challenge, &reordered).is_err());
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
