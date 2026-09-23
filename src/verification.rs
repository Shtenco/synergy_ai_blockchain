//! Replication-first proof-of-inference primitives.
//!
//! V1 deliberately does not pretend that a hash is a proof of correct inference.
//! Finalization requires independently assigned verifier evidence over the same
//! committed execution outcome. More expensive TEE/zk proof lanes can be added later.

use sha2::{Digest, Sha256};

use crate::pq::{
    verify_envelope_authorization, AuthPolicy, AuthorizationDomain, AuthorizationEnvelope,
    AuthorizationValidationContext, ContextSignatureVerifier, HybridAuthorization,
};


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


impl VerifierReceipt {
    pub fn authorization_commitment(
        &self,
        challenge: &VerificationChallenge,
    ) -> Option<[u8; 32]> {
        self.validate_against(challenge).ok()?;

        const DOMAIN: &[u8] = b"SYNERGY/VERIFIER-RECEIPT/V1\0";
        let mut hasher = Sha256::new();
        hasher.update(DOMAIN);
        hasher.update(self.challenge_id);
        hasher.update(self.verifier_id);
        hasher.update(self.recomputed_output_commitment);
        hasher.update(self.trace_commitment);
        hasher.update(self.signature_commitment);
        hasher.update([match self.verdict {
            VerificationVerdict::Match => 1,
            VerificationVerdict::Mismatch => 2,
            VerificationVerdict::Inconclusive => 3,
        }]);
        hasher.update(self.completed_at.to_be_bytes());
        Some(hasher.finalize().into())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifierReceiptAuthorization {
    pub chain_id: [u8; 32],
    pub epoch: u64,
    pub nonce: u64,
    pub expires_at: u64,
    pub receipt: VerifierReceipt,
    pub authorization: HybridAuthorization,
}

impl VerifierReceiptAuthorization {
    pub fn envelope(
        &self,
        challenge: &VerificationChallenge,
    ) -> Option<AuthorizationEnvelope> {
        Some(AuthorizationEnvelope {
            chain_id: self.chain_id,
            domain: AuthorizationDomain::VerificationReceipt,
            epoch: self.epoch,
            nonce: self.nonce,
            expires_at: self.expires_at,
            payload_commitment: self.receipt.authorization_commitment(challenge)?,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifierReceiptValidationContext {
    pub expected_chain_id: [u8; 32],
    pub expected_epoch: u64,
    pub expected_nonce: u64,
    pub expected_verifier_id: [u8; 32],
    pub expected_verifier_keyset_commitment: [u8; 32],
    pub now: u64,
    pub max_future_seconds: u64,
}

pub fn verify_verifier_receipt<V: ContextSignatureVerifier>(
    verifier: &V,
    challenge: &VerificationChallenge,
    authorized: &VerifierReceiptAuthorization,
    validation: &VerifierReceiptValidationContext,
) -> bool {
    if authorized.authorization.policy != AuthPolicy::PqOnly
        || authorized.receipt.verifier_id != validation.expected_verifier_id
        || authorized.authorization.keyset_commitment()
            != Some(validation.expected_verifier_keyset_commitment)
        || authorized.receipt.validate_against(challenge).is_err()
    {
        return false;
    }

    let envelope = match authorized.envelope(challenge) {
        Some(envelope) => envelope,
        None => return false,
    };

    let auth_validation = AuthorizationValidationContext {
        expected_chain_id: validation.expected_chain_id,
        expected_domain: AuthorizationDomain::VerificationReceipt,
        expected_policy: AuthPolicy::PqOnly,
        expected_epoch: validation.expected_epoch,
        expected_nonce: validation.expected_nonce,
        now: validation.now,
        max_future_seconds: validation.max_future_seconds,
    };

    verify_envelope_authorization(
        verifier,
        &authorized.authorization,
        &envelope,
        &auth_validation,
    )
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
    use crate::pq::{
        AuthScheme, ContextSignatureVerifier, SignatureEvidence, ML_DSA_87_PUBLIC_KEY_BYTES,
        ML_DSA_87_SIGNATURE_BYTES, SLH_DSA_SHAKE_256S_PUBLIC_KEY_BYTES,
        SLH_DSA_SHAKE_256S_SIGNATURE_BYTES,
    };

    #[derive(Clone)]
    struct ExpectedVerifier {
        message: Vec<u8>,
        context: Vec<u8>,
    }

    impl ContextSignatureVerifier for ExpectedVerifier {
        fn verify_with_context(
            &self,
            _scheme: AuthScheme,
            _public_key: &[u8],
            message: &[u8],
            context: &[u8],
            _signature: &[u8],
        ) -> bool {
            message == self.message && context == self.context
        }
    }

    fn pq_only_authorization() -> HybridAuthorization {
        HybridAuthorization {
            policy: AuthPolicy::PqOnly,
            evidence: vec![
                SignatureEvidence {
                    scheme: AuthScheme::MlDsa87,
                    public_key: vec![0x71; ML_DSA_87_PUBLIC_KEY_BYTES],
                    signature: vec![0x72; ML_DSA_87_SIGNATURE_BYTES],
                },
                SignatureEvidence {
                    scheme: AuthScheme::SlhDsaShake256s,
                    public_key: vec![0x73; SLH_DSA_SHAKE_256S_PUBLIC_KEY_BYTES],
                    signature: vec![0x74; SLH_DSA_SHAKE_256S_SIGNATURE_BYTES],
                },
            ],
        }
    }

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
    fn verifier_receipt_requires_registered_pq_keyset_and_state_context() {
        let challenge = challenge();
        let receipt = receipt(
            5,
            VerificationVerdict::Match,
            challenge.challenged_output_commitment,
        );
        let authorized = VerifierReceiptAuthorization {
            chain_id: [0x91; 32],
            epoch: 4,
            nonce: 5,
            expires_at: 100,
            receipt,
            authorization: pq_only_authorization(),
        };
        let envelope = authorized
            .envelope(&challenge)
            .expect("verifier receipt envelope");
        let verifier = ExpectedVerifier {
            message: envelope
                .canonical_message(AuthPolicy::PqOnly)
                .expect("verifier receipt message"),
            context: envelope
                .fips_signature_context(AuthPolicy::PqOnly)
                .expect("verifier receipt context"),
        };
        let validation = VerifierReceiptValidationContext {
            expected_chain_id: [0x91; 32],
            expected_epoch: 4,
            expected_nonce: 5,
            expected_verifier_id: [5; 32],
            expected_verifier_keyset_commitment: authorized
                .authorization
                .keyset_commitment()
                .expect("verifier keyset"),
            now: 50,
            max_future_seconds: 60,
        };

        assert!(verify_verifier_receipt(
            &verifier,
            &challenge,
            &authorized,
            &validation,
        ));

        let mut wrong = validation;
        wrong.expected_verifier_keyset_commitment[0] ^= 1;
        assert!(!verify_verifier_receipt(
            &verifier,
            &challenge,
            &authorized,
            &wrong,
        ));
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
