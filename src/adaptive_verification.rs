#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use sha2::{Digest, Sha256};

use crate::pq::{
    verify_envelope_authorization, AuthPolicy, AuthorizationDomain, AuthorizationEnvelope,
    AuthorizationReplayState, AuthorizationValidationContext, ContextSignatureVerifier,
    HybridAuthorization,
};
use crate::verification::{
    aggregate_verifier_receipts, VerificationChallenge, VerificationVerdict, VerifierReceipt,
};

pub const ADAPTIVE_SAMPLE_DOMAIN: &[u8] = b"SYNERGY/ADAPTIVE-SAMPLE/V1\0";
pub const ADAPTIVE_CERT_DOMAIN: &[u8] = b"SYNERGY/ADAPTIVE-VERIFICATION-CERT/V1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdaptiveVerificationPolicy {
    pub samples_per_verifier: u16,
    pub min_independent_verifiers: u16,
    pub full_recompute_replications: u16,
    pub strict_full_recompute: bool,
}

impl AdaptiveVerificationPolicy {
    pub fn validate(&self, shard_count: u32) -> Result<(), &'static str> {
        if shard_count == 0 {
            return Err("adaptive verification requires shards");
        }
        if self.samples_per_verifier == 0
            || u32::from(self.samples_per_verifier) > shard_count
            || self.min_independent_verifiers < 2
            || self.full_recompute_replications < 2
        {
            return Err("invalid adaptive verification policy");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SampledShardReceipt {
    pub challenge_id: [u8; 32],
    pub verifier_id: [u8; 32],
    pub shard_index: u32,
    pub expected_shard_commitment: [u8; 32],
    pub recomputed_shard_commitment: [u8; 32],
    pub trace_commitment: [u8; 32],
    pub completed_at: u64,
}

impl SampledShardReceipt {
    pub fn validate_against(
        &self,
        challenge: &VerificationChallenge,
        expected: [u8; 32],
    ) -> Result<(), &'static str> {
        if self.challenge_id != challenge.challenge_id
            || self.verifier_id == [0; 32]
            || self.trace_commitment == [0; 32]
            || self.expected_shard_commitment != expected
            || self.recomputed_shard_commitment == [0; 32]
        {
            return Err("invalid sampled shard receipt");
        }
        if self.completed_at < challenge.opened_at || self.completed_at > challenge.closes_at {
            return Err("sampled shard receipt outside challenge window");
        }
        Ok(())
    }

    pub fn matches(&self) -> bool {
        self.recomputed_shard_commitment == self.expected_shard_commitment
    }

    pub fn commitment(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(ADAPTIVE_SAMPLE_DOMAIN);
        h.update(self.challenge_id);
        h.update(self.verifier_id);
        h.update(self.shard_index.to_be_bytes());
        h.update(self.expected_shard_commitment);
        h.update(self.recomputed_shard_commitment);
        h.update(self.trace_commitment);
        h.update(self.completed_at.to_be_bytes());
        h.finalize().into()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdaptiveVerifierBundle {
    pub verifier_id: [u8; 32],
    pub samples: Vec<SampledShardReceipt>,
}

impl AdaptiveVerifierBundle {
    pub fn commitment(&self) -> Option<[u8; 32]> {
        if self.verifier_id == [0; 32] || self.samples.is_empty() {
            return None;
        }
        let mut h = Sha256::new();
        h.update(ADAPTIVE_CERT_DOMAIN);
        h.update(b"BUNDLE");
        h.update(self.verifier_id);
        h.update((self.samples.len() as u64).to_be_bytes());
        for sample in &self.samples {
            if sample.verifier_id != self.verifier_id {
                return None;
            }
            h.update(sample.commitment());
        }
        Some(h.finalize().into())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdaptiveBundleAuthorization {
    pub chain_id: [u8; 32],
    pub epoch: u64,
    pub nonce: u64,
    pub expires_at: u64,
    pub bundle: AdaptiveVerifierBundle,
    pub authorization: HybridAuthorization,
}

impl AdaptiveBundleAuthorization {
    pub fn envelope(&self) -> Option<AuthorizationEnvelope> {
        Some(AuthorizationEnvelope {
            chain_id: self.chain_id,
            domain: AuthorizationDomain::AdaptiveVerificationReceipt,
            epoch: self.epoch,
            nonce: self.nonce,
            expires_at: self.expires_at,
            payload_commitment: self.bundle.commitment()?,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdaptiveBundleValidationContext {
    pub expected_chain_id: [u8; 32],
    pub expected_epoch: u64,
    pub expected_nonce: u64,
    pub expected_verifier_id: [u8; 32],
    pub expected_verifier_keyset_commitment: [u8; 32],
    pub now: u64,
    pub max_future_seconds: u64,
}

pub fn verify_adaptive_bundle_and_consume<V: ContextSignatureVerifier>(
    verifier: &V,
    authorized: &AdaptiveBundleAuthorization,
    validation: AdaptiveBundleValidationContext,
    replay: &mut AuthorizationReplayState,
) -> bool {
    if authorized.authorization.policy != AuthPolicy::PqOnly
        || authorized.bundle.verifier_id != validation.expected_verifier_id
        || authorized.authorization.keyset_commitment()
            != Some(validation.expected_verifier_keyset_commitment)
    {
        return false;
    }
    let envelope = match authorized.envelope() {
        Some(envelope) => envelope,
        None => return false,
    };
    let auth_validation = AuthorizationValidationContext {
        expected_chain_id: validation.expected_chain_id,
        expected_domain: AuthorizationDomain::AdaptiveVerificationReceipt,
        expected_policy: AuthPolicy::PqOnly,
        expected_epoch: validation.expected_epoch,
        expected_nonce: validation.expected_nonce,
        now: validation.now,
        max_future_seconds: validation.max_future_seconds,
    };
    if !verify_envelope_authorization(
        verifier,
        &authorized.authorization,
        &envelope,
        &auth_validation,
    ) {
        return false;
    }
    replay.consume_verified_for_subject(
        &authorized.authorization,
        &envelope,
        validation.expected_verifier_id,
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdaptiveVerificationOutcome {
    SampledMatch,
    EscalateToFullRecompute,
    FullMatch,
    FullMismatch,
    Inconclusive,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdaptiveVerificationCertificate {
    pub challenge_id: [u8; 32],
    pub outcome: AdaptiveVerificationOutcome,
    pub verifier_count: u16,
    pub sampled_shard_count: u32,
    pub sample_receipts_root: [u8; 32],
    pub full_receipts_root: [u8; 32],
}

impl AdaptiveVerificationCertificate {
    pub fn commitment(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(ADAPTIVE_CERT_DOMAIN);
        h.update(self.challenge_id);
        h.update([match self.outcome {
            AdaptiveVerificationOutcome::SampledMatch => 1,
            AdaptiveVerificationOutcome::EscalateToFullRecompute => 2,
            AdaptiveVerificationOutcome::FullMatch => 3,
            AdaptiveVerificationOutcome::FullMismatch => 4,
            AdaptiveVerificationOutcome::Inconclusive => 5,
        }]);
        h.update(self.verifier_count.to_be_bytes());
        h.update(self.sampled_shard_count.to_be_bytes());
        h.update(self.sample_receipts_root);
        h.update(self.full_receipts_root);
        h.finalize().into()
    }

    pub fn reward_eligible(&self, allow_sampled_match: bool) -> bool {
        self.outcome == AdaptiveVerificationOutcome::FullMatch
            || (allow_sampled_match && self.outcome == AdaptiveVerificationOutcome::SampledMatch)
    }
}

pub fn deterministic_sample_indices(
    challenge: &VerificationChallenge,
    verifier_id: [u8; 32],
    shard_count: u32,
    sample_count: u16,
) -> Result<Vec<u32>, &'static str> {
    if verifier_id == [0; 32]
        || shard_count == 0
        || sample_count == 0
        || u32::from(sample_count) > shard_count
    {
        return Err("invalid deterministic sample request");
    }

    let mut selected = BTreeSet::new();
    let mut counter = 0u64;
    while selected.len() < usize::from(sample_count) {
        let mut h = Sha256::new();
        h.update(ADAPTIVE_SAMPLE_DOMAIN);
        h.update(challenge.sample_seed_commitment);
        h.update(challenge.challenge_id);
        h.update(challenge.job_id);
        h.update(verifier_id);
        h.update(counter.to_be_bytes());
        let digest: [u8; 32] = h.finalize().into();
        let n = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]) % shard_count;
        selected.insert(n);
        counter = counter.checked_add(1).ok_or("sample counter overflow")?;
    }
    Ok(selected.into_iter().collect())
}

fn canonical_sample_root(
    challenge: &VerificationChallenge,
    shard_commitments: &[[u8; 32]],
    policy: AdaptiveVerificationPolicy,
    bundles: &[AdaptiveVerifierBundle],
) -> Result<(u16, u32, [u8; 32], bool), &'static str> {
    policy.validate(
        u32::try_from(shard_commitments.len()).map_err(|_| "too many verification shards")?,
    )?;
    challenge.validate()?;

    let mut seen_verifiers = BTreeSet::new();
    let mut receipts = BTreeMap::<([u8; 32], u32), [u8; 32]>::new();
    let mut mismatch = false;

    for bundle in bundles {
        if bundle.verifier_id == [0; 32] || !seen_verifiers.insert(bundle.verifier_id) {
            return Err("sample verifier identities must be distinct");
        }
        let expected_indices = deterministic_sample_indices(
            challenge,
            bundle.verifier_id,
            u32::try_from(shard_commitments.len()).map_err(|_| "too many verification shards")?,
            policy.samples_per_verifier,
        )?;
        if bundle.samples.len() != expected_indices.len() {
            return Err("sample bundle does not cover exact deterministic plan");
        }

        let mut by_index = BTreeMap::new();
        for sample in &bundle.samples {
            if sample.verifier_id != bundle.verifier_id || by_index.insert(sample.shard_index, sample).is_some() {
                return Err("duplicate or substituted sampled shard receipt");
            }
        }

        for index in expected_indices {
            let sample = by_index
                .get(&index)
                .ok_or("missing deterministic sampled shard")?;
            let expected = *shard_commitments
                .get(usize::try_from(index).map_err(|_| "sample index overflow")?)
                .ok_or("sample index outside shard set")?;
            sample.validate_against(challenge, expected)?;
            mismatch |= !sample.matches();
            receipts.insert((bundle.verifier_id, index), sample.commitment());
        }
    }

    let verifier_count =
        u16::try_from(seen_verifiers.len()).map_err(|_| "too many sample verifiers")?;
    let sampled_shard_count =
        u32::try_from(receipts.len()).map_err(|_| "too many sample receipts")?;

    let mut h = Sha256::new();
    h.update(ADAPTIVE_CERT_DOMAIN);
    h.update(challenge.challenge_id);
    h.update(verifier_count.to_be_bytes());
    h.update(sampled_shard_count.to_be_bytes());
    for ((verifier_id, index), root) in receipts {
        h.update(verifier_id);
        h.update(index.to_be_bytes());
        h.update(root);
    }
    Ok((verifier_count, sampled_shard_count, h.finalize().into(), mismatch))
}

pub fn evaluate_adaptive_samples(
    challenge: &VerificationChallenge,
    shard_commitments: &[[u8; 32]],
    policy: AdaptiveVerificationPolicy,
    bundles: &[AdaptiveVerifierBundle],
) -> Result<AdaptiveVerificationCertificate, &'static str> {
    let (verifier_count, sampled_shard_count, sample_receipts_root, mismatch) =
        canonical_sample_root(challenge, shard_commitments, policy, bundles)?;

    let outcome = if mismatch
        || verifier_count < policy.min_independent_verifiers
        || policy.strict_full_recompute
    {
        AdaptiveVerificationOutcome::EscalateToFullRecompute
    } else {
        AdaptiveVerificationOutcome::SampledMatch
    };

    Ok(AdaptiveVerificationCertificate {
        challenge_id: challenge.challenge_id,
        outcome,
        verifier_count,
        sampled_shard_count,
        sample_receipts_root,
        full_receipts_root: [0; 32],
    })
}

pub fn resolve_full_recompute(
    challenge: &VerificationChallenge,
    sample_certificate: &AdaptiveVerificationCertificate,
    full_receipts: &[VerifierReceipt],
    required_replications: u16,
) -> Result<AdaptiveVerificationCertificate, &'static str> {
    if sample_certificate.challenge_id != challenge.challenge_id
        || sample_certificate.outcome != AdaptiveVerificationOutcome::EscalateToFullRecompute
        || required_replications < 2
    {
        return Err("invalid adaptive escalation certificate");
    }

    let mut strict = challenge.clone();
    strict.required_replications = required_replications;
    let aggregate = aggregate_verifier_receipts(&strict, full_receipts)?;
    let outcome = match aggregate.final_verdict() {
        VerificationVerdict::Match => AdaptiveVerificationOutcome::FullMatch,
        VerificationVerdict::Mismatch => AdaptiveVerificationOutcome::FullMismatch,
        VerificationVerdict::Inconclusive => AdaptiveVerificationOutcome::Inconclusive,
    };

    Ok(AdaptiveVerificationCertificate {
        challenge_id: challenge.challenge_id,
        outcome,
        verifier_count: aggregate.distinct_verifiers,
        sampled_shard_count: sample_certificate.sampled_shard_count,
        sample_receipts_root: sample_certificate.sample_receipts_root,
        full_receipts_root: aggregate.receipt_root,
    })
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
            closes_at: 100,
        }
    }

    fn shards(n: usize) -> Vec<[u8; 32]> {
        (0..n).map(|i| [u8::try_from(i + 1).unwrap(); 32]).collect()
    }

    fn bundle(
        verifier: u8,
        shard_commitments: &[[u8; 32]],
        policy: AdaptiveVerificationPolicy,
        corrupt_first: bool,
    ) -> AdaptiveVerifierBundle {
        let c = challenge();
        let id = [verifier; 32];
        let indices = deterministic_sample_indices(
            &c,
            id,
            u32::try_from(shard_commitments.len()).unwrap(),
            policy.samples_per_verifier,
        )
        .unwrap();
        let samples = indices
            .iter()
            .enumerate()
            .map(|(position, index)| {
                let expected = shard_commitments[*index as usize];
                let mut actual = expected;
                if corrupt_first && position == 0 {
                    actual[0] ^= 1;
                }
                SampledShardReceipt {
                    challenge_id: c.challenge_id,
                    verifier_id: id,
                    shard_index: *index,
                    expected_shard_commitment: expected,
                    recomputed_shard_commitment: actual,
                    trace_commitment: [verifier.wrapping_add(1); 32],
                    completed_at: 50,
                }
            })
            .collect();
        AdaptiveVerifierBundle { verifier_id: id, samples }
    }

    #[test]
    fn deterministic_sampling_is_stable_and_unique() {
        let c = challenge();
        let a = deterministic_sample_indices(&c, [9; 32], 100, 8).unwrap();
        let b = deterministic_sample_indices(&c, [9; 32], 100, 8).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.len(), 8);
        assert_eq!(a.iter().copied().collect::<BTreeSet<_>>().len(), 8);
    }

    #[test]
    fn clean_samples_avoid_full_recompute() {
        let policy = AdaptiveVerificationPolicy {
            samples_per_verifier: 3,
            min_independent_verifiers: 2,
            full_recompute_replications: 2,
            strict_full_recompute: false,
        };
        let shards = shards(16);
        let cert = evaluate_adaptive_samples(
            &challenge(),
            &shards,
            policy,
            &[bundle(10, &shards, policy, false), bundle(20, &shards, policy, false)],
        )
        .unwrap();
        assert_eq!(cert.outcome, AdaptiveVerificationOutcome::SampledMatch);
        assert!(cert.reward_eligible(true));
    }

    #[test]
    fn any_sample_mismatch_forces_full_recompute() {
        let policy = AdaptiveVerificationPolicy {
            samples_per_verifier: 3,
            min_independent_verifiers: 2,
            full_recompute_replications: 2,
            strict_full_recompute: false,
        };
        let shards = shards(16);
        let cert = evaluate_adaptive_samples(
            &challenge(),
            &shards,
            policy,
            &[bundle(10, &shards, policy, true), bundle(20, &shards, policy, false)],
        )
        .unwrap();
        assert_eq!(
            cert.outcome,
            AdaptiveVerificationOutcome::EscalateToFullRecompute
        );
        assert!(!cert.reward_eligible(true));
    }

    #[test]
    fn strict_mode_always_escalates() {
        let policy = AdaptiveVerificationPolicy {
            samples_per_verifier: 2,
            min_independent_verifiers: 2,
            full_recompute_replications: 2,
            strict_full_recompute: true,
        };
        let shards = shards(8);
        let cert = evaluate_adaptive_samples(
            &challenge(),
            &shards,
            policy,
            &[bundle(10, &shards, policy, false), bundle(20, &shards, policy, false)],
        )
        .unwrap();
        assert_eq!(
            cert.outcome,
            AdaptiveVerificationOutcome::EscalateToFullRecompute
        );
    }
}
