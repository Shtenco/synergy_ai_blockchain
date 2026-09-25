//! SYNA Proof-of-Useful-Inference reward authorization.
//!
//! Monetary authorization is recomputed from the exact canonical verifier
//! receipt set. Callers cannot mint SYNA by supplying counters alone.

use std::collections::BTreeSet;

use sha2::{Digest, Sha256};

use crate::{
    aggregate_verifier_receipts, build_inference_outcome, ComputeSettlement,
    InferenceExecutionPlan, InferenceJob, InferenceOutcome, InferenceReceiptAuthorization,
    InferenceReceiptValidationContext, MvpCheckpoint, PeerDirectory, SynaEmissionPolicy,
    SynaSupplyState, VerificationChallenge, VerificationVerdict, VerifierReceiptAuthorization,
    VerifierReceiptValidationContext,
};
use crate::inference::verify_inference_receipt;
use crate::pq::ContextSignatureVerifier;
use crate::verification::verify_verifier_receipt;

pub const SYNA_REWARD_DOMAIN: &[u8] = b"SYNERGY/SYNA-USEFUL-INFERENCE/V2\0";
pub const SYNA_MINING_REPLAY_DOMAIN: &[u8] = b"SYNERGY/SYNA-MINING-REPLAY/V1\0";

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

    pub fn mining_replay_key(&self) -> Option<[u8; 32]> {
        self.validate_fields().ok()?;
        let mut h = Sha256::new();
        h.update(SYNA_MINING_REPLAY_DOMAIN);
        h.update(crate::pq::CRYPTO_PROFILE_VERSION.to_be_bytes());
        h.update(self.chain_id);
        h.update(self.epoch.to_be_bytes());
        h.update(self.job_id);
        h.update(self.worker_id);
        h.update(self.model_root);
        h.update(self.inference_root);
        h.update(self.verifier_set_root);
        h.update(self.settlement_root);
        h.update(self.checkpoint_root);
        Some(h.finalize().into())
    }
}

#[derive(Debug, Default, Clone)]
pub struct SynaRewardState {
    consumed_mining_keys: BTreeSet<[u8; 32]>,
}

impl SynaRewardState {
    pub fn is_consumed(&self, mining_replay_key: &[u8; 32]) -> bool {
        self.consumed_mining_keys.contains(mining_replay_key)
    }

    fn consume(&mut self, mining_replay_key: [u8; 32]) -> Result<(), &'static str> {
        if !self.consumed_mining_keys.insert(mining_replay_key) {
            return Err("SYNA finalized inference already mined");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SynaInferenceMintContext<'a> {
    pub checkpoint: &'a MvpCheckpoint,
    pub outcome: &'a InferenceOutcome,
    pub job: &'a InferenceJob,
    pub plan: &'a InferenceExecutionPlan,
    pub stage_authorizations: &'a [InferenceReceiptAuthorization],
    pub stage_validations: &'a [InferenceReceiptValidationContext],
    pub settlement: &'a ComputeSettlement,
    pub challenge: &'a VerificationChallenge,
    pub verifier_authorizations: &'a [VerifierReceiptAuthorization],
    pub verifier_validations: &'a [VerifierReceiptValidationContext],
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
    pub pre_supply_state_root: [u8; 32],
    pub supply_state_root: [u8; 32],
}

pub fn authorize_verified_inference_reward_and_mint<V: ContextSignatureVerifier>(
    signature_verifier: &V,
    claim: &SynaRewardClaim,
    context: &SynaInferenceMintContext<'_>,
    policy: &SynaEmissionPolicy,
    reward_state: &mut SynaRewardState,
    supply_state: &mut SynaSupplyState,
) -> Result<SynaMintAuthorization, &'static str> {
    claim.validate_fields()?;
    context.checkpoint.validate()?;
    context.challenge.validate()?;
    policy.validate()?;

    if context.stage_authorizations.len() != context.plan.stages.len()
        || context.stage_validations.len() != context.plan.stages.len()
    {
        return Err("every inference stage requires PQ authorization context");
    }

    let mut stage_receipts = Vec::with_capacity(context.stage_authorizations.len());
    for ((assignment, authorized), validation) in context.plan
        .stages
        .iter()
        .zip(context.stage_authorizations.iter())
        .zip(context.stage_validations.iter())
    {
        if !verify_inference_receipt(
            signature_verifier,
            assignment,
            authorized,
            validation,
        ) {
            return Err("invalid PQ-authorized inference stage receipt");
        }
        stage_receipts.push(authorized.receipt.clone());
    }

    if context.verifier_authorizations.len() != context.verifier_validations.len()
        || context.verifier_authorizations.is_empty()
    {
        return Err("verifier PQ authorization contexts required");
    }

    let mut receipts = Vec::with_capacity(context.verifier_authorizations.len());
    for (authorized, validation) in context.verifier_authorizations
        .iter()
        .zip(context.verifier_validations.iter())
    {
        if !verify_verifier_receipt(
            signature_verifier,
            context.challenge,
            authorized,
            validation,
        ) {
            return Err("invalid PQ-authorized verifier receipt");
        }
        receipts.push(authorized.receipt.clone());
    }

    let aggregate = aggregate_verifier_receipts(context.challenge, &receipts)?;
    if aggregate.final_verdict() != VerificationVerdict::Match {
        return Err("SYNA worker reward requires canonical MATCH verdict");
    }

    let checkpoint_root = context.checkpoint.commitment().ok_or("invalid checkpoint")?;
    let canonical_outcome = build_inference_outcome(
        context.job,
        context.plan,
        &stage_receipts,
        aggregate.receipt_root,
        context.outcome.total_cost,
        context.outcome.output_tokens,
    )
    .map_err(|_| "invalid canonical inference work evidence")?;
    if canonical_outcome != *context.outcome {
        return Err("inference outcome does not match canonical stage receipts");
    }
    let outcome_root = canonical_outcome
        .commitment()
        .ok_or("invalid canonical inference outcome")?;
    if claim.checkpoint_root != checkpoint_root
        || claim.chain_id != context.checkpoint.chain_id
        || claim.epoch != context.checkpoint.epoch
        || claim.model_root != context.checkpoint.model_root
        || claim.inference_root != context.checkpoint.inference_root
        || claim.inference_root != outcome_root
        || context.checkpoint.inference_root != outcome_root
        || claim.useful_work_units != context.outcome.total_compute_units
        || context.job.job_id != context.challenge.job_id
        || context.job.model_root != context.checkpoint.model_root
        || context.outcome.job_id != context.challenge.job_id
        || context.outcome.model_root != context.checkpoint.model_root
        || context.outcome.output_commitment != context.challenge.challenged_output_commitment
        || context.outcome.verifier_evidence_root != aggregate.receipt_root
        || claim.verifier_set_root != aggregate.receipt_root
        || context.checkpoint.verification_root != aggregate.receipt_root
        || claim.job_id != context.challenge.job_id
        || context.settlement.job_id != context.challenge.job_id
        || context.settlement.worker_id != claim.worker_id
        || context.settlement.verifier_set_root != aggregate.receipt_root
        || context.settlement.worker_reward == 0
        || context.settlement.slash_root.is_some()
    {
        return Err("SYNA reward claim binding mismatch");
    }

    let funded_amount = context.settlement
        .total_debit()
        .ok_or("compute settlement debit overflow")?;
    let settlement_root = context.settlement
        .canonical_root(context.challenge, &aggregate, funded_amount)
        .ok_or("invalid compute settlement")?;

    if claim.settlement_root != settlement_root
        || context.checkpoint.settlement_root != settlement_root
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

    let mining_replay_key = claim
        .mining_replay_key()
        .ok_or("invalid SYNA mining replay key")?;
    if reward_state.is_consumed(&mining_replay_key) {
        return Err("SYNA finalized inference already mined");
    }

    let pre_supply_state_root = supply_state
        .commitment()
        .ok_or("invalid pre-mint SYNA supply state")?;

    // Transactional preflight: mutate clones first so failure cannot partially
    // consume the one-shot claim or partially advance supply accounting.
    let mut next_supply = supply_state.clone();
    next_supply.mint_bounded(policy, claim.epoch, expected_reward)?;

    let claim_root = claim.canonical_root().ok_or("invalid SYNA claim root")?;
    let mut next_rewards = reward_state.clone();
    next_rewards.consume(mining_replay_key)?;

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
        pre_supply_state_root,
        supply_state_root,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    use crate::pq::{
        AuthPolicy, AuthScheme, AuthorizationDomain, AuthorizationEnvelope, HybridAuthorization,
        SignatureEvidence, ML_DSA_87_PUBLIC_KEY_BYTES, ML_DSA_87_SIGNATURE_BYTES,
        SLH_DSA_SHAKE_256S_PUBLIC_KEY_BYTES, SLH_DSA_SHAKE_256S_SIGNATURE_BYTES,
    };
    use crate::{
        InferenceStageAssignment, InferenceStageKind, InferenceStageReceipt, VerifierReceipt,
    };

    #[derive(Clone, Copy)]
    struct BindingTestVerifier;

    fn scheme_tag(scheme: AuthScheme) -> u8 {
        match scheme {
            AuthScheme::MlDsa87 => 1,
            AuthScheme::SlhDsaShake256s => 2,
            AuthScheme::Ed25519 => 3,
            AuthScheme::Secp256k1 => 4,
        }
    }

    fn test_signature_digest(
        scheme: AuthScheme,
        public_key: &[u8],
        message: &[u8],
        context: &[u8],
    ) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"SYNERGY/P4-TEST-SIGNATURE/V1\0");
        h.update([scheme_tag(scheme)]);
        h.update(public_key);
        h.update(message);
        h.update(context);
        h.finalize().into()
    }

    impl ContextSignatureVerifier for BindingTestVerifier {
        fn verify_with_context(
            &self,
            scheme: AuthScheme,
            public_key: &[u8],
            message: &[u8],
            context: &[u8],
            signature: &[u8],
        ) -> bool {
            if signature.len() < 32 {
                return false;
            }
            let expected = test_signature_digest(scheme, public_key, message, context);
            signature.get(..32) == Some(expected.as_slice())
        }
    }

    fn signed_pq_authorization(
        envelope: &AuthorizationEnvelope,
        seed: u8,
    ) -> HybridAuthorization {
        let message = envelope.canonical_message(AuthPolicy::PqOnly).unwrap();
        let context = envelope.fips_signature_context(AuthPolicy::PqOnly).unwrap();

        let ml_pk = vec![seed; ML_DSA_87_PUBLIC_KEY_BYTES];
        let slh_pk = vec![seed.wrapping_add(1); SLH_DSA_SHAKE_256S_PUBLIC_KEY_BYTES];

        let mut ml_sig = vec![0u8; ML_DSA_87_SIGNATURE_BYTES];
        ml_sig[..32].copy_from_slice(&test_signature_digest(
            AuthScheme::MlDsa87,
            &ml_pk,
            &message,
            &context,
        ));

        let mut slh_sig = vec![0u8; SLH_DSA_SHAKE_256S_SIGNATURE_BYTES];
        slh_sig[..32].copy_from_slice(&test_signature_digest(
            AuthScheme::SlhDsaShake256s,
            &slh_pk,
            &message,
            &context,
        ));

        HybridAuthorization {
            policy: AuthPolicy::PqOnly,
            evidence: vec![
                SignatureEvidence {
                    scheme: AuthScheme::MlDsa87,
                    public_key: ml_pk,
                    signature: ml_sig,
                },
                SignatureEvidence {
                    scheme: AuthScheme::SlhDsaShake256s,
                    public_key: slh_pk,
                    signature: slh_sig,
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
            opened_at: 1,
            closes_at: 10,
        }
    }

    fn verifier_receipt(
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

    fn authorize_stage(
        receipt: InferenceStageReceipt,
        chain_id: [u8; 32],
        epoch: u64,
        nonce: u64,
    ) -> (InferenceReceiptAuthorization, InferenceReceiptValidationContext) {
        let envelope = AuthorizationEnvelope {
            chain_id,
            domain: AuthorizationDomain::InferenceReceipt,
            epoch,
            nonce,
            expires_at: 100,
            payload_commitment: receipt.authorization_commitment().unwrap(),
        };
        let authorization = signed_pq_authorization(&envelope, receipt.worker_id[0]);
        let validation = InferenceReceiptValidationContext {
            expected_chain_id: chain_id,
            expected_epoch: epoch,
            expected_nonce: nonce,
            expected_worker_id: receipt.worker_id,
            expected_worker_keyset_commitment: authorization.keyset_commitment().unwrap(),
            now: 50,
            max_future_seconds: 60,
        };
        (
            InferenceReceiptAuthorization {
                chain_id,
                epoch,
                nonce,
                expires_at: 100,
                receipt,
                authorization,
            },
            validation,
        )
    }

    fn authorize_verifier(
        receipt: VerifierReceipt,
        challenge: &VerificationChallenge,
        chain_id: [u8; 32],
        epoch: u64,
        nonce: u64,
    ) -> (VerifierReceiptAuthorization, VerifierReceiptValidationContext) {
        let envelope = AuthorizationEnvelope {
            chain_id,
            domain: AuthorizationDomain::VerificationReceipt,
            epoch,
            nonce,
            expires_at: 100,
            payload_commitment: receipt.authorization_commitment(challenge).unwrap(),
        };
        let authorization = signed_pq_authorization(&envelope, receipt.verifier_id[0]);
        let validation = VerifierReceiptValidationContext {
            expected_chain_id: chain_id,
            expected_epoch: epoch,
            expected_nonce: nonce,
            expected_verifier_id: receipt.verifier_id,
            expected_verifier_keyset_commitment: authorization.keyset_commitment().unwrap(),
            now: 50,
            max_future_seconds: 60,
        };
        (
            VerifierReceiptAuthorization {
                chain_id,
                epoch,
                nonce,
                expires_at: 100,
                receipt,
                authorization,
            },
            validation,
        )
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

    struct Fixture {
        challenge: VerificationChallenge,
        job: InferenceJob,
        plan: InferenceExecutionPlan,
        stage_authorizations: Vec<InferenceReceiptAuthorization>,
        stage_validations: Vec<InferenceReceiptValidationContext>,
        outcome: InferenceOutcome,
        settlement: ComputeSettlement,
        checkpoint: MvpCheckpoint,
        verifier_authorizations: Vec<VerifierReceiptAuthorization>,
        verifier_validations: Vec<VerifierReceiptValidationContext>,
        claim: SynaRewardClaim,
    }

    fn fixture() -> Fixture {
        let challenge = challenge();
        let raw_verifiers = vec![
            verifier_receipt(
                5,
                VerificationVerdict::Match,
                challenge.challenged_output_commitment,
            ),
            verifier_receipt(
                6,
                VerificationVerdict::Match,
                challenge.challenged_output_commitment,
            ),
        ];
        let aggregate = aggregate_verifier_receipts(&challenge, &raw_verifiers).unwrap();

        let settlement = ComputeSettlement {
            job_id: challenge.job_id,
            funding_root: [6; 32],
            worker_id: [7; 32],
            storage_provider_id: [8; 32],
            verifier_set_root: aggregate.receipt_root,
            worker_reward: 60,
            storage_reward: 10,
            verifier_reward: 20,
            protocol_fee: 10,
            slash_root: None,
            refund_amount: 0,
        };
        let settlement_root = settlement
            .canonical_root(&challenge, &aggregate, 100)
            .unwrap();

        let mut job = InferenceJob {
            job_id: challenge.job_id,
            requester_id: [30; 32],
            model_root: [11; 32],
            input_commitment: [31; 32],
            execution_plan_root: [1; 32],
            max_output_tokens: 16,
            max_cost: 1_000,
            created_at: 1,
            deadline: 100,
        };

        let stages = vec![InferenceStageAssignment {
            job_id: job.job_id,
            stage_index: 0,
            kind: InferenceStageKind::Decode,
            worker_id: settlement.worker_id,
            model_shard_commitment: [33; 32],
            input_commitment: job.input_commitment,
            resource_limit_commitment: [35; 32],
            lease_expires_at: 50,
        }];
        let plan_root =
            InferenceExecutionPlan::canonical_root_for_stages(job.job_id, &stages).unwrap();
        job.execution_plan_root = plan_root;
        let plan = InferenceExecutionPlan {
            job_id: job.job_id,
            plan_root,
            stages,
        };

        let raw_stage = InferenceStageReceipt {
            job_id: job.job_id,
            stage_index: 0,
            worker_id: settlement.worker_id,
            model_shard_commitment: plan.stages[0].model_shard_commitment,
            input_commitment: plan.stages[0].input_commitment,
            output_commitment: challenge.challenged_output_commitment,
            execution_trace_commitment: [36; 32],
            worker_signature_commitment: [37; 32],
            compute_units: 100,
            bytes_read: 1_000,
            bytes_written: 100,
            elapsed_micros: 500,
        };

        let outcome = build_inference_outcome(
            &job,
            &plan,
            std::slice::from_ref(&raw_stage),
            aggregate.receipt_root,
            100,
            1,
        )
        .unwrap();
        let inference_root = outcome.commitment().unwrap();

        let checkpoint = MvpCheckpoint {
            chain_id: [10; 32],
            epoch: 1,
            sequence: 1,
            previous_checkpoint: [0; 32],
            model_root: job.model_root,
            network_root: [12; 32],
            provider_root: [13; 32],
            inference_root,
            verification_root: aggregate.receipt_root,
            kv_root: [16; 32],
            storage_root: [17; 32],
            settlement_root,
            scheduler_root: [19; 32],
            node_set_root: [20; 32],
        };

        let (stage_authorization, stage_validation) =
            authorize_stage(raw_stage, checkpoint.chain_id, checkpoint.epoch, 1);

        let mut verifier_authorizations = Vec::new();
        let mut verifier_validations = Vec::new();
        for (i, receipt) in raw_verifiers.into_iter().enumerate() {
            let nonce = 10 + u64::try_from(i).unwrap();
            let (authorized, validation) = authorize_verifier(
                receipt,
                &challenge,
                checkpoint.chain_id,
                checkpoint.epoch,
                nonce,
            );
            verifier_authorizations.push(authorized);
            verifier_validations.push(validation);
        }

        let claim = SynaRewardClaim {
            claim_id: [21; 32],
            chain_id: checkpoint.chain_id,
            epoch: checkpoint.epoch,
            job_id: challenge.job_id,
            worker_id: settlement.worker_id,
            model_root: checkpoint.model_root,
            inference_root: checkpoint.inference_root,
            verifier_set_root: aggregate.receipt_root,
            settlement_root,
            checkpoint_root: checkpoint.commitment().unwrap(),
            useful_work_units: outcome.total_compute_units,
            reward_amount: 10,
            reward_policy_version: 1,
        };

        Fixture {
            challenge,
            job,
            plan,
            stage_authorizations: vec![stage_authorization],
            stage_validations: vec![stage_validation],
            outcome,
            settlement,
            checkpoint,
            verifier_authorizations,
            verifier_validations,
            claim,
        }
    }

    fn mint(
        fixture: &Fixture,
        claim: &SynaRewardClaim,
        stage_authorizations: &[InferenceReceiptAuthorization],
        verifier_authorizations: &[VerifierReceiptAuthorization],
        rewards: &mut SynaRewardState,
        supply: &mut SynaSupplyState,
    ) -> Result<SynaMintAuthorization, &'static str> {
        let context = SynaInferenceMintContext {
            checkpoint: &fixture.checkpoint,
            outcome: &fixture.outcome,
            job: &fixture.job,
            plan: &fixture.plan,
            stage_authorizations,
            stage_validations: &fixture.stage_validations,
            settlement: &fixture.settlement,
            challenge: &fixture.challenge,
            verifier_authorizations,
            verifier_validations: &fixture.verifier_validations,
        };
        authorize_verified_inference_reward_and_mint(
            &BindingTestVerifier,
            claim,
            &context,
            &policy(),
            rewards,
            supply,
        )
    }

    fn empty_supply() -> SynaSupplyState {
        SynaSupplyState {
            policy_version: 1,
            current_epoch: 1,
            total_supply: 0,
            epoch_emission: 0,
        }
    }

    #[test]
    fn verified_pq_inference_mints_once_and_updates_supply() {
        let fixture = fixture();
        let mut rewards = SynaRewardState::default();
        let mut supply = empty_supply();

        let auth = mint(
            &fixture,
            &fixture.claim,
            &fixture.stage_authorizations,
            &fixture.verifier_authorizations,
            &mut rewards,
            &mut supply,
        )
        .unwrap();
        assert_eq!(auth.amount, 10);
        assert_eq!(supply.total_supply, 10);
        assert_eq!(auth.supply_state_root, supply.commitment().unwrap());

        assert!(mint(
            &fixture,
            &fixture.claim,
            &fixture.stage_authorizations,
            &fixture.verifier_authorizations,
            &mut rewards,
            &mut supply,
        )
        .is_err());
    }

    #[test]
    fn tampered_worker_receipt_signature_binding_blocks_mint() {
        let fixture = fixture();
        let mut stage_authorizations = fixture.stage_authorizations.clone();
        stage_authorizations[0].receipt.compute_units += 1;

        let mut rewards = SynaRewardState::default();
        let mut supply = empty_supply();
        assert!(mint(
            &fixture,
            &fixture.claim,
            &stage_authorizations,
            &fixture.verifier_authorizations,
            &mut rewards,
            &mut supply,
        )
        .is_err());
        assert_eq!(supply.total_supply, 0);
    }

    #[test]
    fn pq_signed_stage_with_wrong_job_input_cannot_mint() {
        let fixture = fixture();
        let mut changed = fixture.stage_authorizations[0].receipt.clone();
        changed.input_commitment = [99; 32];
        let (resigned, validation) = authorize_stage(
            changed,
            fixture.checkpoint.chain_id,
            fixture.checkpoint.epoch,
            1,
        );
        let stage_authorizations = vec![resigned];
        let stage_validations = vec![validation];

        let context = SynaInferenceMintContext {
            checkpoint: &fixture.checkpoint,
            outcome: &fixture.outcome,
            job: &fixture.job,
            plan: &fixture.plan,
            stage_authorizations: &stage_authorizations,
            stage_validations: &stage_validations,
            settlement: &fixture.settlement,
            challenge: &fixture.challenge,
            verifier_authorizations: &fixture.verifier_authorizations,
            verifier_validations: &fixture.verifier_validations,
        };

        let mut rewards = SynaRewardState::default();
        let mut supply = empty_supply();
        assert!(authorize_verified_inference_reward_and_mint(
            &BindingTestVerifier,
            &fixture.claim,
            &context,
            &policy(),
            &mut rewards,
            &mut supply,
        )
        .is_err());
        assert_eq!(supply.total_supply, 0);
    }

    #[test]
    fn authenticated_but_changed_stage_metering_cannot_match_finalized_outcome() {
        let fixture = fixture();
        let mut changed = fixture.stage_authorizations[0].receipt.clone();
        changed.compute_units = 10_000;
        let (resigned, _) = authorize_stage(
            changed,
            fixture.checkpoint.chain_id,
            fixture.checkpoint.epoch,
            1,
        );
        let stage_authorizations = vec![resigned];

        let mut rewards = SynaRewardState::default();
        let mut supply = empty_supply();
        assert!(mint(
            &fixture,
            &fixture.claim,
            &stage_authorizations,
            &fixture.verifier_authorizations,
            &mut rewards,
            &mut supply,
        )
        .is_err());
        assert_eq!(supply.total_supply, 0);
    }

    #[test]
    fn mismatch_verifier_receipt_blocks_mint() {
        let fixture = fixture();
        let mut receipt = fixture.verifier_authorizations[1].receipt.clone();
        receipt.verdict = VerificationVerdict::Mismatch;
        receipt.recomputed_output_commitment = [99; 32];
        let (resigned, _) = authorize_verifier(
            receipt,
            &fixture.challenge,
            fixture.checkpoint.chain_id,
            fixture.checkpoint.epoch,
            11,
        );
        let mut verifier_authorizations = fixture.verifier_authorizations.clone();
        verifier_authorizations[1] = resigned;

        let mut rewards = SynaRewardState::default();
        let mut supply = empty_supply();
        assert!(mint(
            &fixture,
            &fixture.claim,
            &fixture.stage_authorizations,
            &verifier_authorizations,
            &mut rewards,
            &mut supply,
        )
        .is_err());
    }

    #[test]
    fn inconclusive_verifier_receipt_blocks_mint() {
        let fixture = fixture();
        let mut receipt = fixture.verifier_authorizations[1].receipt.clone();
        receipt.verdict = VerificationVerdict::Inconclusive;
        receipt.recomputed_output_commitment = [0; 32];
        let (resigned, _) = authorize_verifier(
            receipt,
            &fixture.challenge,
            fixture.checkpoint.chain_id,
            fixture.checkpoint.epoch,
            11,
        );
        let mut verifier_authorizations = fixture.verifier_authorizations.clone();
        verifier_authorizations[1] = resigned;

        let mut rewards = SynaRewardState::default();
        let mut supply = empty_supply();
        assert!(mint(
            &fixture,
            &fixture.claim,
            &fixture.stage_authorizations,
            &verifier_authorizations,
            &mut rewards,
            &mut supply,
        )
        .is_err());
        assert_eq!(supply.total_supply, 0);
        assert!(!rewards.is_consumed(
            &fixture.claim.mining_replay_key().unwrap()
        ));
    }

    #[test]
    fn changing_claim_id_cannot_double_mint_same_finalized_inference() {
        let fixture = fixture();
        let mut rewards = SynaRewardState::default();
        let mut supply = empty_supply();

        mint(
            &fixture,
            &fixture.claim,
            &fixture.stage_authorizations,
            &fixture.verifier_authorizations,
            &mut rewards,
            &mut supply,
        )
        .unwrap();

        let mut replayed = fixture.claim.clone();
        replayed.claim_id = [42; 32];
        assert!(mint(
            &fixture,
            &replayed,
            &fixture.stage_authorizations,
            &fixture.verifier_authorizations,
            &mut rewards,
            &mut supply,
        )
        .is_err());
        assert_eq!(supply.total_supply, 10);
    }

    #[test]
    fn policy_upgrade_does_not_change_one_shot_mining_identity() {
        let fixture = fixture();
        let key = fixture.claim.mining_replay_key().unwrap();

        let mut upgraded = fixture.claim;
        upgraded.reward_policy_version += 1;
        assert_eq!(upgraded.mining_replay_key().unwrap(), key);
        assert_ne!(upgraded.canonical_root().unwrap(), key);
    }

    #[test]
    fn caller_cannot_inflate_useful_work_units() {
        let fixture = fixture();
        let mut claim = fixture.claim.clone();
        claim.useful_work_units += 10_000;
        claim.reward_amount = 100;

        let mut rewards = SynaRewardState::default();
        let mut supply = empty_supply();
        assert!(mint(
            &fixture,
            &claim,
            &fixture.stage_authorizations,
            &fixture.verifier_authorizations,
            &mut rewards,
            &mut supply,
        )
        .is_err());
        assert_eq!(supply.total_supply, 0);
    }

    #[test]
    fn caller_cannot_self_choose_reward_amount() {
        let fixture = fixture();
        let mut claim = fixture.claim.clone();
        claim.reward_amount = 99;

        let mut rewards = SynaRewardState::default();
        let mut supply = empty_supply();
        assert!(mint(
            &fixture,
            &claim,
            &fixture.stage_authorizations,
            &fixture.verifier_authorizations,
            &mut rewards,
            &mut supply,
        )
        .is_err());
    }

    #[test]
    fn wrong_registered_worker_keyset_blocks_mint() {
        let fixture = fixture();
        let mut validations = fixture.stage_validations.clone();
        validations[0].expected_worker_keyset_commitment[0] ^= 1;

        let mut rewards = SynaRewardState::default();
        let mut supply = empty_supply();
        let context = SynaInferenceMintContext {
            checkpoint: &fixture.checkpoint,
            outcome: &fixture.outcome,
            job: &fixture.job,
            plan: &fixture.plan,
            stage_authorizations: &fixture.stage_authorizations,
            stage_validations: &validations,
            settlement: &fixture.settlement,
            challenge: &fixture.challenge,
            verifier_authorizations: &fixture.verifier_authorizations,
            verifier_validations: &fixture.verifier_validations,
        };
        assert!(authorize_verified_inference_reward_and_mint(
            &BindingTestVerifier,
            &fixture.claim,
            &context,
            &policy(),
            &mut rewards,
            &mut supply,
        )
        .is_err());
    }
}
