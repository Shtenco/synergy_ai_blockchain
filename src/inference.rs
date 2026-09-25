//! Consensus-safe distributed inference job, plan and receipt primitives.
//!
//! Large-model execution happens off-consensus. These structures define the
//! bounded commitments that can be verified/finalized by protocol logic.

use sha2::{Digest, Sha256};

use crate::pq::{
    verify_envelope_authorization, AuthPolicy, AuthorizationDomain, AuthorizationEnvelope,
    AuthorizationReplayState, AuthorizationValidationContext, ContextSignatureVerifier,
    HybridAuthorization,
};

pub const MAX_INFERENCE_STAGES: usize = 65_536;

const INFERENCE_RECEIPT_DOMAIN: &[u8] = b"SYNERGY/INFERENCE-RECEIPT/V1\0";
pub const INFERENCE_OUTCOME_DOMAIN: &[u8] = b"SYNERGY/INFERENCE-OUTCOME/V1\0";
pub const INFERENCE_WORK_SET_DOMAIN: &[u8] = b"SYNERGY/INFERENCE-WORK-SET/V1\0";
pub const INFERENCE_WORK_AGGREGATE_DOMAIN: &[u8] =
    b"SYNERGY/INFERENCE-WORK-AGGREGATE/V1\0";
pub const INFERENCE_PLAN_DOMAIN: &[u8] = b"SYNERGY/INFERENCE-PLAN/V1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InferenceStageKind {
    ModelLoad,
    Prefill,
    Decode,
    Expert,
    Verification,
    KvRead,
    KvWrite,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InferenceJobState {
    Created,
    Funded,
    Reserved,
    Running,
    AwaitingVerification,
    Finalized,
    Challenged,
    Rejected,
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InferenceJob {
    pub job_id: [u8; 32],
    pub requester_id: [u8; 32],
    pub model_root: [u8; 32],
    pub input_commitment: [u8; 32],
    pub execution_plan_root: [u8; 32],
    pub max_output_tokens: u32,
    pub max_cost: u128,
    pub created_at: u64,
    pub deadline: u64,
}

impl InferenceJob {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.job_id == [0; 32]
            || self.requester_id == [0; 32]
            || self.model_root == [0; 32]
            || self.input_commitment == [0; 32]
            || self.execution_plan_root == [0; 32]
        {
            return Err("inference job commitments required");
        }
        if self.max_output_tokens == 0 {
            return Err("max output tokens must be positive");
        }
        if self.max_cost == 0 {
            return Err("max cost must be positive");
        }
        if self.deadline <= self.created_at {
            return Err("deadline must be after creation");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InferenceStageAssignment {
    pub job_id: [u8; 32],
    pub stage_index: u32,
    pub kind: InferenceStageKind,
    pub worker_id: [u8; 32],
    pub model_shard_commitment: [u8; 32],
    pub input_commitment: [u8; 32],
    pub resource_limit_commitment: [u8; 32],
    pub lease_expires_at: u64,
}

impl InferenceStageAssignment {
    pub fn validate_against(&self, job: &InferenceJob) -> Result<(), &'static str> {
        if self.job_id != job.job_id {
            return Err("stage/job mismatch");
        }
        if self.worker_id == [0; 32]
            || self.model_shard_commitment == [0; 32]
            || self.input_commitment == [0; 32]
            || self.resource_limit_commitment == [0; 32]
        {
            return Err("stage commitments required");
        }
        if self.lease_expires_at > job.deadline || self.lease_expires_at <= job.created_at {
            return Err("stage lease outside job window");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InferenceExecutionPlan {
    pub job_id: [u8; 32],
    pub plan_root: [u8; 32],
    pub stages: Vec<InferenceStageAssignment>,
}

impl InferenceExecutionPlan {
    pub fn canonical_root_for_stages(
        job_id: [u8; 32],
        stages: &[InferenceStageAssignment],
    ) -> Option<[u8; 32]> {
        if job_id == [0; 32] || stages.is_empty() || stages.len() > MAX_INFERENCE_STAGES {
            return None;
        }

        let stage_count = u64::try_from(stages.len()).ok()?;
        let mut h = Sha256::new();
        h.update(INFERENCE_PLAN_DOMAIN);
        h.update(crate::pq::CRYPTO_PROFILE_VERSION.to_be_bytes());
        h.update(job_id);
        h.update(stage_count.to_be_bytes());

        for (i, stage) in stages.iter().enumerate() {
            let expected_index = u32::try_from(i).ok()?;
            if stage.job_id != job_id
                || stage.stage_index != expected_index
                || stage.worker_id == [0; 32]
                || stage.model_shard_commitment == [0; 32]
                || stage.input_commitment == [0; 32]
                || stage.resource_limit_commitment == [0; 32]
                || stage.lease_expires_at == 0
            {
                return None;
            }

            h.update(stage.job_id);
            h.update(stage.stage_index.to_be_bytes());
            h.update([match stage.kind {
                InferenceStageKind::ModelLoad => 1,
                InferenceStageKind::Prefill => 2,
                InferenceStageKind::Decode => 3,
                InferenceStageKind::Expert => 4,
                InferenceStageKind::Verification => 5,
                InferenceStageKind::KvRead => 6,
                InferenceStageKind::KvWrite => 7,
            }]);
            h.update(stage.worker_id);
            h.update(stage.model_shard_commitment);
            h.update(stage.input_commitment);
            h.update(stage.resource_limit_commitment);
            h.update(stage.lease_expires_at.to_be_bytes());
        }

        Some(h.finalize().into())
    }

    pub fn has_canonical_root(&self) -> bool {
        Self::canonical_root_for_stages(self.job_id, &self.stages) == Some(self.plan_root)
    }

    pub fn validate_against(&self, job: &InferenceJob) -> Result<(), &'static str> {
        if self.job_id != job.job_id || self.plan_root != job.execution_plan_root {
            return Err("execution plan/job commitment mismatch");
        }
        if self.stages.is_empty() {
            return Err("execution plan requires stages");
        }
        if self.stages.len() > MAX_INFERENCE_STAGES {
            return Err("execution plan exceeds protocol stage limit");
        }
        if !self.has_canonical_root() {
            return Err("execution plan root is not canonical for its stages");
        }
        if self.stages[0].input_commitment != job.input_commitment {
            return Err("first inference stage must bind the job input");
        }
        for (i, stage) in self.stages.iter().enumerate() {
            stage.validate_against(job)?;
            let expected_index =
                u32::try_from(i).map_err(|_| "execution stage index exceeds u32")?;
            if stage.stage_index != expected_index {
                return Err("stage indices must be contiguous and ordered");
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InferenceStageReceipt {
    pub job_id: [u8; 32],
    pub stage_index: u32,
    pub worker_id: [u8; 32],
    pub model_shard_commitment: [u8; 32],
    pub input_commitment: [u8; 32],
    pub output_commitment: [u8; 32],
    pub execution_trace_commitment: [u8; 32],
    pub worker_signature_commitment: [u8; 32],
    pub compute_units: u64,
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub elapsed_micros: u64,
}

impl InferenceStageReceipt {
    pub fn validate_against(
        &self,
        assignment: &InferenceStageAssignment,
    ) -> Result<(), &'static str> {
        if self.job_id != assignment.job_id
            || self.stage_index != assignment.stage_index
            || self.worker_id != assignment.worker_id
            || self.model_shard_commitment != assignment.model_shard_commitment
            || self.input_commitment != assignment.input_commitment
        {
            return Err("receipt does not match stage assignment");
        }
        if self.output_commitment == [0; 32]
            || self.execution_trace_commitment == [0; 32]
            || self.worker_signature_commitment == [0; 32]
        {
            return Err("receipt commitments required");
        }
        if self.compute_units == 0 || self.elapsed_micros == 0 {
            return Err("execution measurements required");
        }
        Ok(())
    }
}

impl InferenceStageReceipt {
    pub fn authorization_commitment(&self) -> Option<[u8; 32]> {
        if self.output_commitment == [0; 32]
            || self.execution_trace_commitment == [0; 32]
            || self.worker_signature_commitment == [0; 32]
            || self.job_id == [0; 32]
            || self.worker_id == [0; 32]
            || self.model_shard_commitment == [0; 32]
            || self.input_commitment == [0; 32]
            || self.compute_units == 0
            || self.elapsed_micros == 0
        {
            return None;
        }

        let mut hasher = Sha256::new();
        hasher.update(INFERENCE_RECEIPT_DOMAIN);
        hasher.update(self.job_id);
        hasher.update(self.stage_index.to_be_bytes());
        hasher.update(self.worker_id);
        hasher.update(self.model_shard_commitment);
        hasher.update(self.input_commitment);
        hasher.update(self.output_commitment);
        hasher.update(self.execution_trace_commitment);
        hasher.update(self.worker_signature_commitment);
        hasher.update(self.compute_units.to_be_bytes());
        hasher.update(self.bytes_read.to_be_bytes());
        hasher.update(self.bytes_written.to_be_bytes());
        hasher.update(self.elapsed_micros.to_be_bytes());
        Some(hasher.finalize().into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InferenceReceiptAuthorization {
    pub chain_id: [u8; 32],
    pub epoch: u64,
    pub nonce: u64,
    pub expires_at: u64,
    pub receipt: InferenceStageReceipt,
    pub authorization: HybridAuthorization,
}

impl InferenceReceiptAuthorization {
    pub fn envelope(&self) -> Option<AuthorizationEnvelope> {
        Some(AuthorizationEnvelope {
            chain_id: self.chain_id,
            domain: AuthorizationDomain::InferenceReceipt,
            epoch: self.epoch,
            nonce: self.nonce,
            expires_at: self.expires_at,
            payload_commitment: self.receipt.authorization_commitment()?,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InferenceReceiptValidationContext {
    pub expected_chain_id: [u8; 32],
    pub expected_epoch: u64,
    pub expected_nonce: u64,
    pub expected_worker_id: [u8; 32],
    pub expected_worker_keyset_commitment: [u8; 32],
    pub now: u64,
    pub max_future_seconds: u64,
}

pub(crate) fn verify_inference_receipt<V: ContextSignatureVerifier>(
    verifier: &V,
    assignment: &InferenceStageAssignment,
    authorized: &InferenceReceiptAuthorization,
    validation: &InferenceReceiptValidationContext,
) -> bool {
    if authorized.authorization.policy != AuthPolicy::PqOnly
        || authorized.receipt.worker_id != validation.expected_worker_id
        || authorized.authorization.keyset_commitment()
            != Some(validation.expected_worker_keyset_commitment)
        || authorized.receipt.validate_against(assignment).is_err()
    {
        return false;
    }

    let envelope = match authorized.envelope() {
        Some(envelope) => envelope,
        None => return false,
    };

    let auth_validation = AuthorizationValidationContext {
        expected_chain_id: validation.expected_chain_id,
        expected_domain: AuthorizationDomain::InferenceReceipt,
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
pub struct InferenceWorkAggregate {
    pub job_id: [u8; 32],
    pub execution_plan_root: [u8; 32],
    pub receipt_root: [u8; 32],
    pub stage_count: u32,
    pub total_compute_units: u128,
    pub total_bytes_read: u128,
    pub total_bytes_written: u128,
    pub total_elapsed_micros: u128,
    pub final_output_commitment: [u8; 32],
}

impl InferenceWorkAggregate {
    pub fn commitment(&self) -> Option<[u8; 32]> {
        if self.job_id == [0; 32]
            || self.execution_plan_root == [0; 32]
            || self.receipt_root == [0; 32]
            || self.stage_count == 0
            || self.total_compute_units == 0
            || self.total_elapsed_micros == 0
            || self.final_output_commitment == [0; 32]
        {
            return None;
        }

        let mut h = Sha256::new();
        h.update(INFERENCE_WORK_AGGREGATE_DOMAIN);
        h.update(crate::pq::CRYPTO_PROFILE_VERSION.to_be_bytes());
        h.update(self.job_id);
        h.update(self.execution_plan_root);
        h.update(self.receipt_root);
        h.update(self.stage_count.to_be_bytes());
        h.update(self.total_compute_units.to_be_bytes());
        h.update(self.total_bytes_read.to_be_bytes());
        h.update(self.total_bytes_written.to_be_bytes());
        h.update(self.total_elapsed_micros.to_be_bytes());
        h.update(self.final_output_commitment);
        Some(h.finalize().into())
    }
}

pub fn aggregate_inference_stage_receipts(
    job: &InferenceJob,
    plan: &InferenceExecutionPlan,
    receipts: &[InferenceStageReceipt],
) -> Result<InferenceWorkAggregate, &'static str> {
    job.validate()?;
    plan.validate_against(job)?;
    if !plan.has_canonical_root() {
        return Err("execution plan root is not canonical for its stages");
    }
    if receipts.len() != plan.stages.len() || receipts.is_empty() {
        return Err("every inference stage requires exactly one receipt");
    }

    let stage_count =
        u32::try_from(receipts.len()).map_err(|_| "inference receipt count exceeds u32")?;
    let mut hasher = Sha256::new();
    hasher.update(INFERENCE_WORK_SET_DOMAIN);
    hasher.update(crate::pq::CRYPTO_PROFILE_VERSION.to_be_bytes());
    hasher.update(job.job_id);
    hasher.update(plan.plan_root);
    hasher.update(stage_count.to_be_bytes());

    let mut total_compute_units = 0u128;
    let mut total_bytes_read = 0u128;
    let mut total_bytes_written = 0u128;
    let mut total_elapsed_micros = 0u128;
    let mut final_output_commitment = [0u8; 32];
    let mut expected_input_commitment = job.input_commitment;

    for (assignment, receipt) in plan.stages.iter().zip(receipts.iter()) {
        receipt.validate_against(assignment)?;
        if receipt.input_commitment != expected_input_commitment {
            return Err("inference stage chain is disconnected");
        }
        let receipt_commitment = receipt
            .authorization_commitment()
            .ok_or("invalid inference stage receipt commitment")?;
        hasher.update(receipt_commitment);

        total_compute_units = total_compute_units
            .checked_add(u128::from(receipt.compute_units))
            .ok_or("inference compute-unit overflow")?;
        total_bytes_read = total_bytes_read
            .checked_add(u128::from(receipt.bytes_read))
            .ok_or("inference bytes-read overflow")?;
        total_bytes_written = total_bytes_written
            .checked_add(u128::from(receipt.bytes_written))
            .ok_or("inference bytes-written overflow")?;
        total_elapsed_micros = total_elapsed_micros
            .checked_add(u128::from(receipt.elapsed_micros))
            .ok_or("inference elapsed-time overflow")?;
        final_output_commitment = receipt.output_commitment;
        expected_input_commitment = receipt.output_commitment;
    }

    let receipt_root: [u8; 32] = hasher.finalize().into();
    Ok(InferenceWorkAggregate {
        job_id: job.job_id,
        execution_plan_root: plan.plan_root,
        receipt_root,
        stage_count,
        total_compute_units,
        total_bytes_read,
        total_bytes_written,
        total_elapsed_micros,
        final_output_commitment,
    })
}

pub fn build_inference_outcome(
    job: &InferenceJob,
    plan: &InferenceExecutionPlan,
    receipts: &[InferenceStageReceipt],
    verifier_evidence_root: [u8; 32],
    total_cost: u128,
    output_tokens: u32,
) -> Result<InferenceOutcome, &'static str> {
    if verifier_evidence_root == [0; 32] {
        return Err("verifier evidence root required");
    }
    let work = aggregate_inference_stage_receipts(job, plan, receipts)?;
    let outcome = InferenceOutcome {
        job_id: work.job_id,
        model_root: job.model_root,
        output_commitment: work.final_output_commitment,
        receipt_root: work.receipt_root,
        verifier_evidence_root,
        total_compute_units: work.total_compute_units,
        total_cost,
        output_tokens,
    };
    outcome.validate_against(job)?;
    Ok(outcome)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InferenceOutcome {
    pub job_id: [u8; 32],
    pub model_root: [u8; 32],
    pub output_commitment: [u8; 32],
    pub receipt_root: [u8; 32],
    pub verifier_evidence_root: [u8; 32],
    pub total_compute_units: u128,
    pub total_cost: u128,
    pub output_tokens: u32,
}

impl InferenceOutcome {
    fn validate_fields(&self) -> Result<(), &'static str> {
        if self.job_id == [0; 32]
            || self.model_root == [0; 32]
            || self.output_commitment == [0; 32]
            || self.receipt_root == [0; 32]
            || self.verifier_evidence_root == [0; 32]
            || self.total_compute_units == 0
        {
            return Err("outcome commitments and metering required");
        }
        Ok(())
    }

    pub fn validate_against(&self, job: &InferenceJob) -> Result<(), &'static str> {
        self.validate_fields()?;
        if self.job_id != job.job_id || self.model_root != job.model_root {
            return Err("outcome/job mismatch");
        }
        if self.output_tokens > job.max_output_tokens || self.total_cost > job.max_cost {
            return Err("outcome exceeds job bounds");
        }
        Ok(())
    }

    pub fn commitment(&self) -> Option<[u8; 32]> {
        self.validate_fields().ok()?;
        let mut hasher = Sha256::new();
        hasher.update(INFERENCE_OUTCOME_DOMAIN);
        hasher.update(crate::pq::CRYPTO_PROFILE_VERSION.to_be_bytes());
        hasher.update(self.job_id);
        hasher.update(self.model_root);
        hasher.update(self.output_commitment);
        hasher.update(self.receipt_root);
        hasher.update(self.verifier_evidence_root);
        hasher.update(self.total_compute_units.to_be_bytes());
        hasher.update(self.total_cost.to_be_bytes());
        hasher.update(self.output_tokens.to_be_bytes());
        Some(hasher.finalize().into())
    }
}

pub fn verify_inference_receipt_and_consume<V: ContextSignatureVerifier>(
    verifier: &V,
    assignment: &InferenceStageAssignment,
    authorized: &InferenceReceiptAuthorization,
    validation: &InferenceReceiptValidationContext,
    replay: &mut AuthorizationReplayState,
) -> bool {
    if !verify_inference_receipt(verifier, assignment, authorized, validation) {
        return false;
    }
    let envelope = match authorized.envelope() {
        Some(envelope) => envelope,
        None => return false,
    };
    replay.consume_verified_for_subject(
        &authorized.authorization,
        &envelope,
        validation.expected_worker_id,
    )
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
                    public_key: vec![0x61; ML_DSA_87_PUBLIC_KEY_BYTES],
                    signature: vec![0x62; ML_DSA_87_SIGNATURE_BYTES],
                },
                SignatureEvidence {
                    scheme: AuthScheme::SlhDsaShake256s,
                    public_key: vec![0x63; SLH_DSA_SHAKE_256S_PUBLIC_KEY_BYTES],
                    signature: vec![0x64; SLH_DSA_SHAKE_256S_SIGNATURE_BYTES],
                },
            ],
        }
    }

    fn job() -> InferenceJob {
        let default_stages = vec![stage(0), stage(1)];
        let execution_plan_root =
            InferenceExecutionPlan::canonical_root_for_stages([1; 32], &default_stages).unwrap();
        InferenceJob {
            job_id: [1; 32],
            requester_id: [2; 32],
            model_root: [3; 32],
            input_commitment: [4; 32],
            execution_plan_root,
            max_output_tokens: 64,
            max_cost: 1_000,
            created_at: 10,
            deadline: 100,
        }
    }

    fn stage(index: u32) -> InferenceStageAssignment {
        InferenceStageAssignment {
            job_id: [1; 32],
            stage_index: index,
            kind: if index == 0 {
                InferenceStageKind::Prefill
            } else {
                InferenceStageKind::Decode
            },
            worker_id: [10 + index as u8; 32],
            model_shard_commitment: [20 + index as u8; 32],
            input_commitment: if index == 0 {
                [4; 32]
            } else if index == 1 {
                [50; 32]
            } else {
                [30 + index as u8; 32]
            },
            resource_limit_commitment: [40 + index as u8; 32],
            lease_expires_at: 90,
        }
    }

    #[test]
    fn stage_receipt_aggregate_derives_metering_and_final_output() {
        let mut j = job();
        let stages = vec![stage(0), stage(1)];
        let plan_root =
            InferenceExecutionPlan::canonical_root_for_stages(j.job_id, &stages).unwrap();
        j.execution_plan_root = plan_root;
        let plan = InferenceExecutionPlan {
            job_id: j.job_id,
            plan_root,
            stages,
        };
        let receipts = vec![
            InferenceStageReceipt {
                job_id: j.job_id,
                stage_index: 0,
                worker_id: plan.stages[0].worker_id,
                model_shard_commitment: plan.stages[0].model_shard_commitment,
                input_commitment: plan.stages[0].input_commitment,
                output_commitment: [50; 32],
                execution_trace_commitment: [51; 32],
                worker_signature_commitment: [52; 32],
                compute_units: 40,
                bytes_read: 100,
                bytes_written: 20,
                elapsed_micros: 10,
            },
            InferenceStageReceipt {
                job_id: j.job_id,
                stage_index: 1,
                worker_id: plan.stages[1].worker_id,
                model_shard_commitment: plan.stages[1].model_shard_commitment,
                input_commitment: plan.stages[1].input_commitment,
                output_commitment: [60; 32],
                execution_trace_commitment: [61; 32],
                worker_signature_commitment: [62; 32],
                compute_units: 60,
                bytes_read: 200,
                bytes_written: 30,
                elapsed_micros: 20,
            },
        ];

        let work = aggregate_inference_stage_receipts(&j, &plan, &receipts).unwrap();
        assert_eq!(work.total_compute_units, 100);
        assert_eq!(work.stage_count, 2);
        assert_eq!(work.final_output_commitment, [60; 32]);

        let mut forged = receipts.clone();
        forged[1].compute_units = 600;
        assert_ne!(
            aggregate_inference_stage_receipts(&j, &plan, &forged)
                .unwrap()
                .receipt_root,
            work.receipt_root
        );
    }

    #[test]
    fn disconnected_but_individually_valid_stage_chain_is_rejected() {
        let mut j = job();
        let mut stages = vec![stage(0), stage(1)];
        stages[1].input_commitment = [77; 32];
        let plan_root =
            InferenceExecutionPlan::canonical_root_for_stages(j.job_id, &stages).unwrap();
        j.execution_plan_root = plan_root;
        let plan = InferenceExecutionPlan {
            job_id: j.job_id,
            plan_root,
            stages,
        };
        let receipts = vec![
            InferenceStageReceipt {
                job_id: j.job_id,
                stage_index: 0,
                worker_id: plan.stages[0].worker_id,
                model_shard_commitment: plan.stages[0].model_shard_commitment,
                input_commitment: plan.stages[0].input_commitment,
                output_commitment: [50; 32],
                execution_trace_commitment: [51; 32],
                worker_signature_commitment: [52; 32],
                compute_units: 40,
                bytes_read: 100,
                bytes_written: 20,
                elapsed_micros: 10,
            },
            InferenceStageReceipt {
                job_id: j.job_id,
                stage_index: 1,
                worker_id: plan.stages[1].worker_id,
                model_shard_commitment: plan.stages[1].model_shard_commitment,
                input_commitment: plan.stages[1].input_commitment,
                output_commitment: [60; 32],
                execution_trace_commitment: [61; 32],
                worker_signature_commitment: [62; 32],
                compute_units: 60,
                bytes_read: 200,
                bytes_written: 30,
                elapsed_micros: 20,
            },
        ];

        assert!(aggregate_inference_stage_receipts(&j, &plan, &receipts).is_err());
    }

    #[test]
    fn work_commitment_binds_metering_and_final_output() {
        let mut j = job();
        let stages = vec![stage(0), stage(1)];
        let plan_root =
            InferenceExecutionPlan::canonical_root_for_stages(j.job_id, &stages).unwrap();
        j.execution_plan_root = plan_root;
        let plan = InferenceExecutionPlan {
            job_id: j.job_id,
            plan_root,
            stages,
        };
        let receipts = vec![
            InferenceStageReceipt {
                job_id: j.job_id,
                stage_index: 0,
                worker_id: plan.stages[0].worker_id,
                model_shard_commitment: plan.stages[0].model_shard_commitment,
                input_commitment: plan.stages[0].input_commitment,
                output_commitment: [50; 32],
                execution_trace_commitment: [51; 32],
                worker_signature_commitment: [52; 32],
                compute_units: 40,
                bytes_read: 100,
                bytes_written: 20,
                elapsed_micros: 10,
            },
            InferenceStageReceipt {
                job_id: j.job_id,
                stage_index: 1,
                worker_id: plan.stages[1].worker_id,
                model_shard_commitment: plan.stages[1].model_shard_commitment,
                input_commitment: plan.stages[1].input_commitment,
                output_commitment: [60; 32],
                execution_trace_commitment: [61; 32],
                worker_signature_commitment: [62; 32],
                compute_units: 60,
                bytes_read: 200,
                bytes_written: 30,
                elapsed_micros: 20,
            },
        ];

        let work = aggregate_inference_stage_receipts(&j, &plan, &receipts).unwrap();
        let root = work.commitment().unwrap();
        let mut changed = work;
        changed.total_compute_units += 1;
        assert_ne!(changed.commitment().unwrap(), root);
    }

    #[test]
    fn outcome_commitment_binds_compute_metering() {
        let outcome = InferenceOutcome {
            job_id: [1; 32],
            model_root: [3; 32],
            output_commitment: [50; 32],
            receipt_root: [51; 32],
            verifier_evidence_root: [52; 32],
            total_compute_units: 100,
            total_cost: 25,
            output_tokens: 8,
        };
        let root = outcome.commitment().unwrap();

        let mut changed = outcome;
        changed.total_compute_units += 1;
        assert_ne!(changed.commitment().unwrap(), root);
    }

    #[test]
    fn canonical_plan_root_binds_every_stage_assignment() {
        let mut stages = vec![stage(0), stage(1)];
        let root =
            InferenceExecutionPlan::canonical_root_for_stages([1; 32], &stages).unwrap();

        let mut changed = stages.clone();
        changed[1].worker_id[0] ^= 1;
        assert_ne!(
            InferenceExecutionPlan::canonical_root_for_stages([1; 32], &changed).unwrap(),
            root
        );

        stages[1].resource_limit_commitment[0] ^= 1;
        assert_ne!(
            InferenceExecutionPlan::canonical_root_for_stages([1; 32], &stages).unwrap(),
            root
        );
    }

    #[test]
    fn plan_requires_contiguous_order() {
        let j = job();
        let ok = InferenceExecutionPlan {
            job_id: j.job_id,
            plan_root: j.execution_plan_root,
            stages: vec![stage(0), stage(1)],
        };
        assert_eq!(ok.validate_against(&j), Ok(()));

        let bad = InferenceExecutionPlan {
            job_id: j.job_id,
            plan_root: j.execution_plan_root,
            stages: vec![stage(0), stage(2)],
        };
        assert!(bad.validate_against(&j).is_err());
    }

    #[test]
    fn plan_rejects_protocol_stage_count_overflow() {
        let j = job();
        let mut stages = Vec::with_capacity(MAX_INFERENCE_STAGES + 1);
        for i in 0..=MAX_INFERENCE_STAGES {
            let mut assignment = stage(0);
            assignment.stage_index = u32::try_from(i).expect("bounded test index");
            stages.push(assignment);
        }
        let plan = InferenceExecutionPlan {
            job_id: j.job_id,
            plan_root: j.execution_plan_root,
            stages,
        };
        assert!(plan.validate_against(&j).is_err());
    }

    #[test]
    fn receipt_cannot_switch_worker_or_shard() {
        let a = stage(0);
        let mut r = InferenceStageReceipt {
            job_id: a.job_id,
            stage_index: a.stage_index,
            worker_id: a.worker_id,
            model_shard_commitment: a.model_shard_commitment,
            input_commitment: a.input_commitment,
            output_commitment: [50; 32],
            execution_trace_commitment: [51; 32],
            worker_signature_commitment: [52; 32],
            compute_units: 10,
            bytes_read: 100,
            bytes_written: 20,
            elapsed_micros: 1,
        };
        assert_eq!(r.validate_against(&a), Ok(()));
        r.worker_id = [99; 32];
        assert!(r.validate_against(&a).is_err());
    }

    #[test]
    fn inference_receipt_requires_state_aware_pq_authorization() {
        let assignment = stage(0);
        let receipt = InferenceStageReceipt {
            job_id: assignment.job_id,
            stage_index: assignment.stage_index,
            worker_id: assignment.worker_id,
            model_shard_commitment: assignment.model_shard_commitment,
            input_commitment: assignment.input_commitment,
            output_commitment: [50; 32],
            execution_trace_commitment: [51; 32],
            worker_signature_commitment: [52; 32],
            compute_units: 10,
            bytes_read: 100,
            bytes_written: 20,
            elapsed_micros: 1,
        };
        let authorized = InferenceReceiptAuthorization {
            chain_id: [0x71; 32],
            epoch: 7,
            nonce: 8,
            expires_at: 1_100,
            receipt,
            authorization: pq_only_authorization(),
        };
        let envelope = authorized.envelope().expect("receipt envelope");
        let verifier = ExpectedVerifier {
            message: envelope
                .canonical_message(AuthPolicy::PqOnly)
                .expect("receipt message"),
            context: envelope
                .fips_signature_context(AuthPolicy::PqOnly)
                .expect("receipt context"),
        };
        let validation = InferenceReceiptValidationContext {
            expected_chain_id: [0x71; 32],
            expected_epoch: 7,
            expected_nonce: 8,
            expected_worker_id: assignment.worker_id,
            expected_worker_keyset_commitment: authorized
                .authorization
                .keyset_commitment()
                .expect("worker keyset commitment"),
            now: 1_000,
            max_future_seconds: 200,
        };

        assert!(verify_inference_receipt(
            &verifier,
            &assignment,
            &authorized,
            &validation,
        ));

        let mut replay = validation;
        replay.expected_nonce += 1;
        assert!(!verify_inference_receipt(
            &verifier,
            &assignment,
            &authorized,
            &replay,
        ));
    }

    #[test]
    fn inference_receipt_rejects_unregistered_worker_keyset() {
        let assignment = stage(0);
        let receipt = InferenceStageReceipt {
            job_id: assignment.job_id,
            stage_index: assignment.stage_index,
            worker_id: assignment.worker_id,
            model_shard_commitment: assignment.model_shard_commitment,
            input_commitment: assignment.input_commitment,
            output_commitment: [50; 32],
            execution_trace_commitment: [51; 32],
            worker_signature_commitment: [52; 32],
            compute_units: 10,
            bytes_read: 100,
            bytes_written: 20,
            elapsed_micros: 1,
        };
        let authorized = InferenceReceiptAuthorization {
            chain_id: [0x71; 32],
            epoch: 7,
            nonce: 8,
            expires_at: 1_100,
            receipt,
            authorization: pq_only_authorization(),
        };
        let envelope = authorized.envelope().expect("receipt envelope");
        let verifier = ExpectedVerifier {
            message: envelope
                .canonical_message(AuthPolicy::PqOnly)
                .expect("receipt message"),
            context: envelope
                .fips_signature_context(AuthPolicy::PqOnly)
                .expect("receipt context"),
        };
        let mut validation = InferenceReceiptValidationContext {
            expected_chain_id: [0x71; 32],
            expected_epoch: 7,
            expected_nonce: 8,
            expected_worker_id: assignment.worker_id,
            expected_worker_keyset_commitment: authorized
                .authorization
                .keyset_commitment()
                .expect("worker keyset commitment"),
            now: 1_000,
            max_future_seconds: 200,
        };
        validation.expected_worker_keyset_commitment[0] ^= 1;

        assert!(!verify_inference_receipt(
            &verifier,
            &assignment,
            &authorized,
            &validation,
        ));
    }

    #[test]
    fn inference_receipt_rejects_worker_substitution_and_policy_downgrade() {
        let assignment = stage(0);
        let receipt = InferenceStageReceipt {
            job_id: assignment.job_id,
            stage_index: assignment.stage_index,
            worker_id: assignment.worker_id,
            model_shard_commitment: assignment.model_shard_commitment,
            input_commitment: assignment.input_commitment,
            output_commitment: [50; 32],
            execution_trace_commitment: [51; 32],
            worker_signature_commitment: [52; 32],
            compute_units: 10,
            bytes_read: 100,
            bytes_written: 20,
            elapsed_micros: 1,
        };
        let mut authorized = InferenceReceiptAuthorization {
            chain_id: [0x71; 32],
            epoch: 7,
            nonce: 8,
            expires_at: 1_100,
            receipt,
            authorization: pq_only_authorization(),
        };
        let envelope = authorized.envelope().expect("receipt envelope");
        let verifier = ExpectedVerifier {
            message: envelope
                .canonical_message(AuthPolicy::PqOnly)
                .expect("receipt message"),
            context: envelope
                .fips_signature_context(AuthPolicy::PqOnly)
                .expect("receipt context"),
        };
        let validation = InferenceReceiptValidationContext {
            expected_chain_id: [0x71; 32],
            expected_epoch: 7,
            expected_nonce: 8,
            expected_worker_id: assignment.worker_id,
            expected_worker_keyset_commitment: authorized
                .authorization
                .keyset_commitment()
                .expect("worker keyset commitment"),
            now: 1_000,
            max_future_seconds: 200,
        };

        authorized.authorization.policy = AuthPolicy::Online;
        assert!(!verify_inference_receipt(
            &verifier,
            &assignment,
            &authorized,
            &validation,
        ));

        authorized.authorization = pq_only_authorization();
        authorized.receipt.worker_id = [0xFF; 32];
        assert!(!verify_inference_receipt(
            &verifier,
            &assignment,
            &authorized,
            &validation,
        ));
    }

    #[test]
    fn outcome_is_bounded_by_request() {
        let j = job();
        let mut out = InferenceOutcome {
            job_id: j.job_id,
            model_root: j.model_root,
            output_commitment: [6; 32],
            receipt_root: [7; 32],
            verifier_evidence_root: [8; 32],
            total_compute_units: 100,
            total_cost: 900,
            output_tokens: 64,
        };
        assert_eq!(out.validate_against(&j), Ok(()));
        out.total_cost = 1_001;
        assert!(out.validate_against(&j).is_err());
    }
}
