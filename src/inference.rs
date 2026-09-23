//! Consensus-safe distributed inference job, plan and receipt primitives.
//!
//! Large-model execution happens off-consensus. These structures define the
//! bounded commitments that can be verified/finalized by protocol logic.

use sha2::{Digest, Sha256};

use crate::pq::{
    verify_envelope_authorization, AuthPolicy, AuthorizationDomain, AuthorizationEnvelope,
    AuthorizationValidationContext, ContextSignatureVerifier, HybridAuthorization,
};

const INFERENCE_RECEIPT_DOMAIN: &[u8] = b"SYNERGY/INFERENCE-RECEIPT/V1\0";

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
    pub fn validate_against(&self, job: &InferenceJob) -> Result<(), &'static str> {
        if self.job_id != job.job_id || self.plan_root != job.execution_plan_root {
            return Err("execution plan/job commitment mismatch");
        }
        if self.stages.is_empty() {
            return Err("execution plan requires stages");
        }
        for (i, stage) in self.stages.iter().enumerate() {
            stage.validate_against(job)?;
            if stage.stage_index != i as u32 {
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
    pub now: u64,
    pub max_future_seconds: u64,
}

pub fn verify_inference_receipt<V: ContextSignatureVerifier>(
    verifier: &V,
    assignment: &InferenceStageAssignment,
    authorized: &InferenceReceiptAuthorization,
    validation: &InferenceReceiptValidationContext,
) -> bool {
    if authorized.authorization.policy != AuthPolicy::PqOnly
        || authorized.receipt.worker_id != validation.expected_worker_id
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
    pub fn validate_against(&self, job: &InferenceJob) -> Result<(), &'static str> {
        if self.job_id != job.job_id || self.model_root != job.model_root {
            return Err("outcome/job mismatch");
        }
        if self.output_commitment == [0; 32]
            || self.receipt_root == [0; 32]
            || self.verifier_evidence_root == [0; 32]
        {
            return Err("outcome commitments required");
        }
        if self.output_tokens > job.max_output_tokens || self.total_cost > job.max_cost {
            return Err("outcome exceeds job bounds");
        }
        Ok(())
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
        InferenceJob {
            job_id: [1; 32],
            requester_id: [2; 32],
            model_root: [3; 32],
            input_commitment: [4; 32],
            execution_plan_root: [5; 32],
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
            kind: if index == 0 { InferenceStageKind::Prefill } else { InferenceStageKind::Decode },
            worker_id: [10 + index as u8; 32],
            model_shard_commitment: [20 + index as u8; 32],
            input_commitment: [30 + index as u8; 32],
            resource_limit_commitment: [40 + index as u8; 32],
            lease_expires_at: 90,
        }
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

        let mut authorized = authorized;
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
