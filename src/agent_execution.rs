#![forbid(unsafe_code)]

use sha2::{Digest, Sha256};

use crate::pq::{
    verify_envelope_authorization, AuthPolicy, AuthorizationDomain, AuthorizationEnvelope,
    AuthorizationReplayState, AuthorizationValidationContext, ContextSignatureVerifier,
    HybridAuthorization,
};

pub const AGENT_TASK_DOMAIN: &[u8] = b"SYNERGY/AGENT-TASK/V1";
pub const AGENT_EXECUTION_RECEIPT_DOMAIN: &[u8] = b"SYNERGY/AGENT-EXECUTION-RECEIPT/V1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentTaskCommitment {
    pub task_id: [u8; 32],
    pub parent_task_root: [u8; 32],
    pub workspace_root: [u8; 32],
    pub tool_policy_root: [u8; 32],
    pub model_root: [u8; 32],
    pub input_root: [u8; 32],
    pub max_cpu_millis: u32,
    pub max_memory_mib: u32,
    pub expiry_epoch: u64,
}

impl AgentTaskCommitment {
    pub fn root(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(AGENT_TASK_DOMAIN);
        h.update(self.task_id);
        h.update(self.parent_task_root);
        h.update(self.workspace_root);
        h.update(self.tool_policy_root);
        h.update(self.model_root);
        h.update(self.input_root);
        h.update(self.max_cpu_millis.to_be_bytes());
        h.update(self.max_memory_mib.to_be_bytes());
        h.update(self.expiry_epoch.to_be_bytes());
        h.finalize().into()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentExecutionReceipt {
    pub task_root: [u8; 32],
    pub worker_node_id: [u8; 32],
    pub agent_id: [u8; 32],
    pub result_root: [u8; 32],
    pub execution_trace_root: [u8; 32],
    pub cpu_millis_used: u64,
    pub memory_mib_peak: u32,
    pub started_epoch: u64,
    pub finished_epoch: u64,
    pub sequence: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentReceiptError {
    TaskRootMismatch,
    ZeroIdentity,
    EmptyResult,
    InvalidEpochOrder,
    ExpiredTask,
    ResourceLimitExceeded,
    ZeroSequence,
}

impl AgentExecutionReceipt {
    pub fn root(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(AGENT_EXECUTION_RECEIPT_DOMAIN);
        h.update(self.task_root);
        h.update(self.worker_node_id);
        h.update(self.agent_id);
        h.update(self.result_root);
        h.update(self.execution_trace_root);
        h.update(self.cpu_millis_used.to_be_bytes());
        h.update(self.memory_mib_peak.to_be_bytes());
        h.update(self.started_epoch.to_be_bytes());
        h.update(self.finished_epoch.to_be_bytes());
        h.update(self.sequence.to_be_bytes());
        h.finalize().into()
    }

    pub fn validate_against(&self, task: &AgentTaskCommitment) -> Result<(), AgentReceiptError> {
        if self.task_root != task.root() {
            return Err(AgentReceiptError::TaskRootMismatch);
        }
        if self.worker_node_id == [0; 32] || self.agent_id == [0; 32] {
            return Err(AgentReceiptError::ZeroIdentity);
        }
        if self.result_root == [0; 32] || self.execution_trace_root == [0; 32] {
            return Err(AgentReceiptError::EmptyResult);
        }
        if self.started_epoch > self.finished_epoch {
            return Err(AgentReceiptError::InvalidEpochOrder);
        }
        if self.finished_epoch > task.expiry_epoch {
            return Err(AgentReceiptError::ExpiredTask);
        }
        if self.cpu_millis_used > u64::from(task.max_cpu_millis)
            || self.memory_mib_peak > task.max_memory_mib
        {
            return Err(AgentReceiptError::ResourceLimitExceeded);
        }
        if self.sequence == 0 {
            return Err(AgentReceiptError::ZeroSequence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentExecutionAuthorization {
    pub chain_id: [u8; 32],
    pub epoch: u64,
    pub nonce: u64,
    pub expires_at: u64,
    pub receipt: AgentExecutionReceipt,
    pub authorization: HybridAuthorization,
}

impl AgentExecutionAuthorization {
    pub fn envelope(&self) -> AuthorizationEnvelope {
        AuthorizationEnvelope {
            chain_id: self.chain_id,
            domain: AuthorizationDomain::AgentExecutionReceipt,
            epoch: self.epoch,
            nonce: self.nonce,
            expires_at: self.expires_at,
            payload_commitment: self.receipt.root(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AgentExecutionValidationContext {
    pub expected_chain_id: [u8; 32],
    pub expected_epoch: u64,
    pub expected_nonce: u64,
    pub expected_worker_node_id: [u8; 32],
    pub expected_worker_keyset_commitment: [u8; 32],
    pub now: u64,
    pub max_future_seconds: u64,
}

pub fn verify_agent_execution_receipt<V: ContextSignatureVerifier>(
    verifier: &V,
    task: &AgentTaskCommitment,
    authorized: &AgentExecutionAuthorization,
    validation: &AgentExecutionValidationContext,
) -> bool {
    if authorized.authorization.policy != AuthPolicy::PqOnly
        || authorized.receipt.worker_node_id != validation.expected_worker_node_id
        || authorized.authorization.keyset_commitment()
            != Some(validation.expected_worker_keyset_commitment)
        || authorized.receipt.validate_against(task).is_err()
    {
        return false;
    }

    let envelope = authorized.envelope();
    let auth_validation = AuthorizationValidationContext {
        expected_chain_id: validation.expected_chain_id,
        expected_domain: AuthorizationDomain::AgentExecutionReceipt,
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

pub fn verify_agent_execution_receipt_and_consume<V: ContextSignatureVerifier>(
    verifier: &V,
    task: &AgentTaskCommitment,
    authorized: &AgentExecutionAuthorization,
    validation: &AgentExecutionValidationContext,
    replay: &mut AuthorizationReplayState,
) -> bool {
    if !verify_agent_execution_receipt(verifier, task, authorized, validation) {
        return false;
    }

    replay.consume_verified_for_subject(
        &authorized.authorization,
        &authorized.envelope(),
        validation.expected_worker_node_id,
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
                    public_key: vec![0x31; ML_DSA_87_PUBLIC_KEY_BYTES],
                    signature: vec![0x32; ML_DSA_87_SIGNATURE_BYTES],
                },
                SignatureEvidence {
                    scheme: AuthScheme::SlhDsaShake256s,
                    public_key: vec![0x33; SLH_DSA_SHAKE_256S_PUBLIC_KEY_BYTES],
                    signature: vec![0x34; SLH_DSA_SHAKE_256S_SIGNATURE_BYTES],
                },
            ],
        }
    }

    fn task() -> AgentTaskCommitment {
        AgentTaskCommitment {
            task_id: [1; 32],
            parent_task_root: [2; 32],
            workspace_root: [3; 32],
            tool_policy_root: [4; 32],
            model_root: [5; 32],
            input_root: [6; 32],
            max_cpu_millis: 10_000,
            max_memory_mib: 4096,
            expiry_epoch: 100,
        }
    }

    fn receipt(task: &AgentTaskCommitment) -> AgentExecutionReceipt {
        AgentExecutionReceipt {
            task_root: task.root(),
            worker_node_id: [7; 32],
            agent_id: [8; 32],
            result_root: [9; 32],
            execution_trace_root: [10; 32],
            cpu_millis_used: 9000,
            memory_mib_peak: 2048,
            started_epoch: 90,
            finished_epoch: 95,
            sequence: 1,
        }
    }

    #[test]
    fn valid_receipt_is_bound_to_exact_task_and_resources() {
        let task = task();
        assert_eq!(receipt(&task).validate_against(&task), Ok(()));
    }

    #[test]
    fn changed_policy_or_resource_overuse_fails_closed() {
        let task = task();
        let mut changed = task.clone();
        changed.tool_policy_root = [44; 32];
        assert_eq!(
            receipt(&task).validate_against(&changed),
            Err(AgentReceiptError::TaskRootMismatch)
        );

        let mut receipt = receipt(&task);
        receipt.memory_mib_peak = 4097;
        assert_eq!(
            receipt.validate_against(&task),
            Err(AgentReceiptError::ResourceLimitExceeded)
        );
    }

    #[test]
    fn pq_authorized_receipt_consumes_nonce_once() {
        let task = task();
        let auth = pq_only_authorization();
        let authorized = AgentExecutionAuthorization {
            chain_id: [0xA1; 32],
            epoch: 7,
            nonce: 9,
            expires_at: 1_100,
            receipt: receipt(&task),
            authorization: auth.clone(),
        };
        let envelope = authorized.envelope();
        let verifier = ExpectedVerifier {
            message: envelope
                .canonical_message(AuthPolicy::PqOnly)
                .expect("agent receipt message"),
            context: envelope
                .fips_signature_context(AuthPolicy::PqOnly)
                .expect("agent receipt context"),
        };
        let keyset = auth.keyset_commitment().expect("agent worker keyset");
        let validation = AgentExecutionValidationContext {
            expected_chain_id: [0xA1; 32],
            expected_epoch: 7,
            expected_nonce: 9,
            expected_worker_node_id: authorized.receipt.worker_node_id,
            expected_worker_keyset_commitment: keyset,
            now: 1_000,
            max_future_seconds: 200,
        };
        let mut replay = AuthorizationReplayState::new_for_subject(
            [0xA1; 32],
            AuthorizationDomain::AgentExecutionReceipt,
            AuthPolicy::PqOnly,
            authorized.receipt.worker_node_id,
            7,
            9,
        )
        .expect("agent replay state");

        assert!(verify_agent_execution_receipt_and_consume(
            &verifier,
            &task,
            &authorized,
            &validation,
            &mut replay,
        ));
        assert_eq!(replay.next_nonce(), 10);
        assert!(!verify_agent_execution_receipt_and_consume(
            &verifier,
            &task,
            &authorized,
            &validation,
            &mut replay,
        ));
    }

    #[test]
    fn pq_authorized_receipt_rejects_wrong_registered_keyset() {
        let task = task();
        let auth = pq_only_authorization();
        let authorized = AgentExecutionAuthorization {
            chain_id: [0xA1; 32],
            epoch: 7,
            nonce: 9,
            expires_at: 1_100,
            receipt: receipt(&task),
            authorization: auth.clone(),
        };
        let envelope = authorized.envelope();
        let verifier = ExpectedVerifier {
            message: envelope
                .canonical_message(AuthPolicy::PqOnly)
                .expect("agent receipt message"),
            context: envelope
                .fips_signature_context(AuthPolicy::PqOnly)
                .expect("agent receipt context"),
        };
        let mut wrong_keyset = auth.keyset_commitment().expect("agent worker keyset");
        wrong_keyset[0] ^= 1;
        let validation = AgentExecutionValidationContext {
            expected_chain_id: [0xA1; 32],
            expected_epoch: 7,
            expected_nonce: 9,
            expected_worker_node_id: authorized.receipt.worker_node_id,
            expected_worker_keyset_commitment: wrong_keyset,
            now: 1_000,
            max_future_seconds: 200,
        };
        assert!(!verify_agent_execution_receipt(
            &verifier,
            &task,
            &authorized,
            &validation,
        ));
    }
}
