#![forbid(unsafe_code)]

use sha2::{Digest, Sha256};

pub const AGENT_TASK_DOMAIN: &[u8] = b"SYNERGY/AGENT-TASK/V1";
pub const AGENT_EXECUTION_RECEIPT_DOMAIN: &[u8] =
    b"SYNERGY/AGENT-EXECUTION-RECEIPT/V1";

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

    pub fn validate_against(
        &self,
        task: &AgentTaskCommitment,
    ) -> Result<(), AgentReceiptError> {
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
