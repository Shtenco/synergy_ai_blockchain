#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub type AgentId = String;
pub type TaskId = String;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AgentSpec {
    pub id: AgentId,
    pub role: String,
    pub cpu_millis: u32,
    pub memory_mib: u32,
    pub tools: BTreeSet<String>,
    pub remote: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TaskSpec {
    pub id: TaskId,
    pub goal: String,
    pub required_role: Option<String>,
    pub required_tools: BTreeSet<String>,
    pub cpu_millis: u32,
    pub memory_mib: u32,
    pub allow_remote: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TaskLease {
    pub task_id: TaskId,
    pub agent_id: AgentId,
    pub epoch: u64,
    pub lease_root: [u8; 32],
}

#[derive(Default)]
pub struct SwarmScheduler {
    agents: BTreeMap<AgentId, AgentSpec>,
    leases: BTreeMap<TaskId, TaskLease>,
}

impl SwarmScheduler {
    pub fn register(&mut self, agent: AgentSpec) -> bool {
        self.agents.insert(agent.id.clone(), agent).is_none()
    }

    pub fn select(&self, task: &TaskSpec) -> Option<&AgentSpec> {
        self.agents
            .values()
            .filter(|a| task.allow_remote || !a.remote)
            .filter(|a| task.required_role.as_ref().is_none_or(|r| &a.role == r))
            .filter(|a| a.cpu_millis >= task.cpu_millis && a.memory_mib >= task.memory_mib)
            .filter(|a| task.required_tools.is_subset(&a.tools))
            .min_by_key(|a| {
                (
                    a.remote,
                    a.cpu_millis.saturating_sub(task.cpu_millis),
                    a.id.clone(),
                )
            })
    }

    pub fn lease(&mut self, task: &TaskSpec, epoch: u64) -> Option<TaskLease> {
        if self.leases.contains_key(&task.id) {
            return None;
        }
        let agent = self.select(task)?.clone();
        let lease_root = task_lease_root(task, &agent.id, epoch);
        let lease = TaskLease {
            task_id: task.id.clone(),
            agent_id: agent.id,
            epoch,
            lease_root,
        };
        self.leases.insert(task.id.clone(), lease.clone());
        Some(lease)
    }

    pub fn release(&mut self, task_id: &str) -> bool {
        self.leases.remove(task_id).is_some()
    }
}

pub fn task_lease_root(task: &TaskSpec, agent_id: &str, epoch: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"SYNERGY/AGENT-LEASE/V1");
    h.update((task.id.len() as u64).to_be_bytes());
    h.update(task.id.as_bytes());
    h.update((task.goal.len() as u64).to_be_bytes());
    h.update(task.goal.as_bytes());
    h.update((agent_id.len() as u64).to_be_bytes());
    h.update(agent_id.as_bytes());
    h.update(epoch.to_be_bytes());
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tools(xs: &[&str]) -> BTreeSet<String> {
        xs.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn prefers_local_capable_agent_and_leases_once() {
        let mut s = SwarmScheduler::default();
        s.register(AgentSpec {
            id: "local".into(),
            role: "coder".into(),
            cpu_millis: 2000,
            memory_mib: 4096,
            tools: tools(&["git", "cargo"]),
            remote: false,
        });
        s.register(AgentSpec {
            id: "remote".into(),
            role: "coder".into(),
            cpu_millis: 4000,
            memory_mib: 8192,
            tools: tools(&["git", "cargo"]),
            remote: true,
        });
        let t = TaskSpec {
            id: "t1".into(),
            goal: "test".into(),
            required_role: Some("coder".into()),
            required_tools: tools(&["cargo"]),
            cpu_millis: 1000,
            memory_mib: 1024,
            allow_remote: true,
        };
        let l = s.lease(&t, 7).unwrap();
        assert_eq!(l.agent_id, "local");
        assert!(s.lease(&t, 7).is_none());
    }

    #[test]
    fn fails_closed_when_requirements_do_not_fit() {
        let mut s = SwarmScheduler::default();
        s.register(AgentSpec {
            id: "tiny".into(),
            role: "coder".into(),
            cpu_millis: 500,
            memory_mib: 256,
            tools: tools(&["git"]),
            remote: false,
        });
        let t = TaskSpec {
            id: "t2".into(),
            goal: "compile".into(),
            required_role: None,
            required_tools: tools(&["cargo"]),
            cpu_millis: 1000,
            memory_mib: 1024,
            allow_remote: false,
        };
        assert!(s.lease(&t, 1).is_none());
    }
}
