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
    pub expires_epoch: u64,
    pub lease_root: [u8; 32],
}

pub const DEFAULT_LEASE_EPOCHS: u64 = 10;

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
            .filter(|a| self.leases.values().all(|lease| lease.agent_id != a.id))
            .min_by_key(|a| {
                (
                    a.remote,
                    a.cpu_millis.saturating_sub(task.cpu_millis),
                    a.id.clone(),
                )
            })
    }

    pub fn lease(&mut self, task: &TaskSpec, epoch: u64) -> Option<TaskLease> {
        let expires_epoch = epoch.checked_add(DEFAULT_LEASE_EPOCHS)?;
        self.lease_until(task, epoch, expires_epoch)
    }

    pub fn lease_until(
        &mut self,
        task: &TaskSpec,
        epoch: u64,
        expires_epoch: u64,
    ) -> Option<TaskLease> {
        if epoch == 0 || expires_epoch <= epoch || self.leases.contains_key(&task.id) {
            return None;
        }
        let agent = self.select(task)?.clone();
        let lease_root = task_lease_root_with_expiry(task, &agent.id, epoch, expires_epoch);
        let lease = TaskLease {
            task_id: task.id.clone(),
            agent_id: agent.id,
            epoch,
            expires_epoch,
            lease_root,
        };
        self.leases.insert(task.id.clone(), lease.clone());
        Some(lease)
    }

    pub fn expire_leases(&mut self, epoch: u64) -> usize {
        let before = self.leases.len();
        self.leases.retain(|_, lease| epoch < lease.expires_epoch);
        before.saturating_sub(self.leases.len())
    }

    pub fn release(&mut self, task_id: &str) -> bool {
        self.leases.remove(task_id).is_some()
    }

    pub fn unregister_idle(&mut self, agent_id: &str) -> bool {
        if self.leases.values().any(|lease| lease.agent_id == agent_id) {
            return false;
        }
        self.agents.remove(agent_id).is_some()
    }
}

pub fn task_lease_root(task: &TaskSpec, agent_id: &str, epoch: u64) -> [u8; 32] {
    task_lease_root_with_expiry(task, agent_id, epoch, u64::MAX)
}

pub fn task_lease_root_with_expiry(
    task: &TaskSpec,
    agent_id: &str,
    epoch: u64,
    expires_epoch: u64,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"SYNERGY/AGENT-LEASE/V2");
    h.update((task.id.len() as u64).to_be_bytes());
    h.update(task.id.as_bytes());
    h.update((task.goal.len() as u64).to_be_bytes());
    h.update(task.goal.as_bytes());
    h.update((agent_id.len() as u64).to_be_bytes());
    h.update(agent_id.as_bytes());
    h.update(epoch.to_be_bytes());
    h.update(expires_epoch.to_be_bytes());
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
    #[test]
    fn expired_local_lease_fails_over_to_remote_agent() {
        let mut s = SwarmScheduler::default();
        s.register(AgentSpec {
            id: "local".into(),
            role: "coder".into(),
            cpu_millis: 2000,
            memory_mib: 4096,
            tools: tools(&["cargo"]),
            remote: false,
        });
        s.register(AgentSpec {
            id: "remote".into(),
            role: "coder".into(),
            cpu_millis: 4000,
            memory_mib: 8192,
            tools: tools(&["cargo"]),
            remote: true,
        });
        let t = TaskSpec {
            id: "failover".into(),
            goal: "compile".into(),
            required_role: Some("coder".into()),
            required_tools: tools(&["cargo"]),
            cpu_millis: 1000,
            memory_mib: 1024,
            allow_remote: true,
        };

        let first = s.lease_until(&t, 10, 20).expect("local lease");
        assert_eq!(first.agent_id, "local");
        assert!(!s.unregister_idle("local"));
        assert_eq!(s.expire_leases(20), 1);
        assert!(s.unregister_idle("local"));

        let second = s.lease_until(&t, 21, 31).expect("remote failover lease");
        assert_eq!(second.agent_id, "remote");
        assert_ne!(first.lease_root, second.lease_root);
    }

    #[test]
    fn one_agent_cannot_hold_two_active_task_leases() {
        let mut s = SwarmScheduler::default();
        s.register(AgentSpec {
            id: "solo".into(),
            role: "coder".into(),
            cpu_millis: 2000,
            memory_mib: 4096,
            tools: tools(&["cargo"]),
            remote: false,
        });
        let mut a = TaskSpec {
            id: "a".into(),
            goal: "a".into(),
            required_role: None,
            required_tools: tools(&["cargo"]),
            cpu_millis: 1000,
            memory_mib: 1024,
            allow_remote: false,
        };
        let mut b = a.clone();
        b.id = "b".into();
        b.goal = "b".into();

        assert!(s.lease_until(&a, 1, 10).is_some());
        assert!(s.lease_until(&b, 1, 10).is_none());
        assert_eq!(s.expire_leases(10), 1);
        assert!(s.lease_until(&b, 11, 20).is_some());

        a.id = "c".into();
        assert!(s.lease_until(&a, 12, 20).is_none());
    }
}
