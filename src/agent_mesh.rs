#![forbid(unsafe_code)]

use sha2::{Digest, Sha256};

use crate::mesh_overlay::{MeshAddress, MeshPacket, MeshRoute};

pub const AGENT_SERVICE_ADVERTISEMENT_DOMAIN: &[u8] =
    b"SYNERGY/AGENT-MESH/SERVICE/V1";
pub const AGENT_DELEGATION_DOMAIN: &[u8] = b"SYNERGY/AGENT-MESH/DELEGATION/V1";
pub const AGENT_MESH_SERVICE_ID: [u8; 32] = [0xA7; 32];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentServiceAdvertisement {
    pub node_id: [u8; 32],
    pub address: MeshAddress,
    pub agent_capacity: u32,
    pub cpu_millis_available: u32,
    pub memory_mib_available: u32,
    pub gpu_memory_mib_available: u32,
    pub toolset_root: [u8; 32],
    pub model_set_root: [u8; 32],
    pub policy_root: [u8; 32],
    pub epoch: u64,
    pub sequence: u64,
    pub expires_at: u64,
}

impl AgentServiceAdvertisement {
    pub fn validate(&self, now: u64) -> Result<(), &'static str> {
        if self.node_id == [0; 32]
            || self.address.0 == [0; 32]
            || self.agent_capacity == 0
            || self.cpu_millis_available == 0
            || self.memory_mib_available == 0
            || self.toolset_root == [0; 32]
            || self.model_set_root == [0; 32]
            || self.policy_root == [0; 32]
            || self.epoch == 0
            || self.sequence == 0
        {
            return Err("invalid agent service advertisement");
        }
        if now >= self.expires_at {
            return Err("agent service advertisement expired");
        }
        Ok(())
    }

    pub fn commitment(&self, now: u64) -> Option<[u8; 32]> {
        self.validate(now).ok()?;
        let mut h = Sha256::new();
        h.update(AGENT_SERVICE_ADVERTISEMENT_DOMAIN);
        h.update(self.node_id);
        h.update(self.address.0);
        h.update(self.agent_capacity.to_be_bytes());
        h.update(self.cpu_millis_available.to_be_bytes());
        h.update(self.memory_mib_available.to_be_bytes());
        h.update(self.gpu_memory_mib_available.to_be_bytes());
        h.update(self.toolset_root);
        h.update(self.model_set_root);
        h.update(self.policy_root);
        h.update(self.epoch.to_be_bytes());
        h.update(self.sequence.to_be_bytes());
        h.update(self.expires_at.to_be_bytes());
        Some(h.finalize().into())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentDelegation {
    pub task_root: [u8; 32],
    pub lease_root: [u8; 32],
    pub source: MeshAddress,
    pub destination: MeshAddress,
    pub requested_role_root: [u8; 32],
    pub required_toolset_root: [u8; 32],
    pub model_root: [u8; 32],
    pub cpu_millis: u32,
    pub memory_mib: u32,
    pub sequence: u64,
    pub expires_at: u64,
}

impl AgentDelegation {
    pub fn validate(&self, now: u64) -> Result<(), &'static str> {
        if self.task_root == [0; 32]
            || self.lease_root == [0; 32]
            || self.source.0 == [0; 32]
            || self.destination.0 == [0; 32]
            || self.source == self.destination
            || self.requested_role_root == [0; 32]
            || self.required_toolset_root == [0; 32]
            || self.model_root == [0; 32]
            || self.cpu_millis == 0
            || self.memory_mib == 0
            || self.sequence == 0
        {
            return Err("invalid agent delegation");
        }
        if now >= self.expires_at {
            return Err("agent delegation expired");
        }
        Ok(())
    }

    pub fn commitment(&self, now: u64) -> Option<[u8; 32]> {
        self.validate(now).ok()?;
        let mut h = Sha256::new();
        h.update(AGENT_DELEGATION_DOMAIN);
        h.update(self.task_root);
        h.update(self.lease_root);
        h.update(self.source.0);
        h.update(self.destination.0);
        h.update(self.requested_role_root);
        h.update(self.required_toolset_root);
        h.update(self.model_root);
        h.update(self.cpu_millis.to_be_bytes());
        h.update(self.memory_mib.to_be_bytes());
        h.update(self.sequence.to_be_bytes());
        h.update(self.expires_at.to_be_bytes());
        Some(h.finalize().into())
    }

    pub fn encode(&self, now: u64) -> Option<Vec<u8>> {
        let root = self.commitment(now)?;
        let mut out = Vec::with_capacity(32 * 8 + 4 * 2 + 8 * 2);
        out.extend_from_slice(AGENT_DELEGATION_DOMAIN);
        out.extend_from_slice(&self.task_root);
        out.extend_from_slice(&self.lease_root);
        out.extend_from_slice(&self.source.0);
        out.extend_from_slice(&self.destination.0);
        out.extend_from_slice(&self.requested_role_root);
        out.extend_from_slice(&self.required_toolset_root);
        out.extend_from_slice(&self.model_root);
        out.extend_from_slice(&self.cpu_millis.to_be_bytes());
        out.extend_from_slice(&self.memory_mib.to_be_bytes());
        out.extend_from_slice(&self.sequence.to_be_bytes());
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        out.extend_from_slice(&root);
        Some(out)
    }

    pub fn into_mesh_packet(
        &self,
        route: &MeshRoute,
        flow_id: [u8; 32],
        end_to_end_session_root: [u8; 32],
        now: u64,
    ) -> Option<MeshPacket> {
        self.validate(now).ok()?;
        if route.source != self.source || route.destination != self.destination {
            return None;
        }
        MeshPacket::new(
            route,
            flow_id,
            self.sequence,
            end_to_end_session_root,
            self.encode(now)?,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(v: u8) -> MeshAddress {
        MeshAddress([v; 32])
    }

    fn delegation() -> AgentDelegation {
        AgentDelegation {
            task_root: [1; 32],
            lease_root: [2; 32],
            source: addr(3),
            destination: addr(4),
            requested_role_root: [5; 32],
            required_toolset_root: [6; 32],
            model_root: [7; 32],
            cpu_millis: 2000,
            memory_mib: 4096,
            sequence: 1,
            expires_at: 100,
        }
    }

    #[test]
    fn delegation_is_bound_to_exact_pq_mesh_route() {
        let d = delegation();
        let route = MeshRoute {
            source: d.source,
            destination: d.destination,
            hops: vec![d.source, addr(8), d.destination],
            epoch: 1,
        };
        let packet = d
            .into_mesh_packet(&route, [9; 32], [10; 32], 50)
            .expect("agent mesh packet");
        assert_eq!(packet.source, d.source);
        assert_eq!(packet.destination, d.destination);
        assert!(packet.validate_against_route(&route).is_ok());

        let wrong_route = MeshRoute {
            source: d.source,
            destination: addr(11),
            hops: vec![d.source, addr(11)],
            epoch: 1,
        };
        assert!(d
            .into_mesh_packet(&wrong_route, [9; 32], [10; 32], 50)
            .is_none());
    }

    #[test]
    fn expired_or_zero_resource_delegation_fails_closed() {
        let mut d = delegation();
        assert!(d.commitment(100).is_none());
        d.expires_at = 101;
        d.cpu_millis = 0;
        assert!(d.commitment(100).is_none());
    }

    #[test]
    fn advertisement_binds_capacity_models_tools_and_policy() {
        let ad = AgentServiceAdvertisement {
            node_id: [1; 32],
            address: addr(2),
            agent_capacity: 8,
            cpu_millis_available: 8000,
            memory_mib_available: 16384,
            gpu_memory_mib_available: 4096,
            toolset_root: [3; 32],
            model_set_root: [4; 32],
            policy_root: [5; 32],
            epoch: 7,
            sequence: 9,
            expires_at: 100,
        };
        let root = ad.commitment(50).expect("advertisement root");
        let mut changed = ad.clone();
        changed.agent_capacity += 1;
        assert_ne!(changed.commitment(50).expect("changed root"), root);
    }
}
