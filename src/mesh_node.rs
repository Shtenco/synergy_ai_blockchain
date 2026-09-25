use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

use crate::mesh_overlay::{
    mesh_flow_root, MeshAddress, MeshPacket, MeshReplayState, MeshRoute, MeshRoutingTable,
};
use crate::peer_discovery::{NodeRecord, PeerDirectory};

pub const MESH_NODE_CAPABILITY_DOMAIN: &[u8] = b"SYNERGY/PQ-MESH/NODE-CAPABILITIES/V1\0";
pub const MESH_SERVICE_DOMAIN: &[u8] = b"SYNERGY/PQ-MESH/SERVICE/V1\0";
pub const MAX_MESH_SERVICES: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MeshNodeCapabilities {
    pub client: bool,
    pub server: bool,
    pub relay: bool,
    pub validator: bool,
}

impl MeshNodeCapabilities {
    pub const fn full_peer() -> Self {
        Self {
            client: true,
            server: true,
            relay: true,
            validator: true,
        }
    }

    pub fn commitment(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(MESH_NODE_CAPABILITY_DOMAIN);
        h.update(crate::pq::CRYPTO_PROFILE_VERSION.to_be_bytes());
        h.update([
            self.client as u8,
            self.server as u8,
            self.relay as u8,
            self.validator as u8,
        ]);
        h.finalize().into()
    }

    pub fn validate_full_peer(&self) -> Result<(), &'static str> {
        if !(self.client && self.server && self.relay && self.validator) {
            return Err("mesh node must be client+server+relay+validator");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MeshService {
    pub service_id: [u8; 32],
    pub owner: MeshAddress,
    pub port: u16,
    pub protocol: u8,
    pub endpoint_root: [u8; 32],
}

impl MeshService {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.service_id == [0; 32]
            || self.port == 0
            || self.protocol == 0
            || self.endpoint_root == [0; 32]
        {
            return Err("invalid mesh service");
        }
        Ok(())
    }

    pub fn commitment(&self) -> Option<[u8; 32]> {
        self.validate().ok()?;
        let mut h = Sha256::new();
        h.update(MESH_SERVICE_DOMAIN);
        h.update(crate::pq::CRYPTO_PROFILE_VERSION.to_be_bytes());
        h.update(self.service_id);
        h.update(self.owner.0);
        h.update(self.port.to_be_bytes());
        h.update([self.protocol]);
        h.update(self.endpoint_root);
        Some(h.finalize().into())
    }
}

#[derive(Clone, Debug)]
pub struct MeshNode {
    pub address: MeshAddress,
    pub node_id: [u8; 32],
    pub pq_identity_commitment: [u8; 32],
    pub capabilities: MeshNodeCapabilities,
    pub routes: MeshRoutingTable,
    pub replay: MeshReplayState,
    services: BTreeMap<[u8; 32], MeshService>,
}

impl MeshNode {
    pub fn from_record(record: &NodeRecord) -> Option<Self> {
        record.validate().ok()?;
        let address = MeshAddress::from_pq_identity(record.node_id, record.pq_identity_commitment)?;
        Some(Self {
            address,
            node_id: record.node_id,
            pq_identity_commitment: record.pq_identity_commitment,
            capabilities: MeshNodeCapabilities::full_peer(),
            routes: MeshRoutingTable::default(),
            replay: MeshReplayState::default(),
            services: BTreeMap::new(),
        })
    }

    pub fn publish_into_directory(
        &self,
        record: NodeRecord,
        directory: &mut PeerDirectory,
        now: u64,
    ) -> Result<(), &'static str> {
        self.capabilities.validate_full_peer()?;
        if record.node_id != self.node_id
            || record.pq_identity_commitment != self.pq_identity_commitment
        {
            return Err("mesh node identity mismatch");
        }
        directory.upsert(record, now)
    }

    pub fn register_service(&mut self, service: MeshService) -> Result<(), &'static str> {
        self.capabilities.validate_full_peer()?;
        service.validate()?;
        if service.owner != self.address {
            return Err("mesh service owner mismatch");
        }
        if self.services.len() >= MAX_MESH_SERVICES
            && !self.services.contains_key(&service.service_id)
        {
            return Err("mesh service capacity exceeded");
        }
        self.services.insert(service.service_id, service);
        Ok(())
    }

    pub fn service(&self, id: &[u8; 32]) -> Option<&MeshService> {
        self.services.get(id)
    }

    pub fn install_route(&mut self, route: MeshRoute) -> Result<(), &'static str> {
        if route.source != self.address {
            return Err("mesh route must originate at this node");
        }
        self.routes.insert(route)
    }

    pub fn open_flow(
        &self,
        destination: MeshAddress,
        flow_id: [u8; 32],
        sequence: u64,
        end_to_end_session_root: [u8; 32],
        opaque_payload: Vec<u8>,
    ) -> Option<MeshPacket> {
        self.capabilities.validate_full_peer().ok()?;
        let route = self.routes.route(self.address, destination)?;
        mesh_flow_root(self.address, destination, flow_id, end_to_end_session_root)?;
        MeshPacket::new(
            route,
            flow_id,
            sequence,
            end_to_end_session_root,
            opaque_payload,
        )
    }

    pub fn accept_or_forward(
        &mut self,
        packet: &MeshPacket,
        route: &MeshRoute,
    ) -> Result<Option<MeshPacket>, &'static str> {
        self.capabilities.validate_full_peer()?;
        packet.validate_against_route(route)?;
        if packet.current_hop(route) != Some(self.address) {
            return Err("mesh packet delivered to wrong hop");
        }
        self.replay.consume(packet, route)?;
        if self.address == packet.destination {
            return Ok(None);
        }
        if !self.capabilities.relay {
            return Err("mesh relay disabled");
        }
        packet
            .forward(route, self.address)
            .ok_or("mesh forwarding failed")
            .map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer_discovery::NodeRecord;

    fn record(v: u8) -> NodeRecord {
        NodeRecord {
            node_id: [v; 32],
            endpoint_root: [v + 10; 32],
            transport_keyset_root: [v + 20; 32],
            pq_identity_commitment: [v + 30; 32],
            capability_root: [v + 40; 32],
            epoch: 1,
            sequence: 1,
            expires_at: 100,
        }
    }

    #[test]
    fn every_mesh_node_is_client_server_relay_validator() {
        let n = MeshNode::from_record(&record(1)).unwrap();
        assert_eq!(n.capabilities, MeshNodeCapabilities::full_peer());
        assert!(n.capabilities.validate_full_peer().is_ok());
    }

    #[test]
    fn node_can_host_service_and_open_flow() {
        let mut a = MeshNode::from_record(&record(1)).unwrap();
        let b = MeshNode::from_record(&record(2)).unwrap();
        a.register_service(MeshService {
            service_id: [9; 32],
            owner: a.address,
            port: 443,
            protocol: 1,
            endpoint_root: [8; 32],
        })
        .unwrap();
        assert!(a.service(&[9; 32]).is_some());
        a.install_route(MeshRoute {
            source: a.address,
            destination: b.address,
            hops: vec![a.address, b.address],
            epoch: 1,
        })
        .unwrap();
        let p = a
            .open_flow(b.address, [7; 32], 1, [6; 32], vec![5; 64])
            .unwrap();
        assert_eq!(p.destination, b.address);
    }

    #[test]
    fn three_nodes_forward_without_plaintext_interpretation() {
        let mut a = MeshNode::from_record(&record(1)).unwrap();
        let mut b = MeshNode::from_record(&record(2)).unwrap();
        let mut c = MeshNode::from_record(&record(3)).unwrap();
        let r = MeshRoute {
            source: a.address,
            destination: c.address,
            hops: vec![a.address, b.address, c.address],
            epoch: 1,
        };
        a.install_route(r.clone()).unwrap();
        let p = a
            .open_flow(
                c.address,
                [7; 32],
                1,
                [6; 32],
                b"opaque-e2e-ciphertext".to_vec(),
            )
            .unwrap();
        let p = p.forward(&r, a.address).unwrap();
        let p = b.accept_or_forward(&p, &r).unwrap().unwrap();
        assert_eq!(p.opaque_payload, b"opaque-e2e-ciphertext");
        assert!(c.accept_or_forward(&p, &r).unwrap().is_none());
    }

    #[test]
    fn replay_is_rejected_at_relay() {
        let a = MeshNode::from_record(&record(1)).unwrap();
        let mut b = MeshNode::from_record(&record(2)).unwrap();
        let c = MeshNode::from_record(&record(3)).unwrap();
        let r = MeshRoute {
            source: a.address,
            destination: c.address,
            hops: vec![a.address, b.address, c.address],
            epoch: 1,
        };
        let p = MeshPacket::new(&r, [7; 32], 1, [6; 32], vec![5])
            .unwrap()
            .forward(&r, a.address)
            .unwrap();
        assert!(b.accept_or_forward(&p, &r).is_ok());
        assert!(b.accept_or_forward(&p, &r).is_err());
    }
}
