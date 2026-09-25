use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

use crate::peer_discovery::NodeSetSnapshot;

pub const MESH_ADDRESS_DOMAIN: &[u8] = b"SYNERGY/PQ-MESH/ADDRESS/V1\0";
pub const MESH_ROUTE_DOMAIN: &[u8] = b"SYNERGY/PQ-MESH/ROUTE/V1\0";
pub const MESH_PACKET_DOMAIN: &[u8] = b"SYNERGY/PQ-MESH/PACKET/V1\0";
pub const MESH_FLOW_DOMAIN: &[u8] = b"SYNERGY/PQ-MESH/FLOW/V1\0";
pub const MESH_HOP_APPLICATION_DOMAIN: &[u8] = b"SYNERGY/PQ-MESH/HOP-APPLICATION/V1\0";
pub const MAX_MESH_HOPS: usize = 16;
pub const MAX_MESH_ROUTES: usize = 4096;
pub const MAX_MESH_PACKET_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MeshAddress(pub [u8; 32]);

impl MeshAddress {
    pub fn from_pq_identity(node_id: [u8; 32], pq_identity_commitment: [u8; 32]) -> Option<Self> {
        if node_id == [0; 32] || pq_identity_commitment == [0; 32] {
            return None;
        }
        let mut h = Sha256::new();
        h.update(MESH_ADDRESS_DOMAIN);
        h.update(crate::pq::CRYPTO_PROFILE_VERSION.to_be_bytes());
        h.update(node_id);
        h.update(pq_identity_commitment);
        Some(Self(h.finalize().into()))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MeshRoute {
    pub source: MeshAddress,
    pub destination: MeshAddress,
    pub hops: Vec<MeshAddress>,
    pub epoch: u64,
}

impl MeshRoute {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.epoch == 0 || self.hops.len() < 2 || self.hops.len() > MAX_MESH_HOPS {
            return Err("invalid mesh route bounds");
        }
        if self.hops.first() != Some(&self.source) || self.hops.last() != Some(&self.destination) {
            return Err("mesh route endpoints mismatch");
        }
        let mut unique = BTreeSet::new();
        for hop in &self.hops {
            if !unique.insert(*hop) {
                return Err("mesh route contains loop");
            }
        }
        Ok(())
    }

    pub fn commitment(&self) -> Option<[u8; 32]> {
        self.validate().ok()?;
        let mut h = Sha256::new();
        h.update(MESH_ROUTE_DOMAIN);
        h.update(crate::pq::CRYPTO_PROFILE_VERSION.to_be_bytes());
        h.update(self.epoch.to_be_bytes());
        h.update(self.source.0);
        h.update(self.destination.0);
        h.update((self.hops.len() as u64).to_be_bytes());
        for hop in &self.hops {
            h.update(hop.0);
        }
        Some(h.finalize().into())
    }

    pub fn next_hop(&self, current: MeshAddress) -> Option<MeshAddress> {
        self.validate().ok()?;
        let i = self.hops.iter().position(|h| *h == current)?;
        self.hops.get(i + 1).copied()
    }
}

#[derive(Clone, Debug, Default)]
pub struct MeshRoutingTable {
    routes: BTreeMap<(MeshAddress, MeshAddress), MeshRoute>,
}

impl MeshRoutingTable {
    pub fn insert(&mut self, route: MeshRoute) -> Result<(), &'static str> {
        route.validate()?;
        if self.routes.len() >= MAX_MESH_ROUTES
            && !self.routes.contains_key(&(route.source, route.destination))
        {
            return Err("mesh routing table capacity exceeded");
        }
        let key = (route.source, route.destination);
        match self.routes.get(&key) {
            Some(old) if old.epoch > route.epoch => return Err("mesh route epoch downgrade"),
            Some(old) if old.epoch == route.epoch && old.hops.len() <= route.hops.len() => {
                return Err("mesh route not strictly better");
            }
            _ => {}
        }
        self.routes.insert(key, route);
        Ok(())
    }

    pub fn route(&self, source: MeshAddress, destination: MeshAddress) -> Option<&MeshRoute> {
        self.routes.get(&(source, destination))
    }

    pub fn direct_routes_from_snapshot(snapshot: &NodeSetSnapshot) -> Option<Self> {
        snapshot.validate().ok()?;
        let mut table = Self::default();
        let addresses: Vec<MeshAddress> = snapshot
            .records
            .iter()
            .map(|r| MeshAddress::from_pq_identity(r.node_id, r.pq_identity_commitment))
            .collect::<Option<Vec<_>>>()?;
        for source in &addresses {
            for destination in &addresses {
                if source != destination {
                    table.insert(MeshRoute {
                        source: *source,
                        destination: *destination,
                        hops: vec![*source, *destination],
                        epoch: snapshot.epoch,
                    }).ok()?;
                }
            }
        }
        Some(table)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MeshPacket {
    pub source: MeshAddress,
    pub destination: MeshAddress,
    pub flow_id: [u8; 32],
    pub sequence: u64,
    pub hop_index: u8,
    pub route_root: [u8; 32],
    pub end_to_end_session_root: [u8; 32],
    pub opaque_payload: Vec<u8>,
    pub payload_root: [u8; 32],
}

impl MeshPacket {
    pub fn new(
        route: &MeshRoute,
        flow_id: [u8; 32],
        sequence: u64,
        end_to_end_session_root: [u8; 32],
        opaque_payload: Vec<u8>,
    ) -> Option<Self> {
        route.validate().ok()?;
        if flow_id == [0; 32]
            || sequence == 0
            || end_to_end_session_root == [0; 32]
            || opaque_payload.is_empty()
            || opaque_payload.len() > MAX_MESH_PACKET_BYTES
        {
            return None;
        }
        let payload_root = Sha256::digest(&opaque_payload).into();
        Some(Self {
            source: route.source,
            destination: route.destination,
            flow_id,
            sequence,
            hop_index: 0,
            route_root: route.commitment()?,
            end_to_end_session_root,
            opaque_payload,
            payload_root,
        })
    }

    pub fn validate_against_route(&self, route: &MeshRoute) -> Result<(), &'static str> {
        route.validate()?;
        if self.source != route.source
            || self.destination != route.destination
            || self.route_root != route.commitment().ok_or("mesh route commitment unavailable")?
        {
            return Err("mesh packet route mismatch");
        }
        if self.flow_id == [0; 32]
            || self.sequence == 0
            || self.end_to_end_session_root == [0; 32]
            || self.opaque_payload.is_empty()
            || self.opaque_payload.len() > MAX_MESH_PACKET_BYTES
        {
            return Err("invalid mesh packet bounds");
        }
        if Sha256::digest(&self.opaque_payload).as_slice() != self.payload_root {
            return Err("mesh payload commitment mismatch");
        }
        if usize::from(self.hop_index) >= route.hops.len() {
            return Err("mesh hop index out of bounds");
        }
        Ok(())
    }

    pub fn current_hop(&self, route: &MeshRoute) -> Option<MeshAddress> {
        self.validate_against_route(route).ok()?;
        route.hops.get(usize::from(self.hop_index)).copied()
    }

    pub fn forward(&self, route: &MeshRoute, current: MeshAddress) -> Option<Self> {
        self.validate_against_route(route).ok()?;
        if self.current_hop(route)? != current || current == self.destination {
            return None;
        }
        let next_index = self.hop_index.checked_add(1)?;
        if usize::from(next_index) >= route.hops.len() {
            return None;
        }
        let mut out = self.clone();
        out.hop_index = next_index;
        Some(out)
    }

    pub fn commitment(&self, route: &MeshRoute) -> Option<[u8; 32]> {
        self.validate_against_route(route).ok()?;
        let mut h = Sha256::new();
        h.update(MESH_PACKET_DOMAIN);
        h.update(crate::pq::CRYPTO_PROFILE_VERSION.to_be_bytes());
        h.update(self.source.0);
        h.update(self.destination.0);
        h.update(self.flow_id);
        h.update(self.sequence.to_be_bytes());
        h.update([self.hop_index]);
        h.update(self.route_root);
        h.update(self.end_to_end_session_root);
        h.update(self.payload_root);
        Some(h.finalize().into())
    }
}

#[derive(Clone, Debug, Default)]
pub struct MeshReplayState {
    last_sequence: BTreeMap<([u8; 32], MeshAddress, MeshAddress), u64>,
}

impl MeshReplayState {
    pub fn consume(&mut self, packet: &MeshPacket, route: &MeshRoute) -> Result<(), &'static str> {
        packet.validate_against_route(route)?;
        let key = (packet.flow_id, packet.source, packet.destination);
        let previous = self.last_sequence.get(&key).copied().unwrap_or(0);
        if packet.sequence != previous.saturating_add(1) {
            return Err("mesh flow replay or sequence gap");
        }
        self.last_sequence.insert(key, packet.sequence);
        Ok(())
    }
}

pub fn mesh_hop_application_root(
    packet: &MeshPacket,
    route: &MeshRoute,
    current: MeshAddress,
    next: MeshAddress,
) -> Option<[u8; 32]> {
    packet.validate_against_route(route).ok()?;
    if packet.current_hop(route)? != current || route.next_hop(current)? != next {
        return None;
    }
    let mut h = Sha256::new();
    h.update(MESH_HOP_APPLICATION_DOMAIN);
    h.update(crate::pq::CRYPTO_PROFILE_VERSION.to_be_bytes());
    h.update(packet.commitment(route)?);
    h.update(current.0);
    h.update(next.0);
    Some(h.finalize().into())
}

pub fn mesh_flow_root(
    source: MeshAddress,
    destination: MeshAddress,
    flow_id: [u8; 32],
    end_to_end_session_root: [u8; 32],
) -> Option<[u8; 32]> {
    if source == destination || flow_id == [0; 32] || end_to_end_session_root == [0; 32] {
        return None;
    }
    let mut h = Sha256::new();
    h.update(MESH_FLOW_DOMAIN);
    h.update(crate::pq::CRYPTO_PROFILE_VERSION.to_be_bytes());
    h.update(source.0);
    h.update(destination.0);
    h.update(flow_id);
    h.update(end_to_end_session_root);
    Some(h.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer_discovery::{NodeRecord, NodeSetSnapshot};

    fn addr(v: u8) -> MeshAddress { MeshAddress([v; 32]) }

    fn route() -> MeshRoute {
        MeshRoute {
            source: addr(1),
            destination: addr(4),
            hops: vec![addr(1), addr(2), addr(3), addr(4)],
            epoch: 9,
        }
    }

    #[test]
    fn route_rejects_loops_and_endpoint_tamper() {
        let mut r = route();
        assert!(r.validate().is_ok());
        r.hops[2] = addr(2);
        assert!(r.validate().is_err());
        let mut r = route();
        r.hops[0] = addr(9);
        assert!(r.validate().is_err());
    }

    #[test]
    fn packet_forwarding_preserves_end_to_end_ciphertext() {
        let r = route();
        let p = MeshPacket::new(&r, [5;32], 1, [6;32], b"opaque-e2e-ciphertext".to_vec()).unwrap();
        let root = p.payload_root;
        let p = p.forward(&r, addr(1)).unwrap();
        let p = p.forward(&r, addr(2)).unwrap();
        assert_eq!(p.payload_root, root);
        assert_eq!(p.opaque_payload, b"opaque-e2e-ciphertext");
        assert_eq!(p.current_hop(&r), Some(addr(3)));
    }

    #[test]
    fn route_or_payload_tamper_is_rejected() {
        let r = route();
        let mut p = MeshPacket::new(&r, [5;32], 1, [6;32], vec![7;32]).unwrap();
        p.opaque_payload[0] ^= 1;
        assert!(p.validate_against_route(&r).is_err());

        let mut p = MeshPacket::new(&r, [5;32], 1, [6;32], vec![7;32]).unwrap();
        p.route_root[0] ^= 1;
        assert!(p.validate_against_route(&r).is_err());
    }

    #[test]
    fn replay_state_requires_exact_monotonic_flow_sequence() {
        let r = route();
        let mut s = MeshReplayState::default();
        let p1 = MeshPacket::new(&r, [5;32], 1, [6;32], vec![1]).unwrap();
        let p2 = MeshPacket::new(&r, [5;32], 2, [6;32], vec![2]).unwrap();
        assert!(s.consume(&p1, &r).is_ok());
        assert!(s.consume(&p1, &r).is_err());
        assert!(s.consume(&p2, &r).is_ok());
    }

    #[test]
    fn snapshot_builds_direct_symmetric_routes() {
        let records: Vec<NodeRecord> = (1u8..=3).map(|v| NodeRecord {
            node_id:[v;32], endpoint_root:[v+10;32], transport_keyset_root:[v+20;32],
            pq_identity_commitment:[v+30;32], capability_root:[v+40;32],
            epoch:7, sequence:1, expires_at:100,
        }).collect();
        let snapshot = NodeSetSnapshot { epoch:7, records };
        let table = MeshRoutingTable::direct_routes_from_snapshot(&snapshot).unwrap();
        let a = MeshAddress::from_pq_identity([1;32],[31;32]).unwrap();
        let b = MeshAddress::from_pq_identity([2;32],[32;32]).unwrap();
        assert_eq!(table.route(a,b).unwrap().hops, vec![a,b]);
        assert!(table.route(b,a).is_some());
    }

    #[test]
    fn hop_application_root_binds_exact_forwarding_edge() {
        let r=route();
        let p=MeshPacket::new(&r,[5;32],1,[6;32],vec![7;8]).unwrap();
        let a=mesh_hop_application_root(&p,&r,addr(1),addr(2)).unwrap();
        assert!(mesh_hop_application_root(&p,&r,addr(1),addr(3)).is_none());
        let mut p2=p.clone(); p2.sequence=2;
        let b=mesh_hop_application_root(&p2,&r,addr(1),addr(2)).unwrap();
        assert_ne!(a,b);
    }

    #[test]
    fn flow_root_binds_endpoints_and_e2e_session() {
        let a=mesh_flow_root(addr(1),addr(2),[3;32],[4;32]).unwrap();
        let b=mesh_flow_root(addr(1),addr(2),[3;32],[5;32]).unwrap();
        assert_ne!(a,b);
    }
}
