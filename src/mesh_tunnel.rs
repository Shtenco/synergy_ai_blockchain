use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io;

use crate::mesh_overlay::MeshAddress;

pub const MESH_TUNNEL_PACKET_DOMAIN: &[u8] = b"SYNERGY/PQ-MESH/TUNNEL-PACKET/V1\0";
pub const MAX_TUNNEL_IP_PACKET_BYTES: usize = 65_535;
pub const MAX_TUNNEL_ROUTES: usize = 65_536;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum TunnelIpAddress {
    V4([u8; 4]),
    V6([u8; 16]),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TunnelRouteTarget {
    MeshPeer(MeshAddress),
    ExitNode(MeshAddress),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TunnelIpPacket {
    pub version: u8,
    pub source: TunnelIpAddress,
    pub destination: TunnelIpAddress,
    pub bytes: Vec<u8>,
    pub packet_root: [u8; 32],
}

impl TunnelIpPacket {
    pub fn parse(bytes: Vec<u8>) -> Option<Self> {
        if bytes.is_empty() || bytes.len() > MAX_TUNNEL_IP_PACKET_BYTES {
            return None;
        }
        let version = bytes[0] >> 4;
        let (source, destination) = match version {
            4 => {
                if bytes.len() < 20 {
                    return None;
                }
                (
                    TunnelIpAddress::V4(bytes[12..16].try_into().ok()?),
                    TunnelIpAddress::V4(bytes[16..20].try_into().ok()?),
                )
            }
            6 => {
                if bytes.len() < 40 {
                    return None;
                }
                (
                    TunnelIpAddress::V6(bytes[8..24].try_into().ok()?),
                    TunnelIpAddress::V6(bytes[24..40].try_into().ok()?),
                )
            }
            _ => return None,
        };
        let mut h = Sha256::new();
        h.update(MESH_TUNNEL_PACKET_DOMAIN);
        h.update(crate::pq::CRYPTO_PROFILE_VERSION.to_be_bytes());
        h.update([version]);
        match source {
            TunnelIpAddress::V4(v) => {
                h.update([4]);
                h.update(v);
            }
            TunnelIpAddress::V6(v) => {
                h.update([6]);
                h.update(v);
            }
        }
        match destination {
            TunnelIpAddress::V4(v) => {
                h.update([4]);
                h.update(v);
            }
            TunnelIpAddress::V6(v) => {
                h.update([6]);
                h.update(v);
            }
        }
        h.update((bytes.len() as u64).to_be_bytes());
        h.update(&bytes);
        Some(Self {
            version,
            source,
            destination,
            bytes,
            packet_root: h.finalize().into(),
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct MeshTunnelRouting {
    exact: BTreeMap<TunnelIpAddress, MeshAddress>,
    default_exit: Option<MeshAddress>,
}

impl MeshTunnelRouting {
    pub fn set_exact(
        &mut self,
        destination: TunnelIpAddress,
        mesh_peer: MeshAddress,
    ) -> Result<(), &'static str> {
        if self.exact.len() >= MAX_TUNNEL_ROUTES && !self.exact.contains_key(&destination) {
            return Err("tunnel route capacity exceeded");
        }
        self.exact.insert(destination, mesh_peer);
        Ok(())
    }

    pub fn set_default_exit(&mut self, exit: MeshAddress) {
        self.default_exit = Some(exit);
    }

    pub fn target(&self, destination: TunnelIpAddress) -> Option<TunnelRouteTarget> {
        if let Some(peer) = self.exact.get(&destination) {
            return Some(TunnelRouteTarget::MeshPeer(*peer));
        }
        self.default_exit.map(TunnelRouteTarget::ExitNode)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MeshTunnelPolicy {
    pub fail_closed: bool,
    pub allow_plaintext_bypass: bool,
}

impl MeshTunnelPolicy {
    pub const fn secure_default() -> Self {
        Self {
            fail_closed: true,
            allow_plaintext_bypass: false,
        }
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        if !self.fail_closed || self.allow_plaintext_bypass {
            return Err("secure mesh tunnel requires fail-closed no-bypass policy");
        }
        Ok(())
    }
}

pub fn classify_tunnel_packet(
    packet: &TunnelIpPacket,
    routes: &MeshTunnelRouting,
    policy: MeshTunnelPolicy,
) -> Result<TunnelRouteTarget, &'static str> {
    policy.validate()?;
    routes
        .target(packet.destination)
        .ok_or("no protected mesh route or exit node")
}

pub trait MeshTunnelDevice {
    fn read_packet(&mut self, buffer: &mut [u8]) -> io::Result<usize>;
    fn write_packet(&mut self, packet: &[u8]) -> io::Result<()>;
}

#[derive(Default)]
pub struct MemoryTunnelDevice {
    ingress: Vec<Vec<u8>>,
    egress: Vec<Vec<u8>>,
}

impl MemoryTunnelDevice {
    pub fn push_ingress(&mut self, packet: Vec<u8>) {
        self.ingress.push(packet);
    }

    pub fn take_egress(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.egress)
    }
}

impl MeshTunnelDevice for MemoryTunnelDevice {
    fn read_packet(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.ingress.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "no tunnel packet",
            ));
        }
        let packet = self.ingress.remove(0);
        if packet.len() > buffer.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "tunnel buffer too small",
            ));
        }
        buffer[..packet.len()].copy_from_slice(&packet);
        Ok(packet.len())
    }

    fn write_packet(&mut self, packet: &[u8]) -> io::Result<()> {
        if packet.is_empty() || packet.len() > MAX_TUNNEL_IP_PACKET_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid tunnel packet",
            ));
        }
        self.egress.push(packet.to_vec());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4(src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
        let mut p = vec![0u8; 20];
        p[0] = 0x45;
        p[12..16].copy_from_slice(&src);
        p[16..20].copy_from_slice(&dst);
        p
    }

    #[test]
    fn exact_mesh_peer_route_wins_over_exit() {
        let p = TunnelIpPacket::parse(ipv4([10, 0, 0, 1], [10, 0, 0, 2])).unwrap();
        let mut routes = MeshTunnelRouting::default();
        routes.set_default_exit(MeshAddress([9; 32]));
        routes
            .set_exact(TunnelIpAddress::V4([10, 0, 0, 2]), MeshAddress([2; 32]))
            .unwrap();
        assert_eq!(
            classify_tunnel_packet(&p, &routes, MeshTunnelPolicy::secure_default()).unwrap(),
            TunnelRouteTarget::MeshPeer(MeshAddress([2; 32]))
        );
    }

    #[test]
    fn public_destination_uses_protected_exit_node() {
        let p = TunnelIpPacket::parse(ipv4([10, 0, 0, 1], [1, 1, 1, 1])).unwrap();
        let mut routes = MeshTunnelRouting::default();
        routes.set_default_exit(MeshAddress([9; 32]));
        assert_eq!(
            classify_tunnel_packet(&p, &routes, MeshTunnelPolicy::secure_default()).unwrap(),
            TunnelRouteTarget::ExitNode(MeshAddress([9; 32]))
        );
    }

    #[test]
    fn no_exit_means_fail_closed_not_plaintext_bypass() {
        let p = TunnelIpPacket::parse(ipv4([10, 0, 0, 1], [1, 1, 1, 1])).unwrap();
        let routes = MeshTunnelRouting::default();
        assert!(classify_tunnel_packet(&p, &routes, MeshTunnelPolicy::secure_default()).is_err());
    }

    #[test]
    fn insecure_policy_is_rejected() {
        let p = TunnelIpPacket::parse(ipv4([10, 0, 0, 1], [1, 1, 1, 1])).unwrap();
        let mut routes = MeshTunnelRouting::default();
        routes.set_default_exit(MeshAddress([9; 32]));
        assert!(classify_tunnel_packet(
            &p,
            &routes,
            MeshTunnelPolicy {
                fail_closed: false,
                allow_plaintext_bypass: true
            }
        )
        .is_err());
    }
}
