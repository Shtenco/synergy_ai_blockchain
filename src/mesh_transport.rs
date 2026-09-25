use sha2::{Digest, Sha256};

use crate::mesh_overlay::{mesh_flow_root, MeshAddress, MeshPacket, MeshRoute};
use crate::network::{TransportRecordSequence, TransportRole, TransportSessionKey};
use crate::transport_record::{
    decrypt_transport_record, encrypt_transport_record, EncryptedTransportRecord,
};

pub const MESH_E2E_APPLICATION_DOMAIN: &[u8] = b"SYNERGY/PQ-MESH/E2E-APPLICATION/V1\0";
pub const MESH_HOP_HEADER_DOMAIN: &[u8] = b"SYNERGY/PQ-MESH/HOP-HEADER/V1\0";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MeshHopHeader {
    pub packet_root: [u8; 32],
    pub route_root: [u8; 32],
    pub current: MeshAddress,
    pub next: MeshAddress,
}

impl MeshHopHeader {
    pub fn validate(&self, route: &MeshRoute) -> Result<(), &'static str> {
        if self.packet_root == [0; 32] || self.route_root == [0; 32] {
            return Err("mesh hop header roots required");
        }
        if self.route_root != route.commitment().ok_or("mesh route root unavailable")? {
            return Err("mesh hop header route mismatch");
        }
        if route.next_hop(self.current) != Some(self.next) {
            return Err("mesh hop header edge mismatch");
        }
        Ok(())
    }

    pub fn application_root(&self, route: &MeshRoute) -> Option<[u8; 32]> {
        self.validate(route).ok()?;
        let mut h = Sha256::new();
        h.update(MESH_HOP_HEADER_DOMAIN);
        h.update(crate::pq::CRYPTO_PROFILE_VERSION.to_be_bytes());
        h.update(self.packet_root);
        h.update(self.route_root);
        h.update(self.current.0);
        h.update(self.next.0);
        Some(h.finalize().into())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedMeshHop {
    pub header: MeshHopHeader,
    pub record: EncryptedTransportRecord,
}

pub fn encrypt_mesh_end_to_end(
    route: &MeshRoute,
    flow_id: [u8; 32],
    sequence: u64,
    session_root: [u8; 32],
    key: &TransportSessionKey,
    record_sequence: &mut TransportRecordSequence,
    now: u64,
    plaintext: &[u8],
) -> Option<MeshPacket> {
    let flow_root = mesh_flow_root(route.source, route.destination, flow_id, session_root)?;
    let record = encrypt_transport_record(
        key,
        record_sequence,
        now,
        session_root,
        TransportRole::Initiator,
        flow_root,
        plaintext,
    )?;
    let opaque_payload = encode_record(&record)?;
    MeshPacket::new(route, flow_id, sequence, session_root, opaque_payload)
}

pub fn decrypt_mesh_end_to_end(
    packet: &MeshPacket,
    route: &MeshRoute,
    key: &TransportSessionKey,
    record_sequence: &mut TransportRecordSequence,
    now: u64,
) -> Option<Vec<u8>> {
    packet.validate_against_route(route).ok()?;
    if packet.current_hop(route)? != packet.destination {
        return None;
    }
    let flow_root = mesh_flow_root(
        packet.source,
        packet.destination,
        packet.flow_id,
        packet.end_to_end_session_root,
    )?;
    let record = decode_record(&packet.opaque_payload)?;
    decrypt_transport_record(
        key,
        record_sequence,
        now,
        packet.end_to_end_session_root,
        TransportRole::Initiator,
        flow_root,
        &record,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn encrypt_mesh_hop(
    packet: &MeshPacket,
    route: &MeshRoute,
    current: MeshAddress,
    next: MeshAddress,
    hop_session_root: [u8; 32],
    key: &TransportSessionKey,
    record_sequence: &mut TransportRecordSequence,
    now: u64,
) -> Option<EncryptedMeshHop> {
    packet.validate_against_route(route).ok()?;
    if packet.current_hop(route)? != current || route.next_hop(current)? != next {
        return None;
    }
    let packet_root = packet.commitment(route)?;
    let header = MeshHopHeader {
        packet_root,
        route_root: route.commitment()?,
        current,
        next,
    };
    let app_root = header.application_root(route)?;
    let bytes = encode_packet(packet)?;
    let record = encrypt_transport_record(
        key,
        record_sequence,
        now,
        hop_session_root,
        TransportRole::Initiator,
        app_root,
        &bytes,
    )?;
    Some(EncryptedMeshHop { header, record })
}

#[allow(clippy::too_many_arguments)]
pub fn decrypt_mesh_hop(
    wrapped: &EncryptedMeshHop,
    route: &MeshRoute,
    hop_session_root: [u8; 32],
    key: &TransportSessionKey,
    record_sequence: &mut TransportRecordSequence,
    now: u64,
) -> Option<MeshPacket> {
    let app_root = wrapped.header.application_root(route)?;
    let bytes = decrypt_transport_record(
        key,
        record_sequence,
        now,
        hop_session_root,
        TransportRole::Initiator,
        app_root,
        &wrapped.record,
    )?;
    let packet = decode_packet(&bytes)?;
    packet.validate_against_route(route).ok()?;
    if packet.commitment(route)? != wrapped.header.packet_root {
        return None;
    }
    if packet.current_hop(route)? != wrapped.header.current
        || route.next_hop(wrapped.header.current)? != wrapped.header.next
    {
        return None;
    }
    Some(packet)
}

pub fn encode_record(record: &EncryptedTransportRecord) -> Option<Vec<u8>> {
    let len = u32::try_from(record.ciphertext.len()).ok()?;
    let mut out = Vec::with_capacity(12 + 32 + 4 + record.ciphertext.len());
    out.extend_from_slice(&record.nonce);
    out.extend_from_slice(&record.plaintext_commitment);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&record.ciphertext);
    Some(out)
}

pub fn decode_record(bytes: &[u8]) -> Option<EncryptedTransportRecord> {
    if bytes.len() < 48 {
        return None;
    }
    let nonce: [u8; 12] = bytes[0..12].try_into().ok()?;
    let plaintext_commitment: [u8; 32] = bytes[12..44].try_into().ok()?;
    let len = u32::from_be_bytes(bytes[44..48].try_into().ok()?) as usize;
    if len == 0 || bytes.len() != 48 + len {
        return None;
    }
    Some(EncryptedTransportRecord {
        nonce,
        plaintext_commitment,
        ciphertext: bytes[48..].to_vec(),
    })
}

pub fn encode_packet(packet: &MeshPacket) -> Option<Vec<u8>> {
    let len = u32::try_from(packet.opaque_payload.len()).ok()?;
    let mut out = Vec::with_capacity(205 + packet.opaque_payload.len());
    out.extend_from_slice(&packet.source.0);
    out.extend_from_slice(&packet.destination.0);
    out.extend_from_slice(&packet.flow_id);
    out.extend_from_slice(&packet.sequence.to_be_bytes());
    out.push(packet.hop_index);
    out.extend_from_slice(&packet.route_root);
    out.extend_from_slice(&packet.end_to_end_session_root);
    out.extend_from_slice(&packet.payload_root);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&packet.opaque_payload);
    Some(out)
}

pub fn decode_packet(bytes: &[u8]) -> Option<MeshPacket> {
    const FIXED: usize = 205;
    if bytes.len() < FIXED {
        return None;
    }
    let mut o = 0usize;
    let source = MeshAddress(bytes[o..o + 32].try_into().ok()?);
    o += 32;
    let destination = MeshAddress(bytes[o..o + 32].try_into().ok()?);
    o += 32;
    let flow_id = bytes[o..o + 32].try_into().ok()?;
    o += 32;
    let sequence = u64::from_be_bytes(bytes[o..o + 8].try_into().ok()?);
    o += 8;
    let hop_index = bytes[o];
    o += 1;
    let route_root = bytes[o..o + 32].try_into().ok()?;
    o += 32;
    let end_to_end_session_root = bytes[o..o + 32].try_into().ok()?;
    o += 32;
    let payload_root = bytes[o..o + 32].try_into().ok()?;
    o += 32;
    let len = u32::from_be_bytes(bytes[o..o + 4].try_into().ok()?) as usize;
    o += 4;
    if len == 0 || bytes.len() != o + len {
        return None;
    }
    Some(MeshPacket {
        source,
        destination,
        flow_id,
        sequence,
        hop_index,
        route_root,
        end_to_end_session_root,
        opaque_payload: bytes[o..].to_vec(),
        payload_root,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::RekeyPolicy;

    fn addr(v: u8) -> MeshAddress {
        MeshAddress([v; 32])
    }
    fn key(v: u8) -> TransportSessionKey {
        crate::network::transport_session_key_from_test_bytes([v; 32])
    }
    fn seq() -> TransportRecordSequence {
        TransportRecordSequence::new_initiator_to_responder(
            RekeyPolicy {
                max_messages: 100,
                max_seconds: 300,
            },
            10,
        )
        .unwrap()
    }

    #[test]
    fn double_encryption_round_trip_keeps_relay_blind_to_plaintext() {
        let route = MeshRoute {
            source: addr(1),
            destination: addr(3),
            hops: vec![addr(1), addr(2), addr(3)],
            epoch: 1,
        };
        let mut e2e_send = seq();
        let packet = encrypt_mesh_end_to_end(
            &route,
            [4; 32],
            1,
            [5; 32],
            &key(6),
            &mut e2e_send,
            11,
            b"private-ip-payload",
        )
        .unwrap();
        assert!(!packet
            .opaque_payload
            .windows(18)
            .any(|w| w == b"private-ip-payload"));

        let first = packet.forward(&route, addr(1)).unwrap();
        let mut hop_send = seq();
        let wrapped = encrypt_mesh_hop(
            &first,
            &route,
            addr(2),
            addr(3),
            [7; 32],
            &key(8),
            &mut hop_send,
            11,
        )
        .unwrap();
        assert!(!wrapped
            .record
            .ciphertext
            .windows(18)
            .any(|w| w == b"private-ip-payload"));

        let mut hop_recv = seq();
        let decoded =
            decrypt_mesh_hop(&wrapped, &route, [7; 32], &key(8), &mut hop_recv, 11).unwrap();
        let destination = decoded.forward(&route, addr(2)).unwrap();
        let mut e2e_recv = seq();
        let plain =
            decrypt_mesh_end_to_end(&destination, &route, &key(6), &mut e2e_recv, 11).unwrap();
        assert_eq!(plain, b"private-ip-payload");
    }

    #[test]
    fn relay_can_validate_without_knowing_packet_before_decrypt() {
        let route = MeshRoute {
            source: addr(1),
            destination: addr(3),
            hops: vec![addr(1), addr(2), addr(3)],
            epoch: 1,
        };
        let packet = MeshPacket::new(&route, [4; 32], 1, [5; 32], vec![9; 64])
            .unwrap()
            .forward(&route, addr(1))
            .unwrap();
        let mut send = seq();
        let wrapped = encrypt_mesh_hop(
            &packet,
            &route,
            addr(2),
            addr(3),
            [7; 32],
            &key(8),
            &mut send,
            11,
        )
        .unwrap();
        let mut recv = seq();
        let decoded = decrypt_mesh_hop(&wrapped, &route, [7; 32], &key(8), &mut recv, 11).unwrap();
        assert_eq!(decoded, packet);
    }

    #[test]
    fn wrong_hop_key_or_header_tamper_cannot_decrypt() {
        let route = MeshRoute {
            source: addr(1),
            destination: addr(3),
            hops: vec![addr(1), addr(2), addr(3)],
            epoch: 1,
        };
        let packet = MeshPacket::new(&route, [4; 32], 1, [5; 32], vec![9; 64])
            .unwrap()
            .forward(&route, addr(1))
            .unwrap();
        let mut send = seq();
        let wrapped = encrypt_mesh_hop(
            &packet,
            &route,
            addr(2),
            addr(3),
            [7; 32],
            &key(8),
            &mut send,
            11,
        )
        .unwrap();

        let mut recv = seq();
        assert!(decrypt_mesh_hop(&wrapped, &route, [7; 32], &key(99), &mut recv, 11).is_none());

        let mut tampered = wrapped;
        tampered.header.packet_root[0] ^= 1;
        let mut recv = seq();
        assert!(decrypt_mesh_hop(&tampered, &route, [7; 32], &key(8), &mut recv, 11).is_none());
    }
}
