use sha2::{Digest, Sha256};

use crate::mesh_overlay::{mesh_flow_root, MeshAddress, MeshPacket, MeshRoute};
use crate::network::{TransportRecordSequence, TransportRole, TransportSessionKey};
use crate::transport_record::{
    decrypt_transport_record, encrypt_transport_record, EncryptedTransportRecord,
};

pub const MESH_E2E_APPLICATION_DOMAIN: &[u8] = b"SYNERGY/PQ-MESH/E2E-APPLICATION/V1\0";
pub const MESH_HOP_HEADER_DOMAIN: &[u8] = b"SYNERGY/PQ-MESH/HOP-HEADER/V1\0";
pub const MESH_HOP_FRAME_MAGIC: [u8; 4] = *b"SYM1";
pub const MAX_MESH_HOP_FRAME_BYTES: usize = crate::mesh_overlay::MAX_MESH_PACKET_BYTES + 1024;

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

#[allow(clippy::too_many_arguments)]
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

pub fn encode_mesh_hop(wrapped: &EncryptedMeshHop) -> Option<Vec<u8>> {
    let record = encode_record(&wrapped.record)?;
    let record_len = u32::try_from(record.len()).ok()?;
    let mut out = Vec::with_capacity(128 + 4 + record.len());
    out.extend_from_slice(&wrapped.header.packet_root);
    out.extend_from_slice(&wrapped.header.route_root);
    out.extend_from_slice(&wrapped.header.current.0);
    out.extend_from_slice(&wrapped.header.next.0);
    out.extend_from_slice(&record_len.to_be_bytes());
    out.extend_from_slice(&record);
    Some(out)
}

pub fn decode_mesh_hop(bytes: &[u8]) -> Option<EncryptedMeshHop> {
    if bytes.len() < 132 || bytes.len() > MAX_MESH_HOP_FRAME_BYTES {
        return None;
    }
    let packet_root = bytes[0..32].try_into().ok()?;
    let route_root = bytes[32..64].try_into().ok()?;
    let current = MeshAddress(bytes[64..96].try_into().ok()?);
    let next = MeshAddress(bytes[96..128].try_into().ok()?);
    let len = u32::from_be_bytes(bytes[128..132].try_into().ok()?) as usize;
    if len == 0 || bytes.len() != 132 + len {
        return None;
    }
    Some(EncryptedMeshHop {
        header: MeshHopHeader {
            packet_root,
            route_root,
            current,
            next,
        },
        record: decode_record(&bytes[132..])?,
    })
}

pub fn write_mesh_hop_frame<W: std::io::Write>(
    writer: &mut W,
    wrapped: &EncryptedMeshHop,
) -> std::io::Result<()> {
    let body = encode_mesh_hop(wrapped).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "mesh hop encoding failed")
    })?;
    let len = u32::try_from(body.len())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "mesh hop too large"))?;
    writer.write_all(&MESH_HOP_FRAME_MAGIC)?;
    writer.write_all(&len.to_be_bytes())?;
    writer.write_all(&body)?;
    writer.flush()
}

pub fn read_mesh_hop_frame<R: std::io::Read>(reader: &mut R) -> std::io::Result<EncryptedMeshHop> {
    let mut magic = [0u8; 4];
    reader.read_exact(&mut magic)?;
    if magic != MESH_HOP_FRAME_MAGIC {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "mesh hop frame magic mismatch",
        ));
    }
    let mut len_bytes = [0u8; 4];
    reader.read_exact(&mut len_bytes)?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    if len == 0 || len > MAX_MESH_HOP_FRAME_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "mesh hop frame length invalid",
        ));
    }
    let mut body = vec![0u8; len];
    reader.read_exact(&mut body)?;
    decode_mesh_hop(&body).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "mesh hop decoding failed")
    })
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
    fn three_node_tcp_relay_keeps_payload_end_to_end_private() {
        use std::net::{TcpListener, TcpStream};
        use std::thread;

        let route = MeshRoute {
            source: addr(1),
            destination: addr(3),
            hops: vec![addr(1), addr(2), addr(3)],
            epoch: 1,
        };

        let destination_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let destination_addr = destination_listener.local_addr().unwrap();
        let route_c = route.clone();
        let destination = thread::spawn(move || {
            let (mut stream, _) = destination_listener.accept().unwrap();
            let wrapped = read_mesh_hop_frame(&mut stream).unwrap();
            let mut hop_recv = seq();
            let packet_at_b =
                decrypt_mesh_hop(&wrapped, &route_c, [22; 32], &key(23), &mut hop_recv, 11)
                    .unwrap();
            let packet_at_c = packet_at_b.forward(&route_c, addr(2)).unwrap();
            let mut e2e_recv = seq();
            decrypt_mesh_end_to_end(&packet_at_c, &route_c, &key(6), &mut e2e_recv, 11).unwrap()
        });

        let relay_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let relay_addr = relay_listener.local_addr().unwrap();
        let route_b = route.clone();
        let relay = thread::spawn(move || {
            let (mut inbound, _) = relay_listener.accept().unwrap();
            let wrapped_ab = read_mesh_hop_frame(&mut inbound).unwrap();
            let mut recv_ab = seq();
            let packet_at_a =
                decrypt_mesh_hop(&wrapped_ab, &route_b, [12; 32], &key(13), &mut recv_ab, 11)
                    .unwrap();

            assert!(!packet_at_a
                .opaque_payload
                .windows(18)
                .any(|w| w == b"private-ip-payload"));

            let packet_at_b = packet_at_a.forward(&route_b, addr(1)).unwrap();
            let mut send_bc = seq();
            let wrapped_bc = encrypt_mesh_hop(
                &packet_at_b,
                &route_b,
                addr(2),
                addr(3),
                [22; 32],
                &key(23),
                &mut send_bc,
                11,
            )
            .unwrap();
            let mut outbound = TcpStream::connect(destination_addr).unwrap();
            write_mesh_hop_frame(&mut outbound, &wrapped_bc).unwrap();
        });

        let mut e2e_send = seq();
        let packet_at_a = encrypt_mesh_end_to_end(
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
        let mut send_ab = seq();
        let wrapped_ab = encrypt_mesh_hop(
            &packet_at_a,
            &route,
            addr(1),
            addr(2),
            [12; 32],
            &key(13),
            &mut send_ab,
            11,
        )
        .unwrap();

        let mut stream = TcpStream::connect(relay_addr).unwrap();
        write_mesh_hop_frame(&mut stream, &wrapped_ab).unwrap();

        relay.join().unwrap();
        let plain = destination.join().unwrap();
        assert_eq!(plain, b"private-ip-payload");
    }

    #[cfg(feature = "reference-pq")]
    #[test]
    fn real_ml_kem_derived_key_protects_mesh_payload() {
        use crate::network::{
            derive_directional_transport_session_keys, establish_shared_secret,
            InMemoryTransportReplayGuard, MlKem1024Provider, TransportPeerIdentity,
            TransportPolicy, TransportRole, TransportTranscript, TransportValidationContext,
        };
        use crate::pq_reference::ReferenceMlKem1024Provider;

        let mut provider = ReferenceMlKem1024Provider::new();
        let (_initiator_handle, initiator_public) =
            provider.try_generate_keypair().expect("initiator ML-KEM");
        let (responder_handle, responder_public) =
            provider.try_generate_keypair().expect("responder ML-KEM");

        let (ciphertext, sender_shared) =
            provider.encapsulate(&responder_public).expect("ML-KEM encapsulate");
        let receiver_shared = provider
            .decapsulate(&responder_handle, &ciphertext)
            .expect("ML-KEM decapsulate");

        let rekey = RekeyPolicy {
            max_messages: 100,
            max_seconds: 300,
        };
        let transcript = TransportTranscript {
            network_id: [41; 32],
            epoch: 9,
            session_id: [42; 32],
            initiator: TransportPeerIdentity {
                node_id: [1; 32],
                ml_kem1024_public_key: initiator_public,
                legacy_kex_scheme: None,
                legacy_kex_public_key: vec![],
            },
            responder: TransportPeerIdentity {
                node_id: [3; 32],
                ml_kem1024_public_key: responder_public,
                legacy_kex_scheme: None,
                legacy_kex_public_key: vec![],
            },
            policy: TransportPolicy::PqOnly,
            rekey_policy: rekey,
            ml_kem_recipient: TransportRole::Responder,
            ml_kem_ciphertext: ciphertext,
            classical_transcript_hash: None,
        };
        let validation = TransportValidationContext {
            expected_network_id: [41; 32],
            expected_epoch: 9,
            expected_session_id: [42; 32],
        };
        let mut sender_guard =
            InMemoryTransportReplayGuard::new([41; 32], 9).expect("sender replay");
        let mut receiver_guard =
            InMemoryTransportReplayGuard::new([41; 32], 9).expect("receiver replay");

        let sender_secret = establish_shared_secret(
            &mut sender_guard,
            sender_shared,
            None,
            &transcript,
            &validation,
        )
        .expect("sender shared secret");
        let receiver_secret = establish_shared_secret(
            &mut receiver_guard,
            receiver_shared,
            None,
            &transcript,
            &validation,
        )
        .expect("receiver shared secret");

        let sender_keys =
            derive_directional_transport_session_keys(&sender_secret).expect("sender keys");
        let receiver_keys =
            derive_directional_transport_session_keys(&receiver_secret).expect("receiver keys");
        assert_eq!(
            sender_keys.initiator_to_responder().as_bytes(),
            receiver_keys.initiator_to_responder().as_bytes()
        );

        let route = MeshRoute {
            source: addr(1),
            destination: addr(3),
            hops: vec![addr(1), addr(3)],
            epoch: 9,
        };
        let mut send_seq = TransportRecordSequence::new_initiator_to_responder(rekey, 10).unwrap();
        let packet = encrypt_mesh_end_to_end(
            &route,
            [44; 32],
            1,
            [45; 32],
            sender_keys.initiator_to_responder(),
            &mut send_seq,
            11,
            b"real-ml-kem-mesh-payload",
        )
        .unwrap()
        .forward(&route, addr(1))
        .unwrap();

        let mut recv_seq = TransportRecordSequence::new_initiator_to_responder(rekey, 10).unwrap();
        let plain = decrypt_mesh_end_to_end(
            &packet,
            &route,
            receiver_keys.initiator_to_responder(),
            &mut recv_seq,
            11,
        )
        .unwrap();
        assert_eq!(plain, b"real-ml-kem-mesh-payload");
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
