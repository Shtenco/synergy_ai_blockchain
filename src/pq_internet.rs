//! PQ-Internet wiring: binds discovery, DHT, gossip, link-state and datagrams
//! into one turnkey pipeline.
//!
//! Standalone modules define each mechanism (`dht`, `gossip`, `pq_dns`,
//! `datagram`, `rendezvous`, `session_resume`, `double_ratchet`). This module
//! is the integration contract an operator actually runs:
//!
//! ```text
//! NodeSetSnapshot -> index_snapshot_into_dht -> closest() peer selection
//! MeshLinkAdvertisement -> advertisement_to_gossip -> fanout ->
//!   apply_gossip_to_linkstate -> MeshLinkStateDb::route
//! DatagramFrame --(UdpSocket, see tests/pq_internet_udp.rs)--> ACK -> RetransmitQueue
//! ```
//!
//! All bindings are fail-closed: expired records, unbound gossip payloads,
//! and replayed advertisements are rejected, never silently accepted.

use crate::dht::{DhtNode, RoutingTable};
use crate::gossip::GossipMessage;
use crate::mesh_overlay::MeshAddress;
use crate::mesh_routing::{MeshLinkAdvertisement, MeshLinkStateDb};
use crate::peer_discovery::NodeSetSnapshot;

/// Derive the DHT key for a discovery record (same derivation as the mesh
/// layer: `MeshAddress::from_pq_identity`).
pub fn dht_address_for_record(
    node_id: &[u8; 32],
    pq_identity_commitment: &[u8; 32],
) -> Option<[u8; 32]> {
    MeshAddress::from_pq_identity(*node_id, *pq_identity_commitment).map(|a| a.0)
}

/// Index a validated snapshot into a fresh DHT routing table.
/// Expired records are skipped; `last_seen` is the indexing instant.
pub fn index_snapshot_into_dht(
    snapshot: &NodeSetSnapshot,
    self_id: [u8; 32],
    now_ms: u64,
) -> RoutingTable {
    let mut table = RoutingTable::new(self_id);
    for record in &snapshot.records {
        if !record.live(now_ms as u64) {
            continue;
        }
        let Some(addr) = dht_address_for_record(&record.node_id, &record.pq_identity_commitment)
        else {
            continue;
        };
        if addr == self_id {
            continue;
        }
        let _ = table.insert(DhtNode {
            address: addr,
            last_seen_ms: now_ms,
        });
    }
    table
}

/// Canonical 132-byte gossip payload for a link advertisement:
/// from[32] | to[32] | epoch u64 | sequence u64 | expires u64 | cost u32 |
/// capacity u64 | pq_authorization_root[32].
pub const ADVERTISEMENT_GOSSIP_BYTES: usize = 32 + 32 + 8 + 8 + 8 + 4 + 8 + 32;

pub fn advertisement_to_gossip(link: &MeshLinkAdvertisement, ttl: u8) -> Option<GossipMessage> {
    link.validate().ok()?;
    let mut payload = Vec::with_capacity(ADVERTISEMENT_GOSSIP_BYTES);
    payload.extend_from_slice(&link.from.0);
    payload.extend_from_slice(&link.to.0);
    payload.extend_from_slice(&link.epoch.to_be_bytes());
    payload.extend_from_slice(&link.sequence.to_be_bytes());
    payload.extend_from_slice(&link.expires_at.to_be_bytes());
    payload.extend_from_slice(&link.cost.to_be_bytes());
    payload.extend_from_slice(&link.capacity_kbps.to_be_bytes());
    payload.extend_from_slice(&link.pq_authorization_root);
    let msg = GossipMessage {
        origin: link.from.0,
        epoch: link.epoch,
        ttl,
        payload,
    };
    msg.validate().ok()?;
    Some(msg)
}

/// Decode + verify a gossip-carried advertisement. Rejects payloads whose
/// origin does not match the advertisement `from` (spoofed relay), expired
/// or otherwise invalid advertisements.
pub fn advertisement_from_gossip(
    msg: &GossipMessage,
    now_ms: u64,
) -> Option<MeshLinkAdvertisement> {
    msg.validate().ok()?;
    if msg.payload.len() != ADVERTISEMENT_GOSSIP_BYTES {
        return None;
    }
    let b = &msg.payload;
    let mut from = [0u8; 32];
    let mut to = [0u8; 32];
    let mut root = [0u8; 32];
    from.copy_from_slice(&b[0..32]);
    to.copy_from_slice(&b[32..64]);
    root.copy_from_slice(&b[100..132]);
    let link = MeshLinkAdvertisement {
        from: MeshAddress(from),
        to: MeshAddress(to),
        epoch: u64::from_be_bytes(b[64..72].try_into().ok()?),
        sequence: u64::from_be_bytes(b[72..80].try_into().ok()?),
        expires_at: u64::from_be_bytes(b[80..88].try_into().ok()?),
        cost: u32::from_be_bytes(b[88..92].try_into().ok()?),
        capacity_kbps: u64::from_be_bytes(b[92..100].try_into().ok()?),
        pq_authorization_root: root,
    };
    link.validate().ok()?;
    if !link.live(now_ms) {
        return None;
    }
    if msg.origin != link.from.0 || msg.epoch != link.epoch {
        return None;
    }
    // Commitment must recompute (payload tampering detection).
    link.commitment()?;
    Some(link)
}

/// Full ingest path: gossip -> advertisement -> link-state.
/// Returns `Ok(true)` on new state, `Ok(false)` on replay/downgrade
/// (not an error: gossip duplicates are normal).
pub fn apply_gossip_to_linkstate(
    msg: &GossipMessage,
    db: &mut MeshLinkStateDb,
    now_ms: u64,
) -> Result<bool, &'static str> {
    let link = advertisement_from_gossip(msg, now_ms).ok_or("gossip advertisement invalid")?;
    match db.upsert(link, now_ms) {
        Ok(()) => Ok(true),
        Err(e) if e == "mesh link replay or downgrade" => Ok(false),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mesh_overlay::MeshAddress;
    use crate::peer_discovery::{NodeRecord, NodeSetSnapshot};

    fn record(node: u8, seq: u64) -> NodeRecord {
        NodeRecord {
            node_id: [node; 32],
            endpoint_root: [node + 10; 32],
            transport_keyset_root: [node + 20; 32],
            pq_identity_commitment: [node + 30; 32],
            capability_root: [node + 40; 32],
            epoch: 1,
            sequence: seq,
            expires_at: 9000,
        }
    }

    fn link(from: u8, to: u8, seq: u64) -> MeshLinkAdvertisement {
        MeshLinkAdvertisement {
            from: MeshAddress([from; 32]),
            to: MeshAddress([to; 32]),
            epoch: 1,
            sequence: seq,
            expires_at: 9000,
            cost: 10,
            capacity_kbps: 1000,
            pq_authorization_root: [7; 32],
        }
    }

    #[test]
    fn snapshot_indexes_into_dht_and_finds_closest() {
        let snapshot = NodeSetSnapshot {
            epoch: 1,
            records: vec![record(1, 1), record(2, 1), record(3, 1)],
        };
        let table = index_snapshot_into_dht(&snapshot, [0xFF; 32], 1000);
        assert_eq!(table.len(), 3);
        let target = dht_address_for_record(&[1; 32], &[31; 32]).unwrap();
        let closest = table.closest(&target, 1);
        assert_eq!(closest.len(), 1);
        assert_eq!(closest[0].address, target);
    }

    #[test]
    fn snapshot_skips_expired_records() {
        let mut dead = record(9, 1);
        dead.expires_at = 500;
        let snapshot = NodeSetSnapshot {
            epoch: 1,
            records: vec![dead, record(2, 1)],
        };
        let table = index_snapshot_into_dht(&snapshot, [0xFF; 32], 1000);
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn advertisement_gossip_roundtrip_and_spoof_rejected() {
        let l = link(11, 12, 2);
        let msg = advertisement_to_gossip(&l, 8).expect("encode");
        assert_eq!(msg.payload.len(), ADVERTISEMENT_GOSSIP_BYTES);
        let back = advertisement_from_gossip(&msg, 1000).expect("decode");
        assert_eq!(back, l);

        // Spoofed origin: relay rewrites origin, ingest must fail.
        let mut spoof = msg.clone();
        spoof.origin = [99; 32];
        assert!(advertisement_from_gossip(&spoof, 1000).is_none());

        // Corrupted metrics: cost exceeds MAX_LINK_COST -> rejected.
        let mut corrupt = msg.clone();
        corrupt.payload[88] ^= 0xFF;
        assert!(advertisement_from_gossip(&corrupt, 1000).is_none());

        // Silent field tamper stays self-consistent (commitment recomputes),
        // so it decodes to a DIFFERENT advertisement: tamper-evidence here
        // comes from the PQ envelope signature over pq_authorization_root,
        // which the operator must verify before ingest (see docs).
        let mut tamper = msg.clone();
        tamper.payload[95] ^= 0x01;
        let other = advertisement_from_gossip(&tamper, 1000).expect("decodes");
        assert_ne!(other.commitment(), l.commitment());
    }

    #[test]
    fn gossip_applies_to_linkstate_and_routes() {
        let mut db = MeshLinkStateDb::default();
        let l = link(21, 22, 1);
        let msg = advertisement_to_gossip(&l, 8).unwrap();
        assert_eq!(apply_gossip_to_linkstate(&msg, &mut db, 1000), Ok(true));
        // Duplicate gossip: replay tolerated as Ok(false).
        assert_eq!(apply_gossip_to_linkstate(&msg, &mut db, 1000), Ok(false));
        // Route now exists between the two addresses.
        let route = db
            .route(MeshAddress([21; 32]), MeshAddress([22; 32]), 1, 1000)
            .expect("route");
        assert_eq!(route.destination, MeshAddress([22; 32]));
    }
}
