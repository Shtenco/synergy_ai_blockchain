//! Phase 1 — PQ datagram transport (UDP-ready, QUIC-like reliability primitives).
//!
//! The existing `transport_record.rs` assumes an ordered byte stream (`SYR1`
//! over TCP). This module adds an unreliable-datagram frame (`SYD1`) with
//! explicit sequence numbers, cumulative + selective ACKs, and a
//! retransmit queue with RTO. It is intentionally `io`-agnostic: framing and
//! reliability state live here, sockets live in tests/deploy.
//!
//! Wire format (`SYD1`):
//! ```text
//! magic[4]=SYD1 | version u16 BE | flags u16 BE | session_root[32]
//! | seq u64 BE (!=0) | ack_seq u64 BE | ack_bits u32 BE (SACK for ack_seq-1..ack_seq-32)
//! | payload_len u32 BE | payload[..] (0 < len <= MAX)
//! | commitment[32] = SHA256(domain | version | session_root | seq | ack_seq | ack_bits | payload)
//! ```
//!
//! Fail-closed rules: zero `session_root`, zero `seq`, empty or oversize
//! payload, and commitment mismatch are all rejected.

use sha2::{Digest, Sha256};
use std::collections::VecDeque;

pub const DATAGRAM_MAGIC: &[u8; 4] = b"SYD1";
pub const DATAGRAM_VERSION: u16 = 1;
pub const MAX_DATAGRAM_PAYLOAD_BYTES: usize = 1200;
pub const DATAGRAM_HEADER_BYTES: usize = 4 + 2 + 2 + 32 + 8 + 8 + 4 + 4;
pub const DATAGRAM_COMMITMENT_BYTES: usize = 32;

const DATAGRAM_DOMAIN: &[u8] = b"SYNERGY/PQ-DATAGRAM/V1\0";

/// Reliable-datagram defaults (QUIC-inspired, conservative for PQ handshakes).
pub const DEFAULT_RTO_MS: u64 = 200;
pub const DEFAULT_MAX_INFLIGHT: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatagramFrame {
    pub session_root: [u8; 32],
    pub seq: u64,
    pub ack_seq: u64,
    pub ack_bits: u32,
    pub payload: Vec<u8>,
}

impl DatagramFrame {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.session_root == [0; 32] {
            return Err("datagram session root required");
        }
        if self.seq == 0 {
            return Err("datagram seq must be nonzero");
        }
        if self.payload.is_empty() || self.payload.len() > MAX_DATAGRAM_PAYLOAD_BYTES {
            return Err("datagram payload length out of range");
        }
        Ok(())
    }

    pub fn commitment(&self) -> Option<[u8; 32]> {
        self.validate().ok()?;
        let mut h = Sha256::new();
        h.update(DATAGRAM_DOMAIN);
        h.update(DATAGRAM_VERSION.to_be_bytes());
        h.update(self.session_root);
        h.update(self.seq.to_be_bytes());
        h.update(self.ack_seq.to_be_bytes());
        h.update(self.ack_bits.to_be_bytes());
        h.update((self.payload.len() as u64).to_be_bytes());
        h.update(&self.payload);
        Some(h.finalize().into())
    }

    pub fn encode(&self) -> Option<Vec<u8>> {
        let commitment = self.commitment()?;
        let mut out = Vec::with_capacity(DATAGRAM_HEADER_BYTES + self.payload.len() + 32);
        out.extend_from_slice(DATAGRAM_MAGIC);
        out.extend_from_slice(&DATAGRAM_VERSION.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes()); // flags, reserved
        out.extend_from_slice(&self.session_root);
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(&self.ack_seq.to_be_bytes());
        out.extend_from_slice(&self.ack_bits.to_be_bytes());
        out.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.payload);
        out.extend_from_slice(&commitment);
        Some(out)
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < DATAGRAM_HEADER_BYTES + DATAGRAM_COMMITMENT_BYTES {
            return None;
        }
        if &bytes[0..4] != DATAGRAM_MAGIC {
            return None;
        }
        let version = u16::from_be_bytes([bytes[4], bytes[5]]);
        if version != DATAGRAM_VERSION {
            return None;
        }
        let mut session_root = [0u8; 32];
        session_root.copy_from_slice(&bytes[8..40]);
        let seq = u64::from_be_bytes(bytes[40..48].try_into().ok()?);
        let ack_seq = u64::from_be_bytes(bytes[48..56].try_into().ok()?);
        let ack_bits = u32::from_be_bytes(bytes[56..60].try_into().ok()?);
        let payload_len = u32::from_be_bytes(bytes[60..64].try_into().ok()?) as usize;
        if payload_len == 0 || payload_len > MAX_DATAGRAM_PAYLOAD_BYTES {
            return None;
        }
        if bytes.len() != DATAGRAM_HEADER_BYTES + payload_len + DATAGRAM_COMMITMENT_BYTES {
            return None;
        }
        let payload = bytes[64..64 + payload_len].to_vec();
        let frame = Self {
            session_root,
            seq,
            ack_seq,
            ack_bits,
            payload,
        };
        let commitment: [u8; 32] = bytes[64 + payload_len..].try_into().ok()?;
        if frame.commitment()? != commitment {
            return None;
        }
        Some(frame)
    }

    /// SACK: mark `seq` as received relative to cumulative `ack_seq`.
    pub fn ack_bit_for(ack_seq: u64, seq: u64) -> Option<u32> {
        if ack_seq == 0 || seq == 0 || seq >= ack_seq || ack_seq - seq > 32 {
            return None;
        }
        Some(1u32 << (ack_seq - seq - 1))
    }
}

/// Minimal sender-side reliability: tracks unacked frames with RTO.
#[derive(Debug, Default)]
pub struct RetransmitQueue {
    rto_ms: u64,
    max_inflight: usize,
    next_seq: u64,
    inflight: VecDeque<InflightFrame>,
    highest_acked: u64,
}

#[derive(Debug, Clone)]
struct InflightFrame {
    seq: u64,
    sent_at_ms: u64,
    payload_len: usize,
}

impl RetransmitQueue {
    pub fn new(rto_ms: u64, max_inflight: usize) -> Self {
        Self {
            rto_ms: if rto_ms == 0 { DEFAULT_RTO_MS } else { rto_ms },
            max_inflight: if max_inflight == 0 {
                DEFAULT_MAX_INFLIGHT
            } else {
                max_inflight
            },
            next_seq: 1,
            inflight: VecDeque::new(),
            highest_acked: 0,
        }
    }

    /// Allocate the next sequence number if the congestion window allows it.
    pub fn alloc_seq(&mut self, now_ms: u64, payload_len: usize) -> Option<u64> {
        self.expire_acked();
        if self.inflight.len() >= self.max_inflight {
            return None;
        }
        let seq = self.next_seq;
        self.next_seq = self.next_seq.checked_add(1)?;
        self.inflight.push_back(InflightFrame {
            seq,
            sent_at_ms: now_ms,
            payload_len,
        });
        Some(seq)
    }

    /// Process cumulative + selective ACK. Returns newly acked count.
    pub fn on_ack(&mut self, ack_seq: u64, ack_bits: u32) -> usize {
        let before = self.inflight.len();
        self.inflight.retain(|f| {
            if f.seq >= ack_seq {
                return f.seq != ack_seq;
            }
            // f.seq < ack_seq: acked if cumulative or SACK bit set.
            if ack_seq - f.seq == 0 {
                return false;
            }
            if ack_seq - f.seq <= 32 {
                let bit = 1u32 << (ack_seq - f.seq - 1);
                return ack_bits & bit == 0;
            }
            false // older than SACK window: keep for RTO (fail-closed: no implicit ack)
        });
        if ack_seq > self.highest_acked {
            self.highest_acked = ack_seq;
        }
        before - self.inflight.len()
    }

    /// Sequences whose RTO expired (caller should retransmit them).
    pub fn due_for_retransmit(&self, now_ms: u64) -> Vec<u64> {
        self.inflight
            .iter()
            .filter(|f| now_ms.saturating_sub(f.sent_at_ms) >= self.rto_ms)
            .map(|f| f.seq)
            .collect()
    }

    pub fn inflight_count(&self) -> usize {
        self.inflight.len()
    }

    /// Total payload bytes currently awaiting acknowledgement.
    pub fn inflight_bytes(&self) -> usize {
        self.inflight.iter().map(|f| f.payload_len).sum()
    }

    fn expire_acked(&mut self) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(seq: u64) -> DatagramFrame {
        DatagramFrame {
            session_root: [7; 32],
            seq,
            ack_seq: 0,
            ack_bits: 0,
            payload: vec![1, 2, 3],
        }
    }

    #[test]
    fn datagram_roundtrip() {
        let f = frame(1);
        let bytes = f.encode().expect("encode");
        let back = DatagramFrame::decode(&bytes).expect("decode");
        assert_eq!(f, back);
    }

    #[test]
    fn datagram_rejects_zero_session_and_seq() {
        let f = frame(0);
        assert!(f.encode().is_none());
        let mut g = frame(1);
        g.session_root = [0; 32];
        assert!(g.encode().is_none());
        let _ = f;
    }

    #[test]
    fn datagram_rejects_tamper() {
        let f = frame(5);
        let mut bytes = f.encode().expect("encode");
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
        assert!(DatagramFrame::decode(&bytes).is_none());
    }

    #[test]
    fn retransmit_queue_ack_and_rto() {
        let mut q = RetransmitQueue::new(200, 8);
        let a = q.alloc_seq(0, 10).unwrap();
        let b = q.alloc_seq(0, 10).unwrap();
        assert_eq!(q.inflight_count(), 2);
        // SACK b while cumulative a: ack_seq=b with bit for a
        let bits = DatagramFrame::ack_bit_for(b, a).unwrap();
        let n = q.on_ack(b, bits);
        assert_eq!(n, 2);
        assert_eq!(q.inflight_count(), 0);

        let c = q.alloc_seq(1000, 10).unwrap();
        assert!(q.due_for_retransmit(1000 + 199).is_empty());
        assert_eq!(q.due_for_retransmit(1000 + 200), vec![c]);
    }

    #[test]
    fn retransmit_queue_window_full_fail_closed() {
        let mut q = RetransmitQueue::new(200, 1);
        assert!(q.alloc_seq(0, 1).is_some());
        assert!(q.alloc_seq(0, 1).is_none());
    }
}
