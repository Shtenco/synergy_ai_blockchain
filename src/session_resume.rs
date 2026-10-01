//! Phase 1 — PQ session resumption with 0-RTT early data (replay-safe).
//!
//! Full `ML-KEM-1024` handshakes are expensive. A server that already
//! authenticated a peer may issue a resumption ticket bound to the original
//! transcript. The client presents it on reconnect; both sides derive the
//! same resumption root and a 0-RTT exporter without new KEM operations.
//!
//! Fail-closed rules: tickets are single-use per session (replay guard),
//! bound to `network_id + transcript_hash`, and expire via `expires_at`.
//! 0-RTT data MUST be idempotent — the ticket does not carry fresh forward
//! secrecy; a full handshake refreshes the session afterwards.

use sha2::{Digest, Sha256};
use std::collections::HashSet;

pub const RESUMPTION_DOMAIN: &[u8] = b"SYNERGY/PQ-SESSION-RESUME/V1\0";
pub const RESUMPTION_EARLY_DOMAIN: &[u8] = b"SYNERGY/PQ-SESSION-RESUME/0RTT\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResumptionTicket {
    pub network_id: [u8; 32],
    pub epoch: u64,
    pub session_id: [u8; 32],
    pub transcript_hash: [u8; 32],
    pub ticket_id: [u8; 32],
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

impl ResumptionTicket {
    pub fn validate(&self, now_ms: u64) -> Result<(), &'static str> {
        if self.network_id == [0; 32] {
            return Err("resumption network id required");
        }
        if self.epoch == 0 {
            return Err("resumption epoch required");
        }
        if self.session_id == [0; 32]
            || self.transcript_hash == [0; 32]
            || self.ticket_id == [0; 32]
        {
            return Err("resumption commitments required");
        }
        if self.expires_at_ms <= self.issued_at_ms {
            return Err("resumption expiry must be after issuance");
        }
        if now_ms > self.expires_at_ms {
            return Err("resumption ticket expired");
        }
        Ok(())
    }

    /// Deterministic ticket root both sides recompute (no bearer-secret
    /// confusion: the ticket is an opaque handle, the root is the key).
    pub fn ticket_root(&self) -> Option<[u8; 32]> {
        self.validate(self.issued_at_ms).ok()?;
        let mut h = Sha256::new();
        h.update(RESUMPTION_DOMAIN);
        h.update(crate::pq::CRYPTO_PROFILE_VERSION.to_be_bytes());
        h.update(self.network_id);
        h.update(self.epoch.to_be_bytes());
        h.update(self.session_id);
        h.update(self.transcript_hash);
        h.update(self.ticket_id);
        h.update(self.issued_at_ms.to_be_bytes());
        h.update(self.expires_at_ms.to_be_bytes());
        Some(h.finalize().into())
    }

    /// 0-RTT exporter bound to ticket + transcript. Same on both sides.
    pub fn early_exporter(&self, context: &[u8]) -> Option<[u8; 32]> {
        let root = self.ticket_root()?;
        if context.is_empty() || context.len() > 1024 {
            return None;
        }
        let mut h = Sha256::new();
        h.update(RESUMPTION_EARLY_DOMAIN);
        h.update(root);
        h.update(self.transcript_hash);
        h.update((context.len() as u64).to_be_bytes());
        h.update(context);
        Some(h.finalize().into())
    }
}

/// Single-use replay guard per server: `(ticket_id, session_id)` consumed once.
#[derive(Debug, Default)]
pub struct ResumptionReplayGuard {
    consumed: HashSet<([u8; 32], [u8; 32])>,
    max_entries: usize,
}

impl ResumptionReplayGuard {
    pub fn new(max_entries: usize) -> Self {
        Self {
            consumed: HashSet::new(),
            max_entries: if max_entries == 0 { 4096 } else { max_entries },
        }
    }

    pub fn consume(&mut self, ticket: &ResumptionTicket, now_ms: u64) -> Result<(), &'static str> {
        ticket.validate(now_ms)?;
        let key = (ticket.ticket_id, ticket.session_id);
        if self.consumed.contains(&key) {
            return Err("resumption ticket replayed");
        }
        if self.consumed.len() >= self.max_entries {
            return Err("resumption replay guard full (fail-closed)");
        }
        self.consumed.insert(key);
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.consumed.len()
    }

    pub fn is_empty(&self) -> bool {
        self.consumed.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ticket() -> ResumptionTicket {
        ResumptionTicket {
            network_id: [3; 32],
            epoch: 9,
            session_id: [4; 32],
            transcript_hash: [5; 32],
            ticket_id: [6; 32],
            issued_at_ms: 1000,
            expires_at_ms: 2000,
        }
    }

    #[test]
    fn resumption_roundtrip_and_early_exporter_stable() {
        let t = ticket();
        let r1 = t.ticket_root().expect("root");
        let r2 = t.ticket_root().expect("root");
        assert_eq!(r1, r2);
        let e1 = t.early_exporter(b"stage-rpc").expect("early");
        let e2 = t.early_exporter(b"stage-rpc").expect("early");
        assert_eq!(e1, e2);
        assert_ne!(e1, r1);
    }

    #[test]
    fn resumption_rejects_expiry_and_replay() {
        let t = ticket();
        assert!(t.validate(3000).is_err());
        let mut g = ResumptionReplayGuard::new(8);
        assert!(g.consume(&t, 1500).is_ok());
        assert!(g.consume(&t, 1500).is_err());
    }

    #[test]
    fn resumption_ticket_bound_to_transcript() {
        let a = ticket();
        let mut b = ticket();
        b.transcript_hash = [9; 32];
        assert_ne!(a.ticket_root(), b.ticket_root());
        let _ = a;
    }
}
