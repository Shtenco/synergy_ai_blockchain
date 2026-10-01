//! Phase 3 — Double-ratchet messaging over PQ session secrets.
//!
//! Each mesh flow gets a symmetric chain ratchet (`HKDF-SHA256`) for per-
//! message forward secrecy, plus a PQ rekey hook: whenever the transport
//! completes a fresh `ML-KEM-1024` exchange, its 32-byte shared secret is
//! mixed into the chain (post-compromise security). Out-of-order messages
//! are tolerated within a small window via skipped-key storage.
//!
//! KDF labels are domain-separated; chain/message keys are 32 bytes and
//! feed the existing `ChaCha20-Poly1305` record layer.

use hkdf::Hkdf;
use sha2::Sha256;
use std::collections::HashMap;

pub const RATCHET_DOMAIN: &[u8] = b"SYNERGY/PQ-RATCHET/V1\0";
pub const MAX_SKIPPED_KEYS: usize = 16;

fn hkdf_expand(salt: &[u8; 32], ikm: &[u8; 32], info: &[u8], out_len: usize) -> Option<Vec<u8>> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut out = vec![0u8; out_len];
    hk.expand(info, &mut out).ok()?;
    Some(out)
}

fn chain_step(chain_key: &[u8; 32], label: &[u8]) -> Option<([u8; 32], [u8; 32])> {
    let mut info = Vec::with_capacity(RATCHET_DOMAIN.len() + label.len() + 32);
    info.extend_from_slice(RATCHET_DOMAIN);
    info.extend_from_slice(label);
    info.extend_from_slice(&crate::pq::CRYPTO_PROFILE_VERSION.to_be_bytes());
    let salt = [0u8; 32];
    let bytes = hkdf_expand(&salt, chain_key, &info, 64)?;
    let mut next = [0u8; 32];
    let mut msg = [0u8; 32];
    next.copy_from_slice(&bytes[0..32]);
    msg.copy_from_slice(&bytes[32..64]);
    Some((next, msg))
}

#[derive(Debug, Clone)]
pub struct RatchetState {
    chain_key: [u8; 32],
    send_seq: u64,
    recv_seq: u64,
    skipped: HashMap<u64, [u8; 32]>,
}

impl RatchetState {
    pub fn new(chain_key: [u8; 32]) -> Result<Self, &'static str> {
        if chain_key == [0; 32] {
            return Err("ratchet chain key required");
        }
        Ok(Self {
            chain_key,
            send_seq: 0,
            recv_seq: 0,
            skipped: HashMap::new(),
        })
    }

    /// Sender side: ratchet forward, return `(seq, message_key)`.
    pub fn send_ratchet(&mut self) -> Option<(u64, [u8; 32])> {
        let (next, msg) = chain_step(&self.chain_key, b"send-step")?;
        self.chain_key = next;
        self.send_seq = self.send_seq.checked_add(1)?;
        Some((self.send_seq, msg))
    }

    /// Receiver side: accept `seq` (in-order or skipped-window replay-safe).
    /// Returns the message key for that sequence.
    pub fn recv_ratchet(&mut self, seq: u64) -> Option<[u8; 32]> {
        if seq == 0 {
            return None;
        }
        // Late arrival of a previously skipped sequence: consume stored key.
        if let Some(key) = self.skipped.remove(&seq) {
            return Some(key);
        }
        if seq <= self.recv_seq {
            // Duplicate of an already-consumed key: reject (fail-closed).
            return None;
        }
        // Ratchet forward, storing skipped intermediates.
        while self.recv_seq < seq {
            let (next, msg) = chain_step(&self.chain_key, b"send-step")?;
            self.chain_key = next;
            self.recv_seq += 1;
            if self.recv_seq < seq {
                if self.skipped.len() >= MAX_SKIPPED_KEYS {
                    return None; // window exceeded: fail-closed, needs PQ rekey
                }
                self.skipped.insert(self.recv_seq, msg);
            } else {
                return Some(msg);
            }
        }
        None
    }

    /// Mix a fresh PQ shared secret (e.g. new ML-KEM exchange) into the chain.
    pub fn pq_rekey(&mut self, fresh_shared_secret: &[u8; 32]) -> Option<()> {
        if fresh_shared_secret == &[0; 32] {
            return None;
        }
        let mut info = Vec::with_capacity(RATCHET_DOMAIN.len() + 16);
        info.extend_from_slice(RATCHET_DOMAIN);
        info.extend_from_slice(b"pq-rekey");
        info.extend_from_slice(&crate::pq::CRYPTO_PROFILE_VERSION.to_be_bytes());
        let bytes = hkdf_expand(
            &self.chain_key,
            fresh_shared_secret,
            &info,
            32,
        )?;
        self.chain_key.copy_from_slice(&bytes);
        self.skipped.clear();
        Some(())
    }

    pub fn send_seq(&self) -> u64 {
        self.send_seq
    }

    pub fn recv_seq(&self) -> u64 {
        self.recv_seq
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ratchet_send_recv_in_order() {
        let mut a = RatchetState::new([5; 32]).unwrap();
        let mut b = RatchetState::new([5; 32]).unwrap();
        for _ in 0..4 {
            let (seq, k1) = a.send_ratchet().unwrap();
            let k2 = b.recv_ratchet(seq).unwrap();
            assert_eq!(k1, k2);
        }
        assert_eq!(a.send_seq(), 4);
        assert_eq!(b.recv_seq(), 4);
    }

    #[test]
    fn ratchet_out_of_order_within_window() {
        let mut a = RatchetState::new([8; 32]).unwrap();
        let mut b = RatchetState::new([8; 32]).unwrap();
        let mut keys = Vec::new();
        for _ in 0..3 {
            keys.push(a.send_ratchet().unwrap());
        }
        // Deliver 3,1,2 — 3 arrives first, 1..2 recovered from skipped store.
        let k3 = b.recv_ratchet(keys[2].0).unwrap();
        assert_eq!(k3, keys[2].1);
        let k1 = b.recv_ratchet(keys[0].0).unwrap();
        assert_eq!(k1, keys[0].1);
        let k2 = b.recv_ratchet(keys[1].0).unwrap();
        assert_eq!(k2, keys[1].1);
        // Re-delivery of a consumed key is rejected (fail-closed).
        assert!(b.recv_ratchet(keys[0].0).is_none());
    }

    #[test]
    fn ratchet_pq_rekey_changes_stream_and_rejects_zero() {
        let mut a = RatchetState::new([5; 32]).unwrap();
        let (_, before) = a.send_ratchet().unwrap();
        a.pq_rekey(&[9; 32]).unwrap();
        let (_, after) = a.send_ratchet().unwrap();
        assert_ne!(before, after);
        assert!(a.pq_rekey(&[0; 32]).is_none());
        assert!(RatchetState::new([0; 32]).is_err());
    }
}
