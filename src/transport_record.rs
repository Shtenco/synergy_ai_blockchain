//! Authenticated transport records over transcript-bound directional session keys.
//!
//! ML-KEM/authorization establishes the session secret in `network.rs`. This module
//! supplies the missing record cipher: ChaCha20-Poly1305 with deterministic,
//! direction-separated nonces and transcript/application-bound associated data.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use sha2::{Digest, Sha256};

use crate::network::{
    TransportRecordSequence, TransportRole, TransportSessionKey, TRANSPORT_RECORD_NONCE_BYTES,
};

pub const TRANSPORT_RECORD_AAD_DOMAIN: &[u8] = b"SYNERGY/PQ-TRANSPORT-RECORD/V1\0";
pub const MAX_TRANSPORT_RECORD_PLAINTEXT_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedTransportRecord {
    pub nonce: [u8; TRANSPORT_RECORD_NONCE_BYTES],
    pub ciphertext: Vec<u8>,
    pub plaintext_commitment: [u8; 32],
}

fn sender_direction_code(sender: TransportRole) -> u8 {
    match sender {
        TransportRole::Initiator => 1,
        TransportRole::Responder => 2,
    }
}

fn aad(
    session_root: &[u8; 32],
    sender: TransportRole,
    nonce: &[u8; TRANSPORT_RECORD_NONCE_BYTES],
    application_root: &[u8; 32],
) -> Option<Vec<u8>> {
    if session_root == &[0; 32] || application_root == &[0; 32] {
        return None;
    }
    if nonce[0] != 1 || nonce[1] != sender_direction_code(sender) {
        return None;
    }
    let mut aad = Vec::with_capacity(
        TRANSPORT_RECORD_AAD_DOMAIN.len() + 2 + 32 + 1 + TRANSPORT_RECORD_NONCE_BYTES + 32,
    );
    aad.extend_from_slice(TRANSPORT_RECORD_AAD_DOMAIN);
    aad.extend_from_slice(&crate::pq::CRYPTO_PROFILE_VERSION.to_be_bytes());
    aad.extend_from_slice(session_root);
    aad.push(sender.protocol_code());
    aad.extend_from_slice(nonce);
    aad.extend_from_slice(application_root);
    Some(aad)
}

pub fn encrypt_transport_record(
    key: &TransportSessionKey,
    sequence: &mut TransportRecordSequence,
    now: u64,
    session_root: [u8; 32],
    sender: TransportRole,
    application_root: [u8; 32],
    plaintext: &[u8],
) -> Option<EncryptedTransportRecord> {
    if plaintext.is_empty() || plaintext.len() > MAX_TRANSPORT_RECORD_PLAINTEXT_BYTES {
        return None;
    }

    // Do not consume a sequence number if local encryption fails.
    let mut next = *sequence;
    let nonce_bytes = next.next_nonce(now)?;
    let aad = aad(&session_root, sender, &nonce_bytes, &application_root)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key.as_bytes()));
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .ok()?;

    let plaintext_commitment: [u8; 32] = Sha256::digest(plaintext).into();
    *sequence = next;
    Some(EncryptedTransportRecord {
        nonce: nonce_bytes,
        ciphertext,
        plaintext_commitment,
    })
}

pub fn decrypt_transport_record(
    key: &TransportSessionKey,
    sequence: &mut TransportRecordSequence,
    now: u64,
    session_root: [u8; 32],
    sender: TransportRole,
    application_root: [u8; 32],
    record: &EncryptedTransportRecord,
) -> Option<Vec<u8>> {
    if record.ciphertext.is_empty()
        || record.ciphertext.len() > MAX_TRANSPORT_RECORD_PLAINTEXT_BYTES + 16
        || record.plaintext_commitment == [0; 32]
    {
        return None;
    }

    // Derive the exact expected nonce on a clone. A replay, gap, wrong direction,
    // expired rekey window or authentication failure leaves receive state unchanged.
    let mut next = *sequence;
    let expected_nonce = next.next_nonce(now)?;
    if expected_nonce != record.nonce {
        return None;
    }

    let aad = aad(&session_root, sender, &record.nonce, &application_root)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key.as_bytes()));
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&record.nonce),
            Payload {
                msg: &record.ciphertext,
                aad: &aad,
            },
        )
        .ok()?;

    if plaintext.is_empty()
        || plaintext.len() > MAX_TRANSPORT_RECORD_PLAINTEXT_BYTES
        || <[u8; 32]>::from(Sha256::digest(&plaintext)) != record.plaintext_commitment
    {
        return None;
    }

    *sequence = next;
    Some(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::{RekeyPolicy, TransportRecordSequence, TransportSessionKey};

    fn key() -> TransportSessionKey {
        // Tests live in a sibling module and cannot construct the private tuple field.
        // The helper below is exposed crate-private by network.rs.
        crate::network::transport_session_key_from_test_bytes([7; 32])
    }

    #[test]
    fn round_trip_is_authenticated_and_sequence_bound() {
        let key = key();
        let policy = RekeyPolicy {
            max_messages: 4,
            max_seconds: 60,
        };
        let mut send = TransportRecordSequence::new_initiator_to_responder(policy, 10).unwrap();
        let mut recv = TransportRecordSequence::new_initiator_to_responder(policy, 10).unwrap();
        let record = encrypt_transport_record(
            &key,
            &mut send,
            11,
            [1; 32],
            TransportRole::Initiator,
            [2; 32],
            b"secret-stage-payload",
        )
        .unwrap();
        let plain = decrypt_transport_record(
            &key,
            &mut recv,
            11,
            [1; 32],
            TransportRole::Initiator,
            [2; 32],
            &record,
        )
        .unwrap();
        assert_eq!(plain, b"secret-stage-payload");
        assert_eq!(send.next_sequence(), 1);
        assert_eq!(recv.next_sequence(), 1);
    }

    #[test]
    fn replay_and_aad_tamper_fail_without_burning_receive_sequence() {
        let key = key();
        let policy = RekeyPolicy {
            max_messages: 4,
            max_seconds: 60,
        };
        let mut send = TransportRecordSequence::new_initiator_to_responder(policy, 10).unwrap();
        let mut recv = TransportRecordSequence::new_initiator_to_responder(policy, 10).unwrap();
        let record = encrypt_transport_record(
            &key,
            &mut send,
            11,
            [1; 32],
            TransportRole::Initiator,
            [2; 32],
            b"payload",
        )
        .unwrap();

        assert!(decrypt_transport_record(
            &key,
            &mut recv,
            11,
            [1; 32],
            TransportRole::Initiator,
            [9; 32],
            &record
        )
        .is_none());
        assert_eq!(recv.next_sequence(), 0);

        assert!(decrypt_transport_record(
            &key,
            &mut recv,
            11,
            [1; 32],
            TransportRole::Initiator,
            [2; 32],
            &record
        )
        .is_some());
        assert_eq!(recv.next_sequence(), 1);

        assert!(decrypt_transport_record(
            &key,
            &mut recv,
            11,
            [1; 32],
            TransportRole::Initiator,
            [2; 32],
            &record
        )
        .is_none());
        assert_eq!(recv.next_sequence(), 1);
    }
}

pub const TRANSPORT_FRAME_MAGIC: [u8; 4] = *b"SYR1";

#[allow(clippy::too_many_arguments)]
pub fn write_encrypted_transport_frame<W: std::io::Write>(
    writer: &mut W,
    key: &TransportSessionKey,
    sequence: &mut TransportRecordSequence,
    now: u64,
    session_root: [u8; 32],
    sender: TransportRole,
    application_root: [u8; 32],
    plaintext: &[u8],
) -> std::io::Result<[u8; 32]> {
    let record = encrypt_transport_record(
        key,
        sequence,
        now,
        session_root,
        sender,
        application_root,
        plaintext,
    )
    .ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "transport encryption failed",
        )
    })?;

    let ciphertext_len = u32::try_from(record.ciphertext.len()).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "ciphertext too large")
    })?;

    writer.write_all(&TRANSPORT_FRAME_MAGIC)?;
    writer.write_all(&record.nonce)?;
    writer.write_all(&record.plaintext_commitment)?;
    writer.write_all(&ciphertext_len.to_be_bytes())?;
    writer.write_all(&record.ciphertext)?;
    writer.flush()?;
    Ok(record.plaintext_commitment)
}

pub fn read_encrypted_transport_frame<R: std::io::Read>(
    reader: &mut R,
    key: &TransportSessionKey,
    sequence: &mut TransportRecordSequence,
    now: u64,
    session_root: [u8; 32],
    sender: TransportRole,
    application_root: [u8; 32],
) -> std::io::Result<Vec<u8>> {
    let mut magic = [0u8; 4];
    reader.read_exact(&mut magic)?;
    if magic != TRANSPORT_FRAME_MAGIC {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "transport frame magic mismatch",
        ));
    }

    let mut nonce = [0u8; TRANSPORT_RECORD_NONCE_BYTES];
    reader.read_exact(&mut nonce)?;
    let mut plaintext_commitment = [0u8; 32];
    reader.read_exact(&mut plaintext_commitment)?;
    let mut len_bytes = [0u8; 4];
    reader.read_exact(&mut len_bytes)?;
    let ciphertext_len = u32::from_be_bytes(len_bytes) as usize;
    if ciphertext_len == 0 || ciphertext_len > MAX_TRANSPORT_RECORD_PLAINTEXT_BYTES + 16 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "transport ciphertext length invalid",
        ));
    }

    let mut ciphertext = vec![0u8; ciphertext_len];
    reader.read_exact(&mut ciphertext)?;
    let record = EncryptedTransportRecord {
        nonce,
        ciphertext,
        plaintext_commitment,
    };
    decrypt_transport_record(
        key,
        sequence,
        now,
        session_root,
        sender,
        application_root,
        &record,
    )
    .ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "transport authentication failed",
        )
    })
}

#[cfg(test)]
mod socket_tests {
    use super::*;
    use crate::network::{RekeyPolicy, TransportRecordSequence, TransportRole};
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    #[test]
    fn encrypted_record_crosses_real_tcp_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address");
        let policy = RekeyPolicy {
            max_messages: 8,
            max_seconds: 60,
        };
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let key = crate::network::transport_session_key_from_test_bytes([0x44; 32]);
            let mut recv =
                TransportRecordSequence::new_initiator_to_responder(policy, 100).unwrap();
            let plaintext = read_encrypted_transport_frame(
                &mut stream,
                &key,
                &mut recv,
                101,
                [0x11; 32],
                TransportRole::Initiator,
                [0x22; 32],
            )
            .expect("decrypt frame");
            assert_eq!(plaintext, b"remote-kv-or-activation");
            assert_eq!(recv.next_sequence(), 1);
        });

        let mut stream = TcpStream::connect(address).expect("connect");
        let key = crate::network::transport_session_key_from_test_bytes([0x44; 32]);
        let mut send = TransportRecordSequence::new_initiator_to_responder(policy, 100).unwrap();
        write_encrypted_transport_frame(
            &mut stream,
            &key,
            &mut send,
            101,
            [0x11; 32],
            TransportRole::Initiator,
            [0x22; 32],
            b"remote-kv-or-activation",
        )
        .expect("encrypt frame");
        assert_eq!(send.next_sequence(), 1);
        server.join().expect("server");
    }
}
