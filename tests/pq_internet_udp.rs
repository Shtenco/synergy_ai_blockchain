//! Phase 1 socket proof: `SYD1` datagrams cross a real UDP loopback,
//! are ACKed, and clear the sender retransmit queue.

use std::net::UdpSocket;
use std::time::Duration;
use synergy_pq_evm_core::datagram::{DatagramFrame, RetransmitQueue};

#[test]
fn datagram_crosses_udp_loopback_and_acks() {
    let rx = UdpSocket::bind("127.0.0.1:0").expect("bind rx");
    let tx = UdpSocket::bind("127.0.0.1:0").expect("bind tx");
    rx.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    let rx_addr = rx.local_addr().expect("addr");

    let session_root = [42; 32];
    let mut queue = RetransmitQueue::new(200, 8);
    let seq = queue.alloc_seq(0, 5).expect("alloc");

    let frame = DatagramFrame {
        session_root,
        seq,
        ack_seq: 0,
        ack_bits: 0,
        payload: vec![10, 20, 30, 40, 50],
    };
    let bytes = frame.encode().expect("encode");
    tx.send_to(&bytes, rx_addr).expect("send");

    let mut buf = vec![0u8; 2048];
    let (n, _) = rx.recv_from(&mut buf).expect("recv");
    let got = DatagramFrame::decode(&buf[..n]).expect("decode");
    assert_eq!(got, frame);

    // Receiver ACKs cumulatively; sender queue drains.
    let acked = queue.on_ack(got.seq, 0);
    assert_eq!(acked, 1);
    assert_eq!(queue.inflight_count(), 0);
}
