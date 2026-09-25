use std::time::Instant;
use synergy_pq_evm_core::{AgenticEconomyState, Asset};

fn rate(n: u64, secs: f64) -> f64 {
    n as f64 / secs
}

fn main() {
    let n: u64 = std::env::var("TPS_N")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1_000_000);

    let mut s = AgenticEconomyState::genesis(10_000).expect("genesis");
    let t = Instant::now();
    for i in 0..n {
        let from = (i as usize) % 6;
        let to = (from + 1) % 6;
        s.transfer(from, to, Asset::Usdc, 1).expect("transfer");
    }
    let transfer_secs = t.elapsed().as_secs_f64();
    let transfer_commitment = s.commitment();

    let mut a = AgenticEconomyState::genesis(10_000).expect("genesis");
    let safe_actions: [u8; 29] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 25, 26, 27,
        28, 29, 30, 31,
    ];
    let t2 = Instant::now();
    for i in 0..n {
        let actor = (i as usize) % 6;
        let action = safe_actions[(i as usize) % safe_actions.len()];
        a.apply_consensus_action(actor, action)
            .expect("agent action");
        if i % 10_000 == 0 {
            a.advance_block();
        }
    }
    let agent_secs = t2.elapsed().as_secs_f64();
    let agent_commitment = a.commitment();

    let mut cstate = AgenticEconomyState::genesis(10_000).expect("genesis");
    let t3 = Instant::now();
    let mut rolling = [0u8; 32];
    for i in 0..n {
        let actor = (i as usize) % 6;
        let action = safe_actions[(i as usize) % safe_actions.len()];
        cstate
            .apply_consensus_action(actor, action)
            .expect("committed action");
        rolling = cstate.commitment();
        if i % 10_000 == 0 {
            cstate.advance_block();
        }
    }
    let committed_secs = t3.elapsed().as_secs_f64();

    println!("benchmark=synergy_execution_tps_v1");
    println!("transactions={n}");
    println!("transfer_seconds={transfer_secs:.6}");
    println!("transfer_tps={:.2}", rate(n, transfer_secs));
    println!("agent_action_seconds={agent_secs:.6}");
    println!("agent_action_tps={:.2}", rate(n, agent_secs));
    println!("committed_action_seconds={committed_secs:.6}");
    println!("committed_action_tps={:.2}", rate(n, committed_secs));
    println!("committed_rolling={}", hex::encode(rolling));
    println!("transfer_commitment={}", hex::encode(transfer_commitment));
    println!("agent_commitment={}", hex::encode(agent_commitment));
}
