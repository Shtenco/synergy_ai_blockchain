use std::time::Instant;
use sha2::{Digest, Sha256};
use synergy_pq_evm_core::{
    AgenticEconomyReplayState, AgenticEconomyState, AgenticEconomyTransitionReceipt, Asset,
    EconomyAccountingSnapshot, EconomyDecision,
};

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
        a.apply_benchmark_action(actor, action)
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
            .apply_benchmark_action(actor, action)
            .expect("committed action");
        rolling = cstate.commitment();
        if i % 10_000 == 0 {
            cstate.advance_block();
        }
    }
    let committed_secs = t3.elapsed().as_secs_f64();

    let accounting = EconomyAccountingSnapshot {
        hard_nav_micro: 100_000_000,
        collateral_nav_micro: 120_000_000,
        gross_tvl_micro: 200_000_000,
        net_external_capital_flow_micro: 10_000_000,
        realized_external_pnl_micro: 2_000_000,
        gas_paid_micro: 1_000,
        syna_supply_micro: 72_000_000,
    };
    let mut replay = AgenticEconomyReplayState::genesis([1u8; 32]).expect("replay genesis");
    let t4 = Instant::now();
    let mut receipt_rolling = [0u8; 32];
    for i in 0..n {
        let mut h = Sha256::new();
        h.update(b"SYNERGY/TPS/POST-STATE/V1");
        h.update((i + 1).to_be_bytes());
        let post: [u8; 32] = h.finalize().into();
        let receipt = AgenticEconomyTransitionReceipt {
            chain_id: 777_777,
            sequence: i + 1,
            source_block: i + 1,
            decision: EconomyDecision::Trader {
                actor: (i % 6) as u16,
                action: (i % 32) as u8,
            },
            model_checkpoint_root: [7; 32],
            observation_root: [8; 32],
            pre_state_root: replay.state_root,
            post_state_root: post,
            action_log_root: [9; 32],
            accounting,
        };
        receipt_rolling = replay.consume(&receipt).expect("receipt consume");
    }
    let receipt_secs = t4.elapsed().as_secs_f64();

    println!("benchmark=synergy_execution_tps_v2");
    println!("transactions={n}");
    println!("transfer_seconds={transfer_secs:.6}");
    println!("transfer_tps={:.2}", rate(n, transfer_secs));
    println!("agent_action_seconds={agent_secs:.6}");
    println!("agent_action_tps={:.2}", rate(n, agent_secs));
    println!("committed_action_seconds={committed_secs:.6}");
    println!("committed_action_tps={:.2}", rate(n, committed_secs));
    println!("committed_rolling={}", hex::encode(rolling));
    println!("receipt_seconds={receipt_secs:.6}");
    println!("receipt_tps={:.2}", rate(n, receipt_secs));
    println!("receipt_rolling={}", hex::encode(receipt_rolling));
    println!("transfer_commitment={}", hex::encode(transfer_commitment));
    println!("agent_commitment={}", hex::encode(agent_commitment));
}
