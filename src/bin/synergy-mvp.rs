//! Canonical MVP checkpoint finalization CLI.
//!
//! This binary is the only authoritative way to obtain an `MvpCheckpoint`
//! commitment from a run. It reads a JSON input describing the finalization
//! gate (challenge, verifier receipts, settlement, optional slash) and prints
//! the resulting checkpoint with its SHA-256 commitment.
//!
//! Input JSON shape:
//! ```json
//! {
//!   "input": {
//!     "chain_id": "<hex64>", "epoch": 1, "sequence": 1,
//!     "previous_checkpoint": "<hex64>",
//!     "model_root": "<hex64>", "network_root": "<hex64>",
//!     "provider_root": "<hex64>", "inference_root": "<hex64>",
//!     "verification_root": "<hex64>", "kv_root": "<hex64>",
//!     "storage_root": "<hex64>", "scheduler_root": "<hex64>",
//!     "node_set_root": "<hex64>", "funded_amount": 100
//!   },
//!   "challenge": {
//!     "challenge_id": "<hex64>", "job_id": "<hex64>",
//!     "challenged_output_commitment": "<hex64>",
//!     "sample_seed_commitment": "<hex64>",
//!     "required_replications": 2, "opened_at": 1, "closes_at": 10
//!   },
//!   "receipts": [
//!     {
//!       "challenge_id": "<hex64>", "verifier_id": "<hex64>",
//!       "recomputed_output_commitment": "<hex64>",
//!       "work_commitment": "<hex64>", "trace_commitment": "<hex64>",
//!       "signature_commitment": "<hex64>",
//!       "verdict": "Match" | "Mismatch" | "Inconclusive",
//!       "completed_at": 5
//!     }
//!   ],
//!   "settlement": {
//!     "job_id": "<hex64>", "funding_root": "<hex64>",
//!     "worker_id": "<hex64>", "storage_provider_id": "<hex64>",
//!     "verifier_set_root": "<hex64>",
//!     "worker_reward": 60, "storage_reward": 10,
//!     "verifier_reward": 20, "protocol_fee": 10,
//!     "slash_root": "<hex64>" | null, "refund_amount": 0
//!   },
//!   "slash": {
//!     "slash_id": "<hex64>", "job_id": "<hex64>",
//!     "worker_id": "<hex64>",
//!     "challenged_output_commitment": "<hex64>",
//!     "verification_receipt_root": "<hex64>",
//!     "amount": 25, "epoch": 1, "state": "Open" | "Consumed"
//!   } | null
//! }
//! ```

use std::env;
use std::fs;
use std::process::ExitCode;

use serde::{Deserialize, Serialize};
use serde_json;
use synergy_pq_evm_core::{
    aggregate_verifier_receipts, finalize_mvp_checkpoint, ComputeSettlement, MvpCheckpoint,
    MvpFinalizationInput, SlashState, VerificationChallenge, VerificationVerdict, VerifierReceipt,
    WorkerSlash,
};

// ---------------------------------------------------------------------------
// JSON types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct CliInput {
    input: CliFinalizationInput,
    challenge: CliChallenge,
    receipts: Vec<CliReceipt>,
    settlement: CliSettlement,
    slash: Option<CliSlash>,
}

#[derive(Debug, Deserialize)]
struct CliFinalizationInput {
    chain_id: Hex64,
    epoch: u64,
    sequence: u64,
    previous_checkpoint: Hex64,
    model_root: Hex64,
    network_root: Hex64,
    provider_root: Hex64,
    inference_root: Hex64,
    verification_root: Hex64,
    kv_root: Hex64,
    storage_root: Hex64,
    scheduler_root: Hex64,
    node_set_root: Hex64,
    funded_amount: u128,
}

#[derive(Debug, Deserialize)]
struct CliChallenge {
    challenge_id: Hex64,
    job_id: Hex64,
    challenged_output_commitment: Hex64,
    sample_seed_commitment: Hex64,
    required_replications: u16,
    opened_at: u64,
    closes_at: u64,
}

#[derive(Debug, Deserialize)]
struct CliReceipt {
    challenge_id: Hex64,
    verifier_id: Hex64,
    recomputed_output_commitment: Hex64,
    work_commitment: Hex64,
    trace_commitment: Hex64,
    signature_commitment: Hex64,
    verdict: String,
    completed_at: u64,
}

#[derive(Debug, Deserialize)]
struct CliSettlement {
    job_id: Hex64,
    funding_root: Hex64,
    worker_id: Hex64,
    storage_provider_id: Hex64,
    verifier_set_root: Hex64,
    worker_reward: u128,
    storage_reward: u128,
    verifier_reward: u128,
    protocol_fee: u128,
    slash_root: Option<Hex64>,
    refund_amount: u128,
}

#[derive(Debug, Deserialize)]
struct CliSlash {
    slash_id: Hex64,
    job_id: Hex64,
    worker_id: Hex64,
    challenged_output_commitment: Hex64,
    verification_receipt_root: Hex64,
    amount: u128,
    epoch: u64,
    state: String,
}

#[derive(Debug, Serialize)]
struct CliCheckpointOutput {
    chain_id: String,
    epoch: u64,
    sequence: u64,
    previous_checkpoint: String,
    model_root: String,
    network_root: String,
    provider_root: String,
    inference_root: String,
    verification_root: String,
    kv_root: String,
    storage_root: String,
    settlement_root: String,
    scheduler_root: String,
    node_set_root: String,
    commitment: String,
}

// ---------------------------------------------------------------------------
// Hex64 wrapper for serde
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Hex64([u8; 32]);

impl<'de> Deserialize<'de> for Hex64 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        if s.len() != 64 {
            return Err(serde::de::Error::custom("expected 64 hex chars"));
        }
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
                .map_err(|_| serde::de::Error::custom("invalid hex"))?;
        }
        Ok(Hex64(out))
    }
}

impl Serialize for Hex64 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut s = String::with_capacity(64);
        for &byte in &self.0 {
            s.push(HEX[(byte >> 4) as usize] as char);
            s.push(HEX[(byte & 0xf) as usize] as char);
        }
        serializer.serialize_str(&s)
    }
}

impl From<Hex64> for [u8; 32] {
    fn from(h: Hex64) -> Self {
        h.0
    }
}

// ---------------------------------------------------------------------------
// Conversion
// ---------------------------------------------------------------------------

impl From<CliFinalizationInput> for MvpFinalizationInput {
    fn from(i: CliFinalizationInput) -> Self {
        MvpFinalizationInput {
            chain_id: i.chain_id.into(),
            epoch: i.epoch,
            sequence: i.sequence,
            previous_checkpoint: i.previous_checkpoint.into(),
            model_root: i.model_root.into(),
            network_root: i.network_root.into(),
            provider_root: i.provider_root.into(),
            inference_root: i.inference_root.into(),
            verification_root: i.verification_root.into(),
            kv_root: i.kv_root.into(),
            storage_root: i.storage_root.into(),
            scheduler_root: i.scheduler_root.into(),
            node_set_root: i.node_set_root.into(),
            funded_amount: i.funded_amount,
        }
    }
}

impl From<CliChallenge> for VerificationChallenge {
    fn from(c: CliChallenge) -> Self {
        VerificationChallenge {
            challenge_id: c.challenge_id.into(),
            job_id: c.job_id.into(),
            challenged_output_commitment: c.challenged_output_commitment.into(),
            sample_seed_commitment: c.sample_seed_commitment.into(),
            required_replications: c.required_replications,
            opened_at: c.opened_at,
            closes_at: c.closes_at,
        }
    }
}

impl From<CliReceipt> for VerifierReceipt {
    fn from(r: CliReceipt) -> Self {
        let verdict = match r.verdict.as_str() {
            "Match" => VerificationVerdict::Match,
            "Mismatch" => VerificationVerdict::Mismatch,
            "Inconclusive" => VerificationVerdict::Inconclusive,
            other => panic!("unknown verdict: {}", other),
        };
        VerifierReceipt {
            challenge_id: r.challenge_id.into(),
            verifier_id: r.verifier_id.into(),
            recomputed_output_commitment: r.recomputed_output_commitment.into(),
            work_commitment: r.work_commitment.into(),
            trace_commitment: r.trace_commitment.into(),
            signature_commitment: r.signature_commitment.into(),
            verdict,
            completed_at: r.completed_at,
        }
    }
}

impl From<CliSettlement> for ComputeSettlement {
    fn from(s: CliSettlement) -> Self {
        ComputeSettlement {
            job_id: s.job_id.into(),
            funding_root: s.funding_root.into(),
            worker_id: s.worker_id.into(),
            storage_provider_id: s.storage_provider_id.into(),
            verifier_set_root: s.verifier_set_root.into(),
            worker_reward: s.worker_reward,
            storage_reward: s.storage_reward,
            verifier_reward: s.verifier_reward,
            protocol_fee: s.protocol_fee,
            slash_root: s.slash_root.map(Into::into),
            refund_amount: s.refund_amount,
        }
    }
}

impl From<CliSlash> for WorkerSlash {
    fn from(s: CliSlash) -> Self {
        let state = match s.state.as_str() {
            "Open" => SlashState::Open,
            "Consumed" => SlashState::Consumed,
            other => panic!("unknown slash state: {}", other),
        };
        WorkerSlash {
            slash_id: s.slash_id.into(),
            job_id: s.job_id.into(),
            worker_id: s.worker_id.into(),
            challenged_output_commitment: s.challenged_output_commitment.into(),
            verification_receipt_root: s.verification_receipt_root.into(),
            amount: s.amount,
            epoch: s.epoch,
            state,
        }
    }
}

impl From<MvpCheckpoint> for CliCheckpointOutput {
    fn from(cp: MvpCheckpoint) -> Self {
        fn to_hex(b: &[u8; 32]) -> String {
            const HEX: &[u8; 16] = b"0123456789abcdef";
            let mut s = String::with_capacity(64);
            for &byte in b {
                s.push(HEX[(byte >> 4) as usize] as char);
                s.push(HEX[(byte & 0xf) as usize] as char);
            }
            s
        }

        CliCheckpointOutput {
            chain_id: to_hex(&cp.chain_id),
            epoch: cp.epoch,
            sequence: cp.sequence,
            previous_checkpoint: to_hex(&cp.previous_checkpoint),
            model_root: to_hex(&cp.model_root),
            network_root: to_hex(&cp.network_root),
            provider_root: to_hex(&cp.provider_root),
            inference_root: to_hex(&cp.inference_root),
            verification_root: to_hex(&cp.verification_root),
            kv_root: to_hex(&cp.kv_root),
            storage_root: to_hex(&cp.storage_root),
            settlement_root: to_hex(&cp.settlement_root),
            scheduler_root: to_hex(&cp.scheduler_root),
            node_set_root: to_hex(&cp.node_set_root),
            commitment: to_hex(&cp.commitment().unwrap_or([0u8; 32])),
        }
    }
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

fn usage() -> String {
    "usage: synergy-mvp finalize --input <file.json> [--prev <hex64>]\n\
     \n\
     Reads a JSON finalization input and prints the canonical MvpCheckpoint\n\
     with its SHA-256 commitment. --prev overrides previous_checkpoint."
        .to_string()
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("{}", usage());
        return ExitCode::from(2);
    }

    let cmd = args[1].as_str();
    if cmd != "finalize" {
        eprintln!("unknown command: {}", cmd);
        eprintln!("{}", usage());
        return ExitCode::from(2);
    }

    let mut input_path: Option<String> = None;
    let mut prev_override: Option<String> = None;
    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--input" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("--input requires a path");
                    return ExitCode::from(2);
                }
                input_path = Some(args[i].clone());
            }
            "--prev" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("--prev requires a hex64 value");
                    return ExitCode::from(2);
                }
                prev_override = Some(args[i].clone());
            }
            other => {
                eprintln!("unknown argument: {}", other);
                return ExitCode::from(2);
            }
        }
        i += 1;
    }

    let path = match input_path {
        Some(p) => p,
        None => {
            eprintln!("{}", usage());
            return ExitCode::from(2);
        }
    };

    let raw = match fs::read_to_string(&path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("cannot read {}: {}", path, e);
            return ExitCode::from(1);
        }
    };

    let cli_input: CliInput = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("invalid JSON: {}", e);
            return ExitCode::from(1);
        }
    };

    let mut input: MvpFinalizationInput = cli_input.input.into();

    if let Some(prev) = prev_override {
        if prev.len() != 64 {
            eprintln!("--prev must be 64 hex chars");
            return ExitCode::from(1);
        }
        let mut out = [0u8; 32];
        for j in 0..32 {
            out[j] = match u8::from_str_radix(&prev[j * 2..j * 2 + 2], 16) {
                Ok(b) => b,
                Err(_) => {
                    eprintln!("invalid --prev hex");
                    return ExitCode::from(1);
                }
            };
        }
        input.previous_checkpoint = out;
    }

    let challenge: VerificationChallenge = cli_input.challenge.into();
    let receipts: Vec<VerifierReceipt> = cli_input.receipts.into_iter().map(Into::into).collect();
    let settlement: ComputeSettlement = cli_input.settlement.into();
    let slash: Option<WorkerSlash> = cli_input.slash.map(Into::into);

    let mut slash_opt = slash;
    match finalize_mvp_checkpoint(
        &input,
        &challenge,
        &receipts,
        &settlement,
        slash_opt.as_mut(),
    ) {
        Ok(cp) => {
            let out: CliCheckpointOutput = cp.into();
            println!("{}", serde_json::to_string(&out).unwrap());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("finalization failed: {}", e);
            ExitCode::from(1)
        }
    }
}
