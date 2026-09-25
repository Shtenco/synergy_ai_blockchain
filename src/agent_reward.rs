#![forbid(unsafe_code)]

//! SYNA authorization for independently verified agent work.
//!
//! The worker cannot choose its own reward. A task is reward-eligible only
//! after its PQ-authorized execution receipt is independently replicated by
//! the canonical verifier pipeline.

use std::collections::BTreeSet;

use sha2::{Digest, Sha256};

use crate::agent_execution::{
    verify_agent_execution_receipt, AgentExecutionAuthorization, AgentExecutionValidationContext,
    AgentTaskCommitment,
};
use crate::peer_discovery::NodeSetSnapshot;
use crate::pq::ContextSignatureVerifier;
use crate::syna_emission::{SynaEmissionPolicy, SynaSupplyState};
use crate::verification::{
    aggregate_verifier_receipts, verify_verifier_receipt, VerificationChallenge,
    VerificationVerdict, VerifierReceiptAuthorization, VerifierReceiptValidationContext,
};

pub const AGENT_REWARD_DOMAIN: &[u8] = b"SYNERGY/SYNA-VERIFIED-AGENT-WORK/V1";
pub const AGENT_REWARD_STATE_DOMAIN: &[u8] = b"SYNERGY/AGENT-REWARD-STATE/V1";

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AgentRewardState {
    consumed_work: BTreeSet<[u8; 32]>,
}

impl AgentRewardState {
    pub fn commitment(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(AGENT_REWARD_STATE_DOMAIN);
        h.update((self.consumed_work.len() as u64).to_be_bytes());
        for key in &self.consumed_work {
            h.update(key);
        }
        h.finalize().into()
    }

    pub fn is_consumed(&self, key: &[u8; 32]) -> bool {
        self.consumed_work.contains(key)
    }

    fn consume(&mut self, key: [u8; 32]) -> Result<(), &'static str> {
        if !self.consumed_work.insert(key) {
            return Err("verified agent work already rewarded");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SynaAgentMintAuthorization {
    pub task_root: [u8; 32],
    pub execution_receipt_root: [u8; 32],
    pub verifier_set_root: [u8; 32],
    pub worker_node_id: [u8; 32],
    pub reward_amount: u128,
    pub epoch: u64,
    pub reward_state_root: [u8; 32],
    pub supply_state_root: [u8; 32],
}

impl SynaAgentMintAuthorization {
    pub fn commitment(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(AGENT_REWARD_DOMAIN);
        h.update(self.task_root);
        h.update(self.execution_receipt_root);
        h.update(self.verifier_set_root);
        h.update(self.worker_node_id);
        h.update(self.reward_amount.to_be_bytes());
        h.update(self.epoch.to_be_bytes());
        h.update(self.reward_state_root);
        h.update(self.supply_state_root);
        h.finalize().into()
    }
}

fn work_replay_key(
    chain_id: [u8; 32],
    task_root: [u8; 32],
    execution_receipt_root: [u8; 32],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(AGENT_REWARD_DOMAIN);
    h.update(chain_id);
    h.update(task_root);
    h.update(execution_receipt_root);
    h.finalize().into()
}

#[allow(clippy::too_many_arguments)]
pub fn authorize_verified_agent_reward_and_mint<V: ContextSignatureVerifier>(
    signature_verifier: &V,
    chain_id: [u8; 32],
    epoch: u64,
    task: &AgentTaskCommitment,
    execution: &AgentExecutionAuthorization,
    execution_validation: &AgentExecutionValidationContext,
    node_snapshot: &NodeSetSnapshot,
    challenge: &VerificationChallenge,
    verifier_authorizations: &[VerifierReceiptAuthorization],
    verifier_validations: &[VerifierReceiptValidationContext],
    policy: &SynaEmissionPolicy,
    reward_state: &mut AgentRewardState,
    supply_state: &mut SynaSupplyState,
) -> Result<SynaAgentMintAuthorization, &'static str> {
    if chain_id == [0; 32] || epoch == 0 {
        return Err("agent reward chain/epoch required");
    }
    policy.validate()?;
    task.root()
        .iter()
        .any(|b| *b != 0)
        .then_some(())
        .ok_or("agent task root required")?;

    if execution.chain_id != chain_id
        || execution.epoch != epoch
        || execution_validation.expected_chain_id != chain_id
        || execution_validation.expected_epoch != epoch
    {
        return Err("agent execution reward context mismatch");
    }

    let worker = node_snapshot
        .get(&execution.receipt.worker_node_id)
        .ok_or("agent worker not registered in node snapshot")?;
    let worker_keyset = execution
        .authorization
        .keyset_commitment()
        .ok_or("agent worker PQ keyset unavailable")?;
    if worker.pq_identity_commitment != worker_keyset
        || execution_validation.expected_worker_keyset_commitment != worker.pq_identity_commitment
    {
        return Err("agent worker PQ identity does not match registry");
    }
    if !verify_agent_execution_receipt(signature_verifier, task, execution, execution_validation) {
        return Err("invalid PQ-authorized agent execution receipt");
    }

    let task_root = task.root();
    let execution_root = execution.receipt.root();
    if challenge.job_id != task_root
        || challenge.challenged_output_commitment != execution.receipt.result_root
    {
        return Err("agent verification challenge is not bound to execution result");
    }

    if verifier_authorizations.len() != verifier_validations.len()
        || verifier_authorizations.len() < usize::from(challenge.required_replications)
    {
        return Err("independent agent verifier quorum required");
    }

    let mut verifier_ids = BTreeSet::new();
    let mut verifier_keysets = BTreeSet::new();
    let mut receipts = Vec::with_capacity(verifier_authorizations.len());
    for (authorized, validation) in verifier_authorizations
        .iter()
        .zip(verifier_validations.iter())
    {
        if authorized.receipt.verifier_id == execution.receipt.worker_node_id {
            return Err("agent worker cannot verify its own work");
        }
        if !verifier_ids.insert(authorized.receipt.verifier_id)
            || !verifier_keysets.insert(validation.expected_verifier_keyset_commitment)
        {
            return Err("agent verifier identities/keysets must be independent");
        }
        let registered = node_snapshot
            .get(&authorized.receipt.verifier_id)
            .ok_or("agent verifier not registered in node snapshot")?;
        let actual_keyset = authorized
            .authorization
            .keyset_commitment()
            .ok_or("agent verifier PQ keyset unavailable")?;
        if registered.pq_identity_commitment != actual_keyset
            || validation.expected_verifier_keyset_commitment != registered.pq_identity_commitment
        {
            return Err("agent verifier PQ identity does not match registry");
        }
        if !verify_verifier_receipt(signature_verifier, challenge, authorized, validation) {
            return Err("invalid PQ-authorized agent verifier receipt");
        }
        if authorized.receipt.verdict != VerificationVerdict::Match
            || authorized.receipt.work_commitment != execution_root
        {
            return Err("agent verifier did not confirm exact execution receipt");
        }
        receipts.push(authorized.receipt.clone());
    }

    receipts.sort_by_key(|r| r.verifier_id);
    let aggregate = aggregate_verifier_receipts(challenge, &receipts)
        .map_err(|_| "invalid canonical agent verifier aggregate")?;
    if aggregate.final_verdict() != VerificationVerdict::Match {
        return Err("agent work verifier aggregate is not MATCH");
    }

    let amount = policy
        .reward_for_useful_work(policy.min_useful_work_units)
        .ok_or("agent work below emission threshold")?;
    let replay_key = work_replay_key(chain_id, task_root, execution_root);

    let mut next_reward = reward_state.clone();
    next_reward.consume(replay_key)?;
    let reward_state_root = next_reward.commitment();

    let mut next_supply = supply_state.clone();
    next_supply.reward_state_root = reward_state_root;
    next_supply.mint_bounded(policy, epoch, amount)?;
    let supply_state_root = next_supply
        .commitment()
        .ok_or("invalid post-agent-reward supply state")?;

    *reward_state = next_reward;
    *supply_state = next_supply;

    Ok(SynaAgentMintAuthorization {
        task_root,
        execution_receipt_root: execution_root,
        verifier_set_root: aggregate.receipt_root,
        worker_node_id: execution.receipt.worker_node_id,
        reward_amount: amount,
        epoch,
        reward_state_root,
        supply_state_root,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_execution::{AgentExecutionAuthorization, AgentExecutionReceipt};
    use crate::peer_discovery::NodeRecord;
    use crate::pq::{
        AuthPolicy, AuthScheme, ContextSignatureVerifier, HybridAuthorization, SignatureEvidence,
        ML_DSA_87_PUBLIC_KEY_BYTES, ML_DSA_87_SIGNATURE_BYTES, SLH_DSA_SHAKE_256S_PUBLIC_KEY_BYTES,
        SLH_DSA_SHAKE_256S_SIGNATURE_BYTES,
    };
    use crate::verification::{VerifierReceipt, VerifierReceiptAuthorization};

    #[derive(Clone)]
    struct PermissiveVerifier;

    impl ContextSignatureVerifier for PermissiveVerifier {
        fn verify_with_context(
            &self,
            _scheme: AuthScheme,
            _public_key: &[u8],
            _message: &[u8],
            _context: &[u8],
            _signature: &[u8],
        ) -> bool {
            true
        }
    }

    fn auth(v: u8) -> HybridAuthorization {
        HybridAuthorization {
            policy: AuthPolicy::PqOnly,
            evidence: vec![
                SignatureEvidence {
                    scheme: AuthScheme::MlDsa87,
                    public_key: vec![v; ML_DSA_87_PUBLIC_KEY_BYTES],
                    signature: vec![v.wrapping_add(1); ML_DSA_87_SIGNATURE_BYTES],
                },
                SignatureEvidence {
                    scheme: AuthScheme::SlhDsaShake256s,
                    public_key: vec![v.wrapping_add(2); SLH_DSA_SHAKE_256S_PUBLIC_KEY_BYTES],
                    signature: vec![v.wrapping_add(3); SLH_DSA_SHAKE_256S_SIGNATURE_BYTES],
                },
            ],
        }
    }

    fn task() -> AgentTaskCommitment {
        AgentTaskCommitment {
            task_id: [1; 32],
            parent_task_root: [2; 32],
            workspace_root: [3; 32],
            tool_policy_root: [4; 32],
            model_root: [5; 32],
            input_root: [6; 32],
            max_cpu_millis: 10_000,
            max_memory_mib: 4096,
            expiry_epoch: 100,
        }
    }

    fn node(id: u8, keyset: [u8; 32]) -> NodeRecord {
        NodeRecord {
            node_id: [id; 32],
            endpoint_root: [id.wrapping_add(1); 32],
            transport_keyset_root: [id.wrapping_add(2); 32],
            pq_identity_commitment: keyset,
            capability_root: [id.wrapping_add(3); 32],
            epoch: 7,
            sequence: 1,
            expires_at: 2000,
        }
    }

    fn setup() -> (
        AgentTaskCommitment,
        AgentExecutionAuthorization,
        AgentExecutionValidationContext,
        NodeSetSnapshot,
        VerificationChallenge,
        Vec<VerifierReceiptAuthorization>,
        Vec<VerifierReceiptValidationContext>,
    ) {
        let task = task();
        let worker_auth = auth(10);
        let worker_keyset = worker_auth.keyset_commitment().unwrap();
        let execution = AgentExecutionAuthorization {
            chain_id: [0xA1; 32],
            epoch: 7,
            nonce: 1,
            expires_at: 1100,
            receipt: AgentExecutionReceipt {
                task_root: task.root(),
                worker_node_id: [10; 32],
                agent_id: [11; 32],
                result_root: [12; 32],
                execution_trace_root: [13; 32],
                cpu_millis_used: 1000,
                memory_mib_peak: 1000,
                started_epoch: 7,
                finished_epoch: 7,
                sequence: 1,
            },
            authorization: worker_auth,
        };
        let execution_validation = AgentExecutionValidationContext {
            expected_chain_id: [0xA1; 32],
            expected_epoch: 7,
            expected_nonce: 1,
            expected_worker_node_id: [10; 32],
            expected_worker_keyset_commitment: worker_keyset,
            now: 1000,
            max_future_seconds: 200,
        };
        let execution_root = execution.receipt.root();
        let challenge = VerificationChallenge {
            challenge_id: [20; 32],
            job_id: task.root(),
            challenged_output_commitment: execution.receipt.result_root,
            sample_seed_commitment: [21; 32],
            required_replications: 2,
            opened_at: 1000,
            closes_at: 1200,
        };

        let mut records = vec![node(10, worker_keyset)];
        let mut auths = Vec::new();
        let mut validations = Vec::new();
        for (i, v) in [(30u8, 40u8), (31u8, 50u8)] {
            let verifier_auth = auth(v);
            let keyset = verifier_auth.keyset_commitment().unwrap();
            records.push(node(i, keyset));
            auths.push(VerifierReceiptAuthorization {
                chain_id: [0xA1; 32],
                epoch: 7,
                nonce: 1,
                expires_at: 1100,
                receipt: VerifierReceipt {
                    challenge_id: challenge.challenge_id,
                    verifier_id: [i; 32],
                    recomputed_output_commitment: execution.receipt.result_root,
                    work_commitment: execution_root,
                    trace_commitment: [i.wrapping_add(4); 32],
                    signature_commitment: [i.wrapping_add(5); 32],
                    verdict: VerificationVerdict::Match,
                    completed_at: 1050,
                },
                authorization: verifier_auth,
            });
            validations.push(VerifierReceiptValidationContext {
                expected_chain_id: [0xA1; 32],
                expected_epoch: 7,
                expected_nonce: 1,
                expected_verifier_id: [i; 32],
                expected_verifier_keyset_commitment: keyset,
                now: 1000,
                max_future_seconds: 200,
            });
        }
        records.sort_by_key(|r| r.node_id);
        let snapshot = NodeSetSnapshot { epoch: 7, records };

        (
            task,
            execution,
            execution_validation,
            snapshot,
            challenge,
            auths,
            validations,
        )
    }

    fn policy() -> SynaEmissionPolicy {
        SynaEmissionPolicy {
            version: 1,
            max_reward_per_job: 100,
            max_emission_per_epoch: 1000,
            max_supply: Some(10_000),
            min_useful_work_units: 10,
        }
    }

    #[test]
    fn verified_agent_work_mints_once() {
        let (task, execution, ev, snapshot, challenge, auths, vals) = setup();
        let mut reward_state = AgentRewardState::default();
        let mut supply = SynaSupplyState {
            policy_version: 1,
            current_epoch: 7,
            total_supply: 0,
            epoch_emission: 0,
            reward_state_root: reward_state.commitment(),
        };
        let minted = authorize_verified_agent_reward_and_mint(
            &PermissiveVerifier,
            [0xA1; 32],
            7,
            &task,
            &execution,
            &ev,
            &snapshot,
            &challenge,
            &auths,
            &vals,
            &policy(),
            &mut reward_state,
            &mut supply,
        )
        .expect("verified agent reward");
        assert_eq!(minted.reward_amount, 1);
        assert_eq!(supply.total_supply, 1);

        assert!(authorize_verified_agent_reward_and_mint(
            &PermissiveVerifier,
            [0xA1; 32],
            7,
            &task,
            &execution,
            &ev,
            &snapshot,
            &challenge,
            &auths,
            &vals,
            &policy(),
            &mut reward_state,
            &mut supply,
        )
        .is_err());
    }

    #[test]
    fn verifier_mismatch_blocks_agent_reward() {
        let (task, execution, ev, snapshot, challenge, mut auths, vals) = setup();
        auths[0].receipt.verdict = VerificationVerdict::Mismatch;
        auths[0].receipt.recomputed_output_commitment = [0xEE; 32];
        let mut reward_state = AgentRewardState::default();
        let mut supply = SynaSupplyState {
            policy_version: 1,
            current_epoch: 7,
            total_supply: 0,
            epoch_emission: 0,
            reward_state_root: reward_state.commitment(),
        };
        assert!(authorize_verified_agent_reward_and_mint(
            &PermissiveVerifier,
            [0xA1; 32],
            7,
            &task,
            &execution,
            &ev,
            &snapshot,
            &challenge,
            &auths,
            &vals,
            &policy(),
            &mut reward_state,
            &mut supply,
        )
        .is_err());
        assert_eq!(supply.total_supply, 0);
    }
}
