#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use sha2::{Digest, Sha256};

use crate::bitcoin_bridge::BitcoinVerifiedTxProof;
use crate::ethereum_light_client::EthereumFinalizedExecutionAnchor;
use crate::ethereum_proof::{decode_evm_block_header_state_root, keccak256, EthereumAccountProof, EthereumStorageProof};
use crate::pq::{
    verify_envelope_authorization, AuthPolicy, AuthorizationDomain, AuthorizationEnvelope,
    AuthorizationReplayState, AuthorizationValidationContext, ContextSignatureVerifier,
    HybridAuthorization,
};

pub const PQ_BRIDGE_DOMAIN: &[u8] = b"SYNERGY/PQ-OMNICHAIN-BRIDGE/V1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BridgeSourceClass {
    BitcoinL1,
    EthereumL1,
    EthereumL2,
    EthereumL3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BridgeDirection {
    ExternalToSynergy,
    SynergyToExternal,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EvmSettlementScheme {
    DirectStateRoot,
    OpStackOutputRootV0 {
        message_passer_storage_root: [u8; 32],
        l2_block_hash: [u8; 32],
    },
    ArbitrumNitroConfirmedAssertion {
        parent_assertion_hash: [u8; 32],
        inbox_acc: [u8; 32],
        global_state_block_hash: [u8; 32],
        global_state_send_root: [u8; 32],
        inbox_position: u64,
        position_in_message: u64,
        machine_status: u8,
        end_history_root: [u8; 32],
        l2_header_rlp: Vec<u8>,
    },
}

impl EvmSettlementScheme {
    pub fn commitment(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(PQ_BRIDGE_DOMAIN);
        h.update(b"SETTLEMENT-SCHEME/V1");
        match self {
            Self::DirectStateRoot => {
                h.update([1u8]);
            }
            Self::OpStackOutputRootV0 {
                message_passer_storage_root,
                l2_block_hash,
            } => {
                h.update([2u8]);
                h.update(message_passer_storage_root);
                h.update(l2_block_hash);
            }
            Self::ArbitrumNitroConfirmedAssertion {
                parent_assertion_hash,
                inbox_acc,
                global_state_block_hash,
                global_state_send_root,
                inbox_position,
                position_in_message,
                machine_status,
                end_history_root,
                l2_header_rlp,
            } => {
                h.update([3u8]);
                h.update(parent_assertion_hash);
                h.update(inbox_acc);
                h.update(global_state_block_hash);
                h.update(global_state_send_root);
                h.update(inbox_position.to_be_bytes());
                h.update(position_in_message.to_be_bytes());
                h.update([*machine_status]);
                h.update(end_history_root);
                h.update((l2_header_rlp.len() as u64).to_be_bytes());
                h.update(l2_header_rlp);
            }
        }
        h.finalize().into()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvmSettlementHop {
    pub parent_chain_id: u64,
    pub child_chain_id: u64,
    pub settlement_contract: [u8; 20],
    /// Parent-chain storage slot containing the scheme-specific finalized commitment.
    pub state_root_slot: [u8; 32],
    pub claimed_child_state_root: [u8; 32],
    pub scheme: EvmSettlementScheme,
    pub account_proof: EthereumAccountProof,
    pub storage_proof: EthereumStorageProof,
}

impl EvmSettlementHop {
    pub fn verify(&self, parent_state_root: [u8; 32]) -> Result<[u8; 32], &'static str> {
        if self.parent_chain_id == 0
            || self.child_chain_id == 0
            || self.parent_chain_id == self.child_chain_id
            || self.settlement_contract == [0; 20]
            || self.claimed_child_state_root == [0; 32]
            || self.account_proof.state_root != parent_state_root
            || self.account_proof.address != self.settlement_contract
            || self.storage_proof.slot_key != self.state_root_slot
        {
            return Err("invalid EVM settlement hop");
        }

        self.account_proof.verify()?;
        let storage_root = self.account_proof.storage_root()?;
        self.storage_proof.verify(storage_root)?;
        let stored = decode_storage_word(&self.storage_proof.value_rlp)?;

        let expected = match &self.scheme {
            EvmSettlementScheme::DirectStateRoot => self.claimed_child_state_root,
            EvmSettlementScheme::OpStackOutputRootV0 {
                message_passer_storage_root,
                l2_block_hash,
            } => {
                if *message_passer_storage_root == [0; 32] || *l2_block_hash == [0; 32] {
                    return Err("invalid OP Stack output-root preimage");
                }
                op_stack_output_root_v0(
                    self.claimed_child_state_root,
                    *message_passer_storage_root,
                    *l2_block_hash,
                )
            }
            EvmSettlementScheme::ArbitrumNitroConfirmedAssertion {
                parent_assertion_hash,
                inbox_acc,
                global_state_block_hash,
                global_state_send_root,
                inbox_position,
                position_in_message,
                machine_status,
                end_history_root,
                l2_header_rlp,
            } => {
                if *parent_assertion_hash == [0; 32]
                    || *inbox_acc == [0; 32]
                    || *global_state_block_hash == [0; 32]
                    || *global_state_send_root == [0; 32]
                    || *end_history_root == [0; 32]
                    || l2_header_rlp.is_empty()
                    || *machine_status > 2
                {
                    return Err("invalid Arbitrum Nitro assertion preimage");
                }
                if keccak256(l2_header_rlp) != *global_state_block_hash {
                    return Err("Arbitrum GlobalState block hash does not match L2 header");
                }
                if decode_evm_block_header_state_root(l2_header_rlp)?
                    != self.claimed_child_state_root
                {
                    return Err("Arbitrum L2 header state root mismatch");
                }
                arbitrum_nitro_assertion_hash(
                    *parent_assertion_hash,
                    *inbox_acc,
                    *global_state_block_hash,
                    *global_state_send_root,
                    *inbox_position,
                    *position_in_message,
                    *machine_status,
                    *end_history_root,
                )
            }
        };

        if stored != expected {
            return Err("parent settlement commitment mismatch");
        }
        Ok(self.claimed_child_state_root)
    }
}

pub fn op_stack_output_root_v0(
    state_root: [u8; 32],
    message_passer_storage_root: [u8; 32],
    l2_block_hash: [u8; 32],
) -> [u8; 32] {
    let mut preimage = [0u8; 128];
    preimage[32..64].copy_from_slice(&state_root);
    preimage[64..96].copy_from_slice(&message_passer_storage_root);
    preimage[96..128].copy_from_slice(&l2_block_hash);
    keccak256(&preimage)
}

#[allow(clippy::too_many_arguments)]
pub fn arbitrum_nitro_assertion_hash(
    parent_assertion_hash: [u8; 32],
    inbox_acc: [u8; 32],
    block_hash: [u8; 32],
    send_root: [u8; 32],
    inbox_position: u64,
    position_in_message: u64,
    machine_status: u8,
    end_history_root: [u8; 32],
) -> [u8; 32] {
    let mut encoded = [0u8; 192];
    encoded[0..32].copy_from_slice(&block_hash);
    encoded[32..64].copy_from_slice(&send_root);
    encoded[88..96].copy_from_slice(&inbox_position.to_be_bytes());
    encoded[120..128].copy_from_slice(&position_in_message.to_be_bytes());
    encoded[159] = machine_status;
    encoded[160..192].copy_from_slice(&end_history_root);
    let after_state_hash = keccak256(&encoded);

    let mut packed = [0u8; 96];
    packed[..32].copy_from_slice(&parent_assertion_hash);
    packed[32..64].copy_from_slice(&after_state_hash);
    packed[64..].copy_from_slice(&inbox_acc);
    keccak256(&packed)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvmRecursiveSettlementProof {
    pub anchor: EthereumFinalizedExecutionAnchor,
    pub hops: Vec<EvmSettlementHop>,
    pub target_chain_id: u64,
    pub target_event_or_state_root: [u8; 32],
}

impl EvmRecursiveSettlementProof {
    pub fn verify(&self) -> Result<[u8; 32], &'static str> {
        if self.target_chain_id == 0 || self.target_event_or_state_root == [0; 32] {
            return Err("target EVM bridge state required");
        }
        if self.hops.len() > 2 {
            return Err("bridge supports Ethereum L1 plus at most L2/L3 ancestry");
        }

        let mut current_chain = 1u64;
        let mut current_root = self.anchor.state_root();
        for hop in &self.hops {
            if hop.parent_chain_id != current_chain {
                return Err("EVM settlement ancestry is disconnected");
            }
            current_root = hop.verify(current_root)?;
            current_chain = hop.child_chain_id;
        }
        if current_chain != self.target_chain_id || current_root != self.target_event_or_state_root {
            return Err("EVM target state is not finalized through settlement ancestry");
        }

        let mut h = Sha256::new();
        h.update(PQ_BRIDGE_DOMAIN);
        h.update(b"EVM-RECURSIVE");
        h.update(self.anchor.commitment());
        for hop in &self.hops {
            h.update(hop.parent_chain_id.to_be_bytes());
            h.update(hop.child_chain_id.to_be_bytes());
            h.update(hop.settlement_contract);
            h.update(hop.state_root_slot);
            h.update(hop.claimed_child_state_root);
            h.update(hop.scheme.commitment());
        }
        h.update(self.target_chain_id.to_be_bytes());
        h.update(self.target_event_or_state_root);
        Ok(h.finalize().into())
    }

    pub fn source_class(&self) -> Result<BridgeSourceClass, &'static str> {
        match self.hops.len() {
            0 => Ok(BridgeSourceClass::EthereumL1),
            1 => Ok(BridgeSourceClass::EthereumL2),
            2 => Ok(BridgeSourceClass::EthereumL3),
            _ => Err("unsupported EVM settlement depth"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BridgeSourceProof {
    Bitcoin(BitcoinVerifiedTxProof),
    Evm(EvmRecursiveSettlementProof),
}

impl BridgeSourceProof {
    pub fn verify(&self) -> Result<([u8; 32], BridgeSourceClass), &'static str> {
        match self {
            Self::Bitcoin(proof) => Ok((proof.commitment(), BridgeSourceClass::BitcoinL1)),
            Self::Evm(proof) => Ok((proof.verify()?, proof.source_class()?)),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PqBridgeClaim {
    pub direction: BridgeDirection,
    pub source_proof: BridgeSourceProof,
    pub source_asset_root: [u8; 32],
    pub destination_account: [u8; 32],
    pub amount: u128,
    pub claim_id: [u8; 32],
}

impl PqBridgeClaim {
    pub fn commitment(&self) -> Result<[u8; 32], &'static str> {
        if self.direction != BridgeDirection::ExternalToSynergy {
            return Err("source-chain proof claims only authorize external-to-SYNERGY flow");
        }
        let (source_proof_root, class) = self.source_proof.verify()?;
        if self.source_asset_root == [0; 32]
            || self.destination_account == [0; 32]
            || self.amount == 0
            || self.claim_id == [0; 32]
        {
            return Err("invalid bridge claim");
        }
        let mut h = Sha256::new();
        h.update(PQ_BRIDGE_DOMAIN);
        h.update([1u8]);
        h.update([match class {
            BridgeSourceClass::BitcoinL1 => 1,
            BridgeSourceClass::EthereumL1 => 2,
            BridgeSourceClass::EthereumL2 => 3,
            BridgeSourceClass::EthereumL3 => 4,
        }]);
        h.update(source_proof_root);
        h.update(self.source_asset_root);
        h.update(self.destination_account);
        h.update(self.amount.to_be_bytes());
        h.update(self.claim_id);
        Ok(h.finalize().into())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PqBridgeAuthorization {
    pub chain_id: [u8; 32],
    pub epoch: u64,
    pub nonce: u64,
    pub expires_at: u64,
    pub claim: PqBridgeClaim,
    pub authorization: HybridAuthorization,
}

impl PqBridgeAuthorization {
    pub fn envelope(&self) -> Option<AuthorizationEnvelope> {
        Some(AuthorizationEnvelope {
            chain_id: self.chain_id,
            domain: AuthorizationDomain::BridgeProof,
            epoch: self.epoch,
            nonce: self.nonce,
            expires_at: self.expires_at,
            payload_commitment: self.claim.commitment().ok()?,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PqBridgeValidationContext {
    pub expected_chain_id: [u8; 32],
    pub expected_epoch: u64,
    pub expected_nonce: u64,
    pub expected_authority_keyset: [u8; 32],
    pub now: u64,
    pub max_future_seconds: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BridgeClaimReplayState {
    consumed_claim_ids: BTreeSet<[u8; 32]>,
}

impl BridgeClaimReplayState {
    pub fn verify_and_consume<V: ContextSignatureVerifier>(
        &mut self,
        verifier: &V,
        authorized: &PqBridgeAuthorization,
        validation: PqBridgeValidationContext,
        auth_replay: &mut AuthorizationReplayState,
    ) -> Result<[u8; 32], &'static str> {
        if authorized.authorization.policy != AuthPolicy::PqOnly
            || authorized.authorization.keyset_commitment()
                != Some(validation.expected_authority_keyset)
            || self.consumed_claim_ids.contains(&authorized.claim.claim_id)
        {
            return Err("bridge authority/replay validation failed");
        }

        let envelope = authorized.envelope().ok_or("invalid bridge authorization envelope")?;
        let auth_context = AuthorizationValidationContext {
            expected_chain_id: validation.expected_chain_id,
            expected_domain: AuthorizationDomain::BridgeProof,
            expected_policy: AuthPolicy::PqOnly,
            expected_epoch: validation.expected_epoch,
            expected_nonce: validation.expected_nonce,
            now: validation.now,
            max_future_seconds: validation.max_future_seconds,
        };
        if !verify_envelope_authorization(
            verifier,
            &authorized.authorization,
            &envelope,
            &auth_context,
        ) {
            return Err("invalid PQ bridge authorization");
        }
        if !auth_replay.consume_verified_for_subject(
            &authorized.authorization,
            &envelope,
            validation.expected_authority_keyset,
        ) {
            return Err("bridge authorization replay rejected");
        }

        let root = authorized.claim.commitment()?;
        self.consumed_claim_ids.insert(authorized.claim.claim_id);
        Ok(root)
    }
}

fn decode_storage_word(encoded: &[u8]) -> Result<[u8; 32], &'static str> {
    let payload = if encoded.is_empty() {
        return Err("empty storage RLP");
    } else if encoded[0] <= 0x7f {
        &encoded[..1]
    } else if encoded[0] <= 0xb7 {
        let len = usize::from(encoded[0] - 0x80);
        if encoded.len() != 1 + len {
            return Err("invalid storage RLP length");
        }
        &encoded[1..]
    } else {
        return Err("unsupported noncanonical storage RLP");
    };
    if payload.len() > 32 {
        return Err("storage word exceeds 32 bytes");
    }
    let mut out = [0u8; 32];
    out[32 - payload.len()..].copy_from_slice(payload);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_word_decodes_left_padded_u256() {
        let mut encoded = vec![0xa0];
        encoded.extend_from_slice(&[7u8; 32]);
        assert_eq!(decode_storage_word(&encoded).unwrap(), [7u8; 32]);
        assert_eq!(decode_storage_word(&[0x01]).unwrap()[31], 1);
    }

    #[test]
    fn settlement_depth_maps_to_l1_l2_l3() {
        let anchor =
            EthereumFinalizedExecutionAnchor::from_verified_parts(1, [1; 32], [2; 32]).unwrap();
        let p = EvmRecursiveSettlementProof {
            anchor,
            hops: vec![],
            target_chain_id: 1,
            target_event_or_state_root: [2; 32],
        };
        assert_eq!(p.source_class().unwrap(), BridgeSourceClass::EthereumL1);
        assert!(p.verify().is_ok());
    }
}
