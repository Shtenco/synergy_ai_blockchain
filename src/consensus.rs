use sha2::{Digest, Sha256};

use crate::pq::{
    verify_envelope_authorization, AuthPolicy, AuthorizationDomain, AuthorizationEnvelope,
    AuthorizationReplayState, AuthorizationValidationContext, ContextSignatureVerifier, HybridAuthorization,
};

const CONSENSUS_ACTIVATION_DOMAIN: &[u8] = b"SYNERGY/CONSENSUS-ACTIVATION/V1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrecompileAddress(pub u16);

impl PrecompileAddress {
    /// Chain-local reserved addresses. Client integrations map these to
    /// 0x0000000000000000000000000000000000000900 + offset.
    pub const ML_DSA_VERIFY: Self = Self(0x0900);
    pub const SLH_DSA_VERIFY: Self = Self(0x0901);
    pub const NEXUS_INFER: Self = Self(0x0910);
    pub const NEXUS_PROOF_VERIFY: Self = Self(0x0911);
    pub const LEGACY_BINDING_VERIFY: Self = Self(0x0920);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrecompileGasSchedule {
    pub base: u64,
    pub per_input_byte: u64,
    pub per_output_byte: u64,
    pub per_nexus_node: u64,
    pub per_nexus_edge: u64,
    pub per_nexus_layer: u64,
}

impl Default for PrecompileGasSchedule {
    fn default() -> Self {
        Self {
            base: 25_000,
            per_input_byte: 8,
            per_output_byte: 16,
            per_nexus_node: 250,
            per_nexus_edge: 40,
            per_nexus_layer: 5_000,
        }
    }
}

impl PrecompileGasSchedule {
    pub fn nexus_cost(
        &self,
        input_bytes: usize,
        output_bytes: usize,
        nodes: usize,
        edges: usize,
        layers: usize,
    ) -> Option<u64> {
        let input_bytes = u64::try_from(input_bytes).ok()?;
        let output_bytes = u64::try_from(output_bytes).ok()?;
        let nodes = u64::try_from(nodes).ok()?;
        let edges = u64::try_from(edges).ok()?;
        let layers = u64::try_from(layers).ok()?;

        let input = self.per_input_byte.checked_mul(input_bytes)?;
        let output = self.per_output_byte.checked_mul(output_bytes)?;
        let node = self.per_nexus_node.checked_mul(nodes)?;
        let edge = self.per_nexus_edge.checked_mul(edges)?;
        let layer = self.per_nexus_layer.checked_mul(layers)?;
        self.base
            .checked_add(input)?
            .checked_add(output)?
            .checked_add(node)?
            .checked_add(edge)?
            .checked_add(layer)
    }
}

/// Consensus-critical rule: precompile implementation, model manifest hash and gas
/// schedule are activated only at an explicit block height. No validator may fetch
/// model weights or code from the network while executing a block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsensusActivation {
    pub activation_block: u64,
    pub model_manifest_hash: [u8; 32],
    pub implementation_hash: [u8; 32],
    pub gas_schedule: PrecompileGasSchedule,
}


impl ConsensusActivation {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.activation_block == 0 {
            return Err("consensus activation block required");
        }
        if self.model_manifest_hash == [0u8; 32] || self.implementation_hash == [0u8; 32] {
            return Err("consensus activation commitments required");
        }
        if self.gas_schedule.base == 0 {
            return Err("consensus activation gas schedule required");
        }
        Ok(())
    }

    pub fn authorization_commitment(&self) -> Option<[u8; 32]> {
        self.validate().ok()?;
        let mut hasher = Sha256::new();
        hasher.update(CONSENSUS_ACTIVATION_DOMAIN);
        hasher.update(self.activation_block.to_be_bytes());
        hasher.update(self.model_manifest_hash);
        hasher.update(self.implementation_hash);
        hasher.update(self.gas_schedule.base.to_be_bytes());
        hasher.update(self.gas_schedule.per_input_byte.to_be_bytes());
        hasher.update(self.gas_schedule.per_output_byte.to_be_bytes());
        hasher.update(self.gas_schedule.per_nexus_node.to_be_bytes());
        hasher.update(self.gas_schedule.per_nexus_edge.to_be_bytes());
        hasher.update(self.gas_schedule.per_nexus_layer.to_be_bytes());
        Some(hasher.finalize().into())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsensusActivationAuthorization {
    pub chain_id: [u8; 32],
    pub epoch: u64,
    pub nonce: u64,
    pub expires_at: u64,
    pub activation: ConsensusActivation,
    pub authorization: HybridAuthorization,
}

impl ConsensusActivationAuthorization {
    pub fn envelope(&self) -> Option<AuthorizationEnvelope> {
        Some(AuthorizationEnvelope {
            chain_id: self.chain_id,
            domain: AuthorizationDomain::ConsensusActivation,
            epoch: self.epoch,
            nonce: self.nonce,
            expires_at: self.expires_at,
            payload_commitment: self.activation.authorization_commitment()?,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConsensusActivationValidationContext {
    pub expected_chain_id: [u8; 32],
    pub expected_epoch: u64,
    pub expected_nonce: u64,
    pub expected_activation_block: u64,
    pub current_block: u64,
    pub min_activation_delay_blocks: u64,
    pub expected_authority_keyset_commitment: [u8; 32],
    pub now: u64,
    pub max_future_seconds: u64,
}

pub(crate) fn verify_consensus_activation<V: ContextSignatureVerifier>(
    verifier: &V,
    authorized: &ConsensusActivationAuthorization,
    validation: &ConsensusActivationValidationContext,
) -> bool {
    let earliest_activation = match validation
        .current_block
        .checked_add(validation.min_activation_delay_blocks)
    {
        Some(block) => block,
        None => return false,
    };

    if validation.min_activation_delay_blocks == 0
        || authorized.authorization.policy != AuthPolicy::Max
        || authorized.activation.activation_block != validation.expected_activation_block
        || authorized.activation.activation_block < earliest_activation
        || authorized.authorization.keyset_commitment()
            != Some(validation.expected_authority_keyset_commitment)
        || authorized.activation.validate().is_err()
    {
        return false;
    }

    let envelope = match authorized.envelope() {
        Some(envelope) => envelope,
        None => return false,
    };

    let auth_validation = AuthorizationValidationContext {
        expected_chain_id: validation.expected_chain_id,
        expected_domain: AuthorizationDomain::ConsensusActivation,
        expected_policy: AuthPolicy::Max,
        expected_epoch: validation.expected_epoch,
        expected_nonce: validation.expected_nonce,
        now: validation.now,
        max_future_seconds: validation.max_future_seconds,
    };

    verify_envelope_authorization(
        verifier,
        &authorized.authorization,
        &envelope,
        &auth_validation,
    )
}


pub fn verify_consensus_activation_and_consume<V: ContextSignatureVerifier>(
    verifier: &V,
    authorized: &ConsensusActivationAuthorization,
    validation: &ConsensusActivationValidationContext,
    replay: &mut AuthorizationReplayState,
) -> bool {
    if !verify_consensus_activation(verifier, authorized, validation) {
        return false;
    }
    let envelope = match authorized.envelope() {
        Some(envelope) => envelope,
        None => return false,
    };
    replay.consume_verified(&authorized.authorization, &envelope)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pq::{
        AuthScheme, ContextSignatureVerifier, SignatureEvidence, ML_DSA_87_PUBLIC_KEY_BYTES,
        ML_DSA_87_SIGNATURE_BYTES, SECP256K1_PUBLIC_KEY_BYTES, SECP256K1_SIGNATURE_BYTES,
        SLH_DSA_SHAKE_256S_PUBLIC_KEY_BYTES, SLH_DSA_SHAKE_256S_SIGNATURE_BYTES,
    };

    #[derive(Clone)]
    struct ExpectedVerifier {
        message: Vec<u8>,
        context: Vec<u8>,
    }

    impl ContextSignatureVerifier for ExpectedVerifier {
        fn verify_with_context(
            &self,
            _scheme: AuthScheme,
            _public_key: &[u8],
            message: &[u8],
            context: &[u8],
            _signature: &[u8],
        ) -> bool {
            message == self.message && context == self.context
        }
    }

    fn max_authorization() -> HybridAuthorization {
        let mut secp_key = vec![1u8; SECP256K1_PUBLIC_KEY_BYTES];
        secp_key[0] = 0x02;
        let mut secp_sig = vec![2u8; SECP256K1_SIGNATURE_BYTES];
        secp_sig[SECP256K1_SIGNATURE_BYTES - 1] = 0;
        HybridAuthorization {
            policy: AuthPolicy::Max,
            evidence: vec![
                SignatureEvidence {
                    scheme: AuthScheme::Secp256k1,
                    public_key: secp_key,
                    signature: secp_sig,
                },
                SignatureEvidence {
                    scheme: AuthScheme::MlDsa87,
                    public_key: vec![3u8; ML_DSA_87_PUBLIC_KEY_BYTES],
                    signature: vec![4u8; ML_DSA_87_SIGNATURE_BYTES],
                },
                SignatureEvidence {
                    scheme: AuthScheme::SlhDsaShake256s,
                    public_key: vec![5u8; SLH_DSA_SHAKE_256S_PUBLIC_KEY_BYTES],
                    signature: vec![6u8; SLH_DSA_SHAKE_256S_SIGNATURE_BYTES],
                },
            ],
        }
    }

    fn authorized_activation() -> ConsensusActivationAuthorization {
        ConsensusActivationAuthorization {
            chain_id: [0x91; 32],
            epoch: 20,
            nonce: 21,
            expires_at: 1_100,
            activation: ConsensusActivation {
                activation_block: 50_000,
                model_manifest_hash: [0x92; 32],
                implementation_hash: [0x93; 32],
                gas_schedule: PrecompileGasSchedule::default(),
            },
            authorization: max_authorization(),
        }
    }


    #[test]
    fn consensus_activation_requires_registered_max_authority() {
        let authorized = authorized_activation();
        let envelope = authorized.envelope().expect("activation envelope");
        let verifier = ExpectedVerifier {
            message: envelope.canonical_message(AuthPolicy::Max).expect("message"),
            context: envelope.fips_signature_context(AuthPolicy::Max).expect("context"),
        };
        let validation = ConsensusActivationValidationContext {
            expected_chain_id: [0x91; 32],
            expected_epoch: 20,
            expected_nonce: 21,
            expected_activation_block: 50_000,
            current_block: 49_000,
            min_activation_delay_blocks: 100,
            expected_authority_keyset_commitment: authorized
                .authorization
                .keyset_commitment()
                .expect("authority keyset"),
            now: 1_000,
            max_future_seconds: 200,
        };

        assert!(verify_consensus_activation(&verifier, &authorized, &validation));

        let mut wrong = validation;
        wrong.expected_activation_block += 1;
        assert!(!verify_consensus_activation(&verifier, &authorized, &wrong));
    }

    #[test]
    fn consensus_activation_rejects_retroactive_or_zero_delay_activation() {
        let authorized = authorized_activation();
        let envelope = authorized.envelope().expect("activation envelope");
        let verifier = ExpectedVerifier {
            message: envelope.canonical_message(AuthPolicy::Max).expect("message"),
            context: envelope.fips_signature_context(AuthPolicy::Max).expect("context"),
        };
        let mut validation = ConsensusActivationValidationContext {
            expected_chain_id: [0x91; 32],
            expected_epoch: 20,
            expected_nonce: 21,
            expected_activation_block: 50_000,
            current_block: 50_000,
            min_activation_delay_blocks: 1,
            expected_authority_keyset_commitment: authorized
                .authorization
                .keyset_commitment()
                .expect("authority keyset"),
            now: 1_000,
            max_future_seconds: 200,
        };
        assert!(!verify_consensus_activation(&verifier, &authorized, &validation));

        validation.current_block = 49_000;
        validation.min_activation_delay_blocks = 0;
        assert!(!verify_consensus_activation(&verifier, &authorized, &validation));
    }

    #[test]
    fn consensus_activation_commitment_binds_implementation_and_gas_schedule() {
        let base = authorized_activation().activation;
        let commitment = base.authorization_commitment().expect("commitment");

        let mut changed = base.clone();
        changed.implementation_hash[0] ^= 1;
        assert_ne!(commitment, changed.authorization_commitment().expect("impl change"));

        let mut changed = base;
        changed.gas_schedule.base += 1;
        assert_ne!(commitment, changed.authorization_commitment().expect("gas change"));
    }

    #[test]
    fn gas_cost_is_deterministic() {
        let s = PrecompileGasSchedule::default();
        assert_eq!(s.nexus_cost(32, 32, 16, 32, 3), s.nexus_cost(32, 32, 16, 32, 3));
    }
}
