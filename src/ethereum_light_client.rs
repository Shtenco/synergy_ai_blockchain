#![forbid(unsafe_code)]

use blst::min_pk::{PublicKey, Signature};
use blst::BLST_ERROR;
use sha2::{Digest, Sha256};

pub const ETH_SYNC_COMMITTEE_SIZE: usize = 512;
pub const ETH_SYNC_COMMITTEE_BITS_BYTES: usize = 64;
pub const ETH_MIN_FINALITY_PARTICIPANTS: usize = 342;
pub const ETH_SLOTS_PER_EPOCH: u64 = 32;
pub const ETH_EPOCHS_PER_SYNC_COMMITTEE_PERIOD: u64 = 256;
pub const ETH_SLOTS_PER_SYNC_COMMITTEE_PERIOD: u64 =
    ETH_SLOTS_PER_EPOCH * ETH_EPOCHS_PER_SYNC_COMMITTEE_PERIOD;
pub const ETH_DOMAIN_SYNC_COMMITTEE: [u8; 4] = [0x07, 0x00, 0x00, 0x00];
pub const ETH_BLS_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
pub const ETH_EXECUTION_PAYLOAD_GINDEX: u64 = 25;
pub const ETH_EXECUTION_STATE_ROOT_GINDEX_CURRENT: u64 = 34;
pub const ETH_FINALIZED_ROOT_GINDEX_PRE_ELECTRA: u64 = 105;
pub const ETH_FINALIZED_ROOT_GINDEX_ELECTRA: u64 = 169;
pub const ETH_CURRENT_SYNC_COMMITTEE_GINDEX_PRE_ELECTRA: u64 = 54;
pub const ETH_CURRENT_SYNC_COMMITTEE_GINDEX_ELECTRA: u64 = 86;
pub const ETH_NEXT_SYNC_COMMITTEE_GINDEX_PRE_ELECTRA: u64 = 55;
pub const ETH_NEXT_SYNC_COMMITTEE_GINDEX_ELECTRA: u64 = 87;

pub const ETH_ALTAIR_FORK_EPOCH: u64 = 74240;
pub const ETH_BELLATRIX_FORK_EPOCH: u64 = 144896;
pub const ETH_CAPELLA_FORK_EPOCH: u64 = 194048;
pub const ETH_DENEB_FORK_EPOCH: u64 = 269568;
pub const ETH_ELECTRA_FORK_EPOCH: u64 = 364032;
pub const ETH_FULU_FORK_EPOCH: u64 = 411392;

pub const ETH_MAINNET_GENESIS_VALIDATORS_ROOT: [u8; 32] = [
    0x4b, 0x36, 0x3d, 0xb9, 0x4e, 0x28, 0x61, 0x20,
    0xd7, 0x6e, 0xb9, 0x05, 0x34, 0x0f, 0xdd, 0x4e,
    0x54, 0xbf, 0xe9, 0xf0, 0x6b, 0xf3, 0x3f, 0xf6,
    0xcf, 0x5a, 0xd2, 0x7f, 0x51, 0x1b, 0xfe, 0x95,
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BeaconBlockHeader {
    pub slot: u64,
    pub proposer_index: u64,
    pub parent_root: [u8; 32],
    pub state_root: [u8; 32],
    pub body_root: [u8; 32],
}

impl BeaconBlockHeader {
    pub fn hash_tree_root(&self) -> [u8; 32] {
        merkleize(&[
            uint64_root(self.slot),
            uint64_root(self.proposer_index),
            self.parent_root,
            self.state_root,
            self.body_root,
        ])
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionStateWitness {
    pub execution_payload_header_root: [u8; 32],
    pub execution_branch: Vec<[u8; 32]>,
    pub execution_state_root: [u8; 32],
    pub execution_state_root_branch: Vec<[u8; 32]>,
}

impl ExecutionStateWitness {
    pub fn verify_against(&self, beacon: &BeaconBlockHeader) -> Result<(), &'static str> {
        let epoch = beacon.slot / ETH_SLOTS_PER_EPOCH;
        if epoch < ETH_DENEB_FORK_EPOCH {
            return Err("production execution-state witness currently requires Deneb+ header layout");
        }
        if !verify_merkle_branch(
            self.execution_payload_header_root,
            &self.execution_branch,
            ETH_EXECUTION_PAYLOAD_GINDEX,
            beacon.body_root,
        ) {
            return Err("execution payload header is not committed by beacon body");
        }
        if !verify_merkle_branch(
            self.execution_state_root,
            &self.execution_state_root_branch,
            ETH_EXECUTION_STATE_ROOT_GINDEX_CURRENT,
            self.execution_payload_header_root,
        ) {
            return Err("execution state root is not committed by execution payload header");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EthereumLightClientHeader {
    pub beacon: BeaconBlockHeader,
    pub execution: ExecutionStateWitness,
}

impl EthereumLightClientHeader {
    pub fn validate(&self) -> Result<(), &'static str> {
        self.execution.verify_against(&self.beacon)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncCommittee {
    pub pubkeys: Vec<[u8; 48]>,
    pub aggregate_pubkey: [u8; 48],
}

impl SyncCommittee {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.pubkeys.len() != ETH_SYNC_COMMITTEE_SIZE {
            return Err("Ethereum sync committee must contain 512 pubkeys");
        }
        if self.pubkeys.iter().any(|pk| *pk == [0; 48]) || self.aggregate_pubkey == [0; 48] {
            return Err("Ethereum sync committee contains zero public key");
        }
        Ok(())
    }

    pub fn hash_tree_root(&self) -> Result<[u8; 32], &'static str> {
        self.validate()?;
        let pubkey_roots: Vec<[u8; 32]> = self.pubkeys.iter().map(|pk| bytes48_root(pk)).collect();
        let pubkeys_root = merkleize(&pubkey_roots);
        let aggregate_root = bytes48_root(&self.aggregate_pubkey);
        Ok(hash_pair(pubkeys_root, aggregate_root))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncAggregate {
    pub bits: [u8; ETH_SYNC_COMMITTEE_BITS_BYTES],
    pub signature: [u8; 96],
}

impl SyncAggregate {
    pub fn participant_indices(&self) -> Vec<usize> {
        let mut out = Vec::new();
        for (byte_index, byte) in self.bits.iter().enumerate() {
            for bit in 0..8 {
                if (byte >> bit) & 1 == 1 {
                    out.push(byte_index * 8 + bit);
                }
            }
        }
        out
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EthereumMainnetTrustPolicy {
    pub trusted_slot: u64,
    pub trusted_beacon_root: [u8; 32],
    pub valid_until_slot: u64,
}

impl EthereumMainnetTrustPolicy {
    pub fn validate(&self, current_slot: u64) -> Result<(), &'static str> {
        if self.trusted_slot == 0
            || self.trusted_beacon_root == [0; 32]
            || self.valid_until_slot <= self.trusted_slot
            || current_slot < self.trusted_slot
            || current_slot > self.valid_until_slot
        {
            return Err("Ethereum weak-subjectivity trust policy is invalid or expired");
        }
        Ok(())
    }

    pub fn commitment(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"SYNERGY/ETH-MAINNET-TRUST-POLICY/V1\0");
        h.update(self.trusted_slot.to_be_bytes());
        h.update(self.trusted_beacon_root);
        h.update(self.valid_until_slot.to_be_bytes());
        h.finalize().into()
    }
}

pub fn ethereum_mainnet_checkpoint_2026_09_16(
    valid_until_slot: u64,
) -> Result<EthereumMainnetTrustPolicy, &'static str> {
    let policy = EthereumMainnetTrustPolicy {
        trusted_slot: 15_230_720,
        trusted_beacon_root: [
            0xec, 0x14, 0x12, 0xdc, 0xc0, 0x5d, 0x08, 0xed,
            0x69, 0x40, 0x97, 0x5e, 0xee, 0x69, 0x02, 0x65,
            0x13, 0xe5, 0xb3, 0x2d, 0x92, 0x01, 0x95, 0x32,
            0x25, 0xa7, 0xc6, 0x39, 0x50, 0xe3, 0x65, 0x6b,
        ],
        valid_until_slot,
    };
    if valid_until_slot <= policy.trusted_slot {
        return Err("Ethereum checkpoint expiry must advance past trusted slot");
    }
    Ok(policy)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EthereumLightClientBootstrap {
    pub header: EthereumLightClientHeader,
    pub current_sync_committee: SyncCommittee,
    pub current_sync_committee_branch: Vec<[u8; 32]>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EthereumLightClientUpdate {
    pub attested_header: EthereumLightClientHeader,
    pub finalized_header: EthereumLightClientHeader,
    pub finality_branch: Vec<[u8; 32]>,
    pub next_sync_committee: Option<SyncCommittee>,
    pub next_sync_committee_branch: Vec<[u8; 32]>,
    pub sync_aggregate: SyncAggregate,
    pub signature_slot: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EthereumFinalizedExecutionAnchor {
    slot: u64,
    beacon_root: [u8; 32],
    state_root: [u8; 32],
}

impl EthereumFinalizedExecutionAnchor {
    pub(crate) fn from_verified_parts(
        slot: u64,
        beacon_root: [u8; 32],
        state_root: [u8; 32],
    ) -> Result<Self, &'static str> {
        if slot == 0 || beacon_root == [0; 32] || state_root == [0; 32] {
            return Err("invalid finalized Ethereum execution anchor");
        }
        Ok(Self { slot, beacon_root, state_root })
    }

    pub fn slot(&self) -> u64 {
        self.slot
    }

    pub fn beacon_root(&self) -> [u8; 32] {
        self.beacon_root
    }

    pub fn state_root(&self) -> [u8; 32] {
        self.state_root
    }

    pub fn commitment(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"SYNERGY/ETH-FINALIZED-EXECUTION-ANCHOR/V1\0");
        h.update(1u64.to_be_bytes());
        h.update(self.slot.to_be_bytes());
        h.update(self.beacon_root);
        h.update(self.state_root);
        h.finalize().into()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EthereumLightClientStore {
    pub finalized_header: EthereumLightClientHeader,
    pub current_sync_committee: SyncCommittee,
    pub next_sync_committee: Option<SyncCommittee>,
}

impl EthereumLightClientStore {
    pub fn finalized_execution_anchor(
        &self,
    ) -> Result<EthereumFinalizedExecutionAnchor, &'static str> {
        EthereumFinalizedExecutionAnchor::from_verified_parts(
            self.finalized_header.beacon.slot,
            self.finalized_header.beacon.hash_tree_root(),
            self.finalized_header.execution.execution_state_root,
        )
    }

    pub fn initialize(
        bootstrap: EthereumLightClientBootstrap,
        trust_policy: &EthereumMainnetTrustPolicy,
        current_slot: u64,
    ) -> Result<Self, &'static str> {
        trust_policy.validate(current_slot)?;
        bootstrap.header.validate()?;
        bootstrap.current_sync_committee.validate()?;
        if bootstrap.header.beacon.slot != trust_policy.trusted_slot
            || bootstrap.header.beacon.hash_tree_root() != trust_policy.trusted_beacon_root
        {
            return Err("Ethereum weak-subjectivity bootstrap does not match chain trust policy");
        }
        let gindex = current_sync_committee_gindex(bootstrap.header.beacon.slot);
        if !verify_merkle_branch(
            bootstrap.current_sync_committee.hash_tree_root()?,
            &bootstrap.current_sync_committee_branch,
            gindex,
            bootstrap.header.beacon.state_root,
        ) {
            return Err("Ethereum bootstrap sync committee proof invalid");
        }
        Ok(Self {
            finalized_header: bootstrap.header,
            current_sync_committee: bootstrap.current_sync_committee,
            next_sync_committee: None,
        })
    }

    pub fn verify_and_apply(
        &mut self,
        update: &EthereumLightClientUpdate,
    ) -> Result<[u8; 32], &'static str> {
        update.attested_header.validate()?;
        update.finalized_header.validate()?;

        let attested_slot = update.attested_header.beacon.slot;
        let finalized_slot = update.finalized_header.beacon.slot;
        if update.signature_slot <= attested_slot
            || finalized_slot > attested_slot
            || finalized_slot <= self.finalized_header.beacon.slot
        {
            return Err("Ethereum light-client slot ordering invalid");
        }

        let store_period = sync_committee_period(self.finalized_header.beacon.slot);
        let signature_period = sync_committee_period(update.signature_slot);
        if signature_period != store_period && signature_period != store_period + 1 {
            return Err("Ethereum light-client update outside sync committee period window");
        }

        let committee = if signature_period == store_period {
            &self.current_sync_committee
        } else {
            self.next_sync_committee
                .as_ref()
                .ok_or("Ethereum next sync committee unavailable")?
        };

        let participants = update.sync_aggregate.participant_indices();
        if participants.len() < ETH_MIN_FINALITY_PARTICIPANTS {
            return Err("Ethereum sync committee participation below finality threshold");
        }
        verify_sync_committee_signature(
            committee,
            &participants,
            &update.sync_aggregate.signature,
            update.attested_header.beacon.hash_tree_root(),
            update.signature_slot,
        )?;

        let finality_gindex = finalized_root_gindex(attested_slot);
        if !verify_merkle_branch(
            update.finalized_header.beacon.hash_tree_root(),
            &update.finality_branch,
            finality_gindex,
            update.attested_header.beacon.state_root,
        ) {
            return Err("Ethereum finalized-header branch invalid");
        }

        let verified_next = if let Some(next) = &update.next_sync_committee {
            next.validate()?;
            let next_gindex = next_sync_committee_gindex(attested_slot);
            if !verify_merkle_branch(
                next.hash_tree_root()?,
                &update.next_sync_committee_branch,
                next_gindex,
                update.attested_header.beacon.state_root,
            ) {
                return Err("Ethereum next sync committee branch invalid");
            }
            Some(next.clone())
        } else {
            None
        };

        let finalized_period = sync_committee_period(finalized_slot);
        if finalized_period > store_period {
            let current = self
                .next_sync_committee
                .clone()
                .ok_or("cannot rotate Ethereum sync committee without verified next committee")?;
            let future = verified_next
                .ok_or("period transition requires a verified future sync committee")?;
            self.current_sync_committee = current;
            self.next_sync_committee = Some(future);
        } else if self.next_sync_committee.is_none() {
            if let Some(next) = verified_next {
                self.next_sync_committee = Some(next);
            }
        }

        self.finalized_header = update.finalized_header.clone();
        Ok(self.finalized_header.execution.execution_state_root)
    }
}

pub fn sync_committee_period(slot: u64) -> u64 {
    slot / ETH_SLOTS_PER_SYNC_COMMITTEE_PERIOD
}

fn current_sync_committee_gindex(slot: u64) -> u64 {
    if slot / ETH_SLOTS_PER_EPOCH >= ETH_ELECTRA_FORK_EPOCH {
        ETH_CURRENT_SYNC_COMMITTEE_GINDEX_ELECTRA
    } else {
        ETH_CURRENT_SYNC_COMMITTEE_GINDEX_PRE_ELECTRA
    }
}

fn next_sync_committee_gindex(slot: u64) -> u64 {
    if slot / ETH_SLOTS_PER_EPOCH >= ETH_ELECTRA_FORK_EPOCH {
        ETH_NEXT_SYNC_COMMITTEE_GINDEX_ELECTRA
    } else {
        ETH_NEXT_SYNC_COMMITTEE_GINDEX_PRE_ELECTRA
    }
}

fn finalized_root_gindex(slot: u64) -> u64 {
    if slot / ETH_SLOTS_PER_EPOCH >= ETH_ELECTRA_FORK_EPOCH {
        ETH_FINALIZED_ROOT_GINDEX_ELECTRA
    } else {
        ETH_FINALIZED_ROOT_GINDEX_PRE_ELECTRA
    }
}

fn fork_version_for_epoch(epoch: u64) -> [u8; 4] {
    if epoch >= ETH_FULU_FORK_EPOCH {
        [0x06, 0x00, 0x00, 0x00]
    } else if epoch >= ETH_ELECTRA_FORK_EPOCH {
        [0x05, 0x00, 0x00, 0x00]
    } else if epoch >= ETH_DENEB_FORK_EPOCH {
        [0x04, 0x00, 0x00, 0x00]
    } else if epoch >= ETH_CAPELLA_FORK_EPOCH {
        [0x03, 0x00, 0x00, 0x00]
    } else if epoch >= ETH_BELLATRIX_FORK_EPOCH {
        [0x02, 0x00, 0x00, 0x00]
    } else if epoch >= ETH_ALTAIR_FORK_EPOCH {
        [0x01, 0x00, 0x00, 0x00]
    } else {
        [0x00, 0x00, 0x00, 0x00]
    }
}

fn compute_domain(signature_slot: u64) -> [u8; 32] {
    let fork_version_slot = signature_slot.saturating_sub(1);
    let epoch = fork_version_slot / ETH_SLOTS_PER_EPOCH;
    let fork_version = fork_version_for_epoch(epoch);
    let mut version_chunk = [0u8; 32];
    version_chunk[..4].copy_from_slice(&fork_version);
    let fork_data_root = hash_pair(version_chunk, ETH_MAINNET_GENESIS_VALIDATORS_ROOT);
    let mut domain = [0u8; 32];
    domain[..4].copy_from_slice(&ETH_DOMAIN_SYNC_COMMITTEE);
    domain[4..].copy_from_slice(&fork_data_root[..28]);
    domain
}

fn signing_root(object_root: [u8; 32], domain: [u8; 32]) -> [u8; 32] {
    hash_pair(object_root, domain)
}

fn verify_sync_committee_signature(
    committee: &SyncCommittee,
    participants: &[usize],
    signature_bytes: &[u8; 96],
    attested_header_root: [u8; 32],
    signature_slot: u64,
) -> Result<(), &'static str> {
    committee.validate()?;
    if participants.is_empty() || participants.iter().any(|index| *index >= ETH_SYNC_COMMITTEE_SIZE) {
        return Err("invalid Ethereum sync committee participant set");
    }

    let mut parsed = Vec::with_capacity(participants.len());
    for index in participants {
        let pk = PublicKey::from_bytes(&committee.pubkeys[*index])
            .map_err(|_| "invalid Ethereum sync committee BLS public key")?;
        parsed.push(pk);
    }
    let refs: Vec<&PublicKey> = parsed.iter().collect();
    let signature = Signature::from_bytes(signature_bytes)
        .map_err(|_| "invalid Ethereum sync committee BLS signature")?;
    let message = signing_root(attested_header_root, compute_domain(signature_slot));
    if signature.fast_aggregate_verify(true, &message, ETH_BLS_DST, &refs)
        != BLST_ERROR::BLST_SUCCESS
    {
        return Err("Ethereum sync committee BLS aggregate signature invalid");
    }
    Ok(())
}

pub fn verify_merkle_branch(
    leaf: [u8; 32],
    branch: &[[u8; 32]],
    gindex: u64,
    root: [u8; 32],
) -> bool {
    if gindex < 2 {
        return false;
    }
    let depth = 63usize.saturating_sub(gindex.leading_zeros() as usize);
    if branch.len() != depth {
        return false;
    }
    let mut value = leaf;
    for (i, sibling) in branch.iter().enumerate() {
        value = if (gindex >> i) & 1 == 1 {
            hash_pair(*sibling, value)
        } else {
            hash_pair(value, *sibling)
        };
    }
    value == root
}

fn uint64_root(value: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..8].copy_from_slice(&value.to_le_bytes());
    out
}

fn bytes48_root(value: &[u8; 48]) -> [u8; 32] {
    let mut left = [0u8; 32];
    let mut right = [0u8; 32];
    left.copy_from_slice(&value[..32]);
    right[..16].copy_from_slice(&value[32..]);
    hash_pair(left, right)
}

fn hash_pair(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(left);
    h.update(right);
    h.finalize().into()
}

fn merkleize(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0; 32];
    }
    let width = leaves.len().next_power_of_two();
    let mut layer = vec![[0u8; 32]; width];
    layer[..leaves.len()].copy_from_slice(leaves);
    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len() / 2);
        for pair in layer.chunks_exact(2) {
            next.push(hash_pair(pair[0], pair[1]));
        }
        layer = next;
    }
    layer[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn beacon_header_root_is_deterministic() {
        let h = BeaconBlockHeader {
            slot: 1,
            proposer_index: 2,
            parent_root: [3; 32],
            state_root: [4; 32],
            body_root: [5; 32],
        };
        assert_ne!(h.hash_tree_root(), [0; 32]);
        assert_eq!(h.hash_tree_root(), h.hash_tree_root());
    }

    #[test]
    fn signature_domain_uses_pre_signature_slot_fork() {
        let boundary_slot = ETH_FULU_FORK_EPOCH * ETH_SLOTS_PER_EPOCH;
        assert_eq!(
            compute_domain(boundary_slot),
            {
                let mut version_chunk = [0u8; 32];
                version_chunk[..4].copy_from_slice(&[0x05, 0, 0, 0]);
                let fork_data_root =
                    hash_pair(version_chunk, ETH_MAINNET_GENESIS_VALIDATORS_ROOT);
                let mut domain = [0u8; 32];
                domain[..4].copy_from_slice(&ETH_DOMAIN_SYNC_COMMITTEE);
                domain[4..].copy_from_slice(&fork_data_root[..28]);
                domain
            }
        );
    }

    #[test]
    fn fork_version_tracks_mainnet_fulu() {
        assert_eq!(fork_version_for_epoch(ETH_DENEB_FORK_EPOCH), [4, 0, 0, 0]);
        assert_eq!(fork_version_for_epoch(ETH_ELECTRA_FORK_EPOCH), [5, 0, 0, 0]);
        assert_eq!(fork_version_for_epoch(ETH_FULU_FORK_EPOCH), [6, 0, 0, 0]);
    }

    #[test]
    fn sync_committee_period_is_8192_slots() {
        assert_eq!(sync_committee_period(8191), 0);
        assert_eq!(sync_committee_period(8192), 1);
    }

    #[test]
    fn generalized_index_branch_verifier_works() {
        let leaf = [1u8; 32];
        let sibling = [2u8; 32];
        let root = hash_pair(leaf, sibling);
        assert!(verify_merkle_branch(leaf, &[sibling], 2, root));
        assert!(!verify_merkle_branch(leaf, &[sibling], 3, root));
    }

    #[test]
    fn deployment_checkpoint_is_policy_bound_and_expiring() {
        let policy = ethereum_mainnet_checkpoint_2026_09_16(15_400_000).unwrap();
        assert_eq!(policy.trusted_slot, 15_230_720);
        assert_eq!(
            hex::encode(policy.trusted_beacon_root),
            "ec1412dcc05d08ed6940975eee69026513e5b32d9201953225a7c63950e3656b"
        );
        assert!(policy.validate(15_300_000).is_ok());
        assert!(policy.validate(15_500_000).is_err());
    }

    #[test]
    fn mainnet_genesis_validators_root_is_pinned() {
        assert_eq!(
            hex::encode(ETH_MAINNET_GENESIS_VALIDATORS_ROOT),
            "4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95"
        );
    }
}
