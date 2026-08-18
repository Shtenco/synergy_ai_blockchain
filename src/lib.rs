#![forbid(unsafe_code)]

pub mod autopilot;
pub mod cognitive;
pub mod cognitive_market;
pub mod cognitive_registry;
pub mod consensus;
pub mod migration;
pub mod network;
pub mod nexus;
pub mod payments;
pub mod pq;
pub mod storage;
pub mod tx;
pub mod validator;

pub use autopilot::{
    ApprovalMode, AutopilotCapability, AutopilotExecutionReceipt, AutopilotPolicy,
    AutopilotProposal,
};
pub use cognitive::{
    CognitiveEvidence, CognitiveNodeManifest, CognitiveRole, CognitiveWorkReceipt,
    CognitiveWorkRequest, EvidenceKind, WorkVerdict,
};
pub use cognitive_market::{
    reward_breakdown, CognitiveRewardBreakdown, CognitiveRewardPolicy,
    VerifiedMarginalContribution,
};
pub use cognitive_registry::{
    independent_prefix_count, structural_independence, CognitiveNodeProvenance,
    IndependenceVerdict,
};
pub use consensus::{PrecompileAddress, PrecompileGasSchedule};
pub use migration::{LegacyChain, LegacyIdentityBinding};
pub use network::{HybridSharedSecret, TransportPolicy};
pub use nexus::{NexusManifest, NexusMode, NexusRequest, NexusResponse};
pub use payments::{PaymentIntent, PaymentLaneKey, PaymentRail, SettlementBatch, SettlementState};
pub use pq::{AuthPolicy, AuthScheme, HybridAuthorization};
pub use storage::{ArchiveReceipt, ProofOfStorageReceipt, StorageBid, StorageClass};
pub use tx::PqEvmTransaction;
pub use validator::{ValidatorIdentity, ValidatorPolicy};

/// Consensus version for the first SYNERGY PQ-EVM/NEXUS execution profile.
pub const CONSENSUS_PROFILE: &str = "SYNERGY-PQ-EVM-NEXUS/1";
