#![forbid(unsafe_code)]

pub mod autopilot;
pub mod autopilot_budget;
pub mod cognitive;
pub mod cognitive_market;
pub mod cognitive_registry;
pub mod consensus;
pub mod inference;
pub mod kv_cache;
pub mod migration;
pub mod model_shard;
pub mod network;
pub mod nexus;
pub mod payment_funding;
pub mod payments;
pub mod pq;
#[cfg(feature = "reference-pq")]
pub mod pq_reference;
pub mod scheduling;
pub mod service_planes;
pub mod storage;
pub mod tx;
pub mod validator;
pub mod verification;

pub use autopilot::{
    ApprovalMode, AutopilotCapability, AutopilotExecutionReceipt, AutopilotPolicy,
    AutopilotProposal,
};
pub use autopilot_budget::{
    AutopilotBudgetBoundCall, AutopilotBudgetReservation, AutopilotRealizedExecutionReceipt,
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
pub use inference::{
    InferenceExecutionPlan, InferenceJob, InferenceJobState, InferenceOutcome,
    InferenceStageAssignment, InferenceStageKind, InferenceStageReceipt,
};
pub use kv_cache::{KvCacheLease, KvReplicaReceipt};
pub use migration::{LegacyChain, LegacyIdentityBinding};
pub use model_shard::{ModelLineageTransition, ModelManifestCommitment, ModelShardOutput};
pub use network::{
    validate_shared_secret, HybridSharedSecret, MlKem1024Provider, MlKemSharedSecret,
    RekeyPolicy, SecretBytes, TransportPeerIdentity, TransportPolicy,
    MAX_REKEY_MESSAGES, MAX_REKEY_SECONDS, ML_KEM_1024_CIPHERTEXT_BYTES,
    ML_KEM_1024_PUBLIC_KEY_BYTES, ML_KEM_SHARED_SECRET_BYTES,
};
pub use nexus::{NexusManifest, NexusMode, NexusRequest, NexusResponse};
pub use payment_funding::{
    FundedSettlementCommitment, FundingStatus, PaymentFundingConsumptionReceipt,
    PaymentFundingReservation,
};
pub use payments::{PaymentIntent, PaymentLaneKey, PaymentRail, SettlementBatch, SettlementState};
pub use pq::{
    sign_envelope_evidence, verify_envelope_authorization, AuthPolicy, AuthScheme,
    AuthorizationDomain, AuthorizationEnvelope, AuthorizationValidationContext,
    ContextSignatureSigner, ContextSignatureVerifier,
    HybridAuthorization, PqSigningKeyHandle, SchemeRoutedVerifier, SignatureEvidence,
};
#[cfg(feature = "reference-pq")]
pub use pq_reference::{
    MlKemSecretHandle, ReferenceMlKem1024Provider, ReferencePqSignatureVerifier, ReferencePqSigner,
};
pub use scheduling::{can_host, choose_node, placement_score, NodeCapacity, NodeClass, WorkRequirements};
pub use service_planes::{ServicePlaneCapacityEnvelope, ServicePlaneRoots};
pub use storage::{
    ArchiveReceipt, DedupReceipt, DedupScope, ErasurePlacementReceipt,
    ProofOfStorageReceipt, StorageBid, StorageClass,
};
pub use tx::{PqEvmTransaction, TxError, TxValidationContext};
pub use validator::{ValidatorIdentity, ValidatorPolicy};
pub use verification::{
    VerificationAggregate, VerificationChallenge, VerificationVerdict, VerifierReceipt,
};

/// Consensus version for the first integrated SYNERGY PQ-EVM/NEXUS world-compute profile.
pub const CONSENSUS_PROFILE: &str = "SYNERGY-PQ-EVM-NEXUS/2";
