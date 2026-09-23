#![forbid(unsafe_code)]

pub mod autopilot;
pub mod autopilot_budget;
pub mod autopilot_execution_lease;
pub mod cognitive;
pub mod cognitive_market;
pub mod cognitive_registry;
pub mod consensus;
pub mod inference;
pub mod governance;
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
    AutopilotBudgetBoundCall, AutopilotBudgetReservation,
    AutopilotExecutionAuthorization, AutopilotExecutionValidationContext,
    AutopilotRealizedExecutionReceipt,
};
pub use autopilot_execution_lease::{
    authorize_and_lock_autopilot_execution, finalize_autopilot_lease_and_consume,
    AutopilotExecutionLease, AutopilotExecutionLeaseStatus,
    AutopilotLeaseTerminalAuthorization, AutopilotLeaseTerminalReceipt,
    AutopilotLeaseTerminalValidationContext,
};
pub use cognitive::{
    verify_cognitive_evidence_and_consume, CognitiveEvidence, CognitiveEvidenceAuthorization,
    CognitiveEvidenceValidationContext, CognitiveNodeManifest, CognitiveRole,
    CognitiveWorkReceipt, CognitiveWorkRequest, EvidenceKind, WorkVerdict,
};
pub use cognitive_market::{
    reward_breakdown, CognitiveRewardBreakdown, CognitiveRewardPolicy,
    VerifiedMarginalContribution,
};
pub use cognitive_registry::{
    independent_registered_count, structural_independence, CognitiveNodeProvenance,
    IndependenceVerdict,
};
pub use consensus::{
    verify_consensus_activation_and_consume, ConsensusActivation, ConsensusActivationAuthorization,
    ConsensusActivationValidationContext, PrecompileAddress, PrecompileGasSchedule,
};
pub use inference::{
    verify_inference_receipt_and_consume, InferenceExecutionPlan, InferenceJob, InferenceJobState,
    InferenceOutcome, InferenceReceiptAuthorization, InferenceReceiptValidationContext,
    InferenceStageAssignment, InferenceStageKind, InferenceStageReceipt,
};
pub use governance::{
    verify_governance_action_and_consume, GovernanceAction, GovernanceAuthorization,
    GovernanceValidationContext,
};
pub use kv_cache::{
    verify_kv_replica_receipt_and_consume, KvCacheLease, KvReplicaReceipt,
    KvReplicaReceiptAuthorization, KvReplicaReceiptValidationContext, MAX_KV_REPLICAS,
};
pub use migration::{
    verify_binding_and_consume, LegacyChain, LegacyIdentityBinding, LegacyProofVerifier,
    MigrationAuthorization, MigrationError, MigrationValidationContext,
};
pub use model_shard::{
    verify_model_upgrade_and_consume, ModelLineageTransition, ModelManifestCommitment,
    ModelShardOutput, ModelUpgradeAuthorization, ModelUpgradeValidationContext,
};
pub use network::{
    derive_directional_transport_session_keys, establish_authenticated_shared_secret,
    validate_shared_secret,
    ClassicalKexScheme, HybridSharedSecret, InMemoryTransportReplayGuard, MlKem1024Provider,
    MlKemSharedSecret, RekeyPolicy, SecretBytes, TransportPeerAuthorization,
    TransportPeerAuthorizationValidationContext, TransportPeerIdentity, TransportPolicy,
    TransportRecordSequence, TransportReplayGuard, TransportRole, TransportSessionKey,
    TransportSessionKeys, TransportTranscript,
    TransportValidationContext,
    CLASSICAL_SHARED_SECRET_BYTES,
    MAX_REKEY_MESSAGES,
    MAX_REKEY_SECONDS, ML_KEM_1024_CIPHERTEXT_BYTES, ML_KEM_1024_PROTOCOL_CODE,
    ML_KEM_1024_PUBLIC_KEY_BYTES, ML_KEM_SHARED_SECRET_BYTES, SECP256K1_KEX_PUBLIC_KEY_BYTES,
    TRANSPORT_RECORD_NONCE_BYTES, TRANSPORT_TRANSCRIPT_DOMAIN,
    X25519_PUBLIC_KEY_BYTES,
};
pub use nexus::{
    infer_reference_metered, NexusError, NexusManifest, NexusMode, NexusRequest, NexusResponse,
};
pub use payment_funding::{
    FundedSettlementCommitment, FundingStatus, PaymentFundingConsumptionReceipt,
    PaymentFundingReleaseReceipt, PaymentFundingReservation,
};
pub use payments::{
    verify_payment_intent_and_consume, verify_settlement_batch_and_consume, PaymentIntent, PaymentIntentAuthorization,
    PaymentIntentValidationContext, PaymentLaneKey, PaymentRail, SettlementBatch,
    SettlementBatchAuthorization, SettlementBatchValidationContext, SettlementState,
};
pub use pq::{
    authorization_keyset_commitment, primary_account_identity_commitment, sign_envelope_evidence,
    AuthPolicy, AuthScheme,
    AuthorizationDomain, AuthorizationEnvelope, AuthorizationReplayState,
    AuthorizationValidationContext, ContextSignatureSigner, ContextSignatureVerifier,
    HybridAuthorization, PqSigningKeyHandle,
    SchemeRoutedVerifier, SignatureEvidence, CRYPTO_PROFILE_VERSION, ED25519_PUBLIC_KEY_BYTES,
    ED25519_SIGNATURE_BYTES, MAX_AUTHORIZATION_EVIDENCE_BYTES, ML_DSA_87_PUBLIC_KEY_BYTES,
    ML_DSA_87_SIGNATURE_BYTES,
    SECP256K1_PUBLIC_KEY_BYTES, SECP256K1_SIGNATURE_BYTES,
    SLH_DSA_SHAKE_256S_PUBLIC_KEY_BYTES, SLH_DSA_SHAKE_256S_SIGNATURE_BYTES,
};
#[cfg(feature = "reference-pq")]
pub use pq_reference::{
    MlKemSecretHandle, ReferenceMlKem1024Provider, ReferencePqSignatureVerifier, ReferencePqSigner,
};
pub use scheduling::{can_host, choose_node, placement_score, NodeCapacity, NodeClass, WorkRequirements};
pub use service_planes::{
    verify_service_plane_checkpoint_with_finality_and_consume, ServiceFinalityBatch,
    ServiceFinalityItem, ServiceFinalityKind, ServicePlaneCapacityEnvelope,
    ServicePlaneCheckpointAuthorization, ServicePlaneCheckpointValidationContext,
    ServicePlaneRoots, MAX_SERVICE_FINALITY_ITEMS,
};
pub use storage::{
    verify_storage_proof_and_consume, ArchiveReceipt, DedupReceipt, DedupScope, ErasurePlacementReceipt,
    ProofOfStorageReceipt, StorageBid, StorageClass, StorageProofAuthorization,
    StorageProofValidationContext,
};
pub use tx::{PqEvmTransaction, TxError, TxValidationContext, MAX_TX_CALLDATA_BYTES};
pub use validator::{
    verify_validator_vote_and_consume, ValidatorIdentity, ValidatorPolicy,
    ValidatorVoteAuthorization, ValidatorVoteValidationContext,
};
pub use verification::{
    verify_verifier_receipt_and_consume, VerificationAggregate, VerificationChallenge, VerificationVerdict,
    VerifierReceipt, VerifierReceiptAuthorization, VerifierReceiptValidationContext,
};

/// Consensus version for the first integrated SYNERGY PQ-EVM/NEXUS world-compute profile.
pub const CONSENSUS_PROFILE: &str = "SYNERGY-PQ-EVM-NEXUS/2";
