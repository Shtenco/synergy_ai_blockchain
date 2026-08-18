#![forbid(unsafe_code)]

pub mod consensus;
pub mod migration;
pub mod network;
pub mod nexus;
pub mod pq;
pub mod tx;
pub mod validator;

pub use consensus::{PrecompileAddress, PrecompileGasSchedule};
pub use migration::{LegacyChain, LegacyIdentityBinding};
pub use network::{HybridSharedSecret, TransportPolicy};
pub use nexus::{NexusManifest, NexusMode, NexusRequest, NexusResponse};
pub use pq::{AuthPolicy, AuthScheme, HybridAuthorization};
pub use tx::PqEvmTransaction;
pub use validator::{ValidatorIdentity, ValidatorPolicy};

/// Consensus version for the first SYNERGY PQ-EVM/NEXUS execution profile.
pub const CONSENSUS_PROFILE: &str = "SYNERGY-PQ-EVM-NEXUS/1";
