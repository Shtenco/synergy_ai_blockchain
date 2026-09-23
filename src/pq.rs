use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthScheme {
    Secp256k1,
    Ed25519,
    MlDsa87,
    SlhDsaShake256s,
}

pub const CRYPTO_PROFILE_VERSION: u16 = 1;
pub const MAX_AUTHORIZATION_LIFETIME_SECONDS: u64 = 86_400;
pub const SECP256K1_PUBLIC_KEY_BYTES: usize = 33;
pub const SECP256K1_SIGNATURE_BYTES: usize = 65;
pub const ED25519_PUBLIC_KEY_BYTES: usize = 32;
pub const ED25519_SIGNATURE_BYTES: usize = 64;
pub const ML_DSA_87_PUBLIC_KEY_BYTES: usize = 2592;
pub const ML_DSA_87_SIGNATURE_BYTES: usize = 4627;
pub const SLH_DSA_SHAKE_256S_PUBLIC_KEY_BYTES: usize = 64;
pub const SLH_DSA_SHAKE_256S_SIGNATURE_BYTES: usize = 29792;
const SECP256K1_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
    0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];
const SECP256K1_HALF_ORDER: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d,
    0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];

fn scalar_is_nonzero_and_below(value: &[u8], upper_exclusive: &[u8; 32]) -> bool {
    value.len() == 32
        && value.iter().any(|byte| *byte != 0)
        && value < upper_exclusive.as_slice()
}

fn scalar_is_nonzero_and_at_most(value: &[u8], upper_inclusive: &[u8; 32]) -> bool {
    value.len() == 32
        && value.iter().any(|byte| *byte != 0)
        && value <= upper_inclusive.as_slice()
}

fn is_canonical_secp256k1_signature(signature: &[u8]) -> bool {
    if signature.len() != SECP256K1_SIGNATURE_BYTES {
        return false;
    }
    let (compact, recovery) = signature.split_at(64);
    let (r, s) = compact.split_at(32);
    scalar_is_nonzero_and_below(r, &SECP256K1_ORDER)
        && scalar_is_nonzero_and_at_most(s, &SECP256K1_HALF_ORDER)
        && recovery.len() == 1
        && (recovery[0] == 0 || recovery[0] == 1)
}

pub const MAX_AUTHORIZATION_EVIDENCE_BYTES: usize =
    SECP256K1_PUBLIC_KEY_BYTES
    + SECP256K1_SIGNATURE_BYTES
    + ML_DSA_87_PUBLIC_KEY_BYTES
    + ML_DSA_87_SIGNATURE_BYTES
    + SLH_DSA_SHAKE_256S_PUBLIC_KEY_BYTES
    + SLH_DSA_SHAKE_256S_SIGNATURE_BYTES;

impl AuthScheme {
    pub const fn active_in_crypto_profile_v1(self) -> bool {
        matches!(
            self,
            Self::Secp256k1 | Self::MlDsa87 | Self::SlhDsaShake256s
        )
    }

    pub const fn protocol_code(self) -> u8 {
        match self {
            Self::Secp256k1 => 1,
            Self::Ed25519 => 2,
            Self::MlDsa87 => 3,
            Self::SlhDsaShake256s => 4,
        }
    }

    pub fn expected_public_key_bytes(self) -> Option<usize> {
        match self {
            Self::Secp256k1 => Some(SECP256K1_PUBLIC_KEY_BYTES),
            Self::Ed25519 => Some(ED25519_PUBLIC_KEY_BYTES),
            Self::MlDsa87 => Some(ML_DSA_87_PUBLIC_KEY_BYTES),
            Self::SlhDsaShake256s => Some(SLH_DSA_SHAKE_256S_PUBLIC_KEY_BYTES),
        }
    }

    pub fn expected_signature_bytes(self) -> Option<usize> {
        match self {
            Self::Secp256k1 => Some(SECP256K1_SIGNATURE_BYTES),
            Self::Ed25519 => Some(ED25519_SIGNATURE_BYTES),
            Self::MlDsa87 => Some(ML_DSA_87_SIGNATURE_BYTES),
            Self::SlhDsaShake256s => Some(SLH_DSA_SHAKE_256S_SIGNATURE_BYTES),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthPolicy {
    /// EVM compatibility plus mandatory ML-DSA.
    Online,
    /// Classical compatibility plus two independent PQ signature families.
    Max,
    /// Pure PQ account mode for native SYNERGY accounts.
    PqOnly,
}

impl AuthPolicy {
    pub const fn protocol_code(self) -> u8 {
        match self {
            Self::Online => 1,
            Self::Max => 2,
            Self::PqOnly => 3,
        }
    }

    pub const fn required_schemes(self) -> &'static [AuthScheme] {
        const ONLINE: &[AuthScheme] = &[AuthScheme::Secp256k1, AuthScheme::MlDsa87];
        const MAX: &[AuthScheme] = &[
            AuthScheme::Secp256k1,
            AuthScheme::MlDsa87,
            AuthScheme::SlhDsaShake256s,
        ];
        const PQ_ONLY: &[AuthScheme] = &[AuthScheme::MlDsa87, AuthScheme::SlhDsaShake256s];

        match self {
            Self::Online => ONLINE,
            Self::Max => MAX,
            Self::PqOnly => PQ_ONLY,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorizationDomain {
    Transaction,
    ValidatorVote,
    BridgeMigration,
    ModelUpgrade,
    InferenceReceipt,
    Governance,
    VerificationReceipt,
    ConsensusActivation,
    ServicePlaneCheckpoint,
    AutopilotExecution,
    PaymentIntent,
    SettlementBatch,
    StorageProof,
    CognitiveEvidence,
}

impl AuthorizationDomain {
    pub const fn max_lifetime_seconds(self) -> u64 {
        let _ = self;
        MAX_AUTHORIZATION_LIFETIME_SECONDS
    }

    pub const fn protocol_code(self) -> u8 {
        match self {
            Self::Transaction => 1,
            Self::ValidatorVote => 2,
            Self::BridgeMigration => 3,
            Self::ModelUpgrade => 4,
            Self::InferenceReceipt => 5,
            Self::Governance => 6,
            Self::VerificationReceipt => 7,
            Self::ConsensusActivation => 8,
            Self::ServicePlaneCheckpoint => 9,
            Self::AutopilotExecution => 10,
            Self::PaymentIntent => 11,
            Self::SettlementBatch => 12,
            Self::StorageProof => 13,
            Self::CognitiveEvidence => 14,
        }
    }
}

/// Canonical authorization message envelope.
///
/// Signatures cover chain, action domain, authorization policy, epoch, nonce,
/// expiry and the payload commitment. This prevents a valid signature from
/// being replayed across domains or reinterpreted under a weaker policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizationEnvelope {
    pub chain_id: [u8; 32],
    pub domain: AuthorizationDomain,
    pub epoch: u64,
    pub nonce: u64,
    pub expires_at: u64,
    pub payload_commitment: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthorizationValidationContext {
    pub expected_chain_id: [u8; 32],
    pub expected_domain: AuthorizationDomain,
    pub expected_policy: AuthPolicy,
    pub expected_epoch: u64,
    pub expected_nonce: u64,
    pub now: u64,
    pub max_future_seconds: u64,
}


#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizationReplayState {
    chain_id: [u8; 32],
    domain: AuthorizationDomain,
    policy: AuthPolicy,
    epoch: u64,
    next_nonce: u64,
}

impl AuthorizationReplayState {
    pub fn new(
        chain_id: [u8; 32],
        domain: AuthorizationDomain,
        policy: AuthPolicy,
        epoch: u64,
        next_nonce: u64,
    ) -> Option<Self> {
        if chain_id == [0u8; 32] || epoch == 0 {
            return None;
        }
        Some(Self {
            chain_id,
            domain,
            policy,
            epoch,
            next_nonce,
        })
    }

    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    pub const fn next_nonce(&self) -> u64 {
        self.next_nonce
    }

    pub fn rotate_epoch(&mut self, new_epoch: u64, next_nonce: u64) -> bool {
        if new_epoch <= self.epoch {
            return false;
        }
        self.epoch = new_epoch;
        self.next_nonce = next_nonce;
        true
    }

    pub fn verify_and_consume<V: ContextSignatureVerifier>(
        &mut self,
        verifier: &V,
        authorization: &HybridAuthorization,
        envelope: &AuthorizationEnvelope,
        now: u64,
        max_future_seconds: u64,
    ) -> bool {
        let advanced_nonce = match self.next_nonce.checked_add(1) {
            Some(nonce) => nonce,
            None => return false,
        };

        let validation = AuthorizationValidationContext {
            expected_chain_id: self.chain_id,
            expected_domain: self.domain,
            expected_policy: self.policy,
            expected_epoch: self.epoch,
            expected_nonce: self.next_nonce,
            now,
            max_future_seconds,
        };

        if !verify_envelope_authorization(
            verifier,
            authorization,
            envelope,
            &validation,
        ) {
            return false;
        }

        self.next_nonce = advanced_nonce;
        true
    }
}

fn append_policy_suite(out: &mut Vec<u8>, policy: AuthPolicy) {
    let schemes = policy.required_schemes();
    let scheme_count = match policy {
        AuthPolicy::Online => 2u8,
        AuthPolicy::Max => 3u8,
        AuthPolicy::PqOnly => 2u8,
    };
    out.push(scheme_count);
    for scheme in schemes {
        out.push(scheme.protocol_code());
    }
}

impl AuthorizationEnvelope {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.chain_id == [0; 32] || self.payload_commitment == [0; 32] {
            return Err("authorization commitments required");
        }
        if self.expires_at == 0 {
            return Err("authorization expiry required");
        }
        Ok(())
    }

    pub fn validate_in_context(
        &self,
        context: &AuthorizationValidationContext,
    ) -> Result<(), &'static str> {
        self.validate()?;
        if self.chain_id != context.expected_chain_id {
            return Err("authorization chain mismatch");
        }
        if self.domain != context.expected_domain {
            return Err("authorization domain mismatch");
        }
        if self.epoch != context.expected_epoch {
            return Err("authorization epoch mismatch");
        }
        if self.nonce != context.expected_nonce {
            return Err("authorization nonce mismatch");
        }
        if context.now >= self.expires_at {
            return Err("authorization expired");
        }
        if context.max_future_seconds == 0 {
            return Err("authorization lifetime policy required");
        }
        if context.max_future_seconds > self.domain.max_lifetime_seconds() {
            return Err("authorization lifetime policy exceeds protocol ceiling");
        }
        let remaining = self
            .expires_at
            .checked_sub(context.now)
            .ok_or("authorization expired")?;
        if remaining > context.max_future_seconds {
            return Err("authorization expiry exceeds policy horizon");
        }
        Ok(())
    }

    pub fn canonical_message(&self, policy: AuthPolicy) -> Result<Vec<u8>, &'static str> {
        self.validate()?;
        const PREFIX: &[u8] = b"SYNERGY/PQ-AUTH\0";
        let mut out = Vec::with_capacity(PREFIX.len() + 2 + 32 + 2 + 8 * 3 + 32);
        out.extend_from_slice(PREFIX);
        out.extend_from_slice(&CRYPTO_PROFILE_VERSION.to_be_bytes());
        out.extend_from_slice(&self.chain_id);
        out.push(self.domain.protocol_code());
        out.push(policy.protocol_code());
        append_policy_suite(&mut out, policy);
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(&self.nonce.to_be_bytes());
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        out.extend_from_slice(&self.payload_commitment);
        Ok(out)
    }

    /// FIPS 204/205 context for the PQ signature lanes.
    ///
    /// The context is intentionally independent from the canonical message.
    /// It binds the cryptographic signature API to the SYNERGY protocol,
    /// chain, authorization domain and policy a second time. Epoch/nonce/expiry
    /// remain in the canonical message so the context stays a short protocol
    /// namespace rather than a per-signature transcript.
    pub fn fips_signature_context(
        &self,
        policy: AuthPolicy,
    ) -> Result<Vec<u8>, &'static str> {
        self.validate()?;
        Ok(fips_signature_context(&self.chain_id, self.domain, policy))
    }
}

pub fn fips_signature_context(
    chain_id: &[u8; 32],
    domain: AuthorizationDomain,
    policy: AuthPolicy,
) -> Vec<u8> {
    const PREFIX: &[u8] = b"SYNERGY/PQ-FIPS-CONTEXT\0";
    let mut out = Vec::with_capacity(PREFIX.len() + 2 + 32 + 2);
    out.extend_from_slice(PREFIX);
    out.extend_from_slice(&CRYPTO_PROFILE_VERSION.to_be_bytes());
    out.extend_from_slice(chain_id);
    out.push(domain.protocol_code());
    out.push(policy.protocol_code());
    append_policy_suite(&mut out, policy);
    out
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignatureEvidence {
    pub scheme: AuthScheme,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HybridAuthorization {
    pub policy: AuthPolicy,
    pub evidence: Vec<SignatureEvidence>,
}

pub fn primary_account_identity_commitment(
    ml_dsa87_public_key: &[u8],
) -> Option<[u8; 32]> {
    if ml_dsa87_public_key.len() != ML_DSA_87_PUBLIC_KEY_BYTES
        || ml_dsa87_public_key.iter().all(|byte| *byte == 0)
    {
        return None;
    }

    const DOMAIN: &[u8] = b"SYNERGY/PQ-PRIMARY-ACCOUNT/V1\0";
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN);
    hasher.update(CRYPTO_PROFILE_VERSION.to_be_bytes());
    hasher.update([AuthScheme::MlDsa87.protocol_code()]);
    let public_key_len = u64::try_from(ml_dsa87_public_key.len()).ok()?;
    hasher.update(public_key_len.to_be_bytes());
    hasher.update(ml_dsa87_public_key);
    Some(hasher.finalize().into())
}

pub fn authorization_keyset_commitment<'a, I>(
    policy: AuthPolicy,
    keys: I,
) -> Option<[u8; 32]>
where
    I: IntoIterator<Item = (AuthScheme, &'a [u8])>,
{
    let required = policy.required_schemes();
    let mut keys = keys.into_iter();

    const DOMAIN: &[u8] = b"SYNERGY/PQ-AUTH-KEYSET/V1\0";
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN);
    hasher.update(CRYPTO_PROFILE_VERSION.to_be_bytes());
    hasher.update([policy.protocol_code()]);
    let required_count = match policy {
        AuthPolicy::Online => 2u8,
        AuthPolicy::Max => 3u8,
        AuthPolicy::PqOnly => 2u8,
    };
    hasher.update([required_count]);

    for required_scheme in required {
        let (scheme, public_key) = keys.next()?;
        if scheme != *required_scheme {
            return None;
        }
        let expected = scheme.expected_public_key_bytes()?;
        if public_key.len() != expected || public_key.iter().all(|byte| *byte == 0) {
            return None;
        }
        if scheme == AuthScheme::Secp256k1
            && !matches!(public_key.first(), Some(0x02 | 0x03))
        {
            return None;
        }

        hasher.update([scheme.protocol_code()]);
        let public_key_len = u64::try_from(public_key.len()).ok()?;
        hasher.update(public_key_len.to_be_bytes());
        hasher.update(public_key);
    }

    if keys.next().is_some() {
        return None;
    }

    Some(hasher.finalize().into())
}

impl HybridAuthorization {
    pub fn required_schemes(&self) -> &'static [AuthScheme] {
        self.policy.required_schemes()
    }

    /// Canonical, fail-closed authorization shape.
    ///
    /// Exactly one non-empty evidence item is required for every scheme in the
    /// policy. Extra/duplicate lanes are rejected rather than ignored.
    pub fn validate_structure(&self) -> Result<(), &'static str> {
        let required = self.required_schemes();
        if self.evidence.len() != required.len() {
            return Err("authorization evidence count mismatch");
        }

        for (index, evidence) in self.evidence.iter().enumerate() {
            if !required.contains(&evidence.scheme) {
                return Err("authorization contains a scheme outside its policy");
            }
            if evidence.scheme != required[index] {
                return Err("authorization evidence order is noncanonical");
            }
            if evidence.public_key.is_empty() || evidence.signature.is_empty() {
                return Err("authorization evidence must contain key and signature bytes");
            }
            if evidence.public_key.iter().all(|byte| *byte == 0)
                || evidence.signature.iter().all(|byte| *byte == 0)
            {
                return Err("authorization evidence must not be all-zero");
            }

            if let Some(expected) = evidence.scheme.expected_public_key_bytes() {
                if evidence.public_key.len() != expected {
                    return Err("authorization public key length mismatch");
                }
            }
            if let Some(expected) = evidence.scheme.expected_signature_bytes() {
                if evidence.signature.len() != expected {
                    return Err("authorization signature length mismatch");
                }
            }

            if evidence.scheme == AuthScheme::Secp256k1 {
                if !matches!(evidence.public_key.first(), Some(0x02 | 0x03)) {
                    return Err("secp256k1 public key must use compressed encoding");
                }
                if !is_canonical_secp256k1_signature(&evidence.signature) {
                    return Err("secp256k1 signature must use canonical low-S encoding");
                }
            }

            if self.evidence[..index]
                .iter()
                .any(|prior| prior.scheme == evidence.scheme)
            {
                return Err("duplicate authorization scheme");
            }
        }

        if required
            .iter()
            .any(|required_scheme| !self.evidence.iter().any(|e| e.scheme == *required_scheme))
        {
            return Err("required authorization scheme missing");
        }

        let total_evidence_bytes = self.evidence.iter().try_fold(0usize, |acc, evidence| {
            acc.checked_add(evidence.public_key.len())?
                .checked_add(evidence.signature.len())
        });
        if total_evidence_bytes
            .map(|bytes| bytes > MAX_AUTHORIZATION_EVIDENCE_BYTES)
            .unwrap_or(true)
        {
            return Err("authorization evidence exceeds protocol byte budget");
        }

        Ok(())
    }

    pub fn keyset_commitment(&self) -> Option<[u8; 32]> {
        self.validate_structure().ok()?;
        authorization_keyset_commitment(
            self.policy,
            self.evidence
                .iter()
                .map(|evidence| (evidence.scheme, evidence.public_key.as_slice())),
        )
    }

    pub fn primary_account_identity_commitment(&self) -> Option<[u8; 32]> {
        self.validate_structure().ok()?;
        let ml_dsa = self
            .evidence
            .iter()
            .find(|evidence| evidence.scheme == AuthScheme::MlDsa87)?;
        primary_account_identity_commitment(&ml_dsa.public_key)
    }

    pub fn structurally_complete(&self) -> bool {
        self.validate_structure().is_ok()
    }
}

pub trait SignatureVerifier {
    fn verify(&self, scheme: AuthScheme, public_key: &[u8], message: &[u8], signature: &[u8]) -> bool;
}

/// Context-aware verification boundary for FIPS 204/205 signature lanes.
///
/// Classical algorithms do not gain FIPS context semantics. Scheme routing below
/// sends the context only to the PQ backend while classical verification continues
/// to authenticate the already domain-separated canonical message.
pub trait ContextSignatureVerifier {
    fn verify_with_context(
        &self,
        scheme: AuthScheme,
        public_key: &[u8],
        message: &[u8],
        context: &[u8],
        signature: &[u8],
    ) -> bool;
}


/// Opaque handle used by post-quantum signing providers.
///
/// Protocol code never receives raw private-key bytes. A provider may back this
/// handle with an in-process zeroizing key, an OS keystore, HSM or remote signer.
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PqSigningKeyHandle([u8; 32]);

impl PqSigningKeyHandle {
    pub(crate) fn from_random_bytes(bytes: [u8; 32]) -> Option<Self> {
        (bytes != [0u8; 32]).then_some(Self(bytes))
    }

    pub(crate) fn as_id_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[cfg(test)]
    pub(crate) fn is_zero(&self) -> bool {
        self.0 == [0u8; 32]
    }
}

impl Drop for PqSigningKeyHandle {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
    }
}

/// Context-aware signing boundary for the FIPS 204/205 lanes.
///
/// Implementations own private-key custody. Callers receive only public keys,
/// signatures and opaque handles.
pub trait ContextSignatureSigner {
    fn generate_keypair(
        &mut self,
        scheme: AuthScheme,
    ) -> Option<(PqSigningKeyHandle, Vec<u8>)>;

    fn public_key(
        &self,
        scheme: AuthScheme,
        secret_key_handle: &PqSigningKeyHandle,
    ) -> Option<Vec<u8>>;

    fn sign_with_context(
        &self,
        scheme: AuthScheme,
        secret_key_handle: &PqSigningKeyHandle,
        message: &[u8],
        context: &[u8],
    ) -> Option<Vec<u8>>;

    fn remove_key(
        &mut self,
        scheme: AuthScheme,
        secret_key_handle: &PqSigningKeyHandle,
    ) -> bool;
}

/// Produce one PQ signature-evidence lane from an authorization envelope without
/// exposing private-key material to protocol code.
pub fn sign_envelope_evidence<S: ContextSignatureSigner>(
    signer: &S,
    scheme: AuthScheme,
    secret_key_handle: &PqSigningKeyHandle,
    policy: AuthPolicy,
    envelope: &AuthorizationEnvelope,
) -> Option<SignatureEvidence> {
    if !matches!(scheme, AuthScheme::MlDsa87 | AuthScheme::SlhDsaShake256s) {
        return None;
    }

    let public_key = signer.public_key(scheme, secret_key_handle)?;
    if public_key.is_empty() {
        return None;
    }

    let message = envelope.canonical_message(policy).ok()?;
    let context = envelope.fips_signature_context(policy).ok()?;
    let signature = signer.sign_with_context(
        scheme,
        secret_key_handle,
        &message,
        &context,
    )?;

    if signature.is_empty() {
        return None;
    }

    Some(SignatureEvidence {
        scheme,
        public_key,
        signature,
    })
}

/// Routes classical and post-quantum signature families to separate backends.
///
/// This is deliberately scheme-routed rather than "try backend A OR backend B";
/// a PQ backend can never accidentally satisfy the classical lane and vice versa.
pub struct SchemeRoutedVerifier<C, P> {
    pub classical: C,
    pub pq: P,
}

impl<C: SignatureVerifier, P: SignatureVerifier> SignatureVerifier for SchemeRoutedVerifier<C, P> {
    fn verify(
        &self,
        scheme: AuthScheme,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> bool {
        match scheme {
            AuthScheme::Secp256k1 | AuthScheme::Ed25519 => {
                self.classical.verify(scheme, public_key, message, signature)
            }
            AuthScheme::MlDsa87 | AuthScheme::SlhDsaShake256s => {
                self.pq.verify(scheme, public_key, message, signature)
            }
        }
    }
}

impl<C: SignatureVerifier, P: ContextSignatureVerifier> ContextSignatureVerifier
    for SchemeRoutedVerifier<C, P>
{
    fn verify_with_context(
        &self,
        scheme: AuthScheme,
        public_key: &[u8],
        message: &[u8],
        context: &[u8],
        signature: &[u8],
    ) -> bool {
        match scheme {
            AuthScheme::Secp256k1 | AuthScheme::Ed25519 => {
                self.classical.verify(scheme, public_key, message, signature)
            }
            AuthScheme::MlDsa87 | AuthScheme::SlhDsaShake256s => {
                self.pq
                    .verify_with_context(scheme, public_key, message, context, signature)
            }
        }
    }
}

#[cfg(test)]
pub(crate) fn verify_authorization<V: SignatureVerifier>(
    verifier: &V,
    authorization: &HybridAuthorization,
    message: &[u8],
) -> bool {
    if authorization.validate_structure().is_err() {
        return false;
    }
    authorization.required_schemes().iter().all(|required| {
        authorization
            .evidence
            .iter()
            .find(|e| &e.scheme == required)
            .map(|e| verifier.verify(e.scheme, &e.public_key, message, &e.signature))
            .unwrap_or(false)
    })
}

pub(crate) fn verify_authorization_with_context<V: ContextSignatureVerifier>(
    verifier: &V,
    authorization: &HybridAuthorization,
    message: &[u8],
    context: &[u8],
) -> bool {
    if context.len() > 255 || authorization.validate_structure().is_err() {
        return false;
    }
    authorization.required_schemes().iter().all(|required| {
        authorization
            .evidence
            .iter()
            .find(|e| &e.scheme == required)
            .map(|e| {
                verifier.verify_with_context(
                    e.scheme,
                    &e.public_key,
                    message,
                    context,
                    &e.signature,
                )
            })
            .unwrap_or(false)
    })
}

pub fn verify_envelope_authorization<V: ContextSignatureVerifier>(
    verifier: &V,
    authorization: &HybridAuthorization,
    envelope: &AuthorizationEnvelope,
    validation: &AuthorizationValidationContext,
) -> bool {
    if envelope.validate_in_context(validation).is_err()
        || authorization.policy != validation.expected_policy
    {
        return false;
    }

    let message = match envelope.canonical_message(authorization.policy) {
        Ok(message) => message,
        Err(_) => return false,
    };
    let context = match envelope.fips_signature_context(authorization.policy) {
        Ok(context) => context,
        Err(_) => return false,
    };

    verify_authorization_with_context(
        verifier,
        authorization,
        &message,
        &context,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone)]
    struct ReplayVerifier {
        message: Vec<u8>,
        context: Vec<u8>,
    }

    impl ContextSignatureVerifier for ReplayVerifier {
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


    fn evidence(scheme: AuthScheme) -> SignatureEvidence {
        let mut public_key = vec![1; scheme.expected_public_key_bytes().unwrap_or(1)];
        let mut signature = vec![2; scheme.expected_signature_bytes().unwrap_or(1)];
        if scheme == AuthScheme::Secp256k1 {
            public_key[0] = 0x02;
            signature.fill(0);
            signature[31] = 1;
            signature[63] = 1;
            signature[64] = 0;
        }
        SignatureEvidence {
            scheme,
            public_key,
            signature,
        }
    }

    #[test]
    fn authorization_byte_budget_matches_exact_max_policy_suite() {
        assert_eq!(MAX_AUTHORIZATION_EVIDENCE_BYTES, 37_173);

        let auth = HybridAuthorization {
            policy: AuthPolicy::Max,
            evidence: vec![
                evidence(AuthScheme::Secp256k1),
                evidence(AuthScheme::MlDsa87),
                evidence(AuthScheme::SlhDsaShake256s),
            ],
        };
        let total: usize = auth
            .evidence
            .iter()
            .map(|e| e.public_key.len() + e.signature.len())
            .sum();
        assert_eq!(total, MAX_AUTHORIZATION_EVIDENCE_BYTES);
        assert!(auth.validate_structure().is_ok());
    }

    #[test]
    fn max_is_fail_closed() {
        let auth = HybridAuthorization {
            policy: AuthPolicy::Max,
            evidence: vec![
                evidence(AuthScheme::Secp256k1),
                evidence(AuthScheme::MlDsa87),
            ],
        };
        assert!(!auth.structurally_complete());
    }

    #[test]
    fn pq_only_does_not_require_ecc() {
        let auth = HybridAuthorization {
            policy: AuthPolicy::PqOnly,
            evidence: vec![
                evidence(AuthScheme::MlDsa87),
                evidence(AuthScheme::SlhDsaShake256s),
            ],
        };
        assert!(auth.structurally_complete());
    }

    #[test]
    fn reordered_required_schemes_are_rejected_as_noncanonical() {
        let auth = HybridAuthorization {
            policy: AuthPolicy::PqOnly,
            evidence: vec![
                evidence(AuthScheme::SlhDsaShake256s),
                evidence(AuthScheme::MlDsa87),
            ],
        };
        assert!(auth.validate_structure().is_err());
    }

    #[test]
    fn keyset_identity_can_be_derived_without_signature_bytes() {
        let ml = vec![0x31; ML_DSA_87_PUBLIC_KEY_BYTES];
        let slh = vec![0x32; SLH_DSA_SHAKE_256S_PUBLIC_KEY_BYTES];
        let keys = [
            (AuthScheme::MlDsa87, ml.as_slice()),
            (AuthScheme::SlhDsaShake256s, slh.as_slice()),
        ];

        let direct = authorization_keyset_commitment(AuthPolicy::PqOnly, keys)
            .expect("direct keyset commitment");

        let auth = HybridAuthorization {
            policy: AuthPolicy::PqOnly,
            evidence: vec![
                SignatureEvidence {
                    scheme: AuthScheme::MlDsa87,
                    public_key: ml,
                    signature: vec![0x41; ML_DSA_87_SIGNATURE_BYTES],
                },
                SignatureEvidence {
                    scheme: AuthScheme::SlhDsaShake256s,
                    public_key: slh,
                    signature: vec![0x42; SLH_DSA_SHAKE_256S_SIGNATURE_BYTES],
                },
            ],
        };
        assert_eq!(direct, auth.keyset_commitment().expect("authorization keyset"));
    }

    #[test]
    fn primary_account_identity_is_stable_across_authorization_policies() {
        let online = HybridAuthorization {
            policy: AuthPolicy::Online,
            evidence: vec![
                evidence(AuthScheme::Secp256k1),
                evidence(AuthScheme::MlDsa87),
            ],
        };
        let pq_only = HybridAuthorization {
            policy: AuthPolicy::PqOnly,
            evidence: vec![
                evidence(AuthScheme::MlDsa87),
                evidence(AuthScheme::SlhDsaShake256s),
            ],
        };
        let max = HybridAuthorization {
            policy: AuthPolicy::Max,
            evidence: vec![
                evidence(AuthScheme::Secp256k1),
                evidence(AuthScheme::MlDsa87),
                evidence(AuthScheme::SlhDsaShake256s),
            ],
        };

        let identity = online
            .primary_account_identity_commitment()
            .expect("online primary identity");
        assert_eq!(
            identity,
            pq_only
                .primary_account_identity_commitment()
                .expect("PQ-only primary identity")
        );
        assert_eq!(
            identity,
            max.primary_account_identity_commitment()
                .expect("MAX primary identity")
        );

        assert_ne!(
            online.keyset_commitment().expect("online keyset"),
            pq_only.keyset_commitment().expect("PQ-only keyset"),
        );
    }

    #[test]
    fn authorization_keyset_commitment_is_canonical_and_key_bound() {
        let auth = HybridAuthorization {
            policy: AuthPolicy::PqOnly,
            evidence: vec![
                evidence(AuthScheme::MlDsa87),
                evidence(AuthScheme::SlhDsaShake256s),
            ],
        };
        let base = auth.keyset_commitment().expect("keyset commitment");

        let mut changed = auth.clone();
        changed.evidence[0].public_key[0] ^= 1;
        assert_ne!(
            base,
            changed.keyset_commitment().expect("changed keyset commitment")
        );

        let mut reordered = auth;
        reordered.evidence.swap(0, 1);
        assert!(reordered.keyset_commitment().is_none());
    }

    #[test]
    fn duplicate_scheme_is_rejected() {
        let auth = HybridAuthorization {
            policy: AuthPolicy::PqOnly,
            evidence: vec![
                evidence(AuthScheme::MlDsa87),
                evidence(AuthScheme::MlDsa87),
            ],
        };
        assert!(auth.validate_structure().is_err());
    }

    #[test]
    fn extra_scheme_is_rejected_instead_of_ignored() {
        let auth = HybridAuthorization {
            policy: AuthPolicy::Online,
            evidence: vec![
                evidence(AuthScheme::Secp256k1),
                evidence(AuthScheme::MlDsa87),
                evidence(AuthScheme::Ed25519),
            ],
        };
        assert!(auth.validate_structure().is_err());
    }

    #[test]
    fn classical_evidence_requires_canonical_exact_lengths() {
        let auth = HybridAuthorization {
            policy: AuthPolicy::Online,
            evidence: vec![
                SignatureEvidence {
                    scheme: AuthScheme::Secp256k1,
                    public_key: vec![0x02; SECP256K1_PUBLIC_KEY_BYTES + 1],
                    signature: {
                        let mut signature = vec![2; SECP256K1_SIGNATURE_BYTES];
                        signature[SECP256K1_SIGNATURE_BYTES - 1] = 0;
                        signature
                    },
                },
                evidence(AuthScheme::MlDsa87),
            ],
        };
        assert!(auth.validate_structure().is_err());

        let auth = HybridAuthorization {
            policy: AuthPolicy::Online,
            evidence: vec![
                SignatureEvidence {
                    scheme: AuthScheme::Secp256k1,
                    public_key: {
                        let mut key = vec![1; SECP256K1_PUBLIC_KEY_BYTES];
                        key[0] = 0x02;
                        key
                    },
                    signature: vec![2; SECP256K1_SIGNATURE_BYTES - 1],
                },
                evidence(AuthScheme::MlDsa87),
            ],
        };
        assert!(auth.validate_structure().is_err());
    }

    #[test]
    fn oversized_classical_evidence_is_rejected_before_backend_dispatch() {
        let auth = HybridAuthorization {
            policy: AuthPolicy::Online,
            evidence: vec![
                SignatureEvidence {
                    scheme: AuthScheme::Secp256k1,
                    public_key: vec![1; MAX_CLASSICAL_PUBLIC_KEY_BYTES + 1],
                    signature: vec![2; 64],
                },
                evidence(AuthScheme::MlDsa87),
            ],
        };
        assert!(auth.validate_structure().is_err());
    }

    #[test]
    fn secp256k1_encoding_prefix_recovery_and_low_s_are_canonical() {
        let mut bad_key = evidence(AuthScheme::Secp256k1);
        bad_key.public_key[0] = 0x04;
        let auth = HybridAuthorization {
            policy: AuthPolicy::Online,
            evidence: vec![bad_key, evidence(AuthScheme::MlDsa87)],
        };
        assert!(auth.validate_structure().is_err());

        let mut bad_recovery = evidence(AuthScheme::Secp256k1);
        let last = bad_recovery.signature.len() - 1;
        bad_recovery.signature[last] = 27;
        let auth = HybridAuthorization {
            policy: AuthPolicy::Online,
            evidence: vec![bad_recovery, evidence(AuthScheme::MlDsa87)],
        };
        assert!(auth.validate_structure().is_err());

        let mut high_s = evidence(AuthScheme::Secp256k1);
        high_s.signature[32..64].copy_from_slice(&SECP256K1_ORDER);
        high_s.signature[63] -= 1;
        let auth = HybridAuthorization {
            policy: AuthPolicy::Online,
            evidence: vec![high_s, evidence(AuthScheme::MlDsa87)],
        };
        assert!(auth.validate_structure().is_err());
    }

    #[test]
    fn all_zero_key_or_signature_material_is_rejected() {
        let mut bad = evidence(AuthScheme::MlDsa87);
        bad.public_key.fill(0);
        let auth = HybridAuthorization {
            policy: AuthPolicy::PqOnly,
            evidence: vec![bad, evidence(AuthScheme::SlhDsaShake256s)],
        };
        assert!(auth.validate_structure().is_err());
    }

    #[test]
    fn empty_evidence_is_rejected() {
        let mut bad = evidence(AuthScheme::MlDsa87);
        bad.signature.clear();
        let auth = HybridAuthorization {
            policy: AuthPolicy::PqOnly,
            evidence: vec![bad, evidence(AuthScheme::SlhDsaShake256s)],
        };
        assert!(auth.validate_structure().is_err());
    }

    #[test]
    fn crypto_profile_v1_keeps_ed25519_reserved_but_inactive() {
        assert!(!AuthScheme::Ed25519.active_in_crypto_profile_v1());
        assert_eq!(AuthScheme::Ed25519.protocol_code(), 2);

        for policy in [AuthPolicy::Online, AuthPolicy::Max, AuthPolicy::PqOnly] {
            assert!(!policy.required_schemes().contains(&AuthScheme::Ed25519));
            assert!(policy
                .required_schemes()
                .iter()
                .all(|scheme| scheme.active_in_crypto_profile_v1()));
        }
    }

    #[test]
    fn authorization_registry_codes_are_nonzero_and_unique() {
        let schemes = [
            AuthScheme::Secp256k1.protocol_code(),
            AuthScheme::Ed25519.protocol_code(),
            AuthScheme::MlDsa87.protocol_code(),
            AuthScheme::SlhDsaShake256s.protocol_code(),
        ];
        let policies = [
            AuthPolicy::Online.protocol_code(),
            AuthPolicy::Max.protocol_code(),
            AuthPolicy::PqOnly.protocol_code(),
        ];
        let domains = [
            AuthorizationDomain::Transaction.protocol_code(),
            AuthorizationDomain::ValidatorVote.protocol_code(),
            AuthorizationDomain::BridgeMigration.protocol_code(),
            AuthorizationDomain::ModelUpgrade.protocol_code(),
            AuthorizationDomain::InferenceReceipt.protocol_code(),
            AuthorizationDomain::Governance.protocol_code(),
            AuthorizationDomain::VerificationReceipt.protocol_code(),
            AuthorizationDomain::ConsensusActivation.protocol_code(),
            AuthorizationDomain::ServicePlaneCheckpoint.protocol_code(),
            AuthorizationDomain::AutopilotExecution.protocol_code(),
            AuthorizationDomain::PaymentIntent.protocol_code(),
            AuthorizationDomain::SettlementBatch.protocol_code(),
            AuthorizationDomain::StorageProof.protocol_code(),
            AuthorizationDomain::CognitiveEvidence.protocol_code(),
        ];

        for codes in [&schemes[..], &policies[..], &domains[..]] {
            assert!(codes.iter().all(|code| *code != 0));
            for (index, code) in codes.iter().enumerate() {
                assert!(!codes[..index].contains(code));
            }
        }
    }

    #[test]
    fn authorization_wire_format_matches_independent_known_answer() {
        use sha2::{Digest, Sha256};

        let envelope = AuthorizationEnvelope {
            chain_id: [1u8; 32],
            domain: AuthorizationDomain::Transaction,
            epoch: 5,
            nonce: 9,
            expires_at: 100,
            payload_commitment: [2u8; 32],
        };

        let message = envelope.canonical_message(AuthPolicy::PqOnly).unwrap();
        let context = envelope.fips_signature_context(AuthPolicy::PqOnly).unwrap();

        assert_eq!(message.len(), 111);
        assert_eq!(context.len(), 63);
        assert_eq!(
            hex::encode(Sha256::digest(&message)),
            "f1a8e0660f99db442f1e56becc05a1ae6e4dd18d14ede6233eefce9e5009ba16"
        );
        assert_eq!(
            hex::encode(Sha256::digest(&context)),
            "fb28450c0d70acfa64a0c5c04e963eb6bcf20661105431f6d244691162c0f8d5"
        );
    }

    #[test]
    fn policy_algorithm_suite_is_bound_into_message_and_context() {
        let envelope = AuthorizationEnvelope {
            chain_id: [0x21; 32],
            domain: AuthorizationDomain::Transaction,
            epoch: 1,
            nonce: 1,
            expires_at: 100,
            payload_commitment: [0x22; 32],
        };

        let pq_message = envelope.canonical_message(AuthPolicy::PqOnly).unwrap();
        let max_message = envelope.canonical_message(AuthPolicy::Max).unwrap();
        let pq_context = envelope.fips_signature_context(AuthPolicy::PqOnly).unwrap();
        let max_context = envelope.fips_signature_context(AuthPolicy::Max).unwrap();

        assert_ne!(pq_message, max_message);
        assert_ne!(pq_context, max_context);

        assert_eq!(
            AuthPolicy::PqOnly
                .required_schemes()
                .iter()
                .map(|scheme| scheme.protocol_code())
                .collect::<Vec<_>>(),
            vec![
                AuthScheme::MlDsa87.protocol_code(),
                AuthScheme::SlhDsaShake256s.protocol_code(),
            ],
        );
    }

    #[test]
    fn crypto_profile_version_is_bound_into_message_and_fips_context() {
        let envelope = AuthorizationEnvelope {
            chain_id: [0x31; 32],
            domain: AuthorizationDomain::Transaction,
            epoch: 1,
            nonce: 2,
            expires_at: 100,
            payload_commitment: [0x32; 32],
        };

        let message = envelope.canonical_message(AuthPolicy::PqOnly).unwrap();
        let context = envelope.fips_signature_context(AuthPolicy::PqOnly).unwrap();
        let version = CRYPTO_PROFILE_VERSION.to_be_bytes();

        assert!(message.windows(version.len()).any(|window| window == version));
        assert!(context.windows(version.len()).any(|window| window == version));
    }

    #[test]
    fn authorization_domain_and_policy_are_signed_data() {
        let base = AuthorizationEnvelope {
            chain_id: [1; 32],
            domain: AuthorizationDomain::Transaction,
            epoch: 5,
            nonce: 9,
            expires_at: 100,
            payload_commitment: [2; 32],
        };
        let tx_online = base.canonical_message(AuthPolicy::Online).unwrap();

        let mut other_domain = base.clone();
        other_domain.domain = AuthorizationDomain::ModelUpgrade;
        let model_online = other_domain.canonical_message(AuthPolicy::Online).unwrap();
        let tx_pq_only = base.canonical_message(AuthPolicy::PqOnly).unwrap();

        assert_ne!(tx_online, model_online);
        assert_ne!(tx_online, tx_pq_only);
    }

    #[test]
    fn fips_context_is_bounded_and_separated_from_chain_domain_and_policy() {
        let base = AuthorizationEnvelope {
            chain_id: [0xA5; 32],
            domain: AuthorizationDomain::Transaction,
            epoch: 5,
            nonce: 9,
            expires_at: 100,
            payload_commitment: [0x5A; 32],
        };

        let tx_online = base.fips_signature_context(AuthPolicy::Online).unwrap();
        assert!(tx_online.len() <= 255);

        let tx_pq = base.fips_signature_context(AuthPolicy::PqOnly).unwrap();
        assert_ne!(tx_online, tx_pq);

        let mut other_domain = base.clone();
        other_domain.domain = AuthorizationDomain::Governance;
        assert_ne!(
            tx_online,
            other_domain.fips_signature_context(AuthPolicy::Online).unwrap()
        );

        let mut other_chain = base.clone();
        other_chain.chain_id = [0xA6; 32];
        assert_ne!(
            tx_online,
            other_chain.fips_signature_context(AuthPolicy::Online).unwrap()
        );

        // Dynamic replay fields remain message-bound, not context-bound.
        let mut next_nonce = base.clone();
        next_nonce.nonce += 1;
        assert_eq!(
            tx_online,
            next_nonce.fips_signature_context(AuthPolicy::Online).unwrap()
        );
        assert_ne!(
            base.canonical_message(AuthPolicy::Online).unwrap(),
            next_nonce.canonical_message(AuthPolicy::Online).unwrap()
        );
    }

    #[derive(Default)]
    struct MockHandleSigner {
        live: bool,
    }

    impl ContextSignatureSigner for MockHandleSigner {
        fn generate_keypair(
            &mut self,
            scheme: AuthScheme,
        ) -> Option<(PqSigningKeyHandle, Vec<u8>)> {
            if !matches!(scheme, AuthScheme::MlDsa87 | AuthScheme::SlhDsaShake256s) {
                return None;
            }
            self.live = true;
            Some((PqSigningKeyHandle([0xAB; 32]), vec![0xCD]))
        }

        fn public_key(
            &self,
            scheme: AuthScheme,
            secret_key_handle: &PqSigningKeyHandle,
        ) -> Option<Vec<u8>> {
            (self.live
                && matches!(scheme, AuthScheme::MlDsa87 | AuthScheme::SlhDsaShake256s)
                && secret_key_handle == &PqSigningKeyHandle([0xAB; 32]))
                .then_some(vec![0xCD])
        }

        fn sign_with_context(
            &self,
            scheme: AuthScheme,
            secret_key_handle: &PqSigningKeyHandle,
            message: &[u8],
            context: &[u8],
        ) -> Option<Vec<u8>> {
            (self.live
                && matches!(scheme, AuthScheme::MlDsa87 | AuthScheme::SlhDsaShake256s)
                && secret_key_handle == &PqSigningKeyHandle([0xAB; 32])
                && !message.is_empty()
                && !context.is_empty()
                && context.len() <= 255)
                .then_some(vec![0xEF])
        }

        fn remove_key(
            &mut self,
            _scheme: AuthScheme,
            secret_key_handle: &PqSigningKeyHandle,
        ) -> bool {
            if self.live && secret_key_handle == &PqSigningKeyHandle([0xAB; 32]) {
                self.live = false;
                true
            } else {
                false
            }
        }
    }

    #[test]
    fn envelope_signing_uses_only_opaque_key_handles() {
        let envelope = AuthorizationEnvelope {
            chain_id: [0x71; 32],
            domain: AuthorizationDomain::Transaction,
            epoch: 2,
            nonce: 3,
            expires_at: 4,
            payload_commitment: [0x72; 32],
        };
        let mut signer = MockHandleSigner::default();
        let (handle, public_key) = signer
            .generate_keypair(AuthScheme::MlDsa87)
            .expect("PQ keypair");

        let evidence = sign_envelope_evidence(
            &signer,
            AuthScheme::MlDsa87,
            &handle,
            AuthPolicy::PqOnly,
            &envelope,
        )
        .expect("opaque-handle signature evidence");

        assert_eq!(evidence.scheme, AuthScheme::MlDsa87);
        assert_eq!(evidence.public_key, public_key);
        assert_eq!(evidence.signature, vec![0xEF]);

        assert!(signer.remove_key(AuthScheme::MlDsa87, &handle));
        assert!(sign_envelope_evidence(
            &signer,
            AuthScheme::MlDsa87,
            &handle,
            AuthPolicy::PqOnly,
            &envelope,
        )
        .is_none());

        assert!(sign_envelope_evidence(
            &signer,
            AuthScheme::Secp256k1,
            &handle,
            AuthPolicy::Online,
            &envelope,
        )
        .is_none());
    }

    #[test]
    fn envelope_verifier_derives_message_and_context_from_same_policy() {
        #[derive(Clone)]
        struct EnvelopeVerifier {
            expected_message_len: usize,
            expected_context: Vec<u8>,
        }

        impl ContextSignatureVerifier for EnvelopeVerifier {
            fn verify_with_context(
                &self,
                scheme: AuthScheme,
                _public_key: &[u8],
                message: &[u8],
                context: &[u8],
                _signature: &[u8],
            ) -> bool {
                matches!(scheme, AuthScheme::MlDsa87 | AuthScheme::SlhDsaShake256s)
                    && message.len() == self.expected_message_len
                    && context == self.expected_context.as_slice()
            }
        }

        let envelope = AuthorizationEnvelope {
            chain_id: [0x44; 32],
            domain: AuthorizationDomain::InferenceReceipt,
            epoch: 7,
            nonce: 9,
            expires_at: 1000,
            payload_commitment: [0x55; 32],
        };
        let policy = AuthPolicy::PqOnly;
        let expected_message = envelope.canonical_message(policy).unwrap();
        let expected_context = envelope.fips_signature_context(policy).unwrap();

        let auth = HybridAuthorization {
            policy,
            evidence: vec![
                evidence(AuthScheme::MlDsa87),
                evidence(AuthScheme::SlhDsaShake256s),
            ],
        };
        let verifier = EnvelopeVerifier {
            expected_message_len: expected_message.len(),
            expected_context,
        };

        let validation = AuthorizationValidationContext {
            expected_chain_id: envelope.chain_id,
            expected_domain: envelope.domain,
            expected_policy: auth.policy,
            expected_epoch: envelope.epoch,
            expected_nonce: envelope.nonce,
            now: envelope.expires_at - 1,
            max_future_seconds: 60,
        };
        assert!(verify_envelope_authorization(
            &verifier,
            &auth,
            &envelope,
            &validation,
        ));

        let mut wrong_domain = envelope.clone();
        wrong_domain.domain = AuthorizationDomain::Governance;
        assert!(!verify_envelope_authorization(
            &verifier,
            &auth,
            &wrong_domain,
            &validation,
        ));
    }

    #[test]
    fn replay_state_consumes_nonce_exactly_once_and_rotates_forward_only() {
        let envelope = AuthorizationEnvelope {
            chain_id: [0x91; 32],
            domain: AuthorizationDomain::Governance,
            epoch: 12,
            nonce: 44,
            expires_at: 1_000,
            payload_commitment: [0x92; 32],
        };
        let auth = HybridAuthorization {
            policy: AuthPolicy::PqOnly,
            evidence: vec![
                evidence(AuthScheme::MlDsa87),
                evidence(AuthScheme::SlhDsaShake256s),
            ],
        };
        let message = envelope
            .canonical_message(AuthPolicy::PqOnly)
            .expect("message");
        let context = envelope
            .fips_signature_context(AuthPolicy::PqOnly)
            .expect("context");
        let verifier = ReplayVerifier { message, context };

        let mut replay = AuthorizationReplayState::new(
            envelope.chain_id,
            envelope.domain,
            AuthPolicy::PqOnly,
            envelope.epoch,
            envelope.nonce,
        )
        .expect("replay state");

        assert!(replay.verify_and_consume(
            &verifier,
            &auth,
            &envelope,
            999,
            60,
        ));
        assert_eq!(replay.next_nonce(), 45);

        assert!(!replay.verify_and_consume(
            &verifier,
            &auth,
            &envelope,
            999,
            60,
        ));

        assert!(!replay.rotate_epoch(12, 0));
        assert!(!replay.rotate_epoch(11, 0));
        assert!(replay.rotate_epoch(13, 0));
        assert_eq!(replay.epoch(), 13);
        assert_eq!(replay.next_nonce(), 0);
    }

    #[test]
    fn replay_state_fails_closed_at_nonce_overflow() {
        let envelope = AuthorizationEnvelope {
            chain_id: [0xA1; 32],
            domain: AuthorizationDomain::Governance,
            epoch: 1,
            nonce: u64::MAX,
            expires_at: 100,
            payload_commitment: [0xA2; 32],
        };
        let auth = HybridAuthorization {
            policy: AuthPolicy::PqOnly,
            evidence: vec![
                evidence(AuthScheme::MlDsa87),
                evidence(AuthScheme::SlhDsaShake256s),
            ],
        };
        let verifier = ReplayVerifier {
            message: envelope.canonical_message(AuthPolicy::PqOnly).unwrap(),
            context: envelope.fips_signature_context(AuthPolicy::PqOnly).unwrap(),
        };
        let mut replay = AuthorizationReplayState::new(
            envelope.chain_id,
            envelope.domain,
            AuthPolicy::PqOnly,
            envelope.epoch,
            u64::MAX,
        )
        .expect("replay state");

        assert!(!replay.verify_and_consume(
            &verifier,
            &auth,
            &envelope,
            50,
            60,
        ));
        assert_eq!(replay.next_nonce(), u64::MAX);
    }

    #[test]
    fn envelope_state_validation_rejects_replay_epoch_chain_and_expiry_mismatch() {
        let envelope = AuthorizationEnvelope {
            chain_id: [0x91; 32],
            domain: AuthorizationDomain::Governance,
            epoch: 12,
            nonce: 44,
            expires_at: 1_000,
            payload_commitment: [0x92; 32],
        };

        let ok = AuthorizationValidationContext {
            expected_chain_id: [0x91; 32],
            expected_domain: AuthorizationDomain::Governance,
            expected_policy: AuthPolicy::PqOnly,
            expected_epoch: 12,
            expected_nonce: 44,
            now: 999,
            max_future_seconds: 60,
        };
        assert!(envelope.validate_in_context(&ok).is_ok());

        let mut bad = ok;
        bad.expected_chain_id = [0x90; 32];
        assert!(envelope.validate_in_context(&bad).is_err());

        let mut bad = ok;
        bad.expected_domain = AuthorizationDomain::Transaction;
        assert!(envelope.validate_in_context(&bad).is_err());

        let mut bad = ok;
        bad.expected_epoch = 13;
        assert!(envelope.validate_in_context(&bad).is_err());

        let mut bad = ok;
        bad.expected_nonce = 45;
        assert!(envelope.validate_in_context(&bad).is_err());

        let mut bad = ok;
        bad.now = 1_000;
        assert!(envelope.validate_in_context(&bad).is_err());
    }

    #[test]
    fn authorization_context_cannot_weaken_protocol_lifetime_ceiling() {
        let envelope = AuthorizationEnvelope {
            chain_id: [0xA7; 32],
            domain: AuthorizationDomain::Governance,
            epoch: 1,
            nonce: 2,
            expires_at: MAX_AUTHORIZATION_LIFETIME_SECONDS,
            payload_commitment: [0xA8; 32],
        };
        let context = AuthorizationValidationContext {
            expected_chain_id: envelope.chain_id,
            expected_domain: envelope.domain,
            expected_policy: AuthPolicy::PqOnly,
            expected_epoch: envelope.epoch,
            expected_nonce: envelope.nonce,
            now: 0,
            max_future_seconds: MAX_AUTHORIZATION_LIFETIME_SECONDS + 1,
        };

        assert!(envelope.validate_in_context(&context).is_err());

        let mut allowed = context;
        allowed.max_future_seconds = MAX_AUTHORIZATION_LIFETIME_SECONDS;
        assert!(envelope.validate_in_context(&allowed).is_ok());
    }

    #[test]
    fn authorization_rejects_expiry_beyond_domain_policy_horizon() {
        let envelope = AuthorizationEnvelope {
            chain_id: [0xA1; 32],
            domain: AuthorizationDomain::Governance,
            epoch: 1,
            nonce: 2,
            expires_at: 10_000,
            payload_commitment: [0xA2; 32],
        };
        let context = AuthorizationValidationContext {
            expected_chain_id: envelope.chain_id,
            expected_domain: envelope.domain,
            expected_policy: AuthPolicy::PqOnly,
            expected_epoch: envelope.epoch,
            expected_nonce: envelope.nonce,
            now: 9_000,
            max_future_seconds: 900,
        };
        assert!(envelope.validate_in_context(&context).is_err());

        let mut allowed = context;
        allowed.max_future_seconds = 1_000;
        assert!(envelope.validate_in_context(&allowed).is_ok());
    }

    #[derive(Clone, Copy)]
    struct LaneVerifier {
        pq: bool,
    }

    impl SignatureVerifier for LaneVerifier {
        fn verify(
            &self,
            scheme: AuthScheme,
            _public_key: &[u8],
            _message: &[u8],
            _signature: &[u8],
        ) -> bool {
            match scheme {
                AuthScheme::MlDsa87 | AuthScheme::SlhDsaShake256s => self.pq,
                AuthScheme::Secp256k1 | AuthScheme::Ed25519 => !self.pq,
            }
        }
    }

    impl ContextSignatureVerifier for LaneVerifier {
        fn verify_with_context(
            &self,
            scheme: AuthScheme,
            _public_key: &[u8],
            _message: &[u8],
            context: &[u8],
            _signature: &[u8],
        ) -> bool {
            matches!(scheme, AuthScheme::MlDsa87 | AuthScheme::SlhDsaShake256s)
                && self.pq
                && context == b"expected-context"
        }
    }

    #[test]
    fn routed_verifier_cannot_cross_satisfy_lanes() {
        let verifier = SchemeRoutedVerifier {
            classical: LaneVerifier { pq: false },
            pq: LaneVerifier { pq: true },
        };
        assert!(verifier.verify(AuthScheme::Secp256k1, b"k", b"m", b"s"));
        assert!(verifier.verify(AuthScheme::MlDsa87, b"k", b"m", b"s"));
    }

    #[test]
    fn routed_context_verifier_applies_fips_context_only_to_pq_lanes() {
        let verifier = SchemeRoutedVerifier {
            classical: LaneVerifier { pq: false },
            pq: LaneVerifier { pq: true },
        };

        assert!(verifier.verify_with_context(
            AuthScheme::Secp256k1,
            b"k",
            b"canonical-message",
            b"wrong-context-does-not-alter-classical-semantics",
            b"s",
        ));

        assert!(verifier.verify_with_context(
            AuthScheme::MlDsa87,
            b"k",
            b"canonical-message",
            b"expected-context",
            b"s",
        ));
        assert!(!verifier.verify_with_context(
            AuthScheme::MlDsa87,
            b"k",
            b"canonical-message",
            b"wrong-context",
            b"s",
        ));
    }
}
