#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthScheme {
    Secp256k1,
    Ed25519,
    MlDsa87,
    SlhDsaShake256s,
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
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorizationDomain {
    Transaction,
    ValidatorVote,
    BridgeMigration,
    ModelUpgrade,
    InferenceReceipt,
    Governance,
}

impl AuthorizationDomain {
    pub const fn protocol_code(self) -> u8 {
        match self {
            Self::Transaction => 1,
            Self::ValidatorVote => 2,
            Self::BridgeMigration => 3,
            Self::ModelUpgrade => 4,
            Self::InferenceReceipt => 5,
            Self::Governance => 6,
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

    pub fn canonical_message(&self, policy: AuthPolicy) -> Result<Vec<u8>, &'static str> {
        self.validate()?;
        const PREFIX: &[u8] = b"SYNERGY/PQ-AUTH/V1\0";
        let mut out = Vec::with_capacity(PREFIX.len() + 32 + 2 + 8 * 3 + 32);
        out.extend_from_slice(PREFIX);
        out.extend_from_slice(&self.chain_id);
        out.push(self.domain.protocol_code());
        out.push(policy.protocol_code());
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
        const PREFIX: &[u8] = b"SYNERGY/PQ-FIPS-CONTEXT/V1\0";
        let mut out = Vec::with_capacity(PREFIX.len() + 32 + 2);
        out.extend_from_slice(PREFIX);
        out.extend_from_slice(&self.chain_id);
        out.push(self.domain.protocol_code());
        out.push(policy.protocol_code());

        // FIPS 204 and FIPS 205 limit ctx to at most 255 bytes.
        if out.len() > 255 {
            return Err("FIPS signature context exceeds 255 bytes");
        }
        Ok(out)
    }
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

impl HybridAuthorization {
    pub fn required_schemes(&self) -> &'static [AuthScheme] {
        const ONLINE: &[AuthScheme] = &[AuthScheme::Secp256k1, AuthScheme::MlDsa87];
        const MAX: &[AuthScheme] = &[
            AuthScheme::Secp256k1,
            AuthScheme::MlDsa87,
            AuthScheme::SlhDsaShake256s,
        ];
        const PQ_ONLY: &[AuthScheme] = &[AuthScheme::MlDsa87, AuthScheme::SlhDsaShake256s];
        match self.policy {
            AuthPolicy::Online => ONLINE,
            AuthPolicy::Max => MAX,
            AuthPolicy::PqOnly => PQ_ONLY,
        }
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
            if evidence.public_key.is_empty() || evidence.signature.is_empty() {
                return Err("authorization evidence must contain key and signature bytes");
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

        Ok(())
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

pub fn verify_authorization<V: SignatureVerifier>(
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

pub fn verify_authorization_with_context<V: ContextSignatureVerifier>(
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

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence(scheme: AuthScheme) -> SignatureEvidence {
        SignatureEvidence {
            scheme,
            public_key: vec![1],
            signature: vec![2],
        }
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
