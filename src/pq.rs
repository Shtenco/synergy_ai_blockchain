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

    /// Structural fail-closed policy check. Cryptographic verification is supplied
    /// by the node's standards-conformant provider and MUST verify every required lane.
    pub fn structurally_complete(&self) -> bool {
        self.required_schemes()
            .iter()
            .all(|required| self.evidence.iter().any(|e| &e.scheme == required))
    }
}

pub trait SignatureVerifier {
    fn verify(&self, scheme: AuthScheme, public_key: &[u8], message: &[u8], signature: &[u8]) -> bool;
}

pub fn verify_authorization<V: SignatureVerifier>(
    verifier: &V,
    authorization: &HybridAuthorization,
    message: &[u8],
) -> bool {
    if !authorization.structurally_complete() {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn max_is_fail_closed() {
        let auth = HybridAuthorization {
            policy: AuthPolicy::Max,
            evidence: vec![
                SignatureEvidence { scheme: AuthScheme::Secp256k1, public_key: vec![], signature: vec![] },
                SignatureEvidence { scheme: AuthScheme::MlDsa87, public_key: vec![], signature: vec![] },
            ],
        };
        assert!(!auth.structurally_complete());
    }

    #[test]
    fn pq_only_does_not_require_ecc() {
        let auth = HybridAuthorization {
            policy: AuthPolicy::PqOnly,
            evidence: vec![
                SignatureEvidence { scheme: AuthScheme::MlDsa87, public_key: vec![], signature: vec![] },
                SignatureEvidence { scheme: AuthScheme::SlhDsaShake256s, public_key: vec![], signature: vec![] },
            ],
        };
        assert!(auth.structurally_complete());
    }
}
