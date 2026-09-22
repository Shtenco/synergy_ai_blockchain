use crate::pq::{
    verify_authorization_with_context, AuthScheme, AuthorizationDomain, ContextSignatureSigner,
    ContextSignatureVerifier, HybridAuthorization, PqSigningKeyHandle, SignatureEvidence,
};

pub const PQ_TX_DOMAIN: &[u8] = b"SYNERGY-PQ-EVM-TX/1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PqEvmTransaction {
    pub chain_id: u64,
    pub sender_account: [u8; 32],
    pub nonce: u64,
    pub gas_limit: u64,
    pub max_fee_per_gas: [u8; 32],
    pub to: Option<[u8; 20]>,
    pub value: [u8; 32],
    pub data: Vec<u8>,
    pub authorization: HybridAuthorization,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TxValidationContext {
    pub expected_chain_id: u64,
    pub expected_nonce: u64,
    pub required_policy: crate::pq::AuthPolicy,
    pub max_calldata_bytes: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxError {
    ZeroChainId,
    WrongChainId,
    NonceMismatch,
    PolicyMismatch,
    ZeroGasLimit,
    DataTooLarge,
    AuthorizationFailed,
}

fn put_len_prefixed(out: &mut Vec<u8>, field: &[u8]) {
    out.extend_from_slice(&(field.len() as u64).to_be_bytes());
    out.extend_from_slice(field);
}

impl PqEvmTransaction {
    fn authorization_chain_id(&self) -> [u8; 32] {
        let mut chain = [0u8; 32];
        chain[24..].copy_from_slice(&self.chain_id.to_be_bytes());
        chain
    }

    pub fn fips_signature_context(&self) -> Vec<u8> {
        crate::pq::fips_signature_context(
            &self.authorization_chain_id(),
            AuthorizationDomain::Transaction,
            self.authorization.policy,
        )
    }

    pub fn sign_authorization_evidence<S: ContextSignatureSigner>(
        &self,
        signer: &S,
        scheme: AuthScheme,
        secret_key_handle: &PqSigningKeyHandle,
    ) -> Option<SignatureEvidence> {
        if !matches!(scheme, AuthScheme::MlDsa87 | AuthScheme::SlhDsaShake256s) {
            return None;
        }

        let public_key = signer.public_key(scheme, secret_key_handle)?;
        if public_key.is_empty() {
            return None;
        }

        let message = self.signing_preimage();
        let context = self.fips_signature_context();
        let signature =
            signer.sign_with_context(scheme, secret_key_handle, &message, &context)?;

        (!signature.is_empty()).then_some(SignatureEvidence {
            scheme,
            public_key,
            signature,
        })
    }

    /// Canonical signing preimage shared by every authorization lane. Signature
    /// bytes themselves are excluded, preventing circular encoding.
    pub fn signing_preimage(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256 + self.data.len());
        put_len_prefixed(&mut out, PQ_TX_DOMAIN);
        out.extend_from_slice(&self.chain_id.to_be_bytes());
        out.extend_from_slice(&self.sender_account);
        out.extend_from_slice(&self.nonce.to_be_bytes());
        out.extend_from_slice(&self.gas_limit.to_be_bytes());
        out.extend_from_slice(&self.max_fee_per_gas);
        match self.to {
            Some(to) => {
                out.push(1);
                out.extend_from_slice(&to);
            }
            None => out.push(0),
        }
        out.extend_from_slice(&self.value);
        put_len_prefixed(&mut out, &self.data);
        // The policy is part of what is signed; an attacker cannot downgrade MAX
        // to ONLINE without invalidating every signature.
        out.push(match self.authorization.policy {
            crate::pq::AuthPolicy::Online => 1,
            crate::pq::AuthPolicy::Max => 2,
            crate::pq::AuthPolicy::PqOnly => 3,
        });
        out
    }

    pub fn validate<V: ContextSignatureVerifier>(
        &self,
        verifier: &V,
        context: TxValidationContext,
    ) -> Result<(), TxError> {
        if self.chain_id == 0 {
            return Err(TxError::ZeroChainId);
        }
        if self.chain_id != context.expected_chain_id {
            return Err(TxError::WrongChainId);
        }
        if self.nonce != context.expected_nonce {
            return Err(TxError::NonceMismatch);
        }
        if self.authorization.policy != context.required_policy {
            return Err(TxError::PolicyMismatch);
        }
        if self.gas_limit == 0 {
            return Err(TxError::ZeroGasLimit);
        }
        if self.data.len() > context.max_calldata_bytes {
            return Err(TxError::DataTooLarge);
        }
        let message = self.signing_preimage();
        let context = self.fips_signature_context();
        if !verify_authorization_with_context(
            verifier,
            &self.authorization,
            &message,
            &context,
        ) {
            return Err(TxError::AuthorizationFailed);
        }
        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::pq::{AuthPolicy, AuthScheme, ContextSignatureVerifier, SignatureEvidence};

    #[derive(Clone)]
    struct ExpectedTxVerifier {
        message: Vec<u8>,
        context: Vec<u8>,
    }

    impl ContextSignatureVerifier for ExpectedTxVerifier {
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

    fn test_tx() -> PqEvmTransaction {
        PqEvmTransaction {
            chain_id: 8453,
            sender_account: [0x11; 32],
            nonce: 7,
            gas_limit: 100_000,
            max_fee_per_gas: [0x22; 32],
            to: Some([0x33; 20]),
            value: [0x44; 32],
            data: vec![1, 2, 3],
            authorization: HybridAuthorization {
                policy: AuthPolicy::PqOnly,
                evidence: vec![
                    SignatureEvidence {
                        scheme: AuthScheme::MlDsa87,
                        public_key: vec![1],
                        signature: vec![2],
                    },
                    SignatureEvidence {
                        scheme: AuthScheme::SlhDsaShake256s,
                        public_key: vec![3],
                        signature: vec![4],
                    },
                ],
            },
        }
    }

    #[test]
    fn transaction_validation_is_chain_nonce_and_fips_context_bound() {
        let tx = test_tx();
        let verifier = ExpectedTxVerifier {
            message: tx.signing_preimage(),
            context: tx.fips_signature_context(),
        };

        assert_eq!(
            tx.validate(
                &verifier,
                TxValidationContext {
                    expected_chain_id: 8453,
                    expected_nonce: 7,
                    required_policy: AuthPolicy::PqOnly,
                    max_calldata_bytes: 1024,
                },
            ),
            Ok(())
        );

        assert_eq!(
            tx.validate(
                &verifier,
                TxValidationContext {
                    expected_chain_id: 1,
                    expected_nonce: 7,
                    required_policy: AuthPolicy::PqOnly,
                    max_calldata_bytes: 1024,
                },
            ),
            Err(TxError::WrongChainId)
        );

        assert_eq!(
            tx.validate(
                &verifier,
                TxValidationContext {
                    expected_chain_id: 8453,
                    expected_nonce: 8,
                    required_policy: AuthPolicy::PqOnly,
                    max_calldata_bytes: 1024,
                },
            ),
            Err(TxError::NonceMismatch)
        );
    }

    #[test]
    fn transaction_validation_rejects_weaker_or_different_policy() {
        let tx = test_tx();
        let verifier = ExpectedTxVerifier {
            message: tx.signing_preimage(),
            context: tx.fips_signature_context(),
        };

        assert_eq!(
            tx.validate(
                &verifier,
                TxValidationContext {
                    expected_chain_id: 8453,
                    expected_nonce: 7,
                    required_policy: AuthPolicy::Max,
                    max_calldata_bytes: 1024,
                },
            ),
            Err(TxError::PolicyMismatch)
        );
    }

    #[test]
    fn transaction_fips_context_changes_with_chain_or_policy() {
        let tx = test_tx();
        let base = tx.fips_signature_context();

        let mut other_chain = tx.clone();
        other_chain.chain_id = 1;
        assert_ne!(base, other_chain.fips_signature_context());

        let mut other_policy = tx.clone();
        other_policy.authorization.policy = AuthPolicy::Online;
        assert_ne!(base, other_policy.fips_signature_context());
    }
}
