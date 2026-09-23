use crate::pq::{
    verify_authorization_with_context, AuthScheme, AuthorizationDomain, ContextSignatureSigner,
    ContextSignatureVerifier, HybridAuthorization, PqSigningKeyHandle, SignatureEvidence,
};

pub const PQ_TX_DOMAIN: &[u8] = b"SYNERGY-PQ-EVM-TX/1";
pub const MAX_TX_CALLDATA_BYTES: usize = 1_048_576;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PqEvmTransaction {
    pub chain_id: u64,
    pub sender_account: [u8; 32],
    pub nonce: u64,
    pub authorization_epoch: u64,
    pub authorization_expires_at: u64,
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
    pub expected_authorization_epoch: u64,
    pub now: u64,
    pub max_authorization_future_seconds: u64,
    pub required_policy: crate::pq::AuthPolicy,
    pub max_calldata_bytes: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxError {
    ZeroChainId,
    WrongChainId,
    NonceMismatch,
    AuthorizationEpochMismatch,
    AuthorizationExpired,
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
        if !matches!(scheme, AuthScheme::MlDsa87 | AuthScheme::SlhDsaShake256s)
            || self.data.len() > MAX_TX_CALLDATA_BYTES
        {
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
        out.extend_from_slice(&self.authorization_epoch.to_be_bytes());
        out.extend_from_slice(&self.authorization_expires_at.to_be_bytes());
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

        // Classical and PQ lanes must authenticate the same cryptographic
        // semantics. Bind profile, authorization domain, policy and the ordered
        // algorithm suite directly into the transaction preimage; PQ lanes bind
        // the same values again through the FIPS context.
        out.extend_from_slice(&crate::pq::CRYPTO_PROFILE_VERSION.to_be_bytes());
        out.push(AuthorizationDomain::Transaction.protocol_code());
        out.push(self.authorization.policy.protocol_code());
        let schemes = self.authorization.policy.required_schemes();
        out.push(schemes.len() as u8);
        for scheme in schemes {
            out.push(scheme.protocol_code());
        }
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
        if self.authorization_epoch != context.expected_authorization_epoch {
            return Err(TxError::AuthorizationEpochMismatch);
        }
        if self.authorization_expires_at == 0 || context.now >= self.authorization_expires_at {
            return Err(TxError::AuthorizationExpired);
        }
        if context.max_authorization_future_seconds == 0
            || self
                .authorization_expires_at
                .checked_sub(context.now)
                .map(|remaining| remaining > context.max_authorization_future_seconds)
                .unwrap_or(true)
        {
            return Err(TxError::AuthorizationExpired);
        }
        if self.authorization.policy != context.required_policy {
            return Err(TxError::PolicyMismatch);
        }
        if self.authorization.primary_account_identity_commitment() != Some(self.sender_account) {
            return Err(TxError::AuthorizationFailed);
        }
        if self.gas_limit == 0 {
            return Err(TxError::ZeroGasLimit);
        }
        if context.max_calldata_bytes == 0
            || context.max_calldata_bytes > MAX_TX_CALLDATA_BYTES
            || self.data.len() > context.max_calldata_bytes
            || self.data.len() > MAX_TX_CALLDATA_BYTES
        {
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
    use crate::pq::{
        AuthPolicy, AuthScheme, ContextSignatureVerifier, SignatureEvidence,
        ML_DSA_87_PUBLIC_KEY_BYTES, ML_DSA_87_SIGNATURE_BYTES,
        SLH_DSA_SHAKE_256S_PUBLIC_KEY_BYTES, SLH_DSA_SHAKE_256S_SIGNATURE_BYTES,
    };

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
        let authorization = HybridAuthorization {
            policy: AuthPolicy::PqOnly,
            evidence: vec![
                    SignatureEvidence {
                        scheme: AuthScheme::MlDsa87,
                        public_key: vec![1; ML_DSA_87_PUBLIC_KEY_BYTES],
                        signature: vec![2; ML_DSA_87_SIGNATURE_BYTES],
                    },
                    SignatureEvidence {
                        scheme: AuthScheme::SlhDsaShake256s,
                        public_key: vec![3; SLH_DSA_SHAKE_256S_PUBLIC_KEY_BYTES],
                        signature: vec![4; SLH_DSA_SHAKE_256S_SIGNATURE_BYTES],
                    },
            ],
        };
        let sender_account = authorization
            .primary_account_identity_commitment()
            .expect("sender primary account identity");

        PqEvmTransaction {
            chain_id: 8453,
            sender_account,
            nonce: 7,
            authorization_epoch: 12,
            authorization_expires_at: 1_000,
            gas_limit: 100_000,
            max_fee_per_gas: [0x22; 32],
            to: Some([0x33; 20]),
            value: [0x44; 32],
            data: vec![1, 2, 3],
            authorization,
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
                    expected_authorization_epoch: 12,
                    now: 999,
                    max_authorization_future_seconds: 60,
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
                    expected_authorization_epoch: 12,
                    now: 999,
                    max_authorization_future_seconds: 60,
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
                    expected_authorization_epoch: 12,
                    now: 999,
                    max_authorization_future_seconds: 60,
                    required_policy: AuthPolicy::PqOnly,
                    max_calldata_bytes: 1024,
                },
            ),
            Err(TxError::NonceMismatch)
        );
    }

    #[test]
    fn transaction_validation_rejects_wrong_epoch_and_expiry() {
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
                    expected_authorization_epoch: 13,
                    now: 999,
                    max_authorization_future_seconds: 60,
                    required_policy: AuthPolicy::PqOnly,
                    max_calldata_bytes: 1024,
                },
            ),
            Err(TxError::AuthorizationEpochMismatch)
        );

        assert_eq!(
            tx.validate(
                &verifier,
                TxValidationContext {
                    expected_chain_id: 8453,
                    expected_nonce: 7,
                    expected_authorization_epoch: 12,
                    now: 1_000,
                    max_authorization_future_seconds: 60,
                    required_policy: AuthPolicy::PqOnly,
                    max_calldata_bytes: 1024,
                },
            ),
            Err(TxError::AuthorizationExpired)
        );
    }

    #[test]
    fn transaction_validation_rejects_expiry_beyond_policy_horizon() {
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
                    expected_authorization_epoch: 12,
                    now: 900,
                    max_authorization_future_seconds: 99,
                    required_policy: AuthPolicy::PqOnly,
                    max_calldata_bytes: 1024,
                },
            ),
            Err(TxError::AuthorizationExpired)
        );
    }

    #[test]
    fn transaction_calldata_policy_cannot_exceed_protocol_ceiling() {
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
                    expected_authorization_epoch: 12,
                    now: 999,
                    max_authorization_future_seconds: 60,
                    required_policy: AuthPolicy::PqOnly,
                    max_calldata_bytes: MAX_TX_CALLDATA_BYTES + 1,
                },
            ),
            Err(TxError::DataTooLarge)
        );
    }

    #[test]
    fn transaction_rejects_primary_key_not_bound_to_sender_account() {
        let mut tx = test_tx();
        tx.authorization.evidence[0].public_key[0] ^= 1;

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
                    expected_authorization_epoch: 12,
                    now: 999,
                    max_authorization_future_seconds: 60,
                    required_policy: AuthPolicy::PqOnly,
                    max_calldata_bytes: 1024,
                },
            ),
            Err(TxError::AuthorizationFailed)
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
                    expected_authorization_epoch: 12,
                    now: 999,
                    max_authorization_future_seconds: 60,
                    required_policy: AuthPolicy::Max,
                    max_calldata_bytes: 1024,
                },
            ),
            Err(TxError::PolicyMismatch)
        );
    }

    #[test]
    fn transaction_preimage_binds_crypto_profile_and_algorithm_suite() {
        let tx = test_tx();
        let preimage = tx.signing_preimage();
        let version = crate::pq::CRYPTO_PROFILE_VERSION.to_be_bytes();
        assert!(preimage.windows(version.len()).any(|window| window == version));

        let mut other_policy = tx.clone();
        other_policy.authorization.policy = AuthPolicy::Max;
        assert_ne!(preimage, other_policy.signing_preimage());
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
