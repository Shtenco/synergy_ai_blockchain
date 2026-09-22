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
pub enum TxError {
    ZeroChainId,
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
        max_calldata_bytes: usize,
    ) -> Result<(), TxError> {
        if self.chain_id == 0 {
            return Err(TxError::ZeroChainId);
        }
        if self.gas_limit == 0 {
            return Err(TxError::ZeroGasLimit);
        }
        if self.data.len() > max_calldata_bytes {
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
