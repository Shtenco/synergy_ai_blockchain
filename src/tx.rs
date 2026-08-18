use crate::pq::{verify_authorization, HybridAuthorization, SignatureVerifier};

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

    pub fn validate<V: SignatureVerifier>(
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
        if !verify_authorization(verifier, &self.authorization, &message) {
            return Err(TxError::AuthorizationFailed);
        }
        Ok(())
    }
}
