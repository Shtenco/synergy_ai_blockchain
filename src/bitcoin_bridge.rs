#![forbid(unsafe_code)]

use sha2::{Digest, Sha256};

pub const BTC_SPV_DOMAIN: &[u8] = b"SYNERGY/BTC-SPV/V1\0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BitcoinHeader {
    pub raw: [u8; 80],
}

impl BitcoinHeader {
    pub fn block_hash(&self) -> [u8; 32] {
        sha256d(&self.raw)
    }

    pub fn merkle_root_internal(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&self.raw[36..68]);
        out
    }

    pub fn bits(&self) -> u32 {
        u32::from_le_bytes(self.raw[72..76].try_into().expect("fixed header slice"))
    }

    pub fn prev_hash_internal(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&self.raw[4..36]);
        out
    }

    pub fn validate_pow(&self) -> Result<(), &'static str> {
        let target = compact_target(self.bits()).ok_or("invalid bitcoin compact target")?;
        let hash = self.block_hash();
        let mut hash_be = hash;
        hash_be.reverse();
        if hash_be > target {
            return Err("bitcoin header does not satisfy target");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BitcoinMerkleProof {
    pub txid_internal: [u8; 32],
    pub tx_index: u32,
    pub siblings_internal: Vec<[u8; 32]>,
}

impl BitcoinMerkleProof {
    pub fn root(&self) -> [u8; 32] {
        let mut current = self.txid_internal;
        let mut index = self.tx_index;
        for sibling in &self.siblings_internal {
            let mut pair = [0u8; 64];
            if index & 1 == 0 {
                pair[..32].copy_from_slice(&current);
                pair[32..].copy_from_slice(sibling);
            } else {
                pair[..32].copy_from_slice(sibling);
                pair[32..].copy_from_slice(&current);
            }
            current = sha256d(&pair);
            index >>= 1;
        }
        current
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BitcoinSpvProof {
    pub headers: Vec<BitcoinHeader>,
    pub merkle: BitcoinMerkleProof,
    pub min_confirmations: u32,
}

impl BitcoinSpvProof {
    pub fn verify(&self) -> Result<[u8; 32], &'static str> {
        if self.headers.is_empty() || self.min_confirmations == 0 {
            return Err("bitcoin SPV proof requires header chain and confirmations");
        }
        if self.headers.len() < usize::try_from(self.min_confirmations).map_err(|_| "confirmation overflow")? {
            return Err("insufficient bitcoin confirmations");
        }
        for header in &self.headers {
            header.validate_pow()?;
        }
        for pair in self.headers.windows(2) {
            if pair[1].prev_hash_internal() != pair[0].block_hash() {
                return Err("bitcoin header chain is disconnected");
            }
        }
        if self.merkle.root() != self.headers[0].merkle_root_internal() {
            return Err("bitcoin transaction merkle proof mismatch");
        }

        let mut h = Sha256::new();
        h.update(BTC_SPV_DOMAIN);
        h.update(self.merkle.txid_internal);
        h.update(self.headers[0].block_hash());
        h.update(self.headers.last().expect("nonempty").block_hash());
        h.update(self.min_confirmations.to_be_bytes());
        Ok(h.finalize().into())
    }
}

pub fn sha256d(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    Sha256::digest(first).into()
}

fn compact_target(bits: u32) -> Option<[u8; 32]> {
    let exponent = (bits >> 24) as usize;
    let mantissa = bits & 0x007f_ffff;
    if bits & 0x0080_0000 != 0 || mantissa == 0 || exponent > 32 {
        return None;
    }
    let m = [
        ((mantissa >> 16) & 0xff) as u8,
        ((mantissa >> 8) & 0xff) as u8,
        (mantissa & 0xff) as u8,
    ];
    let mut target = [0u8; 32];
    if exponent <= 3 {
        let value = mantissa >> (8 * (3 - exponent));
        let bytes = value.to_be_bytes();
        target[28..].copy_from_slice(&bytes);
    } else {
        let start = 32usize.checked_sub(exponent)?;
        let usable = exponent.min(3);
        target[start..start + usable].copy_from_slice(&m[..usable]);
    }
    Some(target)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_header_pow_and_hash_are_valid() {
        let raw = hex::decode(concat!(
            "01000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a",
            "29ab5f49",
            "ffff001d",
            "1dac2b7c"
        )).unwrap();
        let mut header = [0u8; 80];
        header.copy_from_slice(&raw);
        let h = BitcoinHeader { raw: header };
        assert!(h.validate_pow().is_ok());
        let mut display = h.block_hash();
        display.reverse();
        assert_eq!(
            hex::encode(display),
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        );
    }

    #[test]
    fn one_transaction_merkle_proof_matches_genesis() {
        let txid_internal = hex::decode(
            "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a",
        ).unwrap();
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&txid_internal);
        let p = BitcoinMerkleProof {
            txid_internal: txid,
            tx_index: 0,
            siblings_internal: vec![],
        };
        assert_eq!(p.root(), txid);
    }
}
