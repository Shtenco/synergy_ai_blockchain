#![forbid(unsafe_code)]

use core::cmp::Ordering;
use sha2::{Digest, Sha256};

pub const BTC_SPV_DOMAIN: &[u8] = b"SYNERGY/BTC-SPV/V2\0";
pub const BITCOIN_RETARGET_INTERVAL: u32 = 2016;
pub const BITCOIN_TARGET_TIMESPAN_SECONDS: u64 = 14 * 24 * 60 * 60;
pub const BITCOIN_TARGET_SPACING_SECONDS: u64 = 10 * 60;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Uint256([u64; 4]);

impl Uint256 {
    const ZERO: Self = Self([0; 4]);
    const MAX: Self = Self([u64::MAX; 4]);

    fn from_be_bytes(bytes: [u8; 32]) -> Self {
        let mut limbs = [0u64; 4];
        for (i, chunk) in bytes.chunks_exact(8).enumerate() {
            let mut word = [0u8; 8];
            word.copy_from_slice(chunk);
            limbs[3 - i] = u64::from_be_bytes(word);
        }
        Self(limbs)
    }

    fn to_be_bytes(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..4 {
            out[i * 8..i * 8 + 8].copy_from_slice(&self.0[3 - i].to_be_bytes());
        }
        out
    }

    fn is_zero(self) -> bool {
        self == Self::ZERO
    }

    fn checked_add(self, rhs: Self) -> Option<Self> {
        let mut out = [0u64; 4];
        let mut carry = 0u128;
        for (i, slot) in out.iter_mut().enumerate() {
            let sum = u128::from(self.0[i]) + u128::from(rhs.0[i]) + carry;
            *slot = sum as u64;
            carry = sum >> 64;
        }
        (carry == 0).then_some(Self(out))
    }

    fn checked_sub(self, rhs: Self) -> Option<Self> {
        if self < rhs {
            return None;
        }
        let mut out = [0u64; 4];
        let mut borrow = 0u128;
        for (i, slot) in out.iter_mut().enumerate() {
            let lhs = u128::from(self.0[i]);
            let sub = u128::from(rhs.0[i]) + borrow;
            if lhs >= sub {
                *slot = (lhs - sub) as u64;
                borrow = 0;
            } else {
                *slot = ((1u128 << 64) + lhs - sub) as u64;
                borrow = 1;
            }
        }
        Some(Self(out))
    }

    fn checked_shl1(self) -> Option<Self> {
        let mut out = [0u64; 4];
        let mut carry = 0u64;
        for (i, slot) in out.iter_mut().enumerate() {
            let next = self.0[i] >> 63;
            *slot = (self.0[i] << 1) | carry;
            carry = next;
        }
        (carry == 0).then_some(Self(out))
    }

    fn bit(self, index: usize) -> bool {
        ((self.0[index / 64] >> (index % 64)) & 1) == 1
    }

    fn set_bit(&mut self, index: usize) {
        self.0[index / 64] |= 1u64 << (index % 64);
    }

    fn div(self, divisor: Self) -> Option<Self> {
        if divisor.is_zero() {
            return None;
        }
        let mut quotient = Self::ZERO;
        let mut remainder = Self::ZERO;
        for bit in (0..256).rev() {
            remainder = remainder.checked_shl1()?;
            if self.bit(bit) {
                remainder.0[0] |= 1;
            }
            if remainder >= divisor {
                remainder = remainder.checked_sub(divisor)?;
                quotient.set_bit(bit);
            }
        }
        Some(quotient)
    }

    fn checked_mul_u64(self, rhs: u64) -> Option<Self> {
        let mut out = [0u64; 4];
        let mut carry = 0u128;
        for (i, slot) in out.iter_mut().enumerate() {
            let product = u128::from(self.0[i]) * u128::from(rhs) + carry;
            *slot = product as u64;
            carry = product >> 64;
        }
        (carry == 0).then_some(Self(out))
    }

    fn div_u64(self, rhs: u64) -> Option<Self> {
        if rhs == 0 {
            return None;
        }
        let mut out = [0u64; 4];
        let mut remainder = 0u128;
        for i in (0..4).rev() {
            let value = (remainder << 64) | u128::from(self.0[i]);
            out[i] = (value / u128::from(rhs)) as u64;
            remainder = value % u128::from(rhs);
        }
        Some(Self(out))
    }

    fn bit_len(self) -> usize {
        for i in (0..4).rev() {
            if self.0[i] != 0 {
                return i * 64 + (64 - self.0[i].leading_zeros() as usize);
            }
        }
        0
    }
}

impl Ord for Uint256 {
    fn cmp(&self, other: &Self) -> Ordering {
        for i in (0..4).rev() {
            match self.0[i].cmp(&other.0[i]) {
                Ordering::Equal => {}
                non_eq => return non_eq,
            }
        }
        Ordering::Equal
    }
}

impl PartialOrd for Uint256 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn bitcoin_mainnet_pow_limit() -> Uint256 {
    Uint256::from_be_bytes([
        0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    ])
}

pub fn bitcoin_mainnet_minimum_chain_work() -> [u8; 32] {
    [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01, 0x45, 0xec, 0x03, 0x6a,
        0xcc, 0x5b, 0xa7, 0x40, 0x05, 0x2a, 0xf1, 0xa0,
    ]
}

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

    pub fn time(&self) -> u32 {
        u32::from_le_bytes(self.raw[68..72].try_into().expect("fixed header slice"))
    }

    pub fn bits(&self) -> u32 {
        u32::from_le_bytes(self.raw[72..76].try_into().expect("fixed header slice"))
    }

    pub fn prev_hash_internal(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&self.raw[4..36]);
        out
    }

    pub fn validate_mainnet_pow(&self) -> Result<(), &'static str> {
        let target = compact_target(self.bits()).ok_or("invalid bitcoin compact target")?;
        if target > bitcoin_mainnet_pow_limit() {
            return Err("bitcoin target exceeds mainnet pow limit");
        }
        let hash = self.block_hash();
        let mut hash_be = hash;
        hash_be.reverse();
        if Uint256::from_be_bytes(hash_be) > target {
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
pub struct BitcoinMainnetCheckpoint {
    pub height: u32,
    pub block_hash_internal: [u8; 32],
    pub bits: u32,
    pub block_time: u32,
    pub period_start_time: u32,
    pub chain_work: [u8; 32],
    pub recent_times: Vec<u32>,
}

impl BitcoinMainnetCheckpoint {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.block_hash_internal == [0; 32]
            || self.block_time == 0
            || self.period_start_time == 0
            || self.recent_times.is_empty()
            || self.recent_times.len() > 11
            || self.recent_times.last().copied() != Some(self.block_time)
        {
            return Err("invalid bitcoin trusted checkpoint");
        }
        let expected_times = usize::try_from(self.height.saturating_add(1).min(11))
            .map_err(|_| "checkpoint height overflow")?;
        if self.recent_times.len() != expected_times {
            return Err("bitcoin checkpoint must carry exact median-time-past window");
        }
        let target = compact_target(self.bits).ok_or("invalid checkpoint target")?;
        if target > bitcoin_mainnet_pow_limit() {
            return Err("checkpoint target exceeds mainnet pow limit");
        }
        let chain_work = Uint256::from_be_bytes(self.chain_work);
        if chain_work < Uint256::from_be_bytes(bitcoin_mainnet_minimum_chain_work()) {
            return Err("checkpoint chainwork below Bitcoin Core minimum chainwork");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedBitcoinTip {
    pub height: u32,
    pub block_hash_internal: [u8; 32],
    pub chain_work: [u8; 32],
    pub bits: u32,
    pub block_time: u32,
}

pub fn bitcoin_mainnet_trusted_checkpoint() -> BitcoinMainnetCheckpoint {
    BitcoinMainnetCheckpoint {
        height: 966_143,
        block_hash_internal: [
            0xe3, 0x72, 0x2c, 0x9f, 0x55, 0x1f, 0x86, 0x93,
            0x51, 0xdd, 0xc6, 0x63, 0xa7, 0x52, 0x0e, 0x3c,
            0x04, 0x33, 0xec, 0x69, 0x89, 0x74, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ],
        bits: 0x1702355e,
        block_time: 1_788_925_573,
        period_start_time: 1_788_640_367,
        chain_work: bitcoin_mainnet_minimum_chain_work(),
        recent_times: vec![
            1_788_917_326,
            1_788_917_796,
            1_788_919_437,
            1_788_919_710,
            1_788_921_108,
            1_788_922_141,
            1_788_922_577,
            1_788_924_176,
            1_788_924_139,
            1_788_925_028,
            1_788_925_573,
        ],
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BitcoinMainnetHeaderProof {
    pub headers: Vec<BitcoinHeader>,
}

impl BitcoinMainnetHeaderProof {
    pub fn verify(&self) -> Result<VerifiedBitcoinTip, &'static str> {
        let checkpoint = bitcoin_mainnet_trusted_checkpoint();
        checkpoint.validate()?;

        let mut height = checkpoint.height;
        let mut previous_hash = checkpoint.block_hash_internal;
        let mut previous_bits = checkpoint.bits;
        let mut previous_time = checkpoint.block_time;
        let mut period_start_time = checkpoint.period_start_time;
        let mut chain_work = Uint256::from_be_bytes(checkpoint.chain_work);
        let mut recent_times = checkpoint.recent_times.clone();

        for header in &self.headers {
            let next_height = height.checked_add(1).ok_or("bitcoin height overflow")?;
            if header.prev_hash_internal() != previous_hash {
                return Err("bitcoin header chain is disconnected from trusted checkpoint");
            }

            let expected_bits = next_work_required_mainnet(
                next_height,
                previous_bits,
                previous_time,
                period_start_time,
            )?;
            if header.bits() != expected_bits {
                return Err("bitcoin header violates mainnet difficulty transition");
            }
            header.validate_mainnet_pow()?;

            if header.time() <= median_time_past(&recent_times)? {
                return Err("bitcoin header violates median-time-past");
            }

            chain_work = chain_work
                .checked_add(block_work(header.bits())?)
                .ok_or("bitcoin cumulative chainwork overflow")?;

            height = next_height;
            previous_hash = header.block_hash();
            previous_bits = header.bits();
            previous_time = header.time();

            recent_times.push(previous_time);
            if recent_times.len() > 11 {
                recent_times.remove(0);
            }
            if height % BITCOIN_RETARGET_INTERVAL == 0 {
                period_start_time = previous_time;
            }
        }

        Ok(VerifiedBitcoinTip {
            height,
            block_hash_internal: previous_hash,
            chain_work: chain_work.to_be_bytes(),
            bits: previous_bits,
            block_time: previous_time,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BitcoinMainnetSpvProof {
    pub chain: BitcoinMainnetHeaderProof,
    pub tx_block_offset: u32,
    pub merkle: BitcoinMerkleProof,
    pub min_confirmations: u32,
}

impl BitcoinMainnetSpvProof {
    pub fn verify(&self) -> Result<[u8; 32], &'static str> {
        if self.chain.headers.is_empty() || self.min_confirmations == 0 {
            return Err("bitcoin SPV proof requires post-checkpoint headers and confirmations");
        }
        let tip = self.chain.verify()?;
        let offset = usize::try_from(self.tx_block_offset).map_err(|_| "tx block offset overflow")?;
        let tx_header = self
            .chain
            .headers
            .get(offset)
            .ok_or("bitcoin transaction block outside proved header segment")?;
        let confirmations = self
            .chain
            .headers
            .len()
            .checked_sub(offset)
            .ok_or("confirmation underflow")?;
        if confirmations < usize::try_from(self.min_confirmations).map_err(|_| "confirmation overflow")? {
            return Err("insufficient bitcoin confirmations on best proved chain");
        }
        if self.merkle.root() != tx_header.merkle_root_internal() {
            return Err("bitcoin transaction merkle proof mismatch");
        }

        let mut h = Sha256::new();
        h.update(BTC_SPV_DOMAIN);
        h.update(self.merkle.txid_internal);
        h.update(tx_header.block_hash());
        h.update(tip.block_hash_internal);
        h.update(tip.chain_work);
        h.update(self.min_confirmations.to_be_bytes());
        Ok(h.finalize().into())
    }
}

pub fn sha256d(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    Sha256::digest(first).into()
}

fn compact_target(bits: u32) -> Option<Uint256> {
    let exponent = (bits >> 24) as usize;
    let mantissa = bits & 0x007f_ffff;
    if bits & 0x0080_0000 != 0 || mantissa == 0 || exponent > 32 {
        return None;
    }

    let mut bytes = [0u8; 32];
    if exponent <= 3 {
        let value = mantissa >> (8 * (3 - exponent));
        bytes[28..].copy_from_slice(&value.to_be_bytes());
    } else {
        let start = 32usize.checked_sub(exponent)?;
        bytes[start] = ((mantissa >> 16) & 0xff) as u8;
        if start + 1 < 32 {
            bytes[start + 1] = ((mantissa >> 8) & 0xff) as u8;
        }
        if start + 2 < 32 {
            bytes[start + 2] = (mantissa & 0xff) as u8;
        }
    }
    Some(Uint256::from_be_bytes(bytes))
}

fn target_to_compact(target: Uint256) -> Option<u32> {
    if target.is_zero() {
        return None;
    }
    let bytes = target.to_be_bytes();
    let first = bytes.iter().position(|b| *b != 0)?;
    let mut size = 32usize.checked_sub(first)?;
    let mut mantissa = if size <= 3 {
        let mut value = 0u32;
        for b in &bytes[first..] {
            value = (value << 8) | u32::from(*b);
        }
        value << (8 * (3 - size))
    } else {
        (u32::from(bytes[first]) << 16)
            | (u32::from(bytes[first + 1]) << 8)
            | u32::from(bytes[first + 2])
    };

    if mantissa & 0x0080_0000 != 0 {
        mantissa >>= 8;
        size = size.checked_add(1)?;
    }
    if size > 32 {
        return None;
    }
    Some((u32::try_from(size).ok()? << 24) | (mantissa & 0x007f_ffff))
}

fn block_work(bits: u32) -> Result<Uint256, &'static str> {
    let target = compact_target(bits).ok_or("invalid bitcoin work target")?;
    if target > bitcoin_mainnet_pow_limit() {
        return Err("bitcoin work target exceeds pow limit");
    }
    let divisor = target
        .checked_add(Uint256::from_be_bytes({
            let mut one = [0u8; 32];
            one[31] = 1;
            one
        }))
        .ok_or("bitcoin work divisor overflow")?;
    let numerator = Uint256::MAX
        .checked_sub(target)
        .ok_or("bitcoin work numerator underflow")?;
    numerator
        .div(divisor)
        .and_then(|q| q.checked_add(Uint256::from_be_bytes({
            let mut one = [0u8; 32];
            one[31] = 1;
            one
        })))
        .ok_or("bitcoin block work calculation failed")
}

fn next_work_required_mainnet(
    next_height: u32,
    previous_bits: u32,
    previous_time: u32,
    period_start_time: u32,
) -> Result<u32, &'static str> {
    if next_height % BITCOIN_RETARGET_INTERVAL != 0 {
        return Ok(previous_bits);
    }

    let old_target = compact_target(previous_bits).ok_or("invalid previous bitcoin target")?;
    let actual = i64::from(previous_time) - i64::from(period_start_time);
    let min_span = (BITCOIN_TARGET_TIMESPAN_SECONDS / 4) as i64;
    let max_span = (BITCOIN_TARGET_TIMESPAN_SECONDS * 4) as i64;
    let clamped = actual.clamp(min_span, max_span) as u64;

    let mut next = old_target
        .checked_mul_u64(clamped)
        .ok_or("bitcoin retarget multiplication overflow")?
        .div_u64(BITCOIN_TARGET_TIMESPAN_SECONDS)
        .ok_or("bitcoin retarget division failed")?;
    if next > bitcoin_mainnet_pow_limit() {
        next = bitcoin_mainnet_pow_limit();
    }
    target_to_compact(next).ok_or("bitcoin retarget compact encoding failed")
}

fn median_time_past(times: &[u32]) -> Result<u32, &'static str> {
    if times.is_empty() || times.len() > 11 {
        return Err("invalid bitcoin median-time-past window");
    }
    let mut ordered = times.to_vec();
    ordered.sort_unstable();
    Ok(ordered[ordered.len() / 2])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header_from_hex(hex_header: &str) -> BitcoinHeader {
        let raw = hex::decode(hex_header).unwrap();
        let mut header = [0u8; 80];
        header.copy_from_slice(&raw);
        BitcoinHeader { raw: header }
    }

    #[test]
    fn genesis_header_pow_and_hash_are_valid() {
        let h = header_from_hex(concat!(
            "01000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a",
            "29ab5f49",
            "ffff001d",
            "1dac2b7c"
        ));
        assert!(h.validate_mainnet_pow().is_ok());
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
        )
        .unwrap();
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&txid_internal);
        let p = BitcoinMerkleProof {
            txid_internal: txid,
            tx_index: 0,
            siblings_internal: vec![],
        };
        assert_eq!(p.root(), txid);
    }

    #[test]
    fn diff_one_block_work_matches_bitcoin_core_formula() {
        let work = block_work(0x1d00ffff).unwrap().to_be_bytes();
        assert_eq!(&work[24..], &0x0000000100010001u64.to_be_bytes());
    }

    #[test]
    fn mainnet_retarget_matches_bitcoin_core_pow_test_vector() {
        assert_eq!(
            next_work_required_mainnet(32256, 0x1d00ffff, 1262152739, 1261130161).unwrap(),
            0x1d00d86a
        );
    }

    #[test]
    fn compact_round_trip_matches_pow_limit() {
        let target = compact_target(0x1d00ffff).unwrap();
        assert_eq!(target_to_compact(target), Some(0x1d00ffff));
        assert!(target <= bitcoin_mainnet_pow_limit());
    }

    #[test]
    fn protocol_checkpoint_is_pinned_to_bitcoin_core_assumevalid() {
        let checkpoint = bitcoin_mainnet_trusted_checkpoint();
        assert_eq!(checkpoint.height, 966_143);
        let mut display = checkpoint.block_hash_internal;
        display.reverse();
        assert_eq!(
            hex::encode(display),
            "00000000000000000000748969ec33043c0e52a763c6dd5193861f559f2c72e3"
        );
        assert_eq!(checkpoint.bits, 0x1702355e);
        assert_eq!(checkpoint.block_time, 1_788_925_573);
        assert!(checkpoint.validate().is_ok());
    }

    #[test]
    fn real_mainnet_block_966144_extends_protocol_checkpoint() {
        let header = header_from_hex(
            "00000520e3722c9f551f869351ddc663a7520e3c0433ec6989740000000000000000000021cf969e6fe1a57adbddd252418d212667079f6100330c96d7eaf29c654eee013fd8a06a5e350217d1aa3732"
        );
        let proof = BitcoinMainnetHeaderProof {
            headers: vec![header.clone()],
        };
        let tip = proof.verify().unwrap();
        assert_eq!(tip.height, 966_144);
        let mut display = tip.block_hash_internal;
        display.reverse();
        assert_eq!(
            hex::encode(display),
            "000000000000000000010a8fffd5112dba2e1910198d003453da3be093e4c2d0"
        );

        let mut tampered = header;
        tampered.raw[79] ^= 1;
        assert!(BitcoinMainnetHeaderProof {
            headers: vec![tampered],
        }
        .verify()
        .is_err());
    }
}
