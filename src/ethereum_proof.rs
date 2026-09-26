#![forbid(unsafe_code)]

pub const ETH_MPT_DOMAIN: &[u8] = b"SYNERGY/ETH-MPT/V1\0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EthereumAccountProof {
    pub state_root: [u8; 32],
    pub address: [u8; 20],
    pub account_rlp: Vec<u8>,
    pub proof_nodes: Vec<Vec<u8>>,
}

impl EthereumAccountProof {
    pub fn verify(&self) -> Result<[u8; 32], &'static str> {
        let path = keccak256(&self.address);
        let value = verify_mpt_inclusion(self.state_root, &path, &self.proof_nodes)?;
        if value != self.account_rlp {
            return Err("ethereum account RLP mismatch");
        }
        Ok(keccak256(&self.account_rlp))
    }

    pub fn storage_root(&self) -> Result<[u8; 32], &'static str> {
        let items = decode_list_items(&self.account_rlp)?;
        if items.len() != 4 || items[2].is_list {
            return Err("ethereum account RLP must contain storage root");
        }
        if items[2].payload.len() != 32 {
            return Err("ethereum account storage root length mismatch");
        }
        let mut root = [0u8; 32];
        root.copy_from_slice(items[2].payload);
        Ok(root)
    }

    pub fn code_hash(&self) -> Result<[u8; 32], &'static str> {
        let items = decode_list_items(&self.account_rlp)?;
        if items.len() != 4 || items[3].is_list || items[3].payload.len() != 32 {
            return Err("ethereum account RLP must contain 32-byte code hash");
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(items[3].payload);
        Ok(hash)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EthereumStorageProof {
    pub slot_key: [u8; 32],
    pub value_rlp: Vec<u8>,
    pub proof_nodes: Vec<Vec<u8>>,
}

impl EthereumStorageProof {
    pub fn verify(
        &self,
        storage_root: [u8; 32],
    ) -> Result<[u8; 32], &'static str> {
        let path = keccak256(&self.slot_key);
        let value = verify_mpt_inclusion(storage_root, &path, &self.proof_nodes)?;
        if value != self.value_rlp {
            return Err("ethereum storage RLP mismatch");
        }
        Ok(keccak256(&self.value_rlp))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RlpItem<'a> {
    raw: &'a [u8],
    payload: &'a [u8],
    is_list: bool,
}

fn parse_item(input: &[u8]) -> Result<(RlpItem<'_>, usize), &'static str> {
    let first = *input.first().ok_or("truncated RLP")?;
    match first {
        0x00..=0x7f => Ok((
            RlpItem {
                raw: &input[..1],
                payload: &input[..1],
                is_list: false,
            },
            1,
        )),
        0x80..=0xb7 => {
            let len = usize::from(first - 0x80);
            let end = 1usize.checked_add(len).ok_or("RLP length overflow")?;
            if input.len() < end {
                return Err("truncated RLP bytes");
            }
            Ok((
                RlpItem {
                    raw: &input[..end],
                    payload: &input[1..end],
                    is_list: false,
                },
                end,
            ))
        }
        0xb8..=0xbf => {
            let len_of_len = usize::from(first - 0xb7);
            let header = 1usize.checked_add(len_of_len).ok_or("RLP header overflow")?;
            if input.len() < header {
                return Err("truncated RLP long-bytes length");
            }
            let len = be_usize(&input[1..header])?;
            if len < 56 {
                return Err("noncanonical RLP long bytes");
            }
            let end = header.checked_add(len).ok_or("RLP length overflow")?;
            if input.len() < end {
                return Err("truncated RLP long bytes");
            }
            Ok((
                RlpItem {
                    raw: &input[..end],
                    payload: &input[header..end],
                    is_list: false,
                },
                end,
            ))
        }
        0xc0..=0xf7 => {
            let len = usize::from(first - 0xc0);
            let end = 1usize.checked_add(len).ok_or("RLP list overflow")?;
            if input.len() < end {
                return Err("truncated RLP list");
            }
            Ok((
                RlpItem {
                    raw: &input[..end],
                    payload: &input[1..end],
                    is_list: true,
                },
                end,
            ))
        }
        0xf8..=0xff => {
            let len_of_len = usize::from(first - 0xf7);
            let header = 1usize.checked_add(len_of_len).ok_or("RLP header overflow")?;
            if input.len() < header {
                return Err("truncated RLP long-list length");
            }
            let len = be_usize(&input[1..header])?;
            if len < 56 {
                return Err("noncanonical RLP long list");
            }
            let end = header.checked_add(len).ok_or("RLP list overflow")?;
            if input.len() < end {
                return Err("truncated RLP long list");
            }
            Ok((
                RlpItem {
                    raw: &input[..end],
                    payload: &input[header..end],
                    is_list: true,
                },
                end,
            ))
        }
    }
}

fn be_usize(bytes: &[u8]) -> Result<usize, &'static str> {
    if bytes.is_empty() || bytes[0] == 0 || bytes.len() > core::mem::size_of::<usize>() {
        return Err("invalid RLP length");
    }
    let mut out = 0usize;
    for b in bytes {
        out = out
            .checked_mul(256)
            .and_then(|v| v.checked_add(usize::from(*b)))
            .ok_or("RLP length overflow")?;
    }
    Ok(out)
}

fn decode_list_items(encoded: &[u8]) -> Result<Vec<RlpItem<'_>>, &'static str> {
    let (root, consumed) = parse_item(encoded)?;
    if consumed != encoded.len() || !root.is_list {
        return Err("expected canonical RLP list");
    }
    let mut rest = root.payload;
    let mut out = Vec::new();
    while !rest.is_empty() {
        let (item, used) = parse_item(rest)?;
        out.push(item);
        rest = &rest[used..];
    }
    Ok(out)
}

fn bytes_to_nibbles(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(b >> 4);
        out.push(b & 0x0f);
    }
    out
}

fn compact_path(encoded: &[u8]) -> Result<(bool, Vec<u8>), &'static str> {
    let first = *encoded.first().ok_or("empty hex-prefix path")?;
    let flag = first >> 4;
    if flag > 3 {
        return Err("invalid hex-prefix flag");
    }
    let leaf = flag >= 2;
    let odd = flag & 1 == 1;
    let mut nibbles = Vec::with_capacity(encoded.len() * 2);
    if odd {
        nibbles.push(first & 0x0f);
    } else if first & 0x0f != 0 {
        return Err("noncanonical hex-prefix padding");
    }
    for b in &encoded[1..] {
        nibbles.push(b >> 4);
        nibbles.push(b & 0x0f);
    }
    Ok((leaf, nibbles))
}

fn child_reference(item: RlpItem<'_>) -> Result<Vec<u8>, &'static str> {
    if item.is_list {
        if item.raw.len() >= 32 {
            return Err("embedded trie child must be shorter than 32 bytes");
        }
        Ok(item.raw.to_vec())
    } else if item.payload.is_empty() {
        Err("empty trie child")
    } else {
        Ok(item.payload.to_vec())
    }
}

fn verify_node_reference(expected: &[u8], encoded_node: &[u8]) -> bool {
    if expected.len() == 32 {
        keccak256(encoded_node).as_slice() == expected
    } else {
        expected == encoded_node
    }
}


pub fn decode_evm_block_header_state_root(
    encoded_header: &[u8],
) -> Result<[u8; 32], &'static str> {
    let items = decode_list_items(encoded_header)?;
    if items.len() < 4 || items[3].is_list || items[3].payload.len() != 32 {
        return Err("EVM block header stateRoot field missing or malformed");
    }
    let mut root = [0u8; 32];
    root.copy_from_slice(items[3].payload);
    Ok(root)
}

pub fn verify_mpt_inclusion(
    root: [u8; 32],
    secure_key: &[u8],
    proof_nodes: &[Vec<u8>],
) -> Result<Vec<u8>, &'static str> {
    if proof_nodes.is_empty() {
        return Err("ethereum MPT proof requires nodes");
    }
    let mut expected_ref = root.to_vec();
    let key = bytes_to_nibbles(secure_key);
    let mut offset = 0usize;

    for encoded in proof_nodes {
        if !verify_node_reference(&expected_ref, encoded) {
            return Err("ethereum MPT node reference mismatch");
        }
        let items = decode_list_items(encoded)?;

        if items.len() == 17 {
            if offset == key.len() {
                let value = items[16];
                if value.is_list || value.payload.is_empty() {
                    return Err("ethereum MPT branch has no value");
                }
                return Ok(value.payload.to_vec());
            }
            let nibble = usize::from(key[offset]);
            expected_ref = child_reference(items[nibble])?;
            offset += 1;
        } else if items.len() == 2 {
            if items[0].is_list {
                return Err("ethereum MPT compact path must be bytes");
            }
            let (leaf, path) = compact_path(items[0].payload)?;
            if key.get(offset..offset + path.len()) != Some(path.as_slice()) {
                return Err("ethereum MPT compact path mismatch");
            }
            offset += path.len();
            if leaf {
                if offset != key.len() || items[1].is_list {
                    return Err("ethereum MPT leaf does not terminate exact key");
                }
                return Ok(items[1].payload.to_vec());
            }
            expected_ref = child_reference(items[1])?;
        } else {
            return Err("invalid ethereum MPT node arity");
        }
    }

    Err("ethereum MPT proof ended before value")
}

pub fn keccak256(input: &[u8]) -> [u8; 32] {
    const RATE: usize = 136;
    let mut state = [0u64; 25];
    let mut chunks = input.chunks_exact(RATE);
    for chunk in &mut chunks {
        absorb_block(&mut state, chunk);
        keccak_f1600(&mut state);
    }

    let rem = chunks.remainder();
    let mut block = [0u8; RATE];
    block[..rem.len()].copy_from_slice(rem);
    block[rem.len()] ^= 0x01;
    block[RATE - 1] ^= 0x80;
    absorb_block(&mut state, &block);
    keccak_f1600(&mut state);

    let mut out = [0u8; 32];
    for (i, chunk) in out.chunks_exact_mut(8).enumerate() {
        chunk.copy_from_slice(&state[i].to_le_bytes());
    }
    out
}

fn absorb_block(state: &mut [u64; 25], block: &[u8]) {
    for (i, chunk) in block.chunks_exact(8).enumerate() {
        let mut word = [0u8; 8];
        word.copy_from_slice(chunk);
        state[i] ^= u64::from_le_bytes(word);
    }
}

fn keccak_f1600(a: &mut [u64; 25]) {
    const RC: [u64; 24] = [
        0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
        0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
        0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
        0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
        0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
        0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
        0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
        0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
    ];
    const R: [u32; 25] = [
        0, 1, 62, 28, 27,
        36, 44, 6, 55, 20,
        3, 10, 43, 25, 39,
        41, 45, 15, 21, 8,
        18, 2, 61, 56, 14,
    ];

    for rc in RC {
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        }
        let mut d = [0u64; 5];
        for x in 0..5 {
            d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
        }
        for y in 0..5 {
            for x in 0..5 {
                a[x + 5 * y] ^= d[x];
            }
        }

        let mut b = [0u64; 25];
        for y in 0..5 {
            for x in 0..5 {
                let nx = y;
                let ny = (2 * x + 3 * y) % 5;
                b[nx + 5 * ny] = a[x + 5 * y].rotate_left(R[x + 5 * y]);
            }
        }

        for y in 0..5 {
            for x in 0..5 {
                a[x + 5 * y] =
                    b[x + 5 * y] ^ ((!b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y]);
            }
        }
        a[0] ^= rc;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keccak_matches_ethereum_empty_string_vector() {
        assert_eq!(
            hex::encode(keccak256(b"")),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
    }

    #[test]
    fn rlp_account_extracts_storage_root() {
        let storage = [0x11u8; 32];
        let code = [0x22u8; 32];
        let mut account = Vec::new();
        let payload_len = 1 + 1 + 33 + 33;
        account.push(0xf8);
        account.push(u8::try_from(payload_len).unwrap());
        account.push(0x80);
        account.push(0x80);
        account.push(0xa0);
        account.extend_from_slice(&storage);
        account.push(0xa0);
        account.extend_from_slice(&code);
        let proof = EthereumAccountProof {
            state_root: [1; 32],
            address: [2; 20],
            account_rlp: account,
            proof_nodes: vec![],
        };
        assert_eq!(proof.storage_root().unwrap(), storage);
    }
}
