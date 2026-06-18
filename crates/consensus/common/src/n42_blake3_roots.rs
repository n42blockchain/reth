//! N42 benchmark-only BLAKE3 Merkle roots.
//!
//! This module intentionally does not preserve Ethereum's MPT/receipt trie root
//! format. It is gated behind `N42_BLAKE3_BLOCK_HASH=1` and is meant only for
//! fresh-genesis throughput experiments.

use alloy_eips::Encodable2718;
use alloy_primitives::{Bloom, B256};
use reth_primitives_traits::{Receipt, SignedTransaction};
use std::vec::Vec;

/// Returns true if the N42 BLAKE3 root prototype is enabled.
pub fn enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var("N42_BLAKE3_BLOCK_HASH").is_ok_and(|v| v == "1"))
}

fn blake3_b256(hash: blake3::Hash) -> B256 {
    B256::from_slice(hash.as_bytes())
}

fn leaf(domain: &[u8], index: usize, bytes: &[u8]) -> B256 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"n42-blake3-block-roots-v1");
    hasher.update(domain);
    hasher.update(&(index as u64).to_le_bytes());
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
    blake3_b256(hasher.finalize())
}

fn pair(left: B256, right: B256) -> B256 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"n42-blake3-block-roots-v1");
    hasher.update(b"node");
    hasher.update(left.as_slice());
    hasher.update(right.as_slice());
    blake3_b256(hasher.finalize())
}

/// Merkleize byte payloads with duplicate-last padding for odd levels.
pub fn merkleize(domain: &[u8], payloads: impl IntoIterator<Item = Vec<u8>>) -> B256 {
    let mut leaves = payloads
        .into_iter()
        .enumerate()
        .map(|(idx, bytes)| leaf(domain, idx, &bytes))
        .collect::<Vec<_>>();

    if leaves.is_empty() {
        return leaf(domain, 0, &[]);
    }

    while leaves.len() > 1 {
        let mut next = Vec::with_capacity(leaves.len().div_ceil(2));
        for chunk in leaves.chunks(2) {
            let left = chunk[0];
            let right = chunk.get(1).copied().unwrap_or(left);
            next.push(pair(left, right));
        }
        leaves = next;
    }

    leaves[0]
}

/// Calculate a BLAKE3 transaction root over EIP-2718 transaction bytes.
pub fn calculate_transaction_root<T: SignedTransaction>(transactions: &[T]) -> B256 {
    merkleize(
        b"tx",
        transactions.iter().map(|tx| {
            let mut buf = Vec::with_capacity(tx.encode_2718_len());
            tx.encode_2718(&mut buf);
            buf
        }),
    )
}

/// Calculate a BLAKE3 receipt root and the standard aggregate logs bloom.
pub fn calculate_receipt_root_and_bloom<R: Receipt>(receipts: &[R]) -> (B256, Bloom) {
    let mut bloom = Bloom::ZERO;
    let root = merkleize(
        b"receipt",
        receipts.iter().map(|receipt| {
            let receipt = receipt.with_bloom_ref();
            bloom |= receipt.bloom_ref();
            receipt.encoded_2718()
        }),
    );
    (root, bloom)
}
