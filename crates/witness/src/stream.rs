//! One block's witness: the values it read, framed for positional reading.
//!
//! Every entry is `[len: u8][bytes: len]`. The reader knows from its own
//! position in the execution whether the next entry is an account or a
//! storage slot, so entries carry no type and no key.
//!
//! An account entry with `len == 0` is an absent account. Otherwise its
//! bytes are `[nonce: uint][balance: uint][code: 0 | 1 ‖ hash32]`, where a
//! `uint` is `[n: u8][big-endian bytes: n]` with leading zeros stripped, and
//! a code flag of `0` means the empty-code hash. The longest account is 75
//! bytes.
//!
//! A slot entry is the value's big-endian bytes with leading zeros stripped;
//! zero is `len == 0`.

use alloy_primitives::{B256, KECCAK256_EMPTY as KECCAK_EMPTY, U256};
use revm::state::AccountInfo;

/// Appends the account entry for `info`.
pub fn put_account(out: &mut Vec<u8>, info: Option<&AccountInfo>) {
    let Some(info) = info else {
        out.push(0);
        return;
    };
    let start = out.len();
    out.push(0);
    put_uint(out, &info.nonce.to_be_bytes());
    put_uint(out, &info.balance.to_be_bytes::<32>());
    if info.code_hash == KECCAK_EMPTY {
        out.push(0);
    } else {
        out.push(1);
        out.extend_from_slice(info.code_hash.as_slice());
    }
    let len = out.len() - start - 1;
    debug_assert!(len <= u8::MAX as usize);
    out[start] = len as u8;
}

/// Appends the slot entry for `value`.
pub fn put_slot(out: &mut Vec<u8>, value: U256) {
    put_uint(out, &value.to_be_bytes::<32>());
}

fn put_uint(out: &mut Vec<u8>, be: &[u8]) {
    let first = be.iter().position(|b| *b != 0).unwrap_or(be.len());
    let trimmed = &be[first..];
    out.push(trimmed.len() as u8);
    out.extend_from_slice(trimmed);
}

/// Why a stream could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StreamError {
    /// The execution asked for a value past the end of the stream.
    #[error("witness exhausted after {consumed} bytes: the execution read more than was recorded")]
    Exhausted {
        /// Bytes consumed before the read that found nothing.
        consumed: usize,
    },
    /// An entry does not decode as what the execution asked for.
    #[error("witness malformed at byte {at}: {what}")]
    Malformed {
        /// Offset of the entry.
        at: usize,
        /// What was wrong with it.
        what: &'static str,
    },
}

/// Reads a stream entry by entry.
#[derive(Debug, Clone)]
pub struct StreamReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> StreamReader<'a> {
    /// A reader at the start of `data`.
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Bytes not yet consumed.
    pub const fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    /// Bytes consumed so far.
    pub const fn consumed(&self) -> usize {
        self.pos
    }

    fn entry(&mut self) -> Result<(usize, &'a [u8]), StreamError> {
        let at = self.pos;
        let Some(&len) = self.data.get(at) else {
            return Err(StreamError::Exhausted { consumed: at });
        };
        let start = at + 1;
        let end = start + len as usize;
        let bytes = self
            .data
            .get(start..end)
            .ok_or(StreamError::Malformed { at, what: "entry runs past the end of the stream" })?;
        self.pos = end;
        Ok((at, bytes))
    }

    /// The next entry as an account.
    pub fn next_account(&mut self) -> Result<Option<AccountInfo>, StreamError> {
        let (at, bytes) = self.entry()?;
        if bytes.is_empty() {
            return Ok(None);
        }
        let malformed = |what| StreamError::Malformed { at, what };
        let (nonce, rest) = take_uint(bytes).ok_or_else(|| malformed("nonce"))?;
        if nonce.len() > 8 {
            return Err(malformed("nonce wider than 64 bits"));
        }
        let (balance, rest) = take_uint(rest).ok_or_else(|| malformed("balance"))?;
        if balance.len() > 32 {
            return Err(malformed("balance wider than 256 bits"));
        }
        let code_hash = match rest {
            [0] => KECCAK_EMPTY,
            [1, hash @ ..] if hash.len() == 32 => B256::from_slice(hash),
            _ => return Err(malformed("code hash")),
        };
        Ok(Some(AccountInfo {
            nonce: u64::from_be_bytes(padded::<8>(nonce)),
            balance: U256::from_be_bytes(padded::<32>(balance)),
            code_hash,
            code: None,
            ..Default::default()
        }))
    }

    /// The next entry as a storage slot.
    pub fn next_slot(&mut self) -> Result<U256, StreamError> {
        let (at, bytes) = self.entry()?;
        if bytes.len() > 32 {
            return Err(StreamError::Malformed { at, what: "slot value wider than 256 bits" });
        }
        Ok(U256::from_be_bytes(padded::<32>(bytes)))
    }
}

fn take_uint(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let (&n, rest) = bytes.split_first()?;
    if rest.len() < n as usize {
        return None;
    }
    Some(rest.split_at(n as usize))
}

fn padded<const N: usize>(trimmed: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    out[N - trimmed.len()..].copy_from_slice(trimmed);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account(nonce: u64, balance: U256, code_hash: B256) -> AccountInfo {
        AccountInfo { nonce, balance, code_hash, code: None, ..Default::default() }
    }

    #[test]
    fn accounts_and_slots_round_trip() {
        let mut out = Vec::new();
        let accounts = [
            None,
            Some(account(0, U256::ZERO, KECCAK_EMPTY)),
            Some(account(1, U256::from(1), KECCAK_EMPTY)),
            Some(account(u64::MAX, U256::MAX, B256::repeat_byte(0xAB))),
            Some(account(300, U256::from(1u128 << 100), B256::ZERO)),
        ];
        let slots =
            [U256::ZERO, U256::from(1), U256::from(256), U256::MAX, U256::from(1u128 << 64)];
        for (account, slot) in accounts.iter().zip(&slots) {
            put_account(&mut out, account.as_ref());
            put_slot(&mut out, *slot);
        }

        let mut reader = StreamReader::new(&out);
        for (account, slot) in accounts.iter().zip(&slots) {
            assert_eq!(reader.next_account().unwrap(), *account);
            assert_eq!(reader.next_slot().unwrap(), *slot);
        }
        assert_eq!(reader.remaining(), 0);
        assert_eq!(reader.next_account(), Err(StreamError::Exhausted { consumed: out.len() }));
    }

    #[test]
    fn the_longest_account_fits_its_length_byte() {
        let mut out = Vec::new();
        put_account(&mut out, Some(&account(u64::MAX, U256::MAX, B256::repeat_byte(1))));
        assert_eq!(out.len(), 1 + 75);
        assert_eq!(out[0], 75);
    }

    #[test]
    fn an_absent_account_is_one_zero_byte_and_a_zero_slot_too() {
        let mut out = Vec::new();
        put_account(&mut out, None);
        put_slot(&mut out, U256::ZERO);
        assert_eq!(out, [0, 0]);
    }

    #[test]
    fn a_truncated_entry_is_malformed_not_a_panic() {
        let bytes = [5u8, 1, 2];
        let mut reader = StreamReader::new(&bytes);
        assert!(matches!(reader.next_slot(), Err(StreamError::Malformed { at: 0, .. })));
    }
}
