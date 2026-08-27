//! Recording a witness while a block executes.
//!
//! The execution stage runs blocks through one long-lived [`State`] whose
//! cache carries values from block to block. A re-executor starts every
//! block with a fresh `State`, so the reads *it* will send to its database
//! are not the ones the stage's `State` sends to the provider — a value
//! cached since an earlier block is read from the cache, and never seen
//! below it.
//!
//! The recorder therefore keeps a fresh `State` of its own per block, the
//! *shadow*, with a database that hands back whatever value the stage's
//! `State` just answered and appends it to the stream as it does so. Every
//! read the stage's `State` answers is offered to the shadow; the shadow's
//! own cache decides whether that read reaches its database — which is
//! precisely the decision the re-executor's fresh `State` will make, taken
//! by the same code. Commits are mirrored so the shadow's cache evolves
//! through the block as the re-executor's will.
//!
//! Nothing is guessed about the cache; the only invariant this relies on is
//! that the recorder and the re-executor run the same revm `State` and the
//! same executor, and any breach of what the shadow expects — a slot read
//! for an account it never saw, a commit for one — fails the block loudly.

use crate::{
    store::{StoreError, WitnessWriter},
    stream::{put_account, put_slot},
};
use alloy_primitives::{Address, B256, U256};
use revm::{
    bytecode::Bytecode,
    database::{Database, ObserverError, State, StateReadObserver},
    database_interface::DBErrorMarker,
    state::{Account, AccountInfo},
};
use std::{borrow::Cow, path::PathBuf};

/// The shadow's database: answers with the value staged for it and records
/// what it answered. Asked for anything not staged, it errors — that is a
/// read the recorder did not expect and cannot represent.
#[derive(Debug, Default)]
struct Sink {
    account: Option<Option<AccountInfo>>,
    slot: Option<U256>,
    stream: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
enum SinkError {
    #[error("account {0} was read before any read of it reached the recorder")]
    Account(Address),
    #[error("slot {1} of {0} was read before any read of it reached the recorder")]
    Slot(Address, U256),
    #[error("the shadow state asked for code {0}; it has no business with code")]
    Code(B256),
    #[error(
        "the shadow state asked for the hash of block {0}; it has no business with block hashes"
    )]
    BlockHash(u64),
}

impl DBErrorMarker for SinkError {}

impl Database for Sink {
    type Error = SinkError;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        let info = self.account.take().ok_or(SinkError::Account(address))?;
        put_account(&mut self.stream, info.as_ref());
        Ok(info)
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        Err(SinkError::Code(code_hash))
    }

    fn storage(&mut self, address: Address, index: U256) -> Result<U256, Self::Error> {
        let value = self.slot.take().ok_or(SinkError::Slot(address, index))?;
        put_slot(&mut self.stream, value);
        Ok(value)
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        Err(SinkError::BlockHash(number))
    }
}

/// Records the witness of every block a [`State`] executes, into a
/// [`WitnessWriter`]. Install with
/// [`State::set_read_observer`] (or through the executor) and mark block
/// boundaries with [`begin_block`](StateReadObserver::begin_block) and
/// [`end_block`](StateReadObserver::end_block).
#[derive(Debug)]
pub struct WitnessRecorder {
    shadow: State<Sink>,
    writer: WitnessWriter,
    block: Option<u64>,
    failure: Option<String>,
}

impl WitnessRecorder {
    /// A recorder writing to the store in `dir`, resuming at `next_block`.
    pub fn open(dir: impl Into<PathBuf>, next_block: u64) -> Result<Self, StoreError> {
        Ok(Self::new(WitnessWriter::open(dir, next_block)?))
    }

    /// A recorder writing to `writer`.
    pub fn new(writer: WitnessWriter) -> Self {
        Self { shadow: fresh_shadow(Vec::new()), writer, block: None, failure: None }
    }

    /// The writer, to look at what has been recorded.
    pub const fn writer(&self) -> &WitnessWriter {
        &self.writer
    }

    fn fail(&mut self, what: impl std::fmt::Display) {
        if self.failure.is_none() {
            let block = self
                .block
                .map_or_else(|| "outside any block".to_string(), |n| format!("block {n}"));
            self.failure = Some(format!("recording {block}: {what}"));
        }
    }
}

fn fresh_shadow(stream: Vec<u8>) -> State<Sink> {
    State::builder().with_database(Sink { account: None, slot: None, stream }).build()
}

impl StateReadObserver for WitnessRecorder {
    fn begin_block(&mut self, number: u64) {
        if let Some(open) = self.block.replace(number) {
            self.fail(format!("block {open} never ended"));
        }
        let mut stream = std::mem::take(&mut self.shadow.database.stream);
        stream.clear();
        self.shadow = fresh_shadow(stream);
    }

    fn basic(&mut self, address: Address, info: Option<&AccountInfo>) {
        if self.block.is_none() || self.shadow.cache.accounts.contains_key(&address) {
            return;
        }
        self.shadow.database.account = Some(info.cloned());
        if let Err(err) = self.shadow.basic(address) {
            self.fail(err);
        }
        self.shadow.database.account = None;
    }

    fn storage(&mut self, address: Address, index: U256, value: U256) {
        if self.block.is_none() {
            return;
        }
        if !self.shadow.cache.accounts.contains_key(&address) {
            self.fail(SinkError::Slot(address, index));
            return;
        }
        self.shadow.database.slot = Some(value);
        if let Err(err) = self.shadow.storage(address, index) {
            self.fail(err);
        }
        self.shadow.database.slot = None;
    }

    fn committed(&mut self, address: Address, account: &Account) {
        if self.block.is_none() {
            return;
        }
        if !self.shadow.cache.accounts.contains_key(&address) {
            self.fail(format!("account {address} committed without ever being read"));
            return;
        }
        let _ = self.shadow.cache.apply_account_state(address, Cow::Borrowed(account));
    }

    fn end_block(&mut self) -> Result<(), ObserverError> {
        let Some(number) = self.block.take() else {
            return Err("end of a block that never began".into());
        };
        if let Some(failure) = self.failure.take() {
            return Err(failure.into());
        }
        self.writer.append(number, &self.shadow.database.stream)?;
        self.shadow.database.stream.clear();
        Ok(())
    }

    fn finish(&mut self) -> Result<(), ObserverError> {
        if let Some(failure) = self.failure.take() {
            return Err(failure.into());
        }
        self.writer.flush()?;
        Ok(())
    }
}
