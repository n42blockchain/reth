//! Positional state-read witnesses.
//!
//! A witness is the sequence of values a block's execution read from state —
//! account by account, slot by slot, in the order a fresh
//! [`State`](revm::database::State) sent them to its database — and nothing
//! else: no keys, no ordering information, no code, no block hashes. That is
//! what makes it small and what makes replaying it free of lookups: a
//! re-executor runs the block against a fresh `State` whose database answers
//! each read with the next value in the stream.
//!
//! It also fixes the contract between the two sides. The stream is correct
//! for a re-executor exactly when that re-executor asks its database the
//! same questions in the same order the recorder's fresh `State` did. Both
//! sides here are the same revm `State` and the same reth block executor,
//! so the order is the same by construction; a different EVM, a different
//! `State`, or a different executor would need its own witness.
//!
//! - [`stream`] is the byte format of one block's values.
//! - [`store`] keeps the streams of a chain on disk, one entry per block.
//! - [`record`] is the [`StateReadObserver`](revm::database::StateReadObserver) the execution stage
//!   installs on its batch `State` to write the store.
//! - [`replay`] is the database that serves a stream back to an executor, and the one-call
//!   re-execution of a block from its witness.

pub mod record;
pub mod replay;
pub mod store;
pub mod stream;

pub use record::WitnessRecorder;
pub use replay::{replay_block, ReplayError, WitnessDb};
pub use store::{StoreError, WitnessStore, WitnessWriter};
pub use stream::{StreamError, StreamReader};
