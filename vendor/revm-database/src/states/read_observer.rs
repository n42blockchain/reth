//! Observation of the reads a [`State`](super::State) answers, in the order it answers them.

use primitives::{Address, StorageKey, StorageValue};
use state::{Account, AccountInfo};
use std::boxed::Box;

/// The error an observer reports at a block boundary.
pub type ObserverError = Box<dyn core::error::Error + Send + Sync>;

/// Sees every account and storage read a [`State`](super::State) answers,
/// every account it commits, and the block boundaries its driver marks —
/// in order.
///
/// A `State` calls its observer *after* it has answered a read, whether the
/// answer came from its cache or its database, and *before* it applies a
/// commit. The observer never changes what the `State` returns; it is a
/// witness to the sequence, not a party to it.
///
/// The use this exists for is recording a block's state reads for
/// stateless re-execution. Re-execution runs the block against a fresh
/// `State` whose database serves values positionally, so the record must
/// hold exactly the reads a fresh `State` would send to its database, in
/// exactly their order. An observer gets that by keeping a fresh `State` of
/// its own and letting *it* decide which reads reach a database: the same
/// code makes the same decisions on both sides, and no imitation of the
/// cache is involved.
///
/// The [`DatabaseRef`](database_interface::DatabaseRef) side of a `State`
/// is not observed: it cannot borrow the observer mutably and block
/// execution never reads through it.
pub trait StateReadObserver: Send + 'static {
    /// A block is about to execute; reads until [`end_block`](Self::end_block)
    /// belong to it.
    fn begin_block(&mut self, number: u64) {
        let _ = number;
    }

    /// The `State` answered `basic(address)` with `info`.
    fn basic(&mut self, address: Address, info: Option<&AccountInfo>);

    /// The `State` answered `storage(address, index)` with `value`.
    fn storage(&mut self, address: Address, index: StorageKey, value: StorageValue);

    /// The `State` is about to apply `account` as the new state of `address`.
    fn committed(&mut self, address: Address, account: &Account);

    /// The block that began with [`begin_block`](Self::begin_block) has
    /// executed. An error here is the driver's to surface: the observer's
    /// record is incomplete or inconsistent and the run must not go on as
    /// if it were fine.
    fn end_block(&mut self) -> Result<(), ObserverError> {
        Ok(())
    }

    /// The driver is done with this `State`; anything buffered must reach
    /// its destination now.
    fn finish(&mut self) -> Result<(), ObserverError> {
        Ok(())
    }
}
