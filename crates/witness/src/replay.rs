//! Re-executing a block from its witness, without state.

use crate::stream::{StreamError, StreamReader};
use alloy_primitives::{Address, B256, U256};
use reth_evm::{
    execute::{BasicBlockExecutor, Executor},
    ConfigureEvm,
};
use reth_execution_types::BlockExecutionResult;
use reth_primitives_traits::{BlockTy, ReceiptTy, RecoveredBlock};
use revm::{
    bytecode::Bytecode, database::Database, database_interface::DBErrorMarker, state::AccountInfo,
};

/// Why a block could not be replayed.
#[derive(Debug, thiserror::Error)]
pub enum ReplayError {
    /// The witness ran out or does not decode.
    #[error(transparent)]
    Stream(#[from] StreamError),
    /// The code source has no code for a hash the block needed.
    #[error("no code for hash {0}")]
    MissingCode(B256),
    /// The hash source has no hash for a block `BLOCKHASH` asked for.
    #[error("no hash for block {0}")]
    MissingBlockHash(u64),
    /// The executor refused the block.
    #[error("execution: {0}")]
    Execution(String),
    /// Execution finished with witness left over: it read less than was
    /// recorded, so it did not execute what was recorded.
    #[error("{0} bytes of witness were not consumed")]
    Unconsumed(usize),
}

impl DBErrorMarker for ReplayError {}

/// A database that answers each read with the next value of a witness.
///
/// Code and block hashes are not in the witness; `codes` and `hashes`
/// supply them. `codes` is asked by code hash, `hashes` by block number.
pub struct WitnessDb<'a, C, H> {
    reader: StreamReader<'a>,
    codes: C,
    hashes: H,
}

impl<C, H> core::fmt::Debug for WitnessDb<'_, C, H> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WitnessDb").field("reader", &self.reader).finish_non_exhaustive()
    }
}

impl<'a, C, H> WitnessDb<'a, C, H> {
    /// A database over `witness`.
    pub const fn new(witness: &'a [u8], codes: C, hashes: H) -> Self {
        Self { reader: StreamReader::new(witness), codes, hashes }
    }

    /// The reader, to see how much of the witness was consumed.
    pub const fn reader(&self) -> &StreamReader<'a> {
        &self.reader
    }
}

impl<C, H> Database for WitnessDb<'_, C, H>
where
    C: FnMut(B256) -> Option<Bytecode>,
    H: FnMut(u64) -> Option<B256>,
{
    type Error = ReplayError;

    fn basic(&mut self, _address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        Ok(self.reader.next_account()?)
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        (self.codes)(code_hash).ok_or(ReplayError::MissingCode(code_hash))
    }

    fn storage(&mut self, _address: Address, _index: U256) -> Result<U256, Self::Error> {
        Ok(self.reader.next_slot()?)
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        (self.hashes)(number).ok_or(ReplayError::MissingBlockHash(number))
    }
}

/// Executes `block` against its `witness` with a fresh state, the way the
/// witness was recorded, and returns what execution produced. The caller
/// validates the result against the header (gas used, receipts root) — the
/// witness proves nothing by itself.
pub fn replay_block<E, C, H>(
    evm_config: &E,
    block: &RecoveredBlock<BlockTy<E::Primitives>>,
    witness: &[u8],
    codes: C,
    hashes: H,
) -> Result<BlockExecutionResult<ReceiptTy<E::Primitives>>, ReplayError>
where
    E: ConfigureEvm,
    C: FnMut(B256) -> Option<Bytecode>,
    H: FnMut(u64) -> Option<B256>,
{
    let db = WitnessDb::new(witness, codes, hashes);
    let mut executor = BasicBlockExecutor::new(evm_config, db);
    let result =
        executor.execute_one(block).map_err(|err| ReplayError::Execution(err.to_string()))?;
    let left = executor.into_state().database.reader().remaining();
    if left != 0 {
        return Err(ReplayError::Unconsumed(left));
    }
    Ok(result)
}
