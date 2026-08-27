//! A witness recorded by the batch executor replays block by block against
//! a fresh state, with the same receipts, and passes the same
//! post-execution validation a synced node applies.
//!
//! The blocks are built to hit the places where the batch executor's
//! long-lived cache and a fresh per-block state disagree on what reaches
//! the database: accounts and slots read in an earlier block, a contract
//! created in an earlier block (known storage in the cache, loaded storage
//! in a fresh state), an account first seen absent and then created, reads
//! inside a call that reverts, and withdrawals touching accounts nothing
//! else read.

use alloy_consensus::{
    constants::EMPTY_ROOT_HASH, proofs::calculate_receipt_root, BlockHeader, Header,
    SignableTransaction, TxLegacy, TxReceipt,
};
use alloy_eips::eip4895::{Withdrawal, Withdrawals};
use alloy_primitives::{address, keccak256, Address, Bytes, Signature, TxKind, B256, U256};
use reth_chainspec::{ChainSpec, ChainSpecBuilder};
use reth_ethereum_consensus::validate_block_post_execution;
use reth_ethereum_primitives::{Block, BlockBody, Receipt, TransactionSigned};
use reth_evm::execute::{BasicBlockExecutor, Executor};
use reth_evm_ethereum::EthEvmConfig;
use reth_execution_types::BlockExecutionResult;
use reth_primitives_traits::{proofs, RecoveredBlock};
use reth_witness::{replay_block, ReplayError, WitnessRecorder, WitnessStore, WitnessWriter};
use revm::{
    bytecode::Bytecode,
    database::{CacheDB, EmptyDB},
    state::AccountInfo,
};
use std::{collections::HashMap, sync::Arc};

const ALICE: Address = address!("0x000000000000000000000000000000000000a11c");
const BOB: Address = address!("0x0000000000000000000000000000000000000b0b");
const DAVE: Address = address!("0x000000000000000000000000000000000000da7e");
const COUNTER: Address = address!("0x00000000000000000000000000000000c0047e12");
const REVERTER: Address = address!("0x000000000000000000000000000000000e7e12e1");
const CALLER: Address = address!("0x00000000000000000000000000000000ca11e100");
const WITHDRAWN_TO: Address = address!("0x00000000000000000000000000000000d1d1d1d1");
const COINBASE: Address = address!("0x00000000000000000000000000000000c01b6a5e");

/// PUSH1 0 SLOAD PUSH1 1 ADD PUSH1 0 SSTORE PUSH1 1 SLOAD POP STOP:
/// reads slots 0 and 1, bumps slot 0.
const COUNTER_CODE: &[u8] =
    &[0x60, 0, 0x54, 0x60, 1, 0x01, 0x60, 0, 0x55, 0x60, 1, 0x54, 0x50, 0x00];
/// PUSH1 0 SLOAD POP PUSH1 0 PUSH1 0 REVERT: reads slot 0, then reverts.
const REVERTER_CODE: &[u8] = &[0x60, 0, 0x54, 0x50, 0x60, 0, 0x60, 0, 0xfd];

/// CALL(gas, REVERTER, 0, 0, 0, 0, 0) POP; BALANCE(DAVE) POP; PUSH1 0 SLOAD POP STOP:
/// a read inside a frame that reverts, a cold account read, an own slot read.
fn caller_code() -> Vec<u8> {
    let mut code = vec![0x60, 0, 0x60, 0, 0x60, 0, 0x60, 0, 0x60, 0, 0x73];
    code.extend_from_slice(REVERTER.as_slice());
    code.extend_from_slice(&[0x5a, 0xf1, 0x50, 0x73]);
    code.extend_from_slice(DAVE.as_slice());
    code.extend_from_slice(&[0x31, 0x50, 0x60, 0, 0x54, 0x50, 0x00]);
    code
}

/// Init code: SLOAD 0 POP; SSTORE 0 = 1; return `COUNTER_CODE` as runtime.
fn creator_init_code() -> Vec<u8> {
    let prefix = [0x60, 0, 0x54, 0x50, 0x60, 1, 0x60, 0, 0x55];
    let len = COUNTER_CODE.len() as u8;
    let mut code = prefix.to_vec();
    let offset = (prefix.len() + 11) as u8;
    code.extend_from_slice(&[0x60, len, 0x60, offset, 0x60, 0, 0x39, 0x60, len, 0x60, 0, 0xf3]);
    code.extend_from_slice(COUNTER_CODE);
    code
}

fn chain_spec() -> Arc<ChainSpec> {
    Arc::new(ChainSpecBuilder::mainnet().shanghai_activated().build())
}

fn contract(code: &[u8], balance: u64) -> AccountInfo {
    AccountInfo {
        balance: U256::from(balance),
        nonce: 1,
        code_hash: keccak256(code),
        code: Some(Bytecode::new_raw(Bytes::copy_from_slice(code))),
        ..Default::default()
    }
}

fn eoa(balance: u128) -> AccountInfo {
    AccountInfo { balance: U256::from(balance), nonce: 0, ..Default::default() }
}

fn genesis_db() -> CacheDB<EmptyDB> {
    let mut db = CacheDB::new(EmptyDB::default());
    db.insert_account_info(ALICE, eoa(1_000_000_000_000_000_000));
    db.insert_account_info(BOB, eoa(1_000_000_000_000_000_000));
    db.insert_account_info(COUNTER, contract(COUNTER_CODE, 0));
    db.insert_account_storage(COUNTER, U256::from(0), U256::from(5)).unwrap();
    db.insert_account_storage(COUNTER, U256::from(1), U256::from(7)).unwrap();
    db.insert_account_info(REVERTER, contract(REVERTER_CODE, 0));
    db.insert_account_storage(REVERTER, U256::from(0), U256::from(9)).unwrap();
    db.insert_account_info(CALLER, contract(&caller_code(), 0));
    db.insert_account_storage(CALLER, U256::from(0), U256::from(11)).unwrap();
    db
}

fn tx(nonce: u64, to: TxKind, value: u64, input: Vec<u8>) -> TransactionSigned {
    let tx = TxLegacy {
        chain_id: Some(1),
        nonce,
        gas_price: 10,
        gas_limit: 300_000,
        to,
        value: U256::from(value),
        input: input.into(),
    };
    tx.into_signed(Signature::test_signature()).into()
}

fn header(number: u64, parent: B256) -> Header {
    Header {
        parent_hash: parent,
        number,
        timestamp: 1_700_000_000 + number * 12,
        gas_limit: 30_000_000,
        base_fee_per_gas: Some(7),
        beneficiary: COINBASE,
        withdrawals_root: Some(EMPTY_ROOT_HASH),
        ..Default::default()
    }
}

const fn withdrawal(index: u64, to: Address, gwei: u64) -> Withdrawal {
    Withdrawal { index, validator_index: index, address: to, amount: gwei }
}

/// The chain: three blocks whose headers still lack what execution
/// decides (gas used, receipts root, bloom).
fn blocks() -> Vec<RecoveredBlock<Block>> {
    let created = ALICE.create(2);
    let b1 = (
        vec![
            (ALICE, tx(0, TxKind::Call(COUNTER), 0, vec![])),
            (ALICE, tx(1, TxKind::Call(DAVE), 1_000, vec![])),
            (ALICE, tx(2, TxKind::Create, 0, creator_init_code())),
            (BOB, tx(0, TxKind::Call(CALLER), 0, vec![])),
            (BOB, tx(1, TxKind::Call(REVERTER), 0, vec![])),
        ],
        vec![withdrawal(0, WITHDRAWN_TO, 5), withdrawal(1, ALICE, 5)],
    );
    let b2 = (
        vec![
            (BOB, tx(2, TxKind::Call(COUNTER), 0, vec![])),
            (ALICE, tx(3, TxKind::Call(created), 0, vec![])),
            (ALICE, tx(4, TxKind::Call(WITHDRAWN_TO), 1, vec![])),
        ],
        vec![],
    );
    let b3 = (
        vec![
            (ALICE, tx(5, TxKind::Call(DAVE), 1, vec![])),
            (BOB, tx(3, TxKind::Call(CALLER), 0, vec![])),
            (ALICE, tx(6, TxKind::Call(created), 0, vec![])),
        ],
        vec![withdrawal(2, DAVE, 1)],
    );
    let mut parent = B256::ZERO;
    [b1, b2, b3]
        .into_iter()
        .enumerate()
        .map(|(i, (txs, withdrawals))| {
            let (senders, transactions): (Vec<_>, Vec<_>) = txs.into_iter().unzip();
            let mut header = header(i as u64 + 1, parent);
            header.transactions_root = proofs::calculate_transaction_root(&transactions);
            let body = BlockBody {
                transactions,
                ommers: vec![],
                withdrawals: Some(Withdrawals(withdrawals)),
            };
            let block = RecoveredBlock::new_unhashed(Block { header, body }, senders);
            parent = block.hash();
            block
        })
        .collect()
}

/// Executes the chain in one batch, recording if a recorder is given, and
/// returns the results plus every bytecode execution touched — what a
/// replay needs besides the witness.
fn execute_batch(
    evm_config: &EthEvmConfig,
    blocks: &[RecoveredBlock<Block>],
    recorder: Option<WitnessRecorder>,
) -> (Vec<BlockExecutionResult<Receipt>>, HashMap<B256, Bytecode>) {
    let mut executor = BasicBlockExecutor::new(evm_config, genesis_db());
    if let Some(recorder) = recorder {
        executor.set_read_observer(Some(Box::new(recorder)));
    }
    let mut results = Vec::new();
    for block in blocks {
        if let Some(observer) = executor.read_observer_mut() {
            observer.begin_block(block.number());
        }
        results.push(executor.execute_one(block).expect("block executes"));
        if let Some(observer) = executor.read_observer_mut() {
            observer.end_block().expect("block recorded");
        }
    }
    if let Some(observer) = executor.read_observer_mut() {
        observer.finish().expect("witness flushed");
    }
    // The genesis contracts came in with their accounts; the ones the chain
    // created are in the bundle.
    let mut codes: HashMap<B256, Bytecode> =
        [COUNTER_CODE.to_vec(), REVERTER_CODE.to_vec(), caller_code()]
            .into_iter()
            .map(|code| (keccak256(&code), Bytecode::new_raw(code.into())))
            .collect();
    codes.extend(executor.into_state().bundle_state.contracts);
    (results, codes)
}

/// Puts what execution decided into the headers, so post-execution
/// validation has something to check against.
fn seal_headers(
    blocks: Vec<RecoveredBlock<Block>>,
    results: &[BlockExecutionResult<Receipt>],
) -> Vec<RecoveredBlock<Block>> {
    let mut parent = B256::ZERO;
    blocks
        .into_iter()
        .zip(results)
        .map(|(block, result)| {
            let senders = block.senders().to_vec();
            let mut block = block.into_block();
            block.header.parent_hash = parent;
            block.header.gas_used = result.gas_used;
            block.header.receipts_root = calculate_receipt_root(
                &result.receipts.iter().map(|r| r.with_bloom_ref()).collect::<Vec<_>>(),
            );
            block.header.logs_bloom = result
                .receipts
                .iter()
                .fold(Default::default(), |bloom, r: &Receipt| bloom | r.bloom());
            let block = RecoveredBlock::new_unhashed(block, senders);
            parent = block.hash();
            block
        })
        .collect()
}

fn read_witnesses(dir: &std::path::Path, count: u64) -> Vec<Vec<u8>> {
    let store = WitnessStore::open(dir).unwrap();
    assert_eq!(store.blocks(), count + 1, "block 0 plus the recorded blocks");
    (1..=count)
        .map(|n| {
            let mut out = Vec::new();
            store.read(n, &mut out).unwrap();
            out
        })
        .collect()
}

#[test]
fn a_recorded_chain_replays_block_by_block_from_a_fresh_state() {
    let chain_spec = chain_spec();
    let evm_config = EthEvmConfig::new(chain_spec.clone());

    // A first pass tells us what the headers must say.
    let blocks = seal_headers(blocks(), &execute_batch(&evm_config, &blocks(), None).0);

    // Record.
    let dir = tempfile::tempdir().unwrap();
    let recorder = WitnessRecorder::new(WitnessWriter::open(dir.path(), 1).unwrap());
    let (recorded, codes) = execute_batch(&evm_config, &blocks, Some(recorder));
    assert!(codes.len() >= 4, "the three genesis contracts and the created one: {}", codes.len());
    assert!(
        recorded[0].receipts.iter().any(|r| !r.success),
        "block 1 carries a failed transaction"
    );
    for (block, result) in blocks.iter().zip(&recorded) {
        assert!(
            result.receipts.iter().any(|r| r.success),
            "block {} has successes",
            block.number()
        );
        validate_block_post_execution(block, chain_spec.as_ref(), result, None, None)
            .expect("the recording run passes post-execution validation");
    }

    // Replay each block alone, from nothing but its witness and the codes.
    let witnesses = read_witnesses(dir.path(), blocks.len() as u64);
    for ((block, witness), recorded) in blocks.iter().zip(&witnesses).zip(&recorded) {
        assert!(!witness.is_empty(), "block {} read state", block.number());
        let result =
            replay_block(&evm_config, block, witness, |hash| codes.get(&hash).cloned(), |_| None)
                .unwrap_or_else(|err| panic!("block {} replays: {err}", block.number()));
        assert_eq!(result.receipts, recorded.receipts, "block {}", block.number());
        assert_eq!(result.gas_used, recorded.gas_used, "block {}", block.number());
        validate_block_post_execution(block, chain_spec.as_ref(), &result, None, None)
            .expect("the replay passes post-execution validation");
    }
}

#[test]
fn the_wrong_witness_does_not_pass_as_the_right_one() {
    let chain_spec = chain_spec();
    let evm_config = EthEvmConfig::new(chain_spec.clone());
    let blocks = seal_headers(blocks(), &execute_batch(&evm_config, &blocks(), None).0);
    let dir = tempfile::tempdir().unwrap();
    let recorder = WitnessRecorder::new(WitnessWriter::open(dir.path(), 1).unwrap());
    let (recorded, codes) = execute_batch(&evm_config, &blocks, Some(recorder));
    let witnesses = read_witnesses(dir.path(), blocks.len() as u64);
    let code = |hash: B256| codes.get(&hash).cloned();

    // Block 2 against block 1's witness: the stream runs out, ends with
    // bytes left over, or yields receipts the header refuses.
    let outcome = replay_block(&evm_config, &blocks[1], &witnesses[0], code, |_| None);
    match outcome {
        Err(ReplayError::Stream(_) | ReplayError::Unconsumed(_) | ReplayError::Execution(_)) => {}
        Err(other) => panic!("unexpected error {other}"),
        Ok(result) => {
            assert!(
                result.receipts != recorded[1].receipts ||
                    validate_block_post_execution(
                        &blocks[1],
                        chain_spec.as_ref(),
                        &result,
                        None,
                        None
                    )
                    .is_err(),
                "a foreign witness produced the block's own receipts"
            );
        }
    }

    // A flipped byte in a value changes what the block computes or breaks
    // the stream; it never validates.
    let mut tampered = witnesses[0].clone();
    let last_value = tampered.len() - 1;
    tampered[last_value] ^= 0x01;
    let outcome = replay_block(&evm_config, &blocks[0], &tampered, code, |_| None);
    let validated = outcome.ok().filter(|result| {
        validate_block_post_execution(&blocks[0], chain_spec.as_ref(), result, None, None).is_ok()
    });
    assert!(
        validated.is_none() || validated.unwrap().receipts != recorded[0].receipts,
        "tampering went unnoticed"
    );
}
