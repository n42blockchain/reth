# reth-witness

Positional state-read witnesses: the values a block's execution read from
state, in the order a fresh `State` sent them to its database, and nothing
else. Recorded once by a syncing node, they let every block of the chain be
re-executed on its own, in parallel, with no state and no lookups.

## Recording

```
reth node --debug.witness-dir <DIR> [--debug.max-block <N> --debug.terminate] ...
```

or `witness_dir = "<DIR>"` under `[stages.execution]` in `reth.toml`. The
execution stage then records every block it executes into `<DIR>/witness.idx`
and `<DIR>/witness.NNNN.dat` (2 GiB segments, per-block zstd). Recording is
resumable: a restart continues from the execution checkpoint and drops entries
from the batch that did not commit; unwinding execution unwinds the recording.
It refuses to start if the store ends before the checkpoint — record from the
beginning, or unwind execution to where the store ends.

Only the pipeline's execution stage records; blocks executed by the engine
(live sync at the tip) are not recorded. For a historical range, sync with
`--debug.max-block` past the range, or record while the pipeline catches up.

## Replaying

[`replay_block`] executes a block against its witness with a fresh `State` and
returns what execution produced; the caller validates that against the header
with `validate_block_post_execution` (gas used, receipts root, logs bloom).
Code and block hashes are not in the witness: the replayer supplies them by
code hash and block number.

## Why the order is right

The recorder does not imitate the cache. It keeps a fresh `State` of its own
per block — the same revm type the replayer will use — and offers it every
read the syncing node's batch `State` answers; that fresh `State`'s own cache
decides which reads reach a database, and exactly those are written, in that
order. The two sides run the same `State` and the same block executor, so the
replayer asks the same questions in the same order. Any read the shadow cannot
account for fails the block loudly instead of producing a witness that would
mislead.

The format is therefore tied to the revm and reth versions that recorded it:
a different EVM, `State`, or executor needs its own recording.
