# Block Reorganization (Reorg) Mechanism

This document explains how block reorganization (reorg) is handled in blockchain nodes, based on Reth's implementation and N42's current status.

## Overview

A reorg occurs when the canonical chain switches from one fork to another. This happens when:
- A longer/heavier chain is discovered
- The consensus layer (CL) sends a `forkchoiceUpdated` with a different head
- Network partitions heal and nodes discover better chains

## Reth Reorg Implementation

### 1. Trigger Entry: `on_forkchoice_updated`

**File**: `crates/engine/tree/src/tree/mod.rs:994-1141`

```rust
fn on_forkchoice_updated(&mut self, state: ForkchoiceState) {
    // 1. Validate forkchoice
    self.pre_validate_forkchoice_update(&state)?;

    // 2. Check if head is already canonical
    if self.is_canonical(state.head_block_hash) {
        return; // No reorg needed
    }

    // 3. Analyze chain structure, detect reorg
    let chain_update = self.on_new_head(state.head_block_hash)?;

    // 4. Apply update
    self.on_canonical_chain_update(chain_update);
}
```

### 2. Core Algorithm: `on_new_head` (Reorg Detection)

**File**: `crates/engine/tree/src/tree/mod.rs:639-728`

```rust
fn on_new_head(&mut self, new_head: B256) -> NewCanonicalChain {
    let mut new_chain = vec![];
    let mut current_hash = new_head;

    // Traverse backwards from new head, collecting new chain blocks
    while current_hash != canonical_hash {
        let block = self.tree_state.block_by_hash(current_hash)?;
        new_chain.push(block);
        current_hash = block.parent_hash();
    }

    // Check if simple extension (new block connects directly to canonical head)
    if current_hash == self.canonical_head.hash {
        return NewCanonicalChain::Commit { new: new_chain };
    }

    // Not simple extension -> Reorg occurred
    // Collect replaced old chain
    let mut old_chain = vec![];
    let mut old_hash = self.canonical_head.hash;

    while old_hash != current_hash {
        let old_block = self.tree_state.block_by_hash(old_hash)?;
        old_chain.push(old_block);
        old_hash = old_block.parent_hash();
    }

    NewCanonicalChain::Reorg {
        new: new_chain,  // New canonical chain
        old: old_chain   // Rolled back old chain
    }
}
```

### 3. Core Data Structure: `TreeState`

**File**: `crates/engine/tree/src/tree/state.rs`

```rust
pub struct TreeState<N: NodePrimitives> {
    // Executed blocks indexed by hash (contains EVM state changes)
    blocks_by_hash: HashMap<B256, ExecutedBlockWithTrieUpdates<N>>,

    // Indexed by block number (supports multiple fork blocks at same height)
    blocks_by_number: BTreeMap<BlockNumber, Vec<ExecutedBlockWithTrieUpdates<N>>>,

    // Parent -> child mapping (fast navigation)
    parent_to_child: HashMap<B256, HashSet<B256>>,

    // Key: Saves Trie updates for persisted blocks (for reorg recovery)
    persisted_trie_updates: HashMap<B256, (BlockNumber, Arc<TrieUpdates>)>,

    // Current canonical chain head
    current_canonical_head: BlockNumHash,
}
```

### 4. State Rollback Implementation

**File**: `crates/chain-state/src/in_memory.rs:259-295`

```rust
fn update_blocks(&self, new_blocks: I, reorged_blocks: R) {
    let mut numbers = self.numbers.write();
    let mut blocks = self.blocks.write();

    // 1. Remove reorged old blocks
    for block in reorged_blocks {
        let hash = block.hash();
        let number = block.number();
        blocks.remove(&hash);     // Remove block data from memory
        numbers.remove(&number);  // Remove block number mapping
    }

    // 2. Insert new chain blocks
    for block in new_blocks {
        let parent = blocks.get(&block.parent_hash()).cloned();
        let block_state = BlockState::with_parent(block, parent);
        blocks.insert(block_state.hash(), Arc::new(block_state));
        numbers.insert(block_state.number(), block_state.hash());
    }

    // 3. Clear pending state
    self.pending.send_modify(|p| p.take());
}
```

### 5. Transaction Pool Reorg Handling

**File**: `crates/transaction-pool/src/maintain.rs:309-423`

```rust
CanonStateNotification::Reorg { old, new } => {
    let (old_blocks, old_state) = old.inner();
    let (new_blocks, new_state) = new.inner();

    // 1. Find transactions reorged but not in new chain (need to return to pool)
    let new_mined_txs: HashSet<_> = new_blocks.transaction_hashes().collect();

    let pruned_old_txs: Vec<_> = old_blocks
        .transactions_ecrecovered()
        .filter(|tx| !new_mined_txs.contains(tx.tx_hash()))
        .collect();

    // 2. Find accounts that need state reloading
    let new_changed = new_state.changed_accounts().collect();
    let missing_changed = old_state
        .accounts_iter()
        .filter(|(addr, _)| !new_changed.contains(addr));

    // Load these accounts' state at new tip from DB
    let changed_accounts = load_accounts(client, new_tip.hash(), missing_changed)?;

    // 3. Update transaction pool
    pool.on_canonical_state_change(CanonicalStateUpdate {
        new_tip: new_tip.sealed_block(),
        changed_accounts,
        mined_transactions: new_mined_txs,
        update_kind: PoolUpdateKind::Reorg,
    });

    // 4. Re-inject reorged transactions
    pool.add_external_transactions(pruned_old_txs).await;
}
```

## Complete Flow Diagram

```
┌────────────────────────────────────────────────────────────────────────┐
│                    Reth Reorg Complete Flow                            │
└────────────────────────────────────────────────────────────────────────┘

CL: forkchoiceUpdated(head=H, finalized=F)
                    │
                    ▼
┌─────────────────────────────────────────┐
│  on_forkchoice_updated (tree/mod.rs)    │
│  1. pre_validate_forkchoice_update      │
│  2. Check if head is already canonical  │
└────────────────────┬────────────────────┘
                     │ head not on canonical chain
                     ▼
┌─────────────────────────────────────────┐
│  on_new_head(head_hash) -> Chain Analysis│
│                                         │
│  Canonical:  A ── B ── C ── D (current) │
│                   \                     │
│  New chain:        └── C' ── D' ── E'   │
│                        ↑                │
│                    fork point           │
│                                         │
│  Returns: NewCanonicalChain::Reorg {    │
│    new: [C', D', E'],                   │
│    old: [C, D]                          │
│  }                                      │
└────────────────────┬────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────┐
│  on_canonical_chain_update              │
│                                         │
│  1. TreeState Update                    │
│     - current_canonical_head = E'       │
│     - Reinsert reorged blocks to memory │
│                                         │
│  2. In-memory State Update              │
│     - blocks.remove(C, D)               │
│     - blocks.insert(C', D', E')         │
│     - Remap numbers                     │
│                                         │
│  3. Emit Notification                   │
│     CanonStateNotification::Reorg {     │
│       old: (blocks=[C,D], state),       │
│       new: (blocks=[C',D',E'], state)   │
│     }                                   │
└────────────────────┬────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────┐
│  Transaction Pool (maintain.rs)         │
│                                         │
│  1. Collect reorged transactions        │
│     old_txs = txs_in(C,D) - txs_in(C',D',E')│
│                                         │
│  2. Load dirty accounts' new state      │
│     changed = accounts_changed_in(C,D)  │
│              but_not_in(C',D',E')       │
│     load_accounts(new_tip, changed)     │
│                                         │
│  3. Update pool state                   │
│     pool.on_canonical_state_change()    │
│                                         │
│  4. Re-inject transactions              │
│     pool.add_external_transactions(     │
│       old_txs                           │
│     )                                   │
└─────────────────────────────────────────┘
```

## Key Design Points

### 1. `persisted_trie_updates` - Trie Update Cache

```rust
// Keep Trie updates for last 64 blocks
// Used for fast recovery during reorg
persisted_trie_updates: HashMap<B256, (BlockNumber, Arc<TrieUpdates>)>
```

**Purpose**: When block A is reorged out, if a subsequent reorg brings it back, the Trie information can be directly recovered without re-execution.

**File**: `crates/engine/tree/src/tree/state.rs:237-251`

```rust
pub(crate) fn prune_persisted_trie_updates(&mut self) {
    let retention_blocks = if self.engine_kind.is_opstack() {
        OPSTACK_PERSISTED_TRIE_UPDATES_RETENTION  // OP Stack: 32 blocks
    } else {
        DEFAULT_PERSISTED_TRIE_UPDATES_RETENTION  // Ethereum: 64 blocks
    };

    let earliest_block_to_retain =
        self.current_canonical_head.number.saturating_sub(retention_blocks);

    // Only keep Trie updates for recent N blocks for subsequent reorgs
    self.persisted_trie_updates
        .retain(|_, (block_number, _)| *block_number > earliest_block_to_retain);
}
```

### 2. Dirty Account Tracking in Transaction Pool

```rust
// Find accounts changed in old chain but not in new chain
let missing = old_state.accounts()
    .filter(|a| !new_state.changed_accounts().contains(a));

// Must reload these accounts' nonce/balance from DB
let accounts = load_accounts(new_tip, missing)?;
```

**Purpose**: Ensure transaction validation uses correct account state.

### 3. Blob Transaction Special Handling

```rust
// Recover blob data from blob store during reorg
for tx in pruned_old_transactions {
    if tx.is_eip4844() {
        let sidecar = blob_store.get(tx.hash())?;
        tx.set_sidecar(sidecar);
    }
}
```

### 4. Disk Reorg Detection

**File**: `crates/engine/tree/src/tree/mod.rs:2039-2083`

```rust
fn find_disk_reorg(&self) -> ProviderResult<Option<u64>> {
    let mut canonical = self.state.tree_state.current_canonical_head;
    let mut persisted = self.persistence_state.last_persisted_block;

    // Traverse backwards from canonical until reaching persisted block height
    while canonical.number > persisted.number {
        canonical = parent_num_hash(canonical)?;
    }

    // If canonical chain connects at persisted block, no reorg
    if canonical == persisted {
        return Ok(None);
    }

    // Persisted block not reachable via canonical chain -> reorg occurred
    // Both chains traverse backwards until finding fork point
    while persisted.hash != canonical.hash {
        canonical = parent_num_hash(canonical)?;
        persisted = parent_num_hash(persisted)?;
    }

    // persisted.number is fork point, need to delete all blocks above
    Ok(Some(persisted.number))
}
```

## Key File Locations

| Function | File | Lines |
|----------|------|-------|
| Reorg Detection Entry | `tree/mod.rs` | 994-1141 |
| Chain Analysis Algorithm | `tree/mod.rs` | 639-728 |
| TreeState Data Structure | `tree/state.rs` | 1-407 |
| Canonical Chain Update | `tree/mod.rs` | 2085-2142 |
| In-memory State Update | `in_memory.rs` | 259-307 |
| Trie Input Calculation | `tree/mod.rs` | 2412-2498 |
| Transaction Pool Reorg | `maintain.rs` | 309-423 |
| Disk Reorg Detection | `tree/mod.rs` | 2039-2083 |
| Persisted Trie Management | `tree/state.rs` | 237-251 |

## N42 Current Implementation Status

### Implemented

**Beacon Layer Reorg**:
```rust
// src/stages/beacon_blocks.rs
fn unwind(&mut self, input: UnwindInput) -> Result<UnwindOutput, StageError> {
    // Only handles beacon block deletion
    self.store.remove_blocks_from(input.unwind_to + 1)?;

    Ok(UnwindOutput { checkpoint: StageCheckpoint::new(input.unwind_to) })
}
```

### Not Implemented

The code has an explicit warning:
```rust
// src/stages/beacon_blocks.rs:841-857
warn!(
    target: "sync::stages::beacon_blocks",
    unwind_to = input.unwind_to,
    "Beacon state should be reset to slot {} (not implemented)",
    input.unwind_to
);
```

## N42 vs Reth Comparison

| Feature | Reth | N42 Current Status |
|---------|------|-------------------|
| Reorg Detection | `on_new_head` chain analysis | Simplified version |
| TreeState | Complete fork tree management | Linear storage only |
| EVM State Rollback | `update_blocks` + Trie | Not implemented |
| Transaction Pool Update | Complete dirty account tracking | Relies on default behavior |
| Trie Cache | 64 block Trie update cache | None |
| Engine API | Complete FCU handling | Not integrated |

## Recommendations for N42

### 1. Implement BeaconState Checkpoints

```rust
pub fn checkpoint(&self, slot: u64) -> StateCheckpoint;
pub fn restore_from_checkpoint(&mut self, checkpoint: StateCheckpoint);
```

### 2. Integrate Engine API Handling

```rust
impl N42Node {
    async fn on_forkchoice_updated(
        &self,
        state: ForkchoiceState,
    ) -> Result<ForkchoiceUpdatedResponse> {
        let head = state.head_block_hash;
        let finalized = state.finalized_block_hash;

        // Check if reorg needed
        if !self.is_canonical(head) {
            let fork_point = self.find_fork_point(head)?;

            // Beacon layer unwind
            self.beacon_store.remove_blocks_from(fork_point + 1)?;

            // Execution layer unwind (KEY: not implemented)
            self.unwind_execution(fork_point)?;

            // Re-execute new chain
            self.execute_chain_to(head)?;
        }

        // Update finalized
        self.set_finalized(finalized)?;

        Ok(ForkchoiceUpdatedResponse::valid())
    }
}
```

### 3. Implement Execution Layer State Rollback

```rust
impl N42Node {
    async fn unwind_execution(&mut self, to_block: u64) -> Result<()> {
        let provider = self.provider();

        // Get blocks to revert
        let blocks_to_revert = provider.blocks_from(to_block + 1)?;

        // Revert each block's state
        for block in blocks_to_revert.rev() {
            // Rollback state changes
            provider.revert_state_changes(block)?;

            // Return transactions to pool
            for tx in block.transactions() {
                self.txpool.add_transaction(tx)?;
            }
        }

        Ok(())
    }
}
```

### 4. Add Complete Reorg Tests

- Simulate network partition scenarios
- Verify state consistency after reorg
- Performance benchmarks

## Why POA Has Frequent Reorgs

POA characteristics:
1. **Fast block time** (default 8 seconds)
2. **Multiple nodes can produce blocks simultaneously** (out-of-turn mechanism)
3. **Network latency causes frequent small forks**

```
Time T:
  Validator A (in-turn, diff=2)  ──► Block A
  Validator B (out-of-turn, diff=1) ──► Block B  (after wiggle delay)

Network partition or latency causes different nodes to receive different blocks first → Reorg
```

## Conclusion

Reth's reorg handling is comprehensive and production-ready. For N42 to correctly handle reorgs in production:

1. Integrate Reth's `BlockchainTree` mechanism, or
2. Implement equivalent functionality:
   - TreeState for fork management
   - EVM state rollback via Trie updates
   - Transaction pool dirty account tracking
   - Engine API forkchoiceUpdated handling

## Related Documentation

- [Block Production Flow](./BLOCK_PRODUCTION_FLOW.md) - How blocks are produced
- [Beacon Architecture](./BEACON_ARCHITECTURE.md) - System architecture overview
- [POA eth66 Block Propagation](./POA_ETH66_BLOCK_PROPAGATION.md) - Network broadcast mechanism
