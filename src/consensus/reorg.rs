//! Reorg executor for beacon layer chain reorganization.
//!
//! This module handles the execution of chain reorganizations when the fork choice
//! determines that a stronger chain exists. The executor coordinates:
//!
//! 1. Updating the in-memory block tree
//! 2. Persisting canonical blocks to BeaconStore
//! 3. Notifying the execution layer (Reth) via Engine API
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                     ReorgExecutor                            │
//! │                                                             │
//! │  ┌─────────────┐     ┌──────────────┐     ┌─────────────┐  │
//! │  │ BlockTree   │────▶│ BeaconStore  │────▶│ Engine API  │  │
//! │  │ (in-memory) │     │ (persistent) │     │ (to Reth)   │  │
//! │  └─────────────┘     └──────────────┘     └─────────────┘  │
//! │                                                             │
//! └─────────────────────────────────────────────────────────────┘
//! ```

use super::block_tree::{BeaconBlockTree, BlockTreeError};
use super::fork_choice::ForkChoiceDecision;
use crate::primitives::SignedBeaconBlock;
use crate::storage::{BeaconStore, BeaconStoreError};
use alloy_primitives::B256;
use reth_tracing::tracing::{info, debug};
use std::sync::Arc;
use tokio::sync::mpsc;

/// Error type for reorg operations.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ReorgError {
    /// Block tree error.
    #[error("block tree error: {0}")]
    BlockTree(#[from] BlockTreeError),

    /// Storage error.
    #[error("storage error: {0}")]
    Storage(#[from] BeaconStoreError),

    /// Engine API notification failed.
    #[error("engine API error: {0}")]
    EngineApi(String),

    /// Channel send error.
    #[error("channel send error")]
    ChannelSend,
}

/// Statistics from a reorg operation.
#[derive(Debug, Clone)]
pub struct ReorgStats {
    /// Hash of the common ancestor.
    pub common_ancestor: B256,
    /// Slot of the common ancestor.
    pub common_ancestor_slot: u64,
    /// Number of blocks reverted (removed from canonical chain).
    pub blocks_reverted: usize,
    /// Number of blocks applied (added to canonical chain).
    pub blocks_applied: usize,
    /// New canonical head hash.
    pub new_head: B256,
    /// New canonical head slot.
    pub new_head_slot: u64,
}

/// Forkchoice state for Engine API notification.
#[derive(Debug, Clone, Default)]
pub struct ForkchoiceState {
    /// Hash of the new head block.
    pub head_block_hash: B256,
    /// Hash of the safe block (latest justified).
    pub safe_block_hash: B256,
    /// Hash of the finalized block.
    pub finalized_block_hash: B256,
}

/// Event emitted when reorg occurs.
#[derive(Debug, Clone)]
pub enum ReorgEvent {
    /// A new block was added to the canonical chain.
    NewHead {
        /// The new head block.
        block: SignedBeaconBlock,
        /// Block hash.
        hash: B256,
    },

    /// A chain reorganization occurred.
    Reorg {
        /// Reorg statistics.
        stats: ReorgStats,
        /// Old chain blocks (being replaced).
        old_blocks: Vec<SignedBeaconBlock>,
        /// New chain blocks (being applied).
        new_blocks: Vec<SignedBeaconBlock>,
    },
}

/// Trait for Engine API notifier.
///
/// Implement this trait to connect to the execution layer (Reth).
/// Uses synchronous send since we typically just push to a channel.
pub trait EngineApiNotifier: Send + Sync {
    /// Notify the execution layer of a forkchoice update.
    fn notify_forkchoice_updated(&self, state: ForkchoiceState) -> Result<(), ReorgError>;
}

/// No-op Engine API notifier for testing or standalone beacon node.
#[derive(Debug, Clone, Default)]
pub struct NoopEngineNotifier;

impl EngineApiNotifier for NoopEngineNotifier {
    fn notify_forkchoice_updated(&self, _state: ForkchoiceState) -> Result<(), ReorgError> {
        Ok(())
    }
}

/// Channel-based Engine API notifier.
///
/// Sends forkchoice updates to a channel for processing by another component.
#[derive(Debug, Clone)]
pub struct ChannelEngineNotifier {
    sender: mpsc::UnboundedSender<ForkchoiceState>,
}

impl ChannelEngineNotifier {
    /// Create a new channel-based notifier.
    pub fn new(sender: mpsc::UnboundedSender<ForkchoiceState>) -> Self {
        Self { sender }
    }

    /// Create a new notifier with its receiver.
    pub fn create() -> (Self, mpsc::UnboundedReceiver<ForkchoiceState>) {
        let (sender, receiver) = mpsc::unbounded_channel();
        (Self::new(sender), receiver)
    }
}

impl EngineApiNotifier for ChannelEngineNotifier {
    fn notify_forkchoice_updated(&self, state: ForkchoiceState) -> Result<(), ReorgError> {
        self.sender.send(state).map_err(|_| ReorgError::ChannelSend)
    }
}

/// Reorg executor configuration.
#[derive(Debug, Clone)]
pub struct ReorgConfig {
    /// Emit events for reorgs.
    pub emit_events: bool,
    /// Persist blocks immediately (vs batched).
    pub immediate_persist: bool,
}

impl Default for ReorgConfig {
    fn default() -> Self {
        Self {
            emit_events: true,
            immediate_persist: true,
        }
    }
}

/// Reorg executor for beacon layer.
///
/// Coordinates chain reorganizations:
/// - Updates the in-memory block tree
/// - Persists canonical blocks to storage
/// - Notifies the execution layer
pub struct ReorgExecutor<S: BeaconStore, N: EngineApiNotifier = NoopEngineNotifier> {
    /// Persistent block storage.
    store: Arc<S>,

    /// Engine API notifier.
    engine_notifier: N,

    /// Event sender (optional).
    event_sender: Option<mpsc::UnboundedSender<ReorgEvent>>,

    /// Configuration.
    config: ReorgConfig,
}

impl<S: BeaconStore> ReorgExecutor<S, NoopEngineNotifier> {
    /// Create with default configuration and no-op engine notifier.
    pub fn with_store(store: Arc<S>) -> Self {
        Self {
            store,
            engine_notifier: NoopEngineNotifier,
            event_sender: None,
            config: ReorgConfig::default(),
        }
    }
}

impl<S: BeaconStore, N: EngineApiNotifier> ReorgExecutor<S, N> {
    /// Create a new reorg executor.
    pub fn new(store: Arc<S>, engine_notifier: N, config: ReorgConfig) -> Self {
        Self {
            store,
            engine_notifier,
            event_sender: None,
            config,
        }
    }

    /// Set the event sender for reorg notifications.
    pub fn with_event_sender(mut self, sender: mpsc::UnboundedSender<ReorgEvent>) -> Self {
        self.event_sender = Some(sender);
        self
    }

    /// Execute fork choice decision.
    ///
    /// # Arguments
    /// * `tree` - The in-memory block tree
    /// * `decision` - Fork choice decision to execute
    ///
    /// # Returns
    /// * `Ok(Some(stats))` - Reorg was executed
    /// * `Ok(None)` - No reorg needed (extend or keep)
    pub fn execute(
        &self,
        tree: &mut BeaconBlockTree,
        decision: ForkChoiceDecision,
    ) -> Result<Option<ReorgStats>, ReorgError> {
        match decision {
            ForkChoiceDecision::Extend { block } => {
                self.handle_extend(tree, block)?;
                Ok(None)
            }

            ForkChoiceDecision::Keep { .. } => {
                // Block is kept in tree but not made canonical
                Ok(None)
            }

            ForkChoiceDecision::Reorg {
                common_ancestor,
                common_ancestor_slot,
                old_blocks,
                new_blocks,
                new_head,
            } => {
                let stats = self.handle_reorg(
                    tree,
                    common_ancestor,
                    common_ancestor_slot,
                    old_blocks,
                    new_blocks,
                    new_head,
                )?;
                Ok(Some(stats))
            }
        }
    }

    /// Handle chain extension (simple case).
    fn handle_extend(&self, tree: &mut BeaconBlockTree, block_hash: B256) -> Result<(), ReorgError> {
        // Update canonical head in tree
        tree.set_canonical_head(block_hash)?;

        // Get the block for persistence and notification
        let block = tree
            .get(&block_hash)
            .ok_or(BlockTreeError::BlockNotFound(block_hash))?
            .clone();

        // Persist to storage if configured
        if self.config.immediate_persist {
            self.store.insert_block(block.clone())?;
        }

        // Notify engine API
        let forkchoice = ForkchoiceState {
            head_block_hash: block_hash,
            safe_block_hash: block_hash, // Simplified: same as head
            finalized_block_hash: B256::ZERO, // TODO: track finalized
        };
        self.engine_notifier.notify_forkchoice_updated(forkchoice)?;

        // Emit event
        if self.config.emit_events {
            if let Some(ref sender) = self.event_sender {
                let _ = sender.send(ReorgEvent::NewHead {
                    block,
                    hash: block_hash,
                });
            }
        }

        debug!(
            hash = %block_hash,
            "Chain extended with new head"
        );

        Ok(())
    }

    /// Handle chain reorganization.
    fn handle_reorg(
        &self,
        tree: &mut BeaconBlockTree,
        common_ancestor: B256,
        common_ancestor_slot: u64,
        old_blocks: Vec<SignedBeaconBlock>,
        new_blocks: Vec<SignedBeaconBlock>,
        new_head: B256,
    ) -> Result<ReorgStats, ReorgError> {
        let new_head_slot = new_blocks
            .last()
            .map(|b| b.slot())
            .unwrap_or(common_ancestor_slot);

        info!(
            common_ancestor = %common_ancestor,
            common_ancestor_slot = common_ancestor_slot,
            old_blocks = old_blocks.len(),
            new_blocks = new_blocks.len(),
            new_head = %new_head,
            "Executing reorg"
        );

        // 1. Update canonical head in tree
        tree.set_canonical_head(new_head)?;

        // 2. Update persistent storage
        // Remove old chain blocks from storage
        self.store.remove_blocks_from(common_ancestor_slot + 1)?;

        // Insert new chain blocks
        for block in &new_blocks {
            self.store.insert_block(block.clone())?;
        }

        // 3. Notify Engine API
        let forkchoice = ForkchoiceState {
            head_block_hash: new_head,
            safe_block_hash: common_ancestor, // Safe is at least the common ancestor
            finalized_block_hash: B256::ZERO, // TODO: track finalized
        };
        self.engine_notifier.notify_forkchoice_updated(forkchoice)?;

        // 4. Build stats
        let stats = ReorgStats {
            common_ancestor,
            common_ancestor_slot,
            blocks_reverted: old_blocks.len(),
            blocks_applied: new_blocks.len(),
            new_head,
            new_head_slot,
        };

        // 5. Emit event
        if self.config.emit_events {
            if let Some(ref sender) = self.event_sender {
                let _ = sender.send(ReorgEvent::Reorg {
                    stats: stats.clone(),
                    old_blocks,
                    new_blocks,
                });
            }
        }

        info!(
            blocks_reverted = stats.blocks_reverted,
            blocks_applied = stats.blocks_applied,
            new_head = %stats.new_head,
            new_head_slot = stats.new_head_slot,
            "Reorg completed"
        );

        Ok(stats)
    }

    /// Prune old blocks from the tree and persist them.
    ///
    /// Call this periodically to move finalized blocks to storage.
    pub fn prune_and_persist(&self, tree: &mut BeaconBlockTree, below_slot: u64) -> Result<usize, ReorgError> {
        let pruned = tree.prune(below_slot);
        let count = pruned.len();

        // Persist pruned canonical blocks
        for block in pruned {
            // Only persist if not already in storage
            if self.store.block_by_slot(block.slot())?.is_none() {
                self.store.insert_block(block)?;
            }
        }

        if count > 0 {
            debug!(
                count = count,
                below_slot = below_slot,
                "Pruned and persisted blocks"
            );
        }

        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::{BeaconBlock, BeaconBlockBody};
    use crate::storage::{BeaconStoreReader, BeaconStoreWriter, InMemoryBeaconStore};
    use alloy_primitives::Bytes;

    fn create_block(slot: u64, parent: B256, difficulty: u64) -> SignedBeaconBlock {
        // Use difficulty in state_root to ensure different blocks have different hashes
        let mut state_root = B256::ZERO;
        state_root.0[0] = difficulty as u8;

        let block = BeaconBlock::new(
            slot,
            (slot % 4) as u64,
            parent,
            state_root,
            BeaconBlockBody::default(),
            difficulty,
        );
        SignedBeaconBlock::new(block, Bytes::new())
    }

    #[test]
    fn test_execute_extend() {
        let store = Arc::new(InMemoryBeaconStore::new());
        let executor = ReorgExecutor::with_store(store.clone());

        let mut tree = BeaconBlockTree::default();

        // Insert genesis
        let genesis = create_block(0, B256::ZERO, 2);
        let genesis_hash = tree.insert(genesis).unwrap();
        tree.set_canonical_head(genesis_hash).unwrap();

        // Insert block 1
        let block1 = create_block(1, genesis_hash, 2);
        let hash1 = tree.insert(block1).unwrap();

        // Execute extend decision
        let decision = ForkChoiceDecision::Extend { block: hash1 };
        let result = executor.execute(&mut tree, decision).unwrap();

        assert!(result.is_none());
        assert_eq!(tree.canonical_head_hash(), Some(hash1));

        // Block should be persisted
        assert!(store.block_by_slot(1).unwrap().is_some());
    }

    #[test]
    fn test_execute_keep() {
        let store = Arc::new(InMemoryBeaconStore::new());
        let executor = ReorgExecutor::with_store(store);

        let mut tree = BeaconBlockTree::default();

        let genesis = create_block(0, B256::ZERO, 2);
        let genesis_hash = tree.insert(genesis).unwrap();
        tree.set_canonical_head(genesis_hash).unwrap();

        // Execute keep decision
        let decision = ForkChoiceDecision::Keep { block: genesis_hash };
        let result = executor.execute(&mut tree, decision).unwrap();

        assert!(result.is_none());
    }

    #[test]
    fn test_execute_reorg() {
        let store = Arc::new(InMemoryBeaconStore::new());
        let executor = ReorgExecutor::with_store(store.clone());

        let mut tree = BeaconBlockTree::default();

        // Genesis
        let genesis = create_block(0, B256::ZERO, 2);
        let genesis_hash = tree.insert(genesis.clone()).unwrap();
        tree.set_canonical_head(genesis_hash).unwrap();
        store.insert_block(tree.get(&genesis_hash).unwrap().clone()).unwrap();

        // Old chain: genesis -> old1 (diff=1)
        let old1 = create_block(1, genesis_hash, 1);
        let old1_hash = tree.insert(old1.clone()).unwrap();
        tree.set_canonical_head(old1_hash).unwrap();
        store.insert_block(old1.clone()).unwrap();

        // New chain: genesis -> new1 (diff=2)
        let new1 = create_block(1, genesis_hash, 2);
        let new1_hash = tree.insert(new1.clone()).unwrap();

        // Execute reorg
        let decision = ForkChoiceDecision::Reorg {
            common_ancestor: genesis_hash,
            common_ancestor_slot: 0,
            old_blocks: vec![old1],
            new_blocks: vec![new1.clone()],
            new_head: new1_hash,
        };

        let result = executor.execute(&mut tree, decision).unwrap();

        assert!(result.is_some());
        let stats = result.unwrap();

        assert_eq!(stats.common_ancestor, genesis_hash);
        assert_eq!(stats.blocks_reverted, 1);
        assert_eq!(stats.blocks_applied, 1);
        assert_eq!(stats.new_head, new1_hash);

        // Canonical head should be updated
        assert_eq!(tree.canonical_head_hash(), Some(new1_hash));

        // Storage should have new block
        let stored = store.block_by_slot(1).unwrap().unwrap();
        assert_eq!(stored.block_root(), new1_hash);
    }

    #[test]
    fn test_reorg_with_event_sender() {
        let store = Arc::new(InMemoryBeaconStore::new());
        let (event_tx, mut event_rx) = mpsc::unbounded_channel();

        let executor = ReorgExecutor::with_store(store.clone()).with_event_sender(event_tx);

        let mut tree = BeaconBlockTree::default();

        let genesis = create_block(0, B256::ZERO, 2);
        let genesis_hash = tree.insert(genesis.clone()).unwrap();
        tree.set_canonical_head(genesis_hash).unwrap();

        // Extend chain
        let block1 = create_block(1, genesis_hash, 2);
        let hash1 = tree.insert(block1).unwrap();

        let decision = ForkChoiceDecision::Extend { block: hash1 };
        executor.execute(&mut tree, decision).unwrap();

        // Should receive NewHead event
        let event = event_rx.try_recv().unwrap();
        match event {
            ReorgEvent::NewHead { hash, .. } => {
                assert_eq!(hash, hash1);
            }
            _ => panic!("Expected NewHead event"),
        }
    }

    #[test]
    fn test_channel_engine_notifier() {
        let (notifier, mut receiver) = ChannelEngineNotifier::create();

        let state = ForkchoiceState {
            head_block_hash: B256::repeat_byte(1),
            safe_block_hash: B256::repeat_byte(2),
            finalized_block_hash: B256::repeat_byte(3),
        };

        notifier.notify_forkchoice_updated(state.clone()).unwrap();

        let received = receiver.try_recv().unwrap();
        assert_eq!(received.head_block_hash, state.head_block_hash);
        assert_eq!(received.safe_block_hash, state.safe_block_hash);
        assert_eq!(received.finalized_block_hash, state.finalized_block_hash);
    }

    #[test]
    fn test_prune_and_persist() {
        let store = Arc::new(InMemoryBeaconStore::new());
        let executor = ReorgExecutor::with_store(store.clone());

        let mut tree = BeaconBlockTree::default();

        // Build a chain
        let genesis = create_block(0, B256::ZERO, 2);
        let genesis_hash = tree.insert(genesis).unwrap();

        let block1 = create_block(1, genesis_hash, 2);
        let hash1 = tree.insert(block1).unwrap();

        let block2 = create_block(2, hash1, 2);
        let hash2 = tree.insert(block2).unwrap();

        let block3 = create_block(3, hash2, 2);
        let hash3 = tree.insert(block3).unwrap();

        tree.set_canonical_head(hash3).unwrap();

        // Prune blocks below slot 2
        let pruned = executor.prune_and_persist(&mut tree, 2).unwrap();
        assert_eq!(pruned, 2); // genesis and block1

        // Pruned blocks should be in storage
        assert!(store.block_by_slot(0).unwrap().is_some());
        assert!(store.block_by_slot(1).unwrap().is_some());

        // Pruned blocks should be removed from tree
        assert!(!tree.contains(&genesis_hash));
        assert!(!tree.contains(&hash1));
        assert!(tree.contains(&hash2));
        assert!(tree.contains(&hash3));
    }
}
