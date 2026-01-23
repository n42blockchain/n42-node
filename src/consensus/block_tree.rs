//! In-memory block tree for beacon chain fork management.
//!
//! This module implements an in-memory tree structure that holds recent beacon blocks
//! (typically the last 64 blocks) and supports multiple forks. This design is similar
//! to Reth's TreeState and allows:
//!
//! - Fast fork switching without disk I/O
//! - Multiple side chains to coexist
//! - Efficient common ancestor lookups
//! - Total difficulty calculation for fork choice
//!
//! Blocks older than the retention depth are pruned and persisted to BeaconStore.

use crate::primitives::SignedBeaconBlock;
use alloy_primitives::B256;
use std::collections::{BTreeMap, HashMap, HashSet};

/// Default number of blocks to retain in memory.
pub const DEFAULT_RETENTION_DEPTH: u64 = 64;

/// Error type for block tree operations.
#[derive(Debug, Clone, thiserror::Error)]
pub enum BlockTreeError {
    /// Block not found.
    #[error("block not found: {0}")]
    BlockNotFound(B256),

    /// Parent block not found.
    #[error("parent block not found: {0}")]
    ParentNotFound(B256),

    /// Block already exists.
    #[error("block already exists: {0}")]
    BlockExists(B256),

    /// No canonical head set.
    #[error("no canonical head set")]
    NoCanonicalHead,

    /// Invalid block (slot not increasing).
    #[error("invalid block: slot {block_slot} must be greater than parent slot {parent_slot}")]
    InvalidSlot { block_slot: u64, parent_slot: u64 },
}

/// In-memory block tree maintaining recent blocks and their relationships.
///
/// The tree supports multiple forks and provides efficient operations for:
/// - Finding common ancestors between blocks
/// - Calculating total difficulty along a chain
/// - Switching the canonical head
/// - Pruning old blocks
#[derive(Debug)]
pub struct BeaconBlockTree {
    /// All known blocks indexed by hash.
    blocks: HashMap<B256, SignedBeaconBlock>,

    /// Blocks indexed by slot (multiple blocks possible at same slot due to forks).
    blocks_by_slot: BTreeMap<u64, HashSet<B256>>,

    /// Parent to children mapping for tree traversal.
    children: HashMap<B256, HashSet<B256>>,

    /// Current canonical chain head.
    canonical_head: Option<B256>,

    /// The slot up to which blocks have been persisted (finalized).
    /// Blocks at or below this slot should not be in memory.
    finalized_slot: u64,

    /// Number of blocks to retain in memory beyond finalized.
    retention_depth: u64,
}

impl Default for BeaconBlockTree {
    fn default() -> Self {
        Self::new(DEFAULT_RETENTION_DEPTH)
    }
}

impl BeaconBlockTree {
    /// Create a new empty block tree.
    pub fn new(retention_depth: u64) -> Self {
        Self {
            blocks: HashMap::new(),
            blocks_by_slot: BTreeMap::new(),
            children: HashMap::new(),
            canonical_head: None,
            finalized_slot: 0,
            retention_depth,
        }
    }

    /// Create a block tree with a genesis block.
    pub fn with_genesis(genesis: SignedBeaconBlock, retention_depth: u64) -> Self {
        let mut tree = Self::new(retention_depth);
        let hash = genesis.block_root();
        tree.blocks.insert(hash, genesis.clone());
        tree.blocks_by_slot
            .entry(genesis.slot())
            .or_default()
            .insert(hash);
        tree.canonical_head = Some(hash);
        tree
    }

    /// Insert a new block into the tree.
    ///
    /// The block's parent must already exist in the tree (unless it's below finalized_slot).
    pub fn insert(&mut self, block: SignedBeaconBlock) -> Result<B256, BlockTreeError> {
        let hash = block.block_root();
        let parent_hash = block.parent_root();
        let slot = block.slot();

        // Check if block already exists
        if self.blocks.contains_key(&hash) {
            return Err(BlockTreeError::BlockExists(hash));
        }

        // Verify parent exists (unless parent is finalized/below our view)
        if !parent_hash.is_zero() && slot > self.finalized_slot + 1 {
            if let Some(parent) = self.blocks.get(&parent_hash) {
                // Verify slot is increasing
                if slot <= parent.slot() {
                    return Err(BlockTreeError::InvalidSlot {
                        block_slot: slot,
                        parent_slot: parent.slot(),
                    });
                }
            } else if !self.is_parent_finalized(parent_hash, slot) {
                return Err(BlockTreeError::ParentNotFound(parent_hash));
            }
        }

        // Insert block
        self.blocks.insert(hash, block);
        self.blocks_by_slot.entry(slot).or_default().insert(hash);

        // Update parent-child relationship
        self.children.entry(parent_hash).or_default().insert(hash);

        // If no canonical head, set this as head
        if self.canonical_head.is_none() {
            self.canonical_head = Some(hash);
        }

        Ok(hash)
    }

    /// Check if parent could be a finalized block we don't have in memory.
    fn is_parent_finalized(&self, _parent_hash: B256, block_slot: u64) -> bool {
        // If block is close to finalized slot, parent might be finalized
        block_slot <= self.finalized_slot + 1
    }

    /// Get a block by its hash.
    pub fn get(&self, hash: &B256) -> Option<&SignedBeaconBlock> {
        self.blocks.get(hash)
    }

    /// Check if a block exists in the tree.
    pub fn contains(&self, hash: &B256) -> bool {
        self.blocks.contains_key(hash)
    }

    /// Get the current canonical head block.
    pub fn canonical_head(&self) -> Result<&SignedBeaconBlock, BlockTreeError> {
        self.canonical_head
            .as_ref()
            .and_then(|h| self.blocks.get(h))
            .ok_or(BlockTreeError::NoCanonicalHead)
    }

    /// Get the canonical head hash.
    pub fn canonical_head_hash(&self) -> Option<B256> {
        self.canonical_head
    }

    /// Set a new canonical head.
    ///
    /// The block must exist in the tree.
    pub fn set_canonical_head(&mut self, hash: B256) -> Result<(), BlockTreeError> {
        if !self.blocks.contains_key(&hash) {
            return Err(BlockTreeError::BlockNotFound(hash));
        }
        self.canonical_head = Some(hash);
        Ok(())
    }

    /// Find the common ancestor of two blocks.
    ///
    /// Returns the hash of the most recent common ancestor.
    pub fn find_common_ancestor(&self, a: B256, b: B256) -> Option<B256> {
        // Collect ancestors of block A
        let mut ancestors_a = HashSet::new();
        let mut current = a;

        while let Some(block) = self.blocks.get(&current) {
            ancestors_a.insert(current);
            let parent = block.parent_root();
            if parent.is_zero() || !self.blocks.contains_key(&parent) {
                break;
            }
            current = parent;
        }

        // Walk back from B to find first common ancestor
        current = b;
        while let Some(block) = self.blocks.get(&current) {
            if ancestors_a.contains(&current) {
                return Some(current);
            }
            let parent = block.parent_root();
            if parent.is_zero() || !self.blocks.contains_key(&parent) {
                break;
            }
            current = parent;
        }

        // Check if we ended on an ancestor
        if ancestors_a.contains(&current) {
            return Some(current);
        }

        None
    }

    /// Get the chain of blocks from ancestor (exclusive) to descendant (inclusive).
    ///
    /// Returns blocks in order from oldest to newest.
    pub fn get_chain(&self, ancestor: B256, descendant: B256) -> Vec<SignedBeaconBlock> {
        let mut chain = Vec::new();
        let mut current = descendant;

        while let Some(block) = self.blocks.get(&current) {
            if current == ancestor {
                break;
            }
            chain.push(block.clone());
            let parent = block.parent_root();
            if parent.is_zero() || !self.blocks.contains_key(&parent) {
                break;
            }
            current = parent;
        }

        chain.reverse();
        chain
    }

    /// Calculate total difficulty from a block back to genesis (or finalized).
    ///
    /// For Clique POA:
    /// - In-turn blocks have difficulty 2
    /// - Out-of-turn blocks have difficulty 1
    pub fn total_difficulty(&self, head: B256) -> u64 {
        let mut total = 0u64;
        let mut current = head;

        while let Some(block) = self.blocks.get(&current) {
            total += block.message.difficulty;
            let parent = block.parent_root();
            if parent.is_zero() || !self.blocks.contains_key(&parent) {
                break;
            }
            current = parent;
        }

        total
    }

    /// Calculate total difficulty from ancestor (exclusive) to head (inclusive).
    pub fn difficulty_from(&self, ancestor: B256, head: B256) -> u64 {
        let mut total = 0u64;
        let mut current = head;

        while let Some(block) = self.blocks.get(&current) {
            if current == ancestor {
                break;
            }
            total += block.message.difficulty;
            let parent = block.parent_root();
            if parent.is_zero() {
                break;
            }
            current = parent;
        }

        total
    }

    /// Get all blocks at a specific slot.
    pub fn blocks_at_slot(&self, slot: u64) -> Vec<&SignedBeaconBlock> {
        self.blocks_by_slot
            .get(&slot)
            .map(|hashes| {
                hashes
                    .iter()
                    .filter_map(|h| self.blocks.get(h))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get the canonical chain from finalized slot to head.
    pub fn canonical_chain(&self) -> Vec<SignedBeaconBlock> {
        let Some(head) = self.canonical_head else {
            return Vec::new();
        };

        let mut chain = Vec::new();
        let mut current = head;

        while let Some(block) = self.blocks.get(&current) {
            chain.push(block.clone());
            let parent = block.parent_root();
            if parent.is_zero() || !self.blocks.contains_key(&parent) {
                break;
            }
            current = parent;
        }

        chain.reverse();
        chain
    }

    /// Prune blocks below the given slot.
    ///
    /// Returns the pruned blocks for persistence.
    /// Only prunes blocks that are on the canonical chain.
    pub fn prune(&mut self, below_slot: u64) -> Vec<SignedBeaconBlock> {
        let mut pruned = Vec::new();

        // Get canonical chain hashes to know which blocks to prune
        let canonical_hashes: HashSet<_> = self.canonical_chain().iter().map(|b| b.block_root()).collect();

        // Find slots to remove
        let slots_to_prune: Vec<_> = self
            .blocks_by_slot
            .range(..below_slot)
            .map(|(s, _)| *s)
            .collect();

        for slot in slots_to_prune {
            if let Some(hashes) = self.blocks_by_slot.remove(&slot) {
                for hash in hashes {
                    // Only return canonical blocks for persistence
                    if canonical_hashes.contains(&hash) {
                        if let Some(block) = self.blocks.remove(&hash) {
                            pruned.push(block);
                        }
                    } else {
                        // Remove non-canonical blocks without returning them
                        self.blocks.remove(&hash);
                    }

                    // Clean up children map
                    if let Some(block) = self.blocks.get(&hash) {
                        self.children.remove(&block.parent_root());
                    }
                }
            }
        }

        // Update finalized slot
        if below_slot > self.finalized_slot {
            self.finalized_slot = below_slot.saturating_sub(1);
        }

        // Sort pruned blocks by slot
        pruned.sort_by_key(|b| b.slot());
        pruned
    }

    /// Get the finalized slot.
    pub fn finalized_slot(&self) -> u64 {
        self.finalized_slot
    }

    /// Set the finalized slot (used when loading from storage).
    pub fn set_finalized_slot(&mut self, slot: u64) {
        self.finalized_slot = slot;
    }

    /// Get the number of blocks in the tree.
    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    /// Check if the tree is empty.
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    /// Get all block hashes in the tree.
    pub fn all_hashes(&self) -> Vec<B256> {
        self.blocks.keys().copied().collect()
    }

    /// Get retention depth.
    pub fn retention_depth(&self) -> u64 {
        self.retention_depth
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::{BeaconBlock, BeaconBlockBody};
    use alloy_primitives::Bytes;

    fn create_block(slot: u64, parent: B256, difficulty: u64) -> SignedBeaconBlock {
        // Use difficulty in state_root to ensure different blocks have different hashes
        let mut state_root = B256::ZERO;
        state_root.0[0] = difficulty as u8;

        let block = BeaconBlock::new(
            slot,
            (slot % 4) as u64, // proposer_index
            parent,
            state_root,
            BeaconBlockBody::default(),
            difficulty,
        );
        SignedBeaconBlock::new(block, Bytes::new())
    }

    #[test]
    fn test_insert_and_get() {
        let mut tree = BeaconBlockTree::default();

        let genesis = create_block(0, B256::ZERO, 2);
        let hash = tree.insert(genesis.clone()).unwrap();

        assert!(tree.contains(&hash));
        assert_eq!(tree.get(&hash).unwrap().slot(), 0);
        assert_eq!(tree.len(), 1);
    }

    #[test]
    fn test_insert_chain() {
        let mut tree = BeaconBlockTree::default();

        let genesis = create_block(0, B256::ZERO, 2);
        let genesis_hash = tree.insert(genesis).unwrap();

        let block1 = create_block(1, genesis_hash, 2);
        let hash1 = tree.insert(block1).unwrap();

        let block2 = create_block(2, hash1, 2);
        let hash2 = tree.insert(block2).unwrap();

        assert_eq!(tree.len(), 3);
        assert!(tree.contains(&genesis_hash));
        assert!(tree.contains(&hash1));
        assert!(tree.contains(&hash2));
    }

    #[test]
    fn test_insert_fork() {
        let mut tree = BeaconBlockTree::default();

        let genesis = create_block(0, B256::ZERO, 2);
        let genesis_hash = tree.insert(genesis).unwrap();

        // Main chain
        let block1a = create_block(1, genesis_hash, 2);
        let hash1a = tree.insert(block1a).unwrap();

        // Fork at genesis
        let block1b = create_block(1, genesis_hash, 1);
        let hash1b = tree.insert(block1b).unwrap();

        assert_eq!(tree.len(), 3);
        assert_ne!(hash1a, hash1b);

        // Both blocks at slot 1
        let slot1_blocks = tree.blocks_at_slot(1);
        assert_eq!(slot1_blocks.len(), 2);
    }

    #[test]
    fn test_canonical_head() {
        let mut tree = BeaconBlockTree::default();

        let genesis = create_block(0, B256::ZERO, 2);
        let genesis_hash = tree.insert(genesis).unwrap();

        // First block becomes canonical head
        assert_eq!(tree.canonical_head_hash(), Some(genesis_hash));

        let block1 = create_block(1, genesis_hash, 2);
        let hash1 = tree.insert(block1).unwrap();

        // Update canonical head
        tree.set_canonical_head(hash1).unwrap();
        assert_eq!(tree.canonical_head_hash(), Some(hash1));
    }

    #[test]
    fn test_find_common_ancestor() {
        let mut tree = BeaconBlockTree::default();

        // Genesis -> A1 -> A2
        //        \-> B1 -> B2
        let genesis = create_block(0, B256::ZERO, 2);
        let genesis_hash = tree.insert(genesis).unwrap();

        let a1 = create_block(1, genesis_hash, 2);
        let a1_hash = tree.insert(a1).unwrap();

        let a2 = create_block(2, a1_hash, 2);
        let a2_hash = tree.insert(a2).unwrap();

        let b1 = create_block(1, genesis_hash, 1);
        let b1_hash = tree.insert(b1).unwrap();

        let b2 = create_block(2, b1_hash, 1);
        let b2_hash = tree.insert(b2).unwrap();

        // Common ancestor of A2 and B2 is genesis
        let ancestor = tree.find_common_ancestor(a2_hash, b2_hash);
        assert_eq!(ancestor, Some(genesis_hash));

        // Common ancestor of A2 and A1 is A1
        let ancestor = tree.find_common_ancestor(a2_hash, a1_hash);
        assert_eq!(ancestor, Some(a1_hash));
    }

    #[test]
    fn test_get_chain() {
        let mut tree = BeaconBlockTree::default();

        let genesis = create_block(0, B256::ZERO, 2);
        let genesis_hash = tree.insert(genesis).unwrap();

        let block1 = create_block(1, genesis_hash, 2);
        let hash1 = tree.insert(block1).unwrap();

        let block2 = create_block(2, hash1, 2);
        let hash2 = tree.insert(block2).unwrap();

        let block3 = create_block(3, hash2, 2);
        let hash3 = tree.insert(block3).unwrap();

        // Get chain from genesis to block3
        let chain = tree.get_chain(genesis_hash, hash3);
        assert_eq!(chain.len(), 3);
        assert_eq!(chain[0].slot(), 1);
        assert_eq!(chain[1].slot(), 2);
        assert_eq!(chain[2].slot(), 3);
    }

    #[test]
    fn test_total_difficulty() {
        let mut tree = BeaconBlockTree::default();

        let genesis = create_block(0, B256::ZERO, 2);
        let genesis_hash = tree.insert(genesis).unwrap();

        let block1 = create_block(1, genesis_hash, 2); // in-turn
        let hash1 = tree.insert(block1).unwrap();

        let block2 = create_block(2, hash1, 1); // out-of-turn
        let hash2 = tree.insert(block2).unwrap();

        // Total difficulty: 2 + 2 + 1 = 5
        assert_eq!(tree.total_difficulty(hash2), 5);

        // Difficulty from genesis to block2: 2 + 1 = 3
        assert_eq!(tree.difficulty_from(genesis_hash, hash2), 3);
    }

    #[test]
    fn test_prune() {
        let mut tree = BeaconBlockTree::default();

        let genesis = create_block(0, B256::ZERO, 2);
        let genesis_hash = tree.insert(genesis).unwrap();

        let block1 = create_block(1, genesis_hash, 2);
        let hash1 = tree.insert(block1).unwrap();

        let block2 = create_block(2, hash1, 2);
        let hash2 = tree.insert(block2).unwrap();

        let block3 = create_block(3, hash2, 2);
        let hash3 = tree.insert(block3).unwrap();

        // Set canonical head to latest
        tree.set_canonical_head(hash3).unwrap();

        // Prune blocks below slot 2
        let pruned = tree.prune(2);

        // Genesis and block1 should be pruned
        assert_eq!(pruned.len(), 2);
        assert_eq!(pruned[0].slot(), 0);
        assert_eq!(pruned[1].slot(), 1);

        // Only block2 and block3 should remain
        assert_eq!(tree.len(), 2);
        assert!(!tree.contains(&genesis_hash));
        assert!(!tree.contains(&hash1));
        assert!(tree.contains(&hash2));
        assert!(tree.contains(&hash3));
    }

    #[test]
    fn test_duplicate_insert_fails() {
        let mut tree = BeaconBlockTree::default();

        let genesis = create_block(0, B256::ZERO, 2);
        tree.insert(genesis.clone()).unwrap();

        // Inserting same block again should fail
        let result = tree.insert(genesis);
        assert!(matches!(result, Err(BlockTreeError::BlockExists(_))));
    }

    #[test]
    fn test_canonical_chain() {
        let mut tree = BeaconBlockTree::default();

        let genesis = create_block(0, B256::ZERO, 2);
        let genesis_hash = tree.insert(genesis).unwrap();

        let block1 = create_block(1, genesis_hash, 2);
        let hash1 = tree.insert(block1).unwrap();

        let block2 = create_block(2, hash1, 2);
        let hash2 = tree.insert(block2).unwrap();

        tree.set_canonical_head(hash2).unwrap();

        let chain = tree.canonical_chain();
        assert_eq!(chain.len(), 3);
        assert_eq!(chain[0].slot(), 0);
        assert_eq!(chain[1].slot(), 1);
        assert_eq!(chain[2].slot(), 2);
    }
}
