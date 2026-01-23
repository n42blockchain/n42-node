//! Fork choice logic for Clique POA consensus.
//!
//! This module implements the fork choice rule based on total difficulty:
//! - The chain with higher total difficulty wins
//! - In-turn blocks have difficulty 2, out-of-turn blocks have difficulty 1
//! - On equal difficulty, lower block hash wins (deterministic tie-breaker)
//!
//! # Fork Choice Decision
//!
//! When a new block arrives, three outcomes are possible:
//! - **Extend**: Block extends the current canonical chain
//! - **Reorg**: Block creates a stronger chain, switch to it
//! - **Keep**: Block is from a weaker chain, keep it but don't switch

use super::block_tree::{BeaconBlockTree, BlockTreeError};
use crate::primitives::SignedBeaconBlock;
use alloy_primitives::B256;

/// Maximum reorg depth allowed.
/// Reorgs deeper than this are rejected as potentially malicious.
pub const MAX_REORG_DEPTH: u64 = 64;

/// Fork choice decision result.
#[derive(Debug, Clone)]
pub enum ForkChoiceDecision {
    /// Block extends the current canonical chain.
    /// Simply append it and update the head.
    Extend {
        /// The new block's hash.
        block: B256,
    },

    /// A chain reorganization is needed.
    /// The new chain has higher total difficulty.
    Reorg {
        /// Common ancestor of old and new chain.
        common_ancestor: B256,
        /// Slot of common ancestor.
        common_ancestor_slot: u64,
        /// Blocks being removed from canonical chain (old chain).
        /// Ordered from oldest to newest.
        old_blocks: Vec<SignedBeaconBlock>,
        /// Blocks being added to canonical chain (new chain).
        /// Ordered from oldest to newest.
        new_blocks: Vec<SignedBeaconBlock>,
        /// New head hash.
        new_head: B256,
    },

    /// Block is from a weaker chain.
    /// Keep it in the tree but don't switch canonical head.
    Keep {
        /// The block's hash (kept for potential future reorg).
        block: B256,
    },
}

/// Error type for fork choice operations.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ForkChoiceError {
    /// Block tree error.
    #[error("block tree error: {0}")]
    BlockTree(#[from] BlockTreeError),

    /// Common ancestor not found.
    #[error("common ancestor not found between {0} and {1}")]
    NoCommonAncestor(B256, B256),

    /// Reorg depth exceeded.
    #[error("reorg depth {depth} exceeds maximum {max}")]
    ReorgDepthExceeded { depth: u64, max: u64 },
}

/// Clique POA fork choice implementation.
///
/// Uses total difficulty to determine the canonical chain.
/// This is stateless - all state is in the BeaconBlockTree.
pub struct CliqueForkChoice {
    /// Maximum reorg depth allowed.
    max_reorg_depth: u64,
}

impl Default for CliqueForkChoice {
    fn default() -> Self {
        Self::new(MAX_REORG_DEPTH)
    }
}

impl CliqueForkChoice {
    /// Create a new fork choice instance.
    pub fn new(max_reorg_depth: u64) -> Self {
        Self { max_reorg_depth }
    }

    /// Evaluate a new block and determine fork choice decision.
    ///
    /// # Arguments
    /// * `tree` - The block tree containing all known blocks
    /// * `new_block` - The new block to evaluate
    ///
    /// # Returns
    /// * `ForkChoiceDecision` indicating what action to take
    pub fn evaluate(
        &self,
        tree: &BeaconBlockTree,
        new_block: &SignedBeaconBlock,
    ) -> Result<ForkChoiceDecision, ForkChoiceError> {
        let new_hash = new_block.block_root();
        let parent_hash = new_block.parent_root();

        // Get current canonical head
        let current_head = match tree.canonical_head() {
            Ok(head) => head,
            Err(_) => {
                // No head yet, this block becomes the head
                return Ok(ForkChoiceDecision::Extend { block: new_hash });
            }
        };

        let current_head_hash = current_head.block_root();

        // Case 1: Block extends current chain
        if parent_hash == current_head_hash {
            return Ok(ForkChoiceDecision::Extend { block: new_hash });
        }

        // Case 2: Block is on a different branch - compare total difficulty
        // Find common ancestor
        let common_ancestor = tree
            .find_common_ancestor(current_head_hash, new_hash)
            .ok_or_else(|| ForkChoiceError::NoCommonAncestor(current_head_hash, new_hash))?;

        let common_ancestor_block = tree
            .get(&common_ancestor)
            .ok_or(BlockTreeError::BlockNotFound(common_ancestor))?;
        let common_ancestor_slot = common_ancestor_block.slot();

        // Check reorg depth
        let reorg_depth = current_head.slot().saturating_sub(common_ancestor_slot);
        if reorg_depth > self.max_reorg_depth {
            return Err(ForkChoiceError::ReorgDepthExceeded {
                depth: reorg_depth,
                max: self.max_reorg_depth,
            });
        }

        // Calculate total difficulty from common ancestor
        let current_td = tree.difficulty_from(common_ancestor, current_head_hash);
        let new_td = tree.difficulty_from(common_ancestor, new_hash);

        // Determine winner
        let new_chain_wins = if new_td > current_td {
            true
        } else if new_td == current_td {
            // Tie-breaker: lower hash wins (deterministic)
            new_hash < current_head_hash
        } else {
            false
        };

        if new_chain_wins {
            // Reorg to new chain
            let old_blocks = tree.get_chain(common_ancestor, current_head_hash);
            let new_blocks = tree.get_chain(common_ancestor, new_hash);

            Ok(ForkChoiceDecision::Reorg {
                common_ancestor,
                common_ancestor_slot,
                old_blocks,
                new_blocks,
                new_head: new_hash,
            })
        } else {
            // Keep new block but don't switch
            Ok(ForkChoiceDecision::Keep { block: new_hash })
        }
    }

    /// Compare two chains and determine which is stronger.
    ///
    /// Returns true if chain A is stronger than chain B.
    pub fn is_stronger(&self, tree: &BeaconBlockTree, head_a: B256, head_b: B256) -> bool {
        let td_a = tree.total_difficulty(head_a);
        let td_b = tree.total_difficulty(head_b);

        if td_a > td_b {
            true
        } else if td_a == td_b {
            head_a < head_b
        } else {
            false
        }
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
            (slot % 4) as u64,
            parent,
            state_root,
            BeaconBlockBody::default(),
            difficulty,
        );
        SignedBeaconBlock::new(block, Bytes::new())
    }

    fn setup_basic_tree() -> (BeaconBlockTree, B256) {
        let mut tree = BeaconBlockTree::default();
        let genesis = create_block(0, B256::ZERO, 2);
        let genesis_hash = tree.insert(genesis).unwrap();
        tree.set_canonical_head(genesis_hash).unwrap();
        (tree, genesis_hash)
    }

    #[test]
    fn test_extend_chain() {
        let (mut tree, genesis_hash) = setup_basic_tree();
        let fc = CliqueForkChoice::default();

        let block1 = create_block(1, genesis_hash, 2);
        tree.insert(block1.clone()).unwrap();

        let decision = fc.evaluate(&tree, &block1).unwrap();
        assert!(matches!(decision, ForkChoiceDecision::Extend { .. }));
    }

    #[test]
    fn test_keep_weaker_chain() {
        let (mut tree, genesis_hash) = setup_basic_tree();
        let fc = CliqueForkChoice::default();

        // Add block to canonical chain with high difficulty
        let block1 = create_block(1, genesis_hash, 2);
        let hash1 = tree.insert(block1).unwrap();
        tree.set_canonical_head(hash1).unwrap();

        // Add fork block with lower difficulty
        let fork_block = create_block(1, genesis_hash, 1);
        tree.insert(fork_block.clone()).unwrap();

        let decision = fc.evaluate(&tree, &fork_block).unwrap();
        assert!(matches!(decision, ForkChoiceDecision::Keep { .. }));
    }

    #[test]
    fn test_reorg_to_stronger_chain() {
        let (mut tree, genesis_hash) = setup_basic_tree();
        let fc = CliqueForkChoice::default();

        // Add block to canonical chain with LOW difficulty
        let block1 = create_block(1, genesis_hash, 1);
        let hash1 = tree.insert(block1).unwrap();
        tree.set_canonical_head(hash1).unwrap();

        // Add fork block with HIGH difficulty
        let fork_block = create_block(1, genesis_hash, 2);
        tree.insert(fork_block.clone()).unwrap();

        let decision = fc.evaluate(&tree, &fork_block).unwrap();

        match decision {
            ForkChoiceDecision::Reorg {
                common_ancestor,
                old_blocks,
                new_blocks,
                ..
            } => {
                assert_eq!(common_ancestor, genesis_hash);
                assert_eq!(old_blocks.len(), 1);
                assert_eq!(new_blocks.len(), 1);
                assert_eq!(old_blocks[0].message.difficulty, 1);
                assert_eq!(new_blocks[0].message.difficulty, 2);
            }
            _ => panic!("Expected Reorg decision"),
        }
    }

    #[test]
    fn test_multi_block_reorg() {
        let (mut tree, genesis_hash) = setup_basic_tree();
        let fc = CliqueForkChoice::default();

        // Main chain: genesis -> a1(diff=1) -> a2(diff=1), total=4
        let a1 = create_block(1, genesis_hash, 1);
        let a1_hash = tree.insert(a1).unwrap();

        let a2 = create_block(2, a1_hash, 1);
        let a2_hash = tree.insert(a2).unwrap();
        tree.set_canonical_head(a2_hash).unwrap();

        // Fork chain: genesis -> b1(diff=2) -> b2(diff=2) -> b3(diff=2), total=8
        let b1 = create_block(1, genesis_hash, 2);
        let b1_hash = tree.insert(b1).unwrap();

        let b2 = create_block(2, b1_hash, 2);
        let b2_hash = tree.insert(b2).unwrap();

        let b3 = create_block(3, b2_hash, 2);
        tree.insert(b3.clone()).unwrap();

        let decision = fc.evaluate(&tree, &b3).unwrap();

        match decision {
            ForkChoiceDecision::Reorg {
                common_ancestor,
                old_blocks,
                new_blocks,
                ..
            } => {
                assert_eq!(common_ancestor, genesis_hash);
                assert_eq!(old_blocks.len(), 2); // a1, a2
                assert_eq!(new_blocks.len(), 3); // b1, b2, b3
            }
            _ => panic!("Expected Reorg decision"),
        }
    }

    #[test]
    fn test_tie_breaker() {
        let (mut tree, genesis_hash) = setup_basic_tree();
        let fc = CliqueForkChoice::default();

        // Both chains have same difficulty but different content
        // Use different state_root values to create unique hashes with same difficulty
        let block1 = {
            let mut state_root = B256::ZERO;
            state_root.0[0] = 2; // difficulty
            state_root.0[1] = 1; // unique id
            let block = BeaconBlock::new(1, 1, genesis_hash, state_root, BeaconBlockBody::default(), 2);
            SignedBeaconBlock::new(block, Bytes::new())
        };
        let hash1 = tree.insert(block1).unwrap();
        tree.set_canonical_head(hash1).unwrap();

        let fork_block = {
            let mut state_root = B256::ZERO;
            state_root.0[0] = 2; // same difficulty
            state_root.0[1] = 2; // different unique id
            let block = BeaconBlock::new(1, 1, genesis_hash, state_root, BeaconBlockBody::default(), 2);
            SignedBeaconBlock::new(block, Bytes::new())
        };
        let fork_hash = tree.insert(fork_block.clone()).unwrap();

        let decision = fc.evaluate(&tree, &fork_block).unwrap();

        // Lower hash should win
        if fork_hash < hash1 {
            assert!(matches!(decision, ForkChoiceDecision::Reorg { .. }));
        } else {
            assert!(matches!(decision, ForkChoiceDecision::Keep { .. }));
        }
    }

    #[test]
    fn test_reorg_depth_limit() {
        let (mut tree, genesis_hash) = setup_basic_tree();
        let fc = CliqueForkChoice::new(2); // Max depth of 2

        // Build a chain of 5 blocks
        let mut parent = genesis_hash;
        for i in 1..=5 {
            let block = create_block(i, parent, 1);
            parent = tree.insert(block).unwrap();
        }
        tree.set_canonical_head(parent).unwrap();

        // Try to reorg from genesis (depth = 5 > max of 2)
        let fork_block = create_block(1, genesis_hash, 2);
        tree.insert(fork_block.clone()).unwrap();

        let result = fc.evaluate(&tree, &fork_block);
        assert!(matches!(result, Err(ForkChoiceError::ReorgDepthExceeded { .. })));
    }

    #[test]
    fn test_is_stronger() {
        let (mut tree, genesis_hash) = setup_basic_tree();
        let fc = CliqueForkChoice::default();

        let block_strong = create_block(1, genesis_hash, 2);
        let hash_strong = tree.insert(block_strong).unwrap();

        let block_weak = create_block(1, genesis_hash, 1);
        let hash_weak = tree.insert(block_weak).unwrap();

        // Strong chain (TD=4) should be stronger than weak chain (TD=3)
        assert!(fc.is_stronger(&tree, hash_strong, hash_weak));
        assert!(!fc.is_stronger(&tree, hash_weak, hash_strong));
    }
}
