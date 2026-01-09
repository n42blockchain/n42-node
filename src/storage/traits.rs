//! Storage traits for beacon chain data.
//!
//! This module defines the storage interface for beacon chain blocks,
//! separate from execution layer storage.

use crate::primitives::{BeaconBlockHeader, SignedBeaconBlock};
use alloy_primitives::B256;

/// Error type for beacon storage operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BeaconStoreError {
    /// Block not found.
    #[error("beacon block not found at slot {0}")]
    BlockNotFound(u64),

    /// Header not found.
    #[error("beacon header not found at slot {0}")]
    HeaderNotFound(u64),

    /// Block not found by root.
    #[error("beacon block not found with root {0}")]
    BlockNotFoundByRoot(B256),

    /// Database error.
    #[error("database error: {0}")]
    Database(String),

    /// Encoding error.
    #[error("encoding error: {0}")]
    Encoding(String),
}

/// Read-only access to beacon chain block storage.
///
/// This trait provides methods to query beacon blocks by slot or root.
pub trait BeaconStoreReader {
    /// Get a beacon block header by slot.
    fn header_by_slot(&self, slot: u64) -> Result<Option<BeaconBlockHeader>, BeaconStoreError>;

    /// Get a signed beacon block by slot.
    fn block_by_slot(&self, slot: u64) -> Result<Option<SignedBeaconBlock>, BeaconStoreError>;

    /// Get a signed beacon block by its root (hash).
    fn block_by_root(&self, root: B256) -> Result<Option<SignedBeaconBlock>, BeaconStoreError>;

    /// Get the latest beacon block.
    fn latest_block(&self) -> Result<Option<SignedBeaconBlock>, BeaconStoreError>;

    /// Get the latest slot number.
    fn latest_slot(&self) -> Result<Option<u64>, BeaconStoreError>;

    /// Check if a block exists at the given slot.
    fn has_block(&self, slot: u64) -> Result<bool, BeaconStoreError> {
        Ok(self.header_by_slot(slot)?.is_some())
    }

    /// Get blocks in a slot range (inclusive).
    fn blocks_in_range(
        &self,
        start_slot: u64,
        end_slot: u64,
    ) -> Result<Vec<SignedBeaconBlock>, BeaconStoreError> {
        let mut blocks = Vec::new();
        for slot in start_slot..=end_slot {
            if let Some(block) = self.block_by_slot(slot)? {
                blocks.push(block);
            }
        }
        Ok(blocks)
    }
}

/// Write access to beacon chain block storage.
///
/// This trait provides methods to store beacon blocks.
pub trait BeaconStoreWriter {
    /// Insert a signed beacon block.
    ///
    /// Returns the block root if successful.
    fn insert_block(&self, block: SignedBeaconBlock) -> Result<B256, BeaconStoreError>;

    /// Insert multiple blocks atomically.
    fn insert_blocks(&self, blocks: Vec<SignedBeaconBlock>) -> Result<(), BeaconStoreError> {
        for block in blocks {
            self.insert_block(block)?;
        }
        Ok(())
    }

    /// Remove a block by slot.
    fn remove_block(&self, slot: u64) -> Result<Option<SignedBeaconBlock>, BeaconStoreError>;

    /// Remove blocks in a slot range (for reorgs).
    fn remove_blocks_from(&self, start_slot: u64) -> Result<u64, BeaconStoreError>;
}

/// Combined read-write access to beacon storage.
pub trait BeaconStore: BeaconStoreReader + BeaconStoreWriter {}

impl<T> BeaconStore for T where T: BeaconStoreReader + BeaconStoreWriter {}
