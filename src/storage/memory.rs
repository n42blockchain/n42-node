//! In-memory beacon block storage.
//!
//! This provides a simple in-memory implementation of [`BeaconStore`]
//! for testing and development purposes.

use super::traits::{BeaconStoreError, BeaconStoreReader, BeaconStoreWriter};
use crate::primitives::{BeaconBlockHeader, SignedBeaconBlock};
use alloy_primitives::B256;
use std::{
    collections::BTreeMap,
    sync::{Arc, RwLock},
};

/// In-memory beacon block storage.
///
/// Uses a `BTreeMap` keyed by slot for ordered access.
/// Thread-safe via `RwLock`.
///
/// # Example
///
/// ```ignore
/// use n42_node::storage::InMemoryBeaconStore;
///
/// let store = InMemoryBeaconStore::new();
/// store.insert_block(signed_block)?;
/// let block = store.block_by_slot(100)?;
/// ```
#[derive(Debug, Default)]
pub struct InMemoryBeaconStore {
    /// Blocks indexed by slot.
    blocks: Arc<RwLock<BTreeMap<u64, SignedBeaconBlock>>>,
    /// Block root to slot mapping for fast lookup by root.
    root_to_slot: Arc<RwLock<BTreeMap<B256, u64>>>,
}

impl InMemoryBeaconStore {
    /// Create a new empty in-memory store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create with pre-populated blocks.
    pub fn with_blocks(blocks: Vec<SignedBeaconBlock>) -> Result<Self, BeaconStoreError> {
        let store = Self::new();
        store.insert_blocks(blocks)?;
        Ok(store)
    }

    /// Get the number of stored blocks.
    pub fn len(&self) -> usize {
        self.blocks.read().unwrap().len()
    }

    /// Check if the store is empty.
    pub fn is_empty(&self) -> bool {
        self.blocks.read().unwrap().is_empty()
    }

    /// Clear all stored blocks.
    pub fn clear(&self) {
        self.blocks.write().unwrap().clear();
        self.root_to_slot.write().unwrap().clear();
    }
}

impl BeaconStoreReader for InMemoryBeaconStore {
    fn header_by_slot(&self, slot: u64) -> Result<Option<BeaconBlockHeader>, BeaconStoreError> {
        let blocks = self.blocks.read().map_err(|e| {
            BeaconStoreError::Database(format!("lock poisoned: {}", e))
        })?;

        Ok(blocks.get(&slot).map(|b| b.header()))
    }

    fn block_by_slot(&self, slot: u64) -> Result<Option<SignedBeaconBlock>, BeaconStoreError> {
        let blocks = self.blocks.read().map_err(|e| {
            BeaconStoreError::Database(format!("lock poisoned: {}", e))
        })?;

        Ok(blocks.get(&slot).cloned())
    }

    fn block_by_root(&self, root: B256) -> Result<Option<SignedBeaconBlock>, BeaconStoreError> {
        let root_to_slot = self.root_to_slot.read().map_err(|e| {
            BeaconStoreError::Database(format!("lock poisoned: {}", e))
        })?;

        if let Some(&slot) = root_to_slot.get(&root) {
            drop(root_to_slot);
            self.block_by_slot(slot)
        } else {
            Ok(None)
        }
    }

    fn latest_block(&self) -> Result<Option<SignedBeaconBlock>, BeaconStoreError> {
        let blocks = self.blocks.read().map_err(|e| {
            BeaconStoreError::Database(format!("lock poisoned: {}", e))
        })?;

        Ok(blocks.values().last().cloned())
    }

    fn latest_slot(&self) -> Result<Option<u64>, BeaconStoreError> {
        let blocks = self.blocks.read().map_err(|e| {
            BeaconStoreError::Database(format!("lock poisoned: {}", e))
        })?;

        Ok(blocks.keys().last().copied())
    }
}

impl BeaconStoreWriter for InMemoryBeaconStore {
    fn insert_block(&self, block: SignedBeaconBlock) -> Result<B256, BeaconStoreError> {
        let slot = block.slot();
        let root = block.block_root();

        let mut blocks = self.blocks.write().map_err(|e| {
            BeaconStoreError::Database(format!("lock poisoned: {}", e))
        })?;

        let mut root_to_slot = self.root_to_slot.write().map_err(|e| {
            BeaconStoreError::Database(format!("lock poisoned: {}", e))
        })?;

        blocks.insert(slot, block);
        root_to_slot.insert(root, slot);

        Ok(root)
    }

    fn remove_block(&self, slot: u64) -> Result<Option<SignedBeaconBlock>, BeaconStoreError> {
        let mut blocks = self.blocks.write().map_err(|e| {
            BeaconStoreError::Database(format!("lock poisoned: {}", e))
        })?;

        let mut root_to_slot = self.root_to_slot.write().map_err(|e| {
            BeaconStoreError::Database(format!("lock poisoned: {}", e))
        })?;

        if let Some(block) = blocks.remove(&slot) {
            let root = block.block_root();
            root_to_slot.remove(&root);
            Ok(Some(block))
        } else {
            Ok(None)
        }
    }

    fn remove_blocks_from(&self, start_slot: u64) -> Result<u64, BeaconStoreError> {
        let mut blocks = self.blocks.write().map_err(|e| {
            BeaconStoreError::Database(format!("lock poisoned: {}", e))
        })?;

        let mut root_to_slot = self.root_to_slot.write().map_err(|e| {
            BeaconStoreError::Database(format!("lock poisoned: {}", e))
        })?;

        // Collect slots to remove
        let slots_to_remove: Vec<u64> = blocks
            .range(start_slot..)
            .map(|(&slot, _)| slot)
            .collect();

        let count = slots_to_remove.len() as u64;

        // Remove blocks and their root mappings
        for slot in slots_to_remove {
            if let Some(block) = blocks.remove(&slot) {
                let root = block.block_root();
                root_to_slot.remove(&root);
            }
        }

        Ok(count)
    }
}

impl Clone for InMemoryBeaconStore {
    fn clone(&self) -> Self {
        Self {
            blocks: Arc::clone(&self.blocks),
            root_to_slot: Arc::clone(&self.root_to_slot),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::{BeaconBlock, BeaconBlockBody};
    use alloy_primitives::Bytes;

    fn create_test_block(slot: u64) -> SignedBeaconBlock {
        let block = BeaconBlock::new(
            slot,
            42,
            B256::repeat_byte(slot as u8),
            B256::repeat_byte(0x11),
            BeaconBlockBody::default(),
        );
        SignedBeaconBlock::new(block, Bytes::from_static(&[0x00; 96]))
    }

    #[test]
    fn test_insert_and_get() {
        let store = InMemoryBeaconStore::new();
        let block = create_test_block(100);
        let root = block.block_root();

        store.insert_block(block.clone()).unwrap();

        // Get by slot
        let retrieved = store.block_by_slot(100).unwrap().unwrap();
        assert_eq!(retrieved.slot(), 100);

        // Get by root
        let retrieved = store.block_by_root(root).unwrap().unwrap();
        assert_eq!(retrieved.slot(), 100);
    }

    #[test]
    fn test_latest_block() {
        let store = InMemoryBeaconStore::new();

        assert!(store.latest_block().unwrap().is_none());
        assert!(store.latest_slot().unwrap().is_none());

        store.insert_block(create_test_block(100)).unwrap();
        store.insert_block(create_test_block(200)).unwrap();
        store.insert_block(create_test_block(150)).unwrap();

        let latest = store.latest_block().unwrap().unwrap();
        assert_eq!(latest.slot(), 200);
        assert_eq!(store.latest_slot().unwrap(), Some(200));
    }

    #[test]
    fn test_blocks_in_range() {
        let store = InMemoryBeaconStore::new();

        for slot in [100, 101, 102, 105, 110] {
            store.insert_block(create_test_block(slot)).unwrap();
        }

        let range = store.blocks_in_range(100, 105).unwrap();
        assert_eq!(range.len(), 4);
        assert_eq!(range[0].slot(), 100);
        assert_eq!(range[3].slot(), 105);
    }

    #[test]
    fn test_remove_block() {
        let store = InMemoryBeaconStore::new();
        let block = create_test_block(100);
        let root = block.block_root();

        store.insert_block(block).unwrap();
        assert!(store.has_block(100).unwrap());

        let removed = store.remove_block(100).unwrap().unwrap();
        assert_eq!(removed.slot(), 100);

        assert!(!store.has_block(100).unwrap());
        assert!(store.block_by_root(root).unwrap().is_none());
    }

    #[test]
    fn test_remove_blocks_from() {
        let store = InMemoryBeaconStore::new();

        for slot in 100..110 {
            store.insert_block(create_test_block(slot)).unwrap();
        }

        assert_eq!(store.len(), 10);

        let removed = store.remove_blocks_from(105).unwrap();
        assert_eq!(removed, 5);
        assert_eq!(store.len(), 5);

        assert!(store.has_block(104).unwrap());
        assert!(!store.has_block(105).unwrap());
    }

    #[test]
    fn test_header_by_slot() {
        let store = InMemoryBeaconStore::new();
        store.insert_block(create_test_block(100)).unwrap();

        let header = store.header_by_slot(100).unwrap().unwrap();
        assert_eq!(header.slot, 100);
    }

    #[test]
    fn test_clear() {
        let store = InMemoryBeaconStore::new();

        store.insert_block(create_test_block(100)).unwrap();
        store.insert_block(create_test_block(200)).unwrap();

        assert_eq!(store.len(), 2);

        store.clear();

        assert!(store.is_empty());
    }
}
