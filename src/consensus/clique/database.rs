//! Database abstraction for Clique snapshots.
//!
//! This module provides a trait for snapshot storage and a memory-based implementation
//! for testing purposes.

use super::{CliqueError, Snapshot};
use alloy_primitives::B256;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;

/// Database key prefix for clique snapshots.
pub const CLIQUE_SNAPSHOT_PREFIX: &[u8] = b"clique-";

/// Trait for snapshot database operations.
///
/// This abstraction allows using different storage backends:
/// - Memory-based for testing
/// - MDBX or other persistent storage for production
pub trait SnapshotDatabase: Send + Sync {
    /// Load a snapshot by block hash.
    fn load_snapshot(&self, hash: B256) -> Result<Option<Snapshot>, CliqueError>;

    /// Store a snapshot.
    fn store_snapshot(&self, snapshot: &Snapshot) -> Result<(), CliqueError>;

    /// Delete a snapshot by block hash.
    fn delete_snapshot(&self, hash: B256) -> Result<(), CliqueError>;

    /// Check if a snapshot exists.
    fn has_snapshot(&self, hash: B256) -> Result<bool, CliqueError>;
}

/// Memory-based snapshot database for testing.
#[derive(Debug, Default)]
pub struct MemorySnapshotDatabase {
    snapshots: RwLock<HashMap<B256, Snapshot>>,
}

impl MemorySnapshotDatabase {
    /// Create a new memory database.
    pub fn new() -> Self {
        Self {
            snapshots: RwLock::new(HashMap::new()),
        }
    }

    /// Create a new memory database wrapped in Arc.
    pub fn new_arc() -> Arc<Self> {
        Arc::new(Self::new())
    }

    /// Get the number of stored snapshots.
    pub fn len(&self) -> usize {
        self.snapshots.read().len()
    }

    /// Check if the database is empty.
    pub fn is_empty(&self) -> bool {
        self.snapshots.read().is_empty()
    }

    /// Clear all snapshots.
    pub fn clear(&self) {
        self.snapshots.write().clear();
    }
}

impl SnapshotDatabase for MemorySnapshotDatabase {
    fn load_snapshot(&self, hash: B256) -> Result<Option<Snapshot>, CliqueError> {
        Ok(self.snapshots.read().get(&hash).cloned())
    }

    fn store_snapshot(&self, snapshot: &Snapshot) -> Result<(), CliqueError> {
        self.snapshots.write().insert(snapshot.hash, snapshot.clone());
        Ok(())
    }

    fn delete_snapshot(&self, hash: B256) -> Result<(), CliqueError> {
        self.snapshots.write().remove(&hash);
        Ok(())
    }

    fn has_snapshot(&self, hash: B256) -> Result<bool, CliqueError> {
        Ok(self.snapshots.read().contains_key(&hash))
    }
}

/// A no-op database that doesn't persist anything.
/// Useful for scenarios where snapshot caching is handled externally.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopSnapshotDatabase;

impl SnapshotDatabase for NoopSnapshotDatabase {
    fn load_snapshot(&self, _hash: B256) -> Result<Option<Snapshot>, CliqueError> {
        Ok(None)
    }

    fn store_snapshot(&self, _snapshot: &Snapshot) -> Result<(), CliqueError> {
        Ok(())
    }

    fn delete_snapshot(&self, _hash: B256) -> Result<(), CliqueError> {
        Ok(())
    }

    fn has_snapshot(&self, _hash: B256) -> Result<bool, CliqueError> {
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::clique::snapshot::CliqueConfig;
    use alloy_primitives::Address;

    fn test_config() -> CliqueConfig {
        CliqueConfig {
            period: 15,
            epoch: 30000,
        }
    }

    #[test]
    fn test_memory_database() {
        let db = MemorySnapshotDatabase::new();
        let config = test_config();

        let signers = vec![
            Address::repeat_byte(0x01),
            Address::repeat_byte(0x02),
        ];

        let snapshot = Snapshot::new(config, 100, B256::repeat_byte(0xaa), signers);

        // Store
        db.store_snapshot(&snapshot).unwrap();
        assert_eq!(db.len(), 1);

        // Load
        let loaded = db.load_snapshot(snapshot.hash).unwrap();
        assert!(loaded.is_some());
        let loaded = loaded.unwrap();
        assert_eq!(loaded.number, 100);
        assert_eq!(loaded.hash, B256::repeat_byte(0xaa));

        // Has
        assert!(db.has_snapshot(snapshot.hash).unwrap());
        assert!(!db.has_snapshot(B256::ZERO).unwrap());

        // Delete
        db.delete_snapshot(snapshot.hash).unwrap();
        assert!(db.is_empty());
    }
}
