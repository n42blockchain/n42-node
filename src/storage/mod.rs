//! Beacon chain storage layer.
//!
//! This module provides storage for beacon chain blocks, separate from
//! the execution layer storage handled by reth's built-in storage.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │                    N42 Storage                          │
//! ├─────────────────────────────────────────────────────────┤
//! │                                                         │
//! │  ┌─────────────────────┐  ┌─────────────────────────┐   │
//! │  │   BeaconStore       │  │   ExecutionStore        │   │
//! │  │   (this module)     │  │   (reth built-in)       │   │
//! │  │                     │  │                         │   │
//! │  │  - BeaconHeaders    │  │  - Headers              │   │
//! │  │  - BeaconBodies     │  │  - Bodies               │   │
//! │  │  - RootIndex        │  │  - Transactions         │   │
//! │  │                     │  │  - Receipts             │   │
//! │  └─────────────────────┘  └─────────────────────────┘   │
//! │           │                          │                  │
//! │           └──────────┬───────────────┘                  │
//! │                      ▼                                  │
//! │             ┌─────────────────┐                         │
//! │             │  UnifiedStore   │                         │
//! │             │  (combines both)│                         │
//! │             └─────────────────┘                         │
//! └─────────────────────────────────────────────────────────┘
//! ```
//!
//! # Implementations
//!
//! - [`InMemoryBeaconStore`]: Simple in-memory storage for testing
//! - Future: MDBX-based persistent storage
//!
//! # Usage
//!
//! ```ignore
//! use n42_node::storage::{InMemoryBeaconStore, BeaconStoreReader};
//!
//! let store = InMemoryBeaconStore::new();
//! store.insert_block(signed_block)?;
//!
//! if let Some(block) = store.block_by_slot(100)? {
//!     println!("Found block at slot {}", block.slot());
//! }
//! ```

mod memory;
mod traits;

pub use memory::InMemoryBeaconStore;
pub use traits::{BeaconStore, BeaconStoreError, BeaconStoreReader, BeaconStoreWriter};
