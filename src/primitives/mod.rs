//! N42 primitive types for the node.
//!
//! This module defines the core blockchain types used by N42 nodes:
//!
//! # Modules
//!
//! - [`beacon`]: Beacon chain block types (BeaconBlock, BeaconBlockHeader)
//! - [`unified`]: Unified block combining beacon + execution layers
//!
//! # Architecture
//!
//! N42 uses **unified blocks** (beacon + execution) as the core block type:
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    N42 Unified Architecture                 │
//! ├─────────────────────────────────────────────────────────────┤
//! │                                                             │
//! │  N42NodePrimitives::Block = N42BroadcastBlock               │
//! │    ├── beacon: SignedBeaconBlock                            │
//! │    └── execution: reth_ethereum_primitives::Block           │
//! │                                                             │
//! │  Benefits:                                                  │
//! │  - eth66 NewBlock carries unified block                     │
//! │  - Single download for beacon + execution                   │
//! │  - Atomic sync of both layers                               │
//! │                                                             │
//! └─────────────────────────────────────────────────────────────┘
//! ```

pub mod beacon;
pub mod unified;

// Re-export beacon types
pub use beacon::{
    BeaconBlock, BeaconBlockBody, BeaconBlockHeader, Eth1Data, SignedBeaconBlock,
};

// Re-export unified types
pub use unified::{N42BroadcastBlock, UnifiedBlock, UnifiedBlockBuilder, UnifiedBlockError};

// Re-export standard Ethereum primitives for execution layer
pub use reth_ethereum_primitives::{
    Block as N42Block, BlockBody as N42BlockBody, Receipt as N42Receipt,
    TransactionSigned as N42Transaction,
};

pub use alloy_consensus::Header as N42BlockHeader;

// ============================================================================
// N42 Node Primitives - Unified Block as Core Type
// ============================================================================

use reth_primitives_traits::NodePrimitives;

/// N42 node primitives with unified block (beacon + execution) as the core block type.
///
/// This enables the entire node to work with unified blocks:
/// - **Storage**: Stores `N42BroadcastBlock` (beacon + execution together)
/// - **Network**: eth66 NewBlock carries `N42BroadcastBlock`
/// - **Sync**: Downloads both beacon and execution in one request
///
/// # Type Mapping
///
/// | Type | Implementation |
/// |------|----------------|
/// | `Block` | `N42BroadcastBlock` (beacon + execution) |
/// | `BlockHeader` | `alloy_consensus::Header` |
/// | `BlockBody` | `reth_ethereum_primitives::BlockBody` |
/// | `SignedTx` | `TransactionSigned` |
/// | `Receipt` | `Receipt` |
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct N42NodePrimitives;

impl NodePrimitives for N42NodePrimitives {
    type Block = N42BroadcastBlock;
    type BlockHeader = N42BlockHeader;
    type BlockBody = N42BlockBody;
    type SignedTx = N42Transaction;
    type Receipt = N42Receipt;
}
