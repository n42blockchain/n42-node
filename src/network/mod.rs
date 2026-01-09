//! Network primitives for eth66 P2P communication.
//!
//! This module provides network primitives that configure eth66 to use
//! our custom unified block type (`N42BroadcastBlock`) in the `NewBlock` message.
//!
//! # eth66 Protocol
//!
//! The eth66 protocol uses these message types for block propagation:
//! - `NewBlock`: Broadcast a new block with total difficulty
//! - `NewBlockHashes`: Announce new block hashes
//! - `GetBlockHeaders` / `BlockHeaders`: Request/response headers
//! - `GetBlockBodies` / `BlockBodies`: Request/response bodies
//!
//! # beacon_sync Protocol
//!
//! A custom subprotocol for downloading beacon blocks:
//! - `GetBeaconBlocks`: Request beacon blocks by slot range
//! - `BeaconBlocks`: Response with signed beacon blocks
//!
//! # Custom Block Type
//!
//! By implementing `NetworkPrimitives` with our custom types, we can use
//! eth66 to broadcast `N42BroadcastBlock` (which contains both beacon and
//! execution layer data) instead of standard Ethereum blocks.
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    eth66 NewBlock                           │
//! │                                                             │
//! │  ┌─────────────────────────────────────────────────────┐   │
//! │  │              N42BroadcastBlock                       │   │
//! │  │  ┌──────────────────┐  ┌──────────────────────┐     │   │
//! │  │  │  SignedBeacon    │  │   ExecutionBlock     │     │   │
//! │  │  │  Block           │  │   (reth Block)       │     │   │
//! │  │  └──────────────────┘  └──────────────────────┘     │   │
//! │  └─────────────────────────────────────────────────────┘   │
//! │                                                             │
//! │  + total_difficulty: U256                                   │
//! └─────────────────────────────────────────────────────────────┘
//! ```

pub mod beacon_messages;
pub mod beacon_protocol;
pub mod primitives;

pub use beacon_messages::{
    BeaconBlocksResponse, BeaconSyncMessageId, GetBeaconBlocks, MAX_BEACON_BLOCKS_PER_REQUEST,
    BEACON_SYNC_MESSAGE_COUNT, BEACON_SYNC_PROTOCOL_NAME, BEACON_SYNC_PROTOCOL_VERSION,
};
pub use beacon_protocol::{BeaconSyncEvent, BeaconSyncHandler, BeaconSyncProtocol};
pub use primitives::{N42NetworkPrimitives, N42NewBlock};
