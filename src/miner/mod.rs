//! Clique POA Miner Module
//!
//! This module implements the block production logic for Clique POA consensus,
//! including transaction packing (via reth's PayloadBuilder), seal delay calculation,
//! and block signing.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────┐
//! │  Beacon Layer (POA consensus)               │
//! │  - Miner: block scheduling, signing         │
//! │  - BeaconBlock stores POA fields            │
//! └──────────────────┬──────────────────────────┘
//!                    │ calls
//!                    ↓
//! ┌─────────────────────────────────────────────┐
//! │  Execution Layer (Reth)                     │
//! │  - PayloadBuilder (transaction packing)     │
//! │  - TransactionPool                          │
//! │  - EVM                                      │
//! └─────────────────────────────────────────────┘
//! ```
//!
//! # Modules
//!
//! - [`config`]: Miner configuration (gas limits, recommit interval, etc.)
//! - [`error`]: Error types for mining operations
//! - [`attributes`]: PayloadAttributesProvider trait for execution payload attributes
//! - [`sealer`]: Block sealing (delay calculation, signing)
//! - [`worker`]: Main mining loop with recommit support
//!
//! # Usage
//!
//! ```ignore
//! use n42_node::miner::{MinerConfig, Worker, MinerHandle};
//!
//! // Create miner config
//! let config = MinerConfig::new(coinbase, signing_key)
//!     .with_recommit_interval(Duration::from_secs(2));
//!
//! // Create and start worker
//! let (handle, event_rx) = Worker::spawn(config, pool, provider, clique);
//!
//! // Send commands
//! handle.start_mining(parent_block, timestamp).await?;
//!
//! // Receive events
//! while let Some(event) = event_rx.recv().await {
//!     match event {
//!         MinerEvent::BlockSealed(result) => { /* broadcast block */ }
//!         _ => {}
//!     }
//! }
//! ```

mod attributes;
mod config;
mod error;

pub use attributes::{
    AttributesWithParentRoot, PayloadAttributesProvider, PoaAttributesProvider,
};
pub use config::{MinerConfig, DEFAULT_GAS_CEIL, DEFAULT_GAS_PRICE, DEFAULT_RECOMMIT_INTERVAL};
pub use error::{MinerError, MinerResult};

mod sealer;
pub use sealer::{
    calculate_seal_delay, recover_signer, seal_block, verify_block_signature,
    MiningEnvironment, WIGGLE_TIME_MS,
};

mod worker;
pub use worker::{MinerCommand, MinerEvent, MinerHandle, SealResult, Worker};
