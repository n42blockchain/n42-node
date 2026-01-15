//! N42 Node Types Example
//!
//! This example demonstrates how to implement the core reth traits for creating
//! a custom node implementation. These traits form the foundation for customizing
//! every aspect of a reth node.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                          N42 Node                                   │
//! ├─────────────────────────────────────────────────────────────────────┤
//! │                                                                     │
//! │  ┌─────────────────┐                      ┌─────────────────┐      │
//! │  │   NodeTypes     │                      │    Storage      │      │
//! │  │   (N42Node)     │                      │                 │      │
//! │  └────────┬────────┘                      │  BeaconStore    │      │
//! │           │                               │  ExecutionStore │      │
//! │  ┌────────┼────────┐                      └─────────────────┘      │
//! │  │        │        │                                               │
//! │  ▼        ▼        ▼                                               │
//! │ Primitives  ChainSpec  EngineTypes                                 │
//! │  │                        │                                        │
//! │  ▼                        ▼                                        │
//! │ ┌──────────────┐    ┌──────────────┐                               │
//! │ │ BeaconBlock  │    │PayloadValid. │                               │
//! │ │ UnifiedBlock │    │              │                               │
//! │ │ N42Block     │    └──────────────┘                               │
//! │ └──────────────┘                                                   │
//! │                                                                     │
//! │  ┌──────────────┐    ┌──────────────┐                              │
//! │  │ ConfigureEvm │    │ Components   │                              │
//! │  │ (N42EvmConf) │    │ (Builders)   │                              │
//! │  └──────────────┘    └──────────────┘                              │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Key Traits
//!
//! - [`NodePrimitives`]: Core blockchain types (Block, Header, Body, Transaction, Receipt)
//! - [`NetworkPrimitives`]: Network-format types for P2P communication
//! - [`NodeTypes`]: Top-level trait combining Primitives, ChainSpec, Storage, and Payload types
//! - [`ConfigureEvm`]: EVM configuration and block execution strategy
//! - [`EngineTypes`]: Engine API payload envelope types (V1-V5)
//! - [`PayloadValidator`]: Validates execution payloads from consensus layer
//!
//! # Modules
//!
//! - [`primitives`]: Block types (Beacon, Execution, Unified)
//! - [`storage`]: Beacon chain storage layer
//! - [`node`]: NodeTypes and component builders
//! - [`evm`]: EVM configuration
//! - [`engine`]: Engine API types and validation
//! - [`network`]: Network primitives for P2P

#![warn(unused_crate_dependencies)]
// Dependencies used by binaries
use eyre as _;
use reth_discv4 as _;
use reth_network_api as _;
use reth_network_peers as _;
use secp256k1 as _;
use tokio_stream as _;

pub mod consensus;
pub mod engine;
pub mod evm;
pub mod network;
pub mod node;
pub mod primitives;
pub mod stages;
pub mod storage;
pub mod validation;

// Re-export node types and builders
pub use node::{
    N42ConsensusBuilder, N42ExecutorBuilder, N42NetworkBuilder, N42Node, N42NodePrimitives,
    N42NodeTypes, N42PayloadBuilder, N42PoolBuilder,
};

// Re-export execution layer primitives (from Ethereum)
pub use primitives::{N42Block, N42BlockBody, N42BlockHeader, N42Receipt, N42Transaction};

// Re-export beacon chain primitives
pub use primitives::{
    BeaconBlock, BeaconBlockBody, BeaconBlockHeader, Eth1Data, SignedBeaconBlock,
};

// Re-export unified block types
pub use primitives::{N42BroadcastBlock, UnifiedBlock, UnifiedBlockBuilder, UnifiedBlockError};

// Re-export engine types (custom implementation without Block type restriction)
pub use engine::{N42BuiltPayload, N42EngineTypes, N42PayloadConversionError};

// Re-export network primitives (unified block in eth66 NewBlock)
pub use network::{N42NetworkPrimitives, N42NewBlock};

// Re-export storage types
pub use storage::{BeaconStore, BeaconStoreError, BeaconStoreReader, BeaconStoreWriter, InMemoryBeaconStore};

// Re-export validation types
pub use validation::{
    BeaconBlockValidator, BeaconValidationError, CrossValidationError, CrossValidator,
    ExecutionValidationError, ExecutionValidator, UnifiedBlockValidator, UnifiedValidationError,
};

// Re-export consensus types (POA)
pub use consensus::{
    get_difficulty_from_graffiti, set_difficulty_in_graffiti, PoaConfig, PoaValidationError,
    PoaValidator, PoaWorker, PoaWorkerBuilder, PoaWorkerCommand, PoaWorkerConfig, PoaWorkerEvent,
    PoaWorkerHandle, ValidatorSet, DIFFICULTY_IN_TURN, DIFFICULTY_OUT_OF_TURN, DEFAULT_BLOCK_TIME,
};

// Re-export beacon state types
pub use consensus::{
    process_block, sign_beacon_block, BeaconBlockHeaderLight, BeaconState, BeaconValidator,
    Checkpoint, DomainType, StateTransitionConfig, StateTransitionError, StateTransitionResult,
};

// Re-export Clique POA consensus types
pub use consensus::clique::{
    Clique, CliqueConfig, CliqueError, ChainHeaderReader, ChainConfig,
    HeaderData, Snapshot, SnapshotDatabase, MemorySnapshotDatabase,
    EXTRA_VANITY, EXTRA_SEAL, DIFF_IN_TURN as CLIQUE_DIFF_IN_TURN,
    DIFF_NO_TURN as CLIQUE_DIFF_NO_TURN, NONCE_AUTH_VOTE, NONCE_DROP_VOTE,
};

// Re-export stages
pub use stages::{
    BeaconBlockClient, BeaconBlockDownloader, BeaconBlocksStage, BeaconDownloaderConfig,
    BeaconExecutionMapping, BeaconExecutionMappingProvider, BeaconSyncTarget,
    BeaconSyncTargetProvider, WatchSyncTargetProvider,
};
