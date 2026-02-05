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
// Dependencies used by binaries or mobile SDK
use anyhow as _;
use eyre as _;
use futures_util as _;
use reth_discv4 as _;
use reth_network_api as _;
use reth_network_peers as _;
use reth_revm as _;
use revm_primitives as _;
use secp256k1 as _;
use tokio_stream as _;

pub mod consensus;
pub mod engine;
pub mod evm;
pub mod merkle_db;
pub mod miner;
pub mod mobile_sdk;
pub mod network;
pub mod node;
pub mod pos;
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
    // Trait-based generic validation functions
    validate_proposer, verify_signature_generic, process_slots_generic, ValidationContext,
};

// Re-export consensus traits (BLS signatures)
pub use consensus::{
    BlsVerifier, ProposerSelector, SignatureVerifier, StateProvider,
    ValidatorInfo, ValidatorProvider, ValidatorPubkey, ValidatorSignature,
};

// Re-export unified consensus interface
pub use consensus::{
    ConsensusState, ConsensusVerifier, DefaultVerifier,
    create_pubkey, create_signature, default_verifier,
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

// Re-export miner types
pub use miner::{
    AttributesWithParentRoot, MinerCommand, MinerConfig, MinerError, MinerEvent,
    MinerHandle, MinerResult, MiningEnvironment, PayloadAttributesProvider,
    PoaAttributesProvider, SealResult, Worker,
    calculate_seal_delay, recover_signer, seal_block, verify_block_signature,
    DEFAULT_GAS_CEIL, DEFAULT_GAS_PRICE, DEFAULT_RECOMMIT_INTERVAL, WIGGLE_TIME_MS,
};

// Re-export merkle_db types
pub use merkle_db::{Value, VecTree, Error as VecTreeError};

// Re-export mobile SDK types
pub use mobile_sdk::{
    run_client as mobile_run_client,
    gen_block_verify_result,
    verify as mobile_verify,
    blst_utils::{generate_bls12_381_keypair, derive_pubkey_from_privkey},
    deposit_exit::{
        create_deposit_unsigned_tx, create_exit_unsigned_tx, create_get_exit_fee_unsigned_tx,
        UnsignedTransactionRequest, DEVNET_DEPOSIT_CONTRACT_ADDRESS, TESTNET_DEPOSIT_CONTRACT_ADDRESS,
        EIP7002_CONTRACT_ADDRESS,
    },
};

// Re-export mobile SDK JNI and FFI bindings
pub mod mobile_sdk_ffi {
    pub use crate::mobile_sdk::jni::*;
    pub use crate::mobile_sdk::c_ffi::*;
}

// Re-export POS types
pub use pos::{
    // Core types
    BeaconState as PosBeaconState,
    PosBeaconBlock,
    PosBeaconBlockBody,
    Attestation,
    AttestationData,
    Deposit,
    DepositData,
    DepositMessage,
    VoluntaryExit,
    VoluntaryExitWithSig,
    Eth1Data as PosEth1Data,
    ChainSpec,
    beacon_chain_spec,
    // Validator types
    Validator as PosValidator,
    ValidatorInfo as PosValidatorInfo,
    ValidatorBeforeTx,
    ValidatorChangeset,
    ValidatorRevert,
    // Committee types
    CommitteeCache,
    BeaconCommittee,
    OwnedBeaconCommittee,
    AttestationDuty,
    ActivationQueue,
    // Type aliases
    Epoch,
    Gwei,
    Slot as PosSlot,
    CommitteeIndex,
    BLSPubkey,
    BLSSignature,
    Hash256 as PosHash256,
    // Constants
    SLOTS_PER_EPOCH,
    DOMAIN_CONSTANT_BEACON_ATTESTER,
    SignedRoot,
    RelativeEpoch,
    // Mobile verification types
    BlockVerifyResult,
    UnverifiedBlock,
};
