//! Custom stages for N42 blockchain sync.
//!
//! This module provides custom pipeline stages for syncing the N42 blockchain,
//! which includes both execution layer and beacon layer data.
//!
//! # Stages
//!
//! - [`BeaconBlocksStage`]: Downloads beacon blocks from P2P network (FIRST stage)
//!
//! # Pipeline Integration
//!
//! The beacon blocks stage runs FIRST, defining the canonical chain:
//!
//! ```text
//! ┌──────────────────┐
//! │ BeaconBlocksStage│  Download beacon blocks (defines canonical chain)
//! └──────┬───────────┘
//!        │
//!        │ (provides execution_payload_root for each slot)
//!        ▼
//! ┌──────────────┐
//! │ HeadersStage │  Download execution headers
//! └──────┬───────┘
//!        │
//!        ▼
//! ┌──────────────┐
//! │  BodyStage   │  Download execution bodies
//! └──────┬───────┘
//!        │
//!        ▼
//! ┌──────────────┐
//! │ExecutionStage│  Execute transactions
//! └──────────────┘
//! ```
//!
//! # Design Rationale
//!
//! In a PoS system, the beacon chain defines the canonical chain:
//! - Beacon blocks contain `execution_payload_root` which references execution blocks
//! - By downloading beacon blocks first, we know which execution blocks to download
//! - This prevents downloading execution blocks that aren't part of the canonical chain
//!
//! # Example
//!
//! ```ignore
//! use n42_node::stages::{
//!     BeaconBlocksStage, BeaconSyncTarget, WatchSyncTargetProvider,
//!     downloader::{BeaconBlockDownloader, BeaconDownloaderConfig},
//! };
//!
//! // Create sync target provider
//! let (sync_target_tx, sync_target_provider) = WatchSyncTargetProvider::channel();
//!
//! // Create the downloader
//! let downloader = BeaconBlockDownloader::new(client, BeaconDownloaderConfig::default());
//!
//! // Create the stage
//! let stage = BeaconBlocksStage::new(downloader, beacon_store, sync_target_provider);
//!
//! // Add as FIRST stage in pipeline
//! pipeline.push_stage(stage);
//!
//! // Update sync target from consensus layer or peer discovery
//! sync_target_tx.send(Some(BeaconSyncTarget::finalized(1000, block_root))).unwrap();
//! ```

pub mod beacon_blocks;
pub mod downloader;

pub use beacon_blocks::{
    BeaconBlockRootMismatch, BeaconBlocksStage, BeaconExecutionMapping,
    BeaconExecutionMappingProvider, BeaconSyncTarget, BeaconSyncTargetProvider,
    BeaconValidationStageError, ValidatingBeaconBlocksStage, WatchSyncTargetProvider,
    BEACON_BLOCKS_STAGE_ID, VALIDATING_BEACON_BLOCKS_STAGE_ID,
};
pub use downloader::{
    BeaconBlockClient, BeaconBlockClientError, BeaconBlockDownloader, BeaconBlockDownloaderLike,
    BeaconDownloadError, BeaconDownloadResult, BeaconDownloaderConfig,
};
