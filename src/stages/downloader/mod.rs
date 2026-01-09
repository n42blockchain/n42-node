//! Beacon block downloader components.
//!
//! This module provides the client trait and downloader implementation
//! for fetching beacon blocks from the P2P network.
//!
//! # Components
//!
//! - [`BeaconBlockClient`]: Trait for fetching beacon blocks from peers
//! - [`BeaconBlockDownloader`]: Stream-based downloader implementation
//!
//! # Usage
//!
//! ```ignore
//! use n42_node::stages::downloader::{
//!     BeaconBlockDownloader, BeaconDownloaderConfig,
//! };
//!
//! let downloader = BeaconBlockDownloader::new(client, BeaconDownloaderConfig::default());
//! downloader.set_download_range(100..=200)?;
//!
//! while let Some(result) = downloader.next().await {
//!     let blocks = result?;
//!     // Process blocks...
//! }
//! ```

pub mod client;
pub mod downloader;

pub use client::{
    BeaconBlockClient, BeaconBlockClientError, BeaconBlockResult, BeaconBlocksFut,
    PeerBeaconBlockResponse, PeerBeaconBlockResult, SingleBeaconBlockRequest,
};
pub use downloader::{
    BeaconBlockDownloader, BeaconBlockDownloaderLike, BeaconDownloadError, BeaconDownloadResult,
    BeaconDownloaderConfig,
};
