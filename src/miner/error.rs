//! Miner error types.

use alloy_primitives::B256;
use std::time::Duration;
use thiserror::Error;

/// Errors that can occur during mining operations.
#[derive(Debug, Error)]
pub enum MinerError {
    /// Failed to build payload.
    #[error("failed to build payload: {0}")]
    PayloadBuildFailed(String),

    /// Failed to seal block.
    #[error("failed to seal block: {0}")]
    SealFailed(String),

    /// Invalid signing key.
    #[error("invalid signing key: {0}")]
    InvalidSigningKey(String),

    /// Not authorized to mine (not in validator set).
    #[error("not authorized to mine: signer {signer:?} not in validator set")]
    NotAuthorized { signer: alloy_primitives::Address },

    /// Parent block not found.
    #[error("parent block not found: {0:?}")]
    ParentNotFound(B256),

    /// Mining was cancelled.
    #[error("mining cancelled: {0}")]
    Cancelled(String),

    /// Timeout waiting for seal.
    #[error("seal timeout after {0:?}")]
    SealTimeout(Duration),

    /// Channel communication error.
    #[error("channel error: {0}")]
    ChannelError(String),

    /// State provider error.
    #[error("state provider error: {0}")]
    StateError(String),

    /// Transaction pool error.
    #[error("transaction pool error: {0}")]
    PoolError(String),

    /// Consensus error.
    #[error("consensus error: {0}")]
    ConsensusError(String),

    /// Block validation failed.
    #[error("block validation failed: {0}")]
    ValidationFailed(String),

    /// Signature error.
    #[error("signature error: {0}")]
    SignatureError(String),
}

/// Result type for miner operations.
pub type MinerResult<T> = Result<T, MinerError>;
