//! Clique consensus errors.

use alloy_primitives::{Address, B256};
use thiserror::Error;

/// Clique consensus errors.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CliqueError {
    /// Unknown block error.
    #[error("unknown block")]
    UnknownBlock,

    /// Block is from the future.
    #[error("block from future: block time {block_time}, current time {current_time}")]
    FutureBlock {
        block_time: u64,
        current_time: u64,
    },

    /// Unknown ancestor error.
    #[error("unknown ancestor")]
    UnknownAncestor,

    /// Checkpoint block has non-zero beneficiary.
    #[error("beneficiary in checkpoint block non-zero")]
    InvalidCheckpointBeneficiary,

    /// Invalid vote nonce (not 0x00..0 or 0xff..f).
    #[error("vote nonce not 0x00..0 or 0xff..f")]
    InvalidVote,

    /// Checkpoint block has non-zero vote nonce.
    #[error("vote nonce in checkpoint block non-zero")]
    InvalidCheckpointVote,

    /// Missing vanity in extra-data.
    #[error("extra-data 32 byte vanity prefix missing")]
    MissingVanity,

    /// Missing signature in extra-data.
    #[error("extra-data 65 byte signature suffix missing")]
    MissingSignature,

    /// Non-checkpoint block contains signer list.
    #[error("non-checkpoint block contains extra signer list")]
    ExtraSigners,

    /// Invalid signer list on checkpoint block.
    #[error("invalid signer list on checkpoint block")]
    InvalidCheckpointSigners,

    /// Mismatching signer list on checkpoint block.
    #[error("mismatching signer list on checkpoint block")]
    MismatchingCheckpointSigners,

    /// Non-zero mix digest.
    #[error("non-zero mix digest")]
    InvalidMixDigest,

    /// Non-empty uncle hash.
    #[error("non empty uncle hash")]
    InvalidUncleHash,

    /// Invalid difficulty (not 1 or 2).
    #[error("invalid difficulty: expected 1 or 2, got {difficulty}")]
    InvalidDifficulty { difficulty: u64 },

    /// Wrong difficulty for signer's turn.
    #[error("wrong difficulty: signer {signer} at block {block}, expected {expected}, got {actual}")]
    WrongDifficulty {
        signer: Address,
        block: u64,
        expected: u64,
        actual: u64,
    },

    /// Invalid timestamp (too close to parent).
    #[error("invalid timestamp: parent {parent_time} + period {period} > block {block_time}")]
    InvalidTimestamp {
        parent_time: u64,
        period: u64,
        block_time: u64,
    },

    /// Invalid voting chain.
    #[error("invalid voting chain")]
    InvalidVotingChain,

    /// Unauthorized signer.
    #[error("unauthorized signer: {signer}")]
    UnauthorizedSigner { signer: Address },

    /// Signer recently signed.
    #[error("signer {signer} recently signed at block {recent_block}")]
    RecentlySigned {
        signer: Address,
        recent_block: u64,
    },

    /// Gas limit exceeded.
    #[error("invalid gasLimit: have {gas_limit}, max {max_gas_limit}")]
    GasLimitExceeded {
        gas_limit: u64,
        max_gas_limit: u64,
    },

    /// Gas used exceeds gas limit.
    #[error("invalid gasUsed: have {gas_used}, gasLimit {gas_limit}")]
    GasUsedExceeded { gas_used: u64, gas_limit: u64 },

    /// Signature recovery failed.
    #[error("signature recovery failed: {message}")]
    SignatureRecoveryFailed { message: String },

    /// Database error.
    #[error("database error: {message}")]
    DatabaseError { message: String },

    /// Snapshot not found.
    #[error("snapshot not found for hash {hash}")]
    SnapshotNotFound { hash: B256 },

    /// Sealing not supported (deprecated in go-ethereum).
    #[error("clique (poa) sealing not supported")]
    SealingNotSupported,
}
