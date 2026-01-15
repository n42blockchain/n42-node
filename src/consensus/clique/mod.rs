//! Clique Proof-of-Authority consensus engine.
//!
//! Ported from go-ethereum's clique implementation.
//! Database operations are abstracted via traits to allow memory-based testing.

mod clique;
mod snapshot;
mod error;
mod database;

pub use clique::{Clique, ChainHeaderReader, ChainConfig};
pub use snapshot::{CliqueConfig, HeaderData, Snapshot, Vote, Tally};
pub use error::CliqueError;
pub use database::{SnapshotDatabase, MemorySnapshotDatabase};

/// Fixed number of extra-data prefix bytes reserved for signer vanity.
pub const EXTRA_VANITY: usize = 32;

/// Fixed number of extra-data suffix bytes reserved for signer seal (65 bytes signature).
pub const EXTRA_SEAL: usize = 65;

/// Default number of blocks after which to checkpoint and reset the pending votes.
pub const EPOCH_LENGTH: u64 = 30000;

/// Number of blocks after which to save the vote snapshot to the database.
pub const CHECKPOINT_INTERVAL: u64 = 1024;

/// Number of recent vote snapshots to keep in memory.
pub const INMEMORY_SNAPSHOTS: usize = 128;

/// Number of recent block signatures to keep in memory.
pub const INMEMORY_SIGNATURES: usize = 4096;

/// Block difficulty for in-turn signatures.
pub const DIFF_IN_TURN: u64 = 2;

/// Block difficulty for out-of-turn signatures.
pub const DIFF_NO_TURN: u64 = 1;

/// Magic nonce number to vote on adding a new signer.
pub const NONCE_AUTH_VOTE: [u8; 8] = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];

/// Magic nonce number to vote on removing a signer.
pub const NONCE_DROP_VOTE: [u8; 8] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
