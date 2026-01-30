//! Merkle DB - VecTree implementation for efficient validator storage.
//!
//! This module provides a Merkle tree-based vector storage (VecTree) that supports:
//! - O(log n) updates with only affected path nodes being updated
//! - Differential save/restore for efficient persistence
//! - SSZ-compatible tree hashing

use ssz::{Decode, Encode};
use tree_hash::TreeHash;

pub mod tree;
pub mod error;
pub mod utils;

pub use tree::{Tree, VecTree};
pub use error::Error;
pub use utils::{tree_height, zero_tree_root};

/// Trait for types that can be stored in a VecTree.
pub trait Value: Encode + Decode + TreeHash + PartialEq + Clone + Default {}

impl<T> Value for T where T: Encode + Decode + TreeHash + PartialEq + Clone + Default {}
