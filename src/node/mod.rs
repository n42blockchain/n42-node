//! N42 node type definitions.
//!
//! This module implements the core node traits:
//! - [`NodePrimitives`]: Core blockchain types
//! - [`NodeTypes`]: Top-level type combining all components
//! - Component builders for pool, executor, network, consensus, payload

mod components;
mod payload;
mod primitives;
mod types;

pub use components::{
    N42ConsensusBuilder, N42ExecutorBuilder, N42NetworkBuilder, N42PoolBuilder,
};
pub use payload::N42PayloadBuilder;
pub use primitives::N42NodePrimitives;
pub use types::{N42Node, N42NodeTypes};
