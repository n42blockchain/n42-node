//! NodeTypes implementation - the top-level type tying everything together.
//!
//! [`NodeTypes`] is the umbrella trait that defines all type parameters for a node.
//! It combines primitives, chain specification, storage, and payload types.

use super::N42NodePrimitives;
use crate::engine::N42EngineTypes;
use reth_chainspec::ChainSpec;
use reth_node_types::NodeTypes;
use reth_provider::EthStorage;

/// N42 node type combining all components.
///
/// This is the main type that gets passed to the node builder.
/// It defines the complete type configuration for a custom node.
///
/// # Components
///
/// - **Primitives**: Core blockchain types (blocks, transactions, receipts)
/// - **ChainSpec**: Chain configuration and hardfork rules
/// - **Storage**: Database storage configuration
/// - **Payload**: Engine API payload types
#[derive(Debug, Clone, Default)]
pub struct N42Node;

/// Type alias for clearer documentation.
pub type N42NodeTypes = N42Node;

impl NodeTypes for N42Node {
    /// Core blockchain primitive types.
    type Primitives = N42NodePrimitives;

    /// Chain specification with hardfork configuration.
    type ChainSpec = ChainSpec;

    /// Storage layer configuration.
    type Storage = EthStorage;

    /// Engine API payload types.
    type Payload = N42EngineTypes;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_types() {
        fn assert_node_types<N: NodeTypes>() {}
        assert_node_types::<N42Node>();
    }
}
