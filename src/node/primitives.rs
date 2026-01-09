//! NodePrimitives implementation for N42 with unified blocks.
//!
//! [`NodePrimitives`] is the foundational trait that defines all core blockchain
//! types for a node. It ties together Block, Header, Body, Transaction, and Receipt.
//!
//! # N42 Unified Block Architecture
//!
//! N42 uses `N42BroadcastBlock` as the core block type:
//! - **Block** = `N42BroadcastBlock` (beacon + execution unified)
//! - **eth66 NewBlock** carries the unified block
//! - **Sync** downloads both layers in one request
//!
//! This breaks the `EthEngineTypes` limitation by using custom `N42EngineTypes`.

// Re-export from primitives module
pub use crate::primitives::N42NodePrimitives;

#[cfg(test)]
mod tests {
    use super::*;
    use reth_primitives_traits::NodePrimitives;

    #[test]
    fn test_primitives_types() {
        fn assert_primitives<P: NodePrimitives>() {}
        assert_primitives::<N42NodePrimitives>();
    }
}
