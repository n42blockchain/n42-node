//! NetworkPrimitives implementation for P2P communication.
//!
//! [`NetworkPrimitives`] defines the types used for devp2p network messages.
//! These types must be RLP encodable/decodable for wire protocol compatibility.
//!
//! # N42 Network Architecture
//!
//! N42 uses unified blocks in eth66/67/68 NewBlock messages:
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    N42 Network Layer                            │
//! ├─────────────────────────────────────────────────────────────────┤
//! │                                                                 │
//! │  eth66/67/68 Protocol with unified blocks:                      │
//! │  ┌───────────────────────────────────────────────────────────┐  │
//! │  │  NewBlock<N42BroadcastBlock>                              │  │
//! │  │  ├── beacon: SignedBeaconBlock                            │  │
//! │  │  └── execution: Block                                     │  │
//! │  │                                                           │  │
//! │  │  Benefits:                                                │  │
//! │  │  - Single message carries both CL + EL data               │  │
//! │  │  - Atomic sync of complete block state                    │  │
//! │  └───────────────────────────────────────────────────────────┘  │
//! │                                                                 │
//! └─────────────────────────────────────────────────────────────────┘
//! ```

use crate::primitives::{N42BroadcastBlock, N42NodePrimitives};
use reth_ethereum_primitives::PooledTransactionVariant;
use reth_network::primitives::BasicNetworkPrimitives;

/// NewBlock message type for N42 unified blocks.
///
/// Uses `NewBlock<N42BroadcastBlock>` to carry both beacon and execution
/// data in a single eth66 message.
pub type N42NewBlock = reth_ethereum::network::eth_wire::NewBlock<N42BroadcastBlock>;

/// N42 network primitives for P2P communication.
///
/// Uses `N42BroadcastBlock` as the block type, enabling unified block
/// broadcast and sync via the standard eth protocol.
///
/// # Type Mapping
///
/// | Network Type | N42 Type |
/// |--------------|----------|
/// | `Block` | `N42BroadcastBlock` (beacon + execution) |
/// | `BlockHeader` | `alloy_consensus::Header` |
/// | `BlockBody` | `BlockBody` |
/// | `NewBlockPayload` | `NewBlock<N42BroadcastBlock>` |
pub type N42NetworkPrimitives =
    BasicNetworkPrimitives<N42NodePrimitives, PooledTransactionVariant, N42NewBlock>;

#[cfg(test)]
mod tests {
    use super::*;
    use reth_network::NetworkPrimitives;

    #[test]
    fn test_network_primitives_alias() {
        fn assert_network_primitives<N: NetworkPrimitives>() {}
        assert_network_primitives::<N42NetworkPrimitives>();
    }

    #[test]
    fn test_new_block_payload() {
        use reth_ethereum::network::eth_wire::NewBlockPayload;
        fn assert_new_block_payload<T: NewBlockPayload>() {}
        assert_new_block_payload::<N42NewBlock>();
    }
}
