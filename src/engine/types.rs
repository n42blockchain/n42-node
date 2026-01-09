//! Engine API types for N42 unified blocks.
//!
//! This module implements custom engine types that work with `N42BroadcastBlock`,
//! breaking the `EthEngineTypes` limitation of requiring `reth_ethereum_primitives::Block`.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    N42 Engine Types                         │
//! ├─────────────────────────────────────────────────────────────┤
//! │                                                             │
//! │  N42BuiltPayload                                            │
//! │    ├── block: SealedBlock<N42BroadcastBlock>                │
//! │    │           ├── beacon: SignedBeaconBlock                │
//! │    │           └── execution: Block                         │
//! │    ├── fees: U256                                           │
//! │    └── sidecars: BlobSidecars                               │
//! │                                                             │
//! │  Conversion to ExecutionPayload:                            │
//! │    N42BuiltPayload.block.execution -> ExecutionPayloadV*    │
//! │                                                             │
//! └─────────────────────────────────────────────────────────────┘
//! ```

use crate::primitives::N42NodePrimitives;
use alloy_eips::eip7685::Requests;
use alloy_primitives::U256;
use alloy_rpc_types_engine::{
    ExecutionData, ExecutionPayload, ExecutionPayloadEnvelopeV2, ExecutionPayloadEnvelopeV3,
    ExecutionPayloadEnvelopeV4, ExecutionPayloadEnvelopeV5, ExecutionPayloadFieldV2,
    ExecutionPayloadV1, ExecutionPayloadV3, PayloadAttributes,
};
use reth_engine_primitives::EngineTypes;
use reth_ethereum_engine_primitives::{BlobSidecars, EthPayloadBuilderAttributes};
use reth_payload_primitives::{BuiltPayload, PayloadTypes};
use reth_primitives_traits::{Block as BlockTrait, NodePrimitives, SealedBlock};
use std::sync::Arc;

/// N42 built payload containing a unified block (beacon + execution).
///
/// This type wraps a `SealedBlock<N42BroadcastBlock>` and provides conversions
/// to the standard Engine API envelope types by extracting the execution portion.
#[derive(Debug, Clone)]
pub struct N42BuiltPayload {
    /// The sealed unified block.
    pub block: Arc<SealedBlock<<N42NodePrimitives as NodePrimitives>::Block>>,
    /// Total fees collected.
    pub fees: U256,
    /// Blob sidecars for EIP-4844/7594 transactions.
    pub sidecars: BlobSidecars,
    /// EIP-7685 execution layer requests.
    pub requests: Option<Requests>,
}

impl N42BuiltPayload {
    /// Create a new built payload.
    pub fn new(
        block: Arc<SealedBlock<<N42NodePrimitives as NodePrimitives>::Block>>,
        fees: U256,
        requests: Option<Requests>,
    ) -> Self {
        Self { block, fees, sidecars: BlobSidecars::default(), requests }
    }

    /// Set blob sidecars.
    pub fn with_sidecars(mut self, sidecars: BlobSidecars) -> Self {
        self.sidecars = sidecars;
        self
    }

    /// Get the execution block for conversion to Engine API payloads.
    fn execution_block(&self) -> reth_ethereum_primitives::Block {
        // Extract execution block from the unified block
        // SealedBlock provides header() and body() which come from the unified block
        reth_ethereum_primitives::Block::new(
            self.block.header().clone(),
            self.block.body().clone(),
        )
    }
}

impl BuiltPayload for N42BuiltPayload {
    type Primitives = N42NodePrimitives;

    fn block(&self) -> &SealedBlock<<Self::Primitives as NodePrimitives>::Block> {
        &self.block
    }

    fn fees(&self) -> U256 {
        self.fees
    }

    fn requests(&self) -> Option<Requests> {
        self.requests.clone()
    }
}

// ============================================================================
// ExecutionPayload Envelope Conversions
// ============================================================================

/// Error during payload conversion.
#[derive(Debug, Clone, thiserror::Error)]
pub enum N42PayloadConversionError {
    /// Unexpected EIP-4844 sidecars in V5 payload.
    #[error("unexpected EIP-4844 sidecars in V5 envelope")]
    UnexpectedEip4844Sidecars,
    /// Unexpected EIP-7594 sidecars in V3/V4 payload.
    #[error("unexpected EIP-7594 sidecars in V3/V4 envelope")]
    UnexpectedEip7594Sidecars,
}

// V1: engine_getPayloadV1
impl TryFrom<N42BuiltPayload> for ExecutionPayloadV1 {
    type Error = N42PayloadConversionError;

    fn try_from(value: N42BuiltPayload) -> Result<Self, Self::Error> {
        Ok(Self::from_block_unchecked(value.block.hash(), &value.execution_block()))
    }
}

// V2: engine_getPayloadV2
impl TryFrom<N42BuiltPayload> for ExecutionPayloadEnvelopeV2 {
    type Error = N42PayloadConversionError;

    fn try_from(value: N42BuiltPayload) -> Result<Self, Self::Error> {
        Ok(Self {
            block_value: value.fees,
            execution_payload: ExecutionPayloadFieldV2::from_block_unchecked(
                value.block.hash(),
                &value.execution_block(),
            ),
        })
    }
}

// V3: engine_getPayloadV3
impl TryFrom<N42BuiltPayload> for ExecutionPayloadEnvelopeV3 {
    type Error = N42PayloadConversionError;

    fn try_from(value: N42BuiltPayload) -> Result<Self, Self::Error> {
        use alloy_rpc_types_engine::BlobsBundleV1;

        let blobs_bundle = match &value.sidecars {
            BlobSidecars::Empty => BlobsBundleV1::empty(),
            BlobSidecars::Eip4844(sidecars) => BlobsBundleV1::from(sidecars.clone()),
            BlobSidecars::Eip7594(_) => return Err(N42PayloadConversionError::UnexpectedEip7594Sidecars),
        };

        Ok(Self {
            execution_payload: ExecutionPayloadV3::from_block_unchecked(
                value.block.hash(),
                &value.execution_block(),
            ),
            block_value: value.fees,
            should_override_builder: false,
            blobs_bundle,
        })
    }
}

// V4: engine_getPayloadV4
impl TryFrom<N42BuiltPayload> for ExecutionPayloadEnvelopeV4 {
    type Error = N42PayloadConversionError;

    fn try_from(value: N42BuiltPayload) -> Result<Self, Self::Error> {
        let requests = value.requests.clone().unwrap_or_default();
        let v3: ExecutionPayloadEnvelopeV3 = value.try_into()?;
        Ok(Self {
            execution_requests: requests,
            envelope_inner: v3,
        })
    }
}

// V5: engine_getPayloadV5
impl TryFrom<N42BuiltPayload> for ExecutionPayloadEnvelopeV5 {
    type Error = N42PayloadConversionError;

    fn try_from(value: N42BuiltPayload) -> Result<Self, Self::Error> {
        use alloy_rpc_types_engine::BlobsBundleV2;

        let blobs_bundle = match &value.sidecars {
            BlobSidecars::Empty => BlobsBundleV2::empty(),
            BlobSidecars::Eip7594(sidecars) => BlobsBundleV2::from(sidecars.clone()),
            BlobSidecars::Eip4844(_) => return Err(N42PayloadConversionError::UnexpectedEip4844Sidecars),
        };

        Ok(Self {
            execution_payload: ExecutionPayloadV3::from_block_unchecked(
                value.block.hash(),
                &value.execution_block(),
            ),
            block_value: value.fees,
            should_override_builder: false,
            blobs_bundle,
            execution_requests: value.requests.unwrap_or_default(),
        })
    }
}

// ============================================================================
// N42 Engine Types
// ============================================================================

/// N42 engine types for Engine API communication with unified blocks.
///
/// This type removes the `Block = reth_ethereum_primitives::Block` constraint
/// from `EthEngineTypes`, allowing use of `N42BroadcastBlock`.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub struct N42EngineTypes;

impl PayloadTypes for N42EngineTypes {
    type BuiltPayload = N42BuiltPayload;
    type PayloadAttributes = PayloadAttributes;
    type PayloadBuilderAttributes = EthPayloadBuilderAttributes;
    type ExecutionData = ExecutionData;

    fn block_to_payload(
        block: SealedBlock<<<Self::BuiltPayload as BuiltPayload>::Primitives as NodePrimitives>::Block>,
    ) -> Self::ExecutionData {
        // Extract execution block from unified block
        let hash = block.hash();
        let unified = block.into_block();
        let execution = reth_ethereum_primitives::Block::new(
            unified.header().clone(),
            unified.body().clone(),
        );
        let (payload, sidecar) = ExecutionPayload::from_block_unchecked(hash, &execution);
        ExecutionData { payload, sidecar }
    }
}

impl EngineTypes for N42EngineTypes {
    type ExecutionPayloadEnvelopeV1 = ExecutionPayloadV1;
    type ExecutionPayloadEnvelopeV2 = ExecutionPayloadEnvelopeV2;
    type ExecutionPayloadEnvelopeV3 = ExecutionPayloadEnvelopeV3;
    type ExecutionPayloadEnvelopeV4 = ExecutionPayloadEnvelopeV4;
    type ExecutionPayloadEnvelopeV5 = ExecutionPayloadEnvelopeV5;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_implements_engine_types() {
        fn assert_engine_types<T: EngineTypes>() {}
        assert_engine_types::<N42EngineTypes>();
    }

    #[test]
    fn test_implements_payload_types() {
        fn assert_payload_types<T: PayloadTypes>() {}
        assert_payload_types::<N42EngineTypes>();
    }

    #[test]
    fn test_built_payload() {
        fn assert_built_payload<T: BuiltPayload>() {}
        assert_built_payload::<N42BuiltPayload>();
    }
}
