//! Payload validation for Engine API.
//!
//! [`PayloadValidator`] validates execution payloads received from the
//! consensus layer via the Engine API's `newPayload` method.
//!
//! # Validation Stages
//!
//! 1. **Structural Validation** (`ensure_well_formed_payload`)
//!    - Verify payload fields match hardfork requirements
//!    - Check transaction validity (signatures, gas limits)
//!    - Validate withdrawals format
//!    - Verify blob versioned hashes
//!
//! 2. **Post-Execution Validation** (`validate_block_post_execution_with_hashed_state`)
//!    - Verify state updates (L2-specific, e.g., account abstraction)
//!    - N42 validation after EVM execution
//!
//! 3. **Attribute Validation** (`validate_payload_attributes_against_header`)
//!    - Verify timestamp is increasing
//!    - Check suggested fee recipient (if applicable)

use alloy_rpc_types_engine::ExecutionData;
use reth_chainspec::{ChainSpec, EthChainSpec, EthereumHardforks};
use reth_consensus::ConsensusError;
use reth_engine_primitives::PayloadValidator;
use reth_ethereum_payload_builder::EthereumExecutionPayloadValidator;
use reth_ethereum_primitives::Block;
use reth_payload_primitives::{InvalidPayloadAttributesError, NewPayloadError, PayloadAttributes, PayloadTypes};
use reth_primitives_traits::RecoveredBlock;
use reth_trie_common::HashedPostState;
use std::sync::Arc;

/// N42 payload validator extending standard Ethereum validation.
///
/// This validator wraps the standard Ethereum validator and adds
/// custom validation rules on top.
///
/// # Use Cases
///
/// - **L2 Rollups**: Validate L1 origin data, batch proofs
/// - **Private Networks**: Check validator permissions
/// - **N42 Consensus**: Additional block validity rules
#[derive(Debug, Clone)]
pub struct N42PayloadValidator<C = ChainSpec> {
    /// Inner Ethereum payload validator.
    inner: EthereumExecutionPayloadValidator<C>,
    /// N42 validation flag (example).
    #[allow(dead_code)]
    strict_mode: bool,
}

impl<C> N42PayloadValidator<C> {
    /// Create a new validator with the given chain spec.
    pub fn new(chain_spec: Arc<C>) -> Self {
        Self {
            inner: EthereumExecutionPayloadValidator::new(chain_spec),
            strict_mode: false,
        }
    }

    /// Create with strict validation mode enabled.
    pub fn strict(chain_spec: Arc<C>) -> Self {
        Self {
            inner: EthereumExecutionPayloadValidator::new(chain_spec),
            strict_mode: true,
        }
    }

    /// Get the chain spec.
    pub fn chain_spec(&self) -> &C {
        self.inner.chain_spec()
    }
}

impl<C, Types> PayloadValidator<Types> for N42PayloadValidator<C>
where
    C: EthChainSpec + EthereumHardforks + 'static,
    Types: PayloadTypes<ExecutionData = ExecutionData>,
{
    type Block = Block;

    /// Validate payload structure and recover transactions.
    fn ensure_well_formed_payload(
        &self,
        payload: ExecutionData,
    ) -> Result<RecoveredBlock<Self::Block>, NewPayloadError> {
        // Use the inner validator for standard validation
        let sealed_block = self.inner.ensure_well_formed_payload(payload)?;

        // N42 validation could be added here before recovery
        // Example: Check extra_data for proposer signature

        // Recover transaction signers
        sealed_block.try_recover().map_err(|e| NewPayloadError::Other(e.into()))
    }

    /// Validate block after EVM execution.
    fn validate_block_post_execution_with_hashed_state(
        &self,
        _state_updates: &HashedPostState,
        _block: &RecoveredBlock<Self::Block>,
    ) -> Result<(), ConsensusError> {
        // N42 post-execution validation could go here
        // Example: Verify L2 fee distribution
        Ok(())
    }

    /// Validate payload attributes against parent header.
    fn validate_payload_attributes_against_header(
        &self,
        attr: &Types::PayloadAttributes,
        header: &<Self::Block as reth_primitives_traits::Block>::Header,
    ) -> Result<(), InvalidPayloadAttributesError> {
        use alloy_consensus::BlockHeader;

        // Timestamp must be strictly increasing
        if attr.timestamp() <= header.timestamp() {
            return Err(InvalidPayloadAttributesError::InvalidTimestamp);
        }

        // N42 attribute validation could go here
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reth_chainspec::MAINNET;
    use reth_ethereum_engine_primitives::EthEngineTypes;

    #[test]
    fn test_create_validator() {
        let validator = N42PayloadValidator::new(MAINNET.clone());
        assert!(!validator.strict_mode);
    }

    #[test]
    fn test_strict_validator() {
        let validator = N42PayloadValidator::strict(MAINNET.clone());
        assert!(validator.strict_mode);
    }

    #[test]
    fn test_implements_payload_validator() {
        fn assert_payload_validator<V: PayloadValidator<EthEngineTypes>>() {}
        assert_payload_validator::<N42PayloadValidator<ChainSpec>>();
    }
}
