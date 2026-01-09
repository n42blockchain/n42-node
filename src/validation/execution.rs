//! Execution layer block validation.
//!
//! This module provides validation for execution layer blocks.
//! In production, this would delegate to reth's full consensus validation.

use alloy_consensus::BlockHeader;
use alloy_primitives::B256;
use reth_primitives_traits::{Block as BlockTrait, SealedBlock};

/// Errors that can occur during execution block validation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ExecutionValidationError {
    /// Block hash mismatch.
    #[error("block hash mismatch: computed {computed}, sealed {sealed}")]
    HashMismatch {
        /// Computed hash from header.
        computed: B256,
        /// Sealed hash in block.
        sealed: B256,
    },

    /// Invalid block number (not sequential).
    #[error("invalid block number: expected {expected}, got {actual}")]
    InvalidBlockNumber {
        /// Expected block number.
        expected: u64,
        /// Actual block number.
        actual: u64,
    },

    /// Invalid parent hash.
    #[error("parent hash mismatch: expected {expected}, got {actual}")]
    ParentHashMismatch {
        /// Expected parent hash.
        expected: B256,
        /// Actual parent hash in header.
        actual: B256,
    },

    /// Block timestamp not increasing.
    #[error("timestamp not increasing: parent {parent}, block {block}")]
    TimestampNotIncreasing {
        /// Parent timestamp.
        parent: u64,
        /// Block timestamp.
        block: u64,
    },

    /// Invalid gas usage.
    #[error("gas used {gas_used} exceeds gas limit {gas_limit}")]
    GasExceedsLimit {
        /// Gas used.
        gas_used: u64,
        /// Gas limit.
        gas_limit: u64,
    },
}

/// Execution block validator.
///
/// Validates execution layer block structure and consistency.
///
/// Note: This is a simplified validator for demonstration.
/// Production validation would include:
/// - Full consensus rule validation via `reth_consensus::Consensus`
/// - EIP-4844 blob transaction validation
/// - State root verification
/// - Transaction execution verification
#[derive(Debug, Clone, Default)]
pub struct ExecutionValidator {
    /// Whether to validate gas limits.
    validate_gas: bool,
}

impl ExecutionValidator {
    /// Create a new execution validator.
    pub fn new() -> Self {
        Self { validate_gas: true }
    }

    /// Create a validator that skips gas validation.
    pub fn without_gas_validation() -> Self {
        Self { validate_gas: false }
    }

    /// Validate a sealed execution block.
    ///
    /// Checks:
    /// - Gas used doesn't exceed gas limit
    pub fn validate<B>(&self, block: &SealedBlock<B>) -> Result<(), ExecutionValidationError>
    where
        B: BlockTrait<Header: BlockHeader>,
    {
        if self.validate_gas {
            let gas_used = block.header().gas_used();
            let gas_limit = block.header().gas_limit();

            if gas_used > gas_limit {
                return Err(ExecutionValidationError::GasExceedsLimit { gas_used, gas_limit });
            }
        }

        Ok(())
    }

    /// Validate an execution block against its parent.
    ///
    /// Additional checks:
    /// - Block number is parent + 1
    /// - Parent hash matches parent's hash
    /// - Timestamp is greater than parent
    pub fn validate_against_parent<B>(
        &self,
        block: &SealedBlock<B>,
        parent: &SealedBlock<B>,
    ) -> Result<(), ExecutionValidationError>
    where
        B: BlockTrait<Header: BlockHeader>,
    {
        // Check block number
        let expected_number = parent.header().number() + 1;
        let actual_number = block.header().number();

        if actual_number != expected_number {
            return Err(ExecutionValidationError::InvalidBlockNumber {
                expected: expected_number,
                actual: actual_number,
            });
        }

        // Check parent hash
        let expected_parent_hash = parent.hash();
        let actual_parent_hash = block.header().parent_hash();

        if actual_parent_hash != expected_parent_hash {
            return Err(ExecutionValidationError::ParentHashMismatch {
                expected: expected_parent_hash,
                actual: actual_parent_hash,
            });
        }

        // Check timestamp
        let parent_timestamp = parent.header().timestamp();
        let block_timestamp = block.header().timestamp();

        if block_timestamp <= parent_timestamp {
            return Err(ExecutionValidationError::TimestampNotIncreasing {
                parent: parent_timestamp,
                block: block_timestamp,
            });
        }

        // Run basic validation
        self.validate(block)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::Header;
    use reth_ethereum_primitives::{Block, BlockBody};

    fn create_test_block(number: u64, parent_hash: B256, timestamp: u64) -> SealedBlock<Block> {
        let header = Header { number, parent_hash, timestamp, ..Default::default() };
        SealedBlock::seal_slow(Block::new(header, BlockBody::default()))
    }

    #[test]
    fn test_validate_execution_block() {
        let validator = ExecutionValidator::new();
        let block = create_test_block(100, B256::ZERO, 1000);

        assert!(validator.validate(&block).is_ok());
    }

    #[test]
    fn test_validate_gas_exceeds_limit() {
        let validator = ExecutionValidator::new();

        let header =
            Header { number: 100, gas_used: 100_000, gas_limit: 50_000, ..Default::default() };
        let block = SealedBlock::seal_slow(Block::new(header, BlockBody::default()));

        let result = validator.validate(&block);
        assert!(matches!(result, Err(ExecutionValidationError::GasExceedsLimit { .. })));
    }

    #[test]
    fn test_validate_parent_linkage() {
        let validator = ExecutionValidator::new();

        let parent = create_test_block(100, B256::ZERO, 1000);
        let child = create_test_block(101, parent.hash(), 1001);

        assert!(validator.validate_against_parent(&child, &parent).is_ok());
    }

    #[test]
    fn test_validate_invalid_block_number() {
        let validator = ExecutionValidator::new();

        let parent = create_test_block(100, B256::ZERO, 1000);
        let child = create_test_block(103, parent.hash(), 1001); // Wrong number

        let result = validator.validate_against_parent(&child, &parent);
        assert!(matches!(result, Err(ExecutionValidationError::InvalidBlockNumber { .. })));
    }

    #[test]
    fn test_validate_parent_hash_mismatch() {
        let validator = ExecutionValidator::new();

        let parent = create_test_block(100, B256::ZERO, 1000);
        let child = create_test_block(101, B256::repeat_byte(0xFF), 1001); // Wrong parent hash

        let result = validator.validate_against_parent(&child, &parent);
        assert!(matches!(result, Err(ExecutionValidationError::ParentHashMismatch { .. })));
    }

    #[test]
    fn test_validate_timestamp_not_increasing() {
        let validator = ExecutionValidator::new();

        let parent = create_test_block(100, B256::ZERO, 1000);
        let child = create_test_block(101, parent.hash(), 999); // Timestamp <= parent

        let result = validator.validate_against_parent(&child, &parent);
        assert!(matches!(result, Err(ExecutionValidationError::TimestampNotIncreasing { .. })));
    }
}
