//! Cross-reference validation between beacon and execution blocks.
//!
//! This module validates the linkage between beacon chain blocks
//! and execution layer blocks.

use crate::primitives::UnifiedBlock;
use alloy_consensus::BlockHeader;
use alloy_primitives::B256;
use reth_primitives_traits::Block as BlockTrait;

/// Errors that can occur during cross-reference validation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CrossValidationError {
    /// Beacon block root doesn't match execution header's parent_beacon_block_root.
    #[error("beacon root mismatch: execution expects {expected}, beacon has {actual}")]
    BeaconRootMismatch {
        /// Expected beacon root (from execution header).
        expected: B256,
        /// Actual beacon block root.
        actual: B256,
    },

    /// Execution block hash doesn't match beacon's execution_payload_root.
    #[error("execution hash mismatch: beacon expects {expected}, execution has {actual}")]
    ExecutionHashMismatch {
        /// Expected execution hash (from beacon body).
        expected: B256,
        /// Actual execution block hash.
        actual: B256,
    },

    /// Missing parent_beacon_block_root in execution header.
    #[error("execution header missing parent_beacon_block_root (pre-Cancun block?)")]
    MissingBeaconRoot,
}

/// Cross-reference validator.
///
/// Validates that beacon and execution blocks correctly reference each other:
/// 1. Execution header's `parent_beacon_block_root` matches beacon block root
/// 2. Beacon body's `execution_payload_root` matches execution block hash
#[derive(Debug, Clone, Default)]
pub struct CrossValidator {
    /// Whether to strictly require parent_beacon_block_root.
    strict_beacon_root: bool,
}

impl CrossValidator {
    /// Create a new cross-reference validator.
    pub fn new() -> Self {
        Self { strict_beacon_root: true }
    }

    /// Create a validator that doesn't require parent_beacon_block_root.
    ///
    /// Useful for pre-Cancun blocks that don't have this field.
    pub fn lenient() -> Self {
        Self { strict_beacon_root: false }
    }

    /// Validate cross-references in a unified block.
    ///
    /// Checks:
    /// 1. Beacon block root matches execution header's parent_beacon_block_root
    /// 2. Execution block hash matches beacon body's execution_payload_root
    pub fn validate<B>(&self, block: &UnifiedBlock<B>) -> Result<(), CrossValidationError>
    where
        B: BlockTrait<Header: BlockHeader>,
    {
        // Get beacon block root
        let beacon_root = block.beacon.block_root();

        // Check execution header has parent_beacon_block_root
        let execution_beacon_root = block.execution.header().parent_beacon_block_root();

        match execution_beacon_root {
            Some(expected_beacon_root) => {
                // Validate beacon root matches
                if expected_beacon_root != beacon_root {
                    return Err(CrossValidationError::BeaconRootMismatch {
                        expected: expected_beacon_root,
                        actual: beacon_root,
                    });
                }
            }
            None => {
                if self.strict_beacon_root {
                    return Err(CrossValidationError::MissingBeaconRoot);
                }
            }
        }

        // Get execution block hash
        let execution_hash = block.execution.hash();

        // Get expected execution root from beacon
        let expected_execution_root = block.beacon.message.body.execution_payload_root;

        // Validate execution root matches
        if expected_execution_root != execution_hash {
            return Err(CrossValidationError::ExecutionHashMismatch {
                expected: expected_execution_root,
                actual: execution_hash,
            });
        }

        Ok(())
    }

    /// Validate just the beacon root cross-reference.
    pub fn validate_beacon_root<B>(&self, block: &UnifiedBlock<B>) -> Result<(), CrossValidationError>
    where
        B: BlockTrait<Header: BlockHeader>,
    {
        let beacon_root = block.beacon.block_root();

        match block.execution.header().parent_beacon_block_root() {
            Some(expected) if expected != beacon_root => {
                Err(CrossValidationError::BeaconRootMismatch { expected, actual: beacon_root })
            }
            None if self.strict_beacon_root => Err(CrossValidationError::MissingBeaconRoot),
            _ => Ok(()),
        }
    }

    /// Validate just the execution hash cross-reference.
    pub fn validate_execution_hash<B>(
        &self,
        block: &UnifiedBlock<B>,
    ) -> Result<(), CrossValidationError>
    where
        B: BlockTrait<Header: BlockHeader>,
    {
        let execution_hash = block.execution.hash();
        let expected = block.beacon.message.body.execution_payload_root;

        if expected != execution_hash {
            return Err(CrossValidationError::ExecutionHashMismatch {
                expected,
                actual: execution_hash,
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::{BeaconBlock, BeaconBlockBody, SignedBeaconBlock};
    use alloy_consensus::Header;
    use alloy_primitives::Bytes;
    use reth_ethereum_primitives::{Block, BlockBody};
    use reth_primitives_traits::SealedBlock;

    #[allow(dead_code)]
    fn create_matching_blocks() -> UnifiedBlock {
        // First create the execution block to get its hash
        let header = Header { number: 100, ..Default::default() };
        let execution = SealedBlock::seal_slow(Block::new(header, BlockBody::default()));
        let execution_hash = execution.hash();

        // Create beacon block with matching execution_payload_root
        let body = BeaconBlockBody { execution_payload_root: execution_hash, ..Default::default() };
        let beacon_block = BeaconBlock::new(100, 42, B256::ZERO, B256::repeat_byte(0x11), body);
        let beacon = SignedBeaconBlock::new(beacon_block, Bytes::from_static(&[0x00; 96]));
        let beacon_root = beacon.block_root();

        // Recreate execution block with matching parent_beacon_block_root
        let header =
            Header { number: 100, parent_beacon_block_root: Some(beacon_root), ..Default::default() };
        let execution = SealedBlock::seal_slow(Block::new(header, BlockBody::default()));
        let execution_hash = execution.hash();

        // Recreate beacon with updated execution hash
        let body = BeaconBlockBody { execution_payload_root: execution_hash, ..Default::default() };
        let beacon_block = BeaconBlock::new(100, 42, B256::ZERO, B256::repeat_byte(0x11), body);
        let beacon = SignedBeaconBlock::new(beacon_block, Bytes::from_static(&[0x00; 96]));
        let beacon_root = beacon.block_root();

        // Final execution with correct beacon root
        let header =
            Header { number: 100, parent_beacon_block_root: Some(beacon_root), ..Default::default() };
        let execution = SealedBlock::seal_slow(Block::new(header, BlockBody::default()));
        let execution_hash = execution.hash();

        // Final beacon with correct execution hash
        let body = BeaconBlockBody { execution_payload_root: execution_hash, ..Default::default() };
        let beacon_block = BeaconBlock::new(100, 42, B256::ZERO, B256::repeat_byte(0x11), body);
        let beacon = SignedBeaconBlock::new(beacon_block, Bytes::from_static(&[0x00; 96]));

        // Final execution
        let header = Header {
            number: 100,
            parent_beacon_block_root: Some(beacon.block_root()),
            ..Default::default()
        };
        let execution = SealedBlock::seal_slow(Block::new(header, BlockBody::default()));

        // Final beacon
        let body =
            BeaconBlockBody { execution_payload_root: execution.hash(), ..Default::default() };
        let beacon_block = BeaconBlock::new(100, 42, B256::ZERO, B256::repeat_byte(0x11), body);
        let beacon = SignedBeaconBlock::new(beacon_block, Bytes::from_static(&[0x00; 96]));

        // Rebuild execution one more time
        let header = Header {
            number: 100,
            parent_beacon_block_root: Some(beacon.block_root()),
            ..Default::default()
        };
        let execution = SealedBlock::seal_slow(Block::new(header, BlockBody::default()));

        // Rebuild beacon one more time
        let body =
            BeaconBlockBody { execution_payload_root: execution.hash(), ..Default::default() };
        let beacon_block = BeaconBlock::new(100, 42, B256::ZERO, B256::repeat_byte(0x11), body);
        let beacon = SignedBeaconBlock::new(beacon_block, Bytes::from_static(&[0x00; 96]));

        UnifiedBlock::new(beacon, execution)
    }

    #[test]
    fn test_cross_validation_mismatch() {
        let validator = CrossValidator::new();

        // Create mismatched blocks
        let beacon = SignedBeaconBlock::new(
            BeaconBlock::new(
                100,
                42,
                B256::ZERO,
                B256::ZERO,
                BeaconBlockBody { execution_payload_root: B256::repeat_byte(0xFF), ..Default::default() },
            ),
            Bytes::from_static(&[0x00; 96]),
        );

        let header = Header {
            number: 100,
            parent_beacon_block_root: Some(B256::repeat_byte(0xAA)), // Wrong!
            ..Default::default()
        };
        let execution = SealedBlock::seal_slow(Block::new(header, BlockBody::default()));

        let block = UnifiedBlock::new(beacon, execution);

        let result = validator.validate(&block);
        assert!(matches!(result, Err(CrossValidationError::BeaconRootMismatch { .. })));
    }

    #[test]
    fn test_cross_validation_missing_beacon_root() {
        let validator = CrossValidator::new();

        let beacon = SignedBeaconBlock::new(
            BeaconBlock::new(100, 42, B256::ZERO, B256::ZERO, BeaconBlockBody::default()),
            Bytes::from_static(&[0x00; 96]),
        );

        // No parent_beacon_block_root
        let header = Header { number: 100, ..Default::default() };
        let execution = SealedBlock::seal_slow(Block::new(header, BlockBody::default()));

        let block = UnifiedBlock::new(beacon, execution);

        let result = validator.validate(&block);
        assert!(matches!(result, Err(CrossValidationError::MissingBeaconRoot)));
    }

    #[test]
    fn test_lenient_validation() {
        let validator = CrossValidator::lenient();

        let beacon = SignedBeaconBlock::new(
            BeaconBlock::new(100, 42, B256::ZERO, B256::ZERO, BeaconBlockBody::default()),
            Bytes::from_static(&[0x00; 96]),
        );

        let header = Header { number: 100, ..Default::default() };
        let execution = SealedBlock::seal_slow(Block::new(header, BlockBody::default()));

        let block = UnifiedBlock::new(beacon, execution);

        // Should only fail on execution hash mismatch, not missing beacon root
        let result = validator.validate(&block);
        assert!(matches!(result, Err(CrossValidationError::ExecutionHashMismatch { .. })));
    }
}
