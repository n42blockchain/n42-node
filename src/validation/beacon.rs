//! Beacon chain block validation.
//!
//! This module provides validation for beacon chain blocks, including:
//! - Slot ordering and consistency
//! - Parent linkage verification
//! - Signature validation (simplified for demo)

use crate::primitives::SignedBeaconBlock;
use alloy_primitives::B256;

/// Errors that can occur during beacon block validation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BeaconValidationError {
    /// Invalid slot number.
    #[error("invalid slot: expected > {expected}, got {actual}")]
    InvalidSlot {
        /// Expected minimum slot.
        expected: u64,
        /// Actual slot received.
        actual: u64,
    },

    /// Parent root mismatch.
    #[error("parent root mismatch: expected {expected}, got {actual}")]
    ParentRootMismatch {
        /// Expected parent root.
        expected: B256,
        /// Actual parent root in block.
        actual: B256,
    },

    /// Slot not greater than parent.
    #[error("slot {slot} is not greater than parent slot {parent_slot}")]
    SlotNotIncreasing {
        /// Block slot.
        slot: u64,
        /// Parent slot.
        parent_slot: u64,
    },

    /// Invalid signature (simplified check).
    #[error("invalid signature: signature length {length} < 96 bytes")]
    InvalidSignature {
        /// Actual signature length.
        length: usize,
    },

    /// Empty block body.
    #[error("empty block body")]
    EmptyBody,
}

/// Beacon block validator.
///
/// Validates beacon chain block structure and consistency.
/// Note: This is a simplified validator for demonstration purposes.
/// A production implementation would include:
/// - Full BLS signature verification
/// - Attestation validation
/// - Proposer slashing checks
/// - State transition validation
#[derive(Debug, Clone, Default)]
pub struct BeaconBlockValidator {
    /// Whether to validate signatures (simplified check).
    validate_signatures: bool,
}

impl BeaconBlockValidator {
    /// Create a new beacon block validator.
    pub fn new() -> Self {
        Self { validate_signatures: true }
    }

    /// Create a validator that skips signature validation.
    pub fn without_signature_validation() -> Self {
        Self { validate_signatures: false }
    }

    /// Validate a beacon block.
    ///
    /// Checks:
    /// - Signature length (simplified)
    pub fn validate(&self, block: &SignedBeaconBlock) -> Result<(), BeaconValidationError> {
        // Check signature length (simplified BLS check)
        if self.validate_signatures && block.signature.len() < 96 {
            return Err(BeaconValidationError::InvalidSignature { length: block.signature.len() });
        }

        Ok(())
    }

    /// Validate a beacon block against its parent.
    ///
    /// Additional checks:
    /// - Slot is greater than parent slot
    /// - Parent root matches parent's block root
    pub fn validate_parent(
        &self,
        block: &SignedBeaconBlock,
        parent: &SignedBeaconBlock,
    ) -> Result<(), BeaconValidationError> {
        // Check slot ordering
        if block.slot() <= parent.slot() {
            return Err(BeaconValidationError::SlotNotIncreasing {
                slot: block.slot(),
                parent_slot: parent.slot(),
            });
        }

        // Check parent root linkage
        let expected_parent_root = parent.block_root();
        let actual_parent_root = block.parent_root();

        if actual_parent_root != expected_parent_root {
            return Err(BeaconValidationError::ParentRootMismatch {
                expected: expected_parent_root,
                actual: actual_parent_root,
            });
        }

        Ok(())
    }

    /// Validate that a slot is greater than a minimum.
    pub fn validate_slot_after(
        &self,
        slot: u64,
        min_slot: u64,
    ) -> Result<(), BeaconValidationError> {
        if slot <= min_slot {
            return Err(BeaconValidationError::InvalidSlot { expected: min_slot, actual: slot });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::{BeaconBlock, BeaconBlockBody};
    use alloy_primitives::Bytes;

    fn create_test_beacon_block(slot: u64, parent_root: B256) -> SignedBeaconBlock {
        SignedBeaconBlock::new(
            BeaconBlock::new(
                slot,
                42,
                parent_root,
                B256::repeat_byte(0x02),
                BeaconBlockBody::default(),
            ),
            Bytes::from_static(&[0x00; 96]),
        )
    }

    #[test]
    fn test_validate_beacon_block() {
        let validator = BeaconBlockValidator::new();
        let block = create_test_beacon_block(100, B256::ZERO);

        assert!(validator.validate(&block).is_ok());
    }

    #[test]
    fn test_validate_invalid_signature_length() {
        let validator = BeaconBlockValidator::new();
        let block = SignedBeaconBlock::new(
            BeaconBlock::new(100, 42, B256::ZERO, B256::ZERO, BeaconBlockBody::default()),
            Bytes::from_static(&[0x00; 10]), // Too short
        );

        let result = validator.validate(&block);
        assert!(matches!(result, Err(BeaconValidationError::InvalidSignature { length: 10 })));
    }

    #[test]
    fn test_validate_skip_signature() {
        let validator = BeaconBlockValidator::without_signature_validation();
        let block = SignedBeaconBlock::new(
            BeaconBlock::new(100, 42, B256::ZERO, B256::ZERO, BeaconBlockBody::default()),
            Bytes::from_static(&[0x00; 10]), // Too short, but skipped
        );

        assert!(validator.validate(&block).is_ok());
    }

    #[test]
    fn test_validate_parent_linkage() {
        let validator = BeaconBlockValidator::new();

        let parent = create_test_beacon_block(100, B256::ZERO);
        let parent_root = parent.block_root();

        let child = create_test_beacon_block(101, parent_root);

        assert!(validator.validate_parent(&child, &parent).is_ok());
    }

    #[test]
    fn test_validate_parent_slot_not_increasing() {
        let validator = BeaconBlockValidator::new();

        let parent = create_test_beacon_block(100, B256::ZERO);
        let parent_root = parent.block_root();

        // Child has same slot as parent
        let child = create_test_beacon_block(100, parent_root);

        let result = validator.validate_parent(&child, &parent);
        assert!(matches!(result, Err(BeaconValidationError::SlotNotIncreasing { .. })));
    }

    #[test]
    fn test_validate_parent_root_mismatch() {
        let validator = BeaconBlockValidator::new();

        let parent = create_test_beacon_block(100, B256::ZERO);

        // Child has wrong parent root
        let child = create_test_beacon_block(101, B256::repeat_byte(0xFF));

        let result = validator.validate_parent(&child, &parent);
        assert!(matches!(result, Err(BeaconValidationError::ParentRootMismatch { .. })));
    }
}
