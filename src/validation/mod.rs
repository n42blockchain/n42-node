//! Validation module for unified blocks.
//!
//! This module provides validation logic for:
//! - Beacon chain blocks (slot ordering, parent linkage)
//! - Execution layer blocks (via reth consensus)
//! - Cross-references between beacon and execution blocks
//!
//! # Validation Flow
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                     UnifiedBlock                            │
//! └────────────────────────┬────────────────────────────────────┘
//!                          │
//!          ┌───────────────┼───────────────┐
//!          ▼               ▼               ▼
//!    ┌──────────┐   ┌──────────┐   ┌──────────────┐
//!    │  Beacon  │   │  Cross   │   │  Execution   │
//!    │ Validate │   │ Validate │   │   Validate   │
//!    └────┬─────┘   └────┬─────┘   └──────┬───────┘
//!         │              │                │
//!         │  ┌───────────┴─────────────┐  │
//!         │  │                         │  │
//!         ▼  ▼                         ▼  ▼
//!    ┌───────────┐                ┌───────────┐
//!    │   Valid   │                │  Invalid  │
//!    │  (store)  │                │  (reject) │
//!    └───────────┘                └───────────┘
//! ```

mod beacon;
mod cross;
mod execution;

pub use beacon::{BeaconBlockValidator, BeaconValidationError};
pub use cross::{CrossValidator, CrossValidationError};
pub use execution::{ExecutionValidator, ExecutionValidationError};

use crate::primitives::UnifiedBlock;
use reth_primitives_traits::Block as BlockTrait;

/// Combined validation error for unified blocks.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UnifiedValidationError {
    /// Beacon block validation failed.
    #[error("beacon validation failed: {0}")]
    Beacon(#[from] BeaconValidationError),

    /// Cross-reference validation failed.
    #[error("cross-reference validation failed: {0}")]
    Cross(#[from] CrossValidationError),

    /// Execution block validation failed.
    #[error("execution validation failed: {0}")]
    Execution(#[from] ExecutionValidationError),
}

/// Unified block validator combining all validation stages.
///
/// This validator runs all three validation stages:
/// 1. Beacon block validation
/// 2. Cross-reference validation
/// 3. Execution block validation
#[derive(Debug, Clone)]
pub struct UnifiedBlockValidator {
    /// Beacon block validator.
    pub beacon: BeaconBlockValidator,
    /// Cross-reference validator.
    pub cross: CrossValidator,
    /// Execution block validator.
    pub execution: ExecutionValidator,
}

impl Default for UnifiedBlockValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl UnifiedBlockValidator {
    /// Create a new unified block validator.
    pub fn new() -> Self {
        Self {
            beacon: BeaconBlockValidator::new(),
            cross: CrossValidator::new(),
            execution: ExecutionValidator::new(),
        }
    }

    /// Validate a unified block.
    ///
    /// Runs all validation stages in order:
    /// 1. Beacon block structure validation
    /// 2. Cross-reference validation (beacon root matches execution header)
    /// 3. Execution block validation
    pub fn validate<B>(&self, block: &UnifiedBlock<B>) -> Result<(), UnifiedValidationError>
    where
        B: BlockTrait<Header: alloy_consensus::BlockHeader>,
    {
        // 1. Validate beacon block
        self.beacon.validate(&block.beacon)?;

        // 2. Validate cross-references
        self.cross.validate(block)?;

        // 3. Validate execution block
        self.execution.validate(&block.execution)?;

        Ok(())
    }

    /// Validate a unified block against a parent.
    ///
    /// Additionally validates that:
    /// - Beacon block's parent_root matches parent's block_root
    /// - Slots are correctly ordered
    pub fn validate_against_parent<B>(
        &self,
        block: &UnifiedBlock<B>,
        parent: &UnifiedBlock<B>,
    ) -> Result<(), UnifiedValidationError>
    where
        B: BlockTrait<Header: alloy_consensus::BlockHeader>,
    {
        // First run basic validation
        self.validate(block)?;

        // Validate beacon parent linkage
        self.beacon.validate_parent(&block.beacon, &parent.beacon)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unified_validator_creation() {
        let validator = UnifiedBlockValidator::new();
        assert!(format!("{:?}", validator).contains("UnifiedBlockValidator"));
    }
}
