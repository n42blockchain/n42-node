//! POA block validation.

use super::PoaConfig;
use crate::primitives::SignedBeaconBlock;
use alloy_primitives::{Address, B256};

/// POA validation errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PoaValidationError {
    /// Block proposer is not a valid validator.
    #[error("invalid proposer: {proposer} is not a validator")]
    InvalidProposer {
        /// The invalid proposer address
        proposer: Address,
    },

    /// Block difficulty is invalid.
    #[error("invalid difficulty: expected {expected}, got {actual}")]
    InvalidDifficulty {
        /// Expected difficulty
        expected: u64,
        /// Actual difficulty in block
        actual: u64,
    },

    /// Slot number is not increasing.
    #[error("slot not increasing: parent slot {parent_slot}, block slot {block_slot}")]
    SlotNotIncreasing {
        /// Parent slot
        parent_slot: u64,
        /// Block slot
        block_slot: u64,
    },

    /// Parent hash mismatch.
    #[error("parent hash mismatch: expected {expected}, got {actual}")]
    ParentHashMismatch {
        /// Expected parent hash
        expected: B256,
        /// Actual parent hash in block
        actual: B256,
    },

    /// Block is from the future.
    #[error("block from future: block time {block_time}, current time {current_time}")]
    FutureBlock {
        /// Block timestamp
        block_time: u64,
        /// Current timestamp
        current_time: u64,
    },
}

/// POA block validator.
///
/// Validates that:
/// 1. Proposer is a valid validator
/// 2. Difficulty matches in-turn/out-of-turn status
/// 3. Slot is increasing
/// 4. Parent linkage is correct
#[derive(Debug, Clone)]
pub struct PoaValidator {
    config: PoaConfig,
}

impl PoaValidator {
    /// Create a new POA validator.
    pub fn new(config: PoaConfig) -> Self {
        Self { config }
    }

    /// Get the POA configuration.
    pub fn config(&self) -> &PoaConfig {
        &self.config
    }

    /// Validate a beacon block.
    pub fn validate_block(
        &self,
        block: &SignedBeaconBlock,
        parent: Option<&SignedBeaconBlock>,
    ) -> Result<(), PoaValidationError> {
        let slot = block.slot();
        let proposer = self.get_proposer_address(block);

        // 1. Check proposer is a validator
        if !self.config.validators.contains(&proposer) {
            return Err(PoaValidationError::InvalidProposer { proposer });
        }

        // 2. Check difficulty matches in-turn status
        let expected_difficulty = self.config.expected_difficulty(slot, proposer);
        let actual_difficulty = self.get_block_difficulty(block);

        if expected_difficulty != actual_difficulty {
            return Err(PoaValidationError::InvalidDifficulty {
                expected: expected_difficulty,
                actual: actual_difficulty,
            });
        }

        // 3. Check slot is increasing (if we have parent)
        if let Some(parent) = parent {
            let parent_slot = parent.slot();
            if slot <= parent_slot {
                return Err(PoaValidationError::SlotNotIncreasing {
                    parent_slot,
                    block_slot: slot,
                });
            }

            // 4. Check parent hash
            let expected_parent = parent.block_root();
            let actual_parent = block.parent_root();
            if expected_parent != actual_parent {
                return Err(PoaValidationError::ParentHashMismatch {
                    expected: expected_parent,
                    actual: actual_parent,
                });
            }
        }

        Ok(())
    }

    /// Check if a block is in-turn (produced by the assigned validator).
    pub fn is_in_turn(&self, block: &SignedBeaconBlock) -> bool {
        let slot = block.slot();
        let proposer = self.get_proposer_address(block);
        self.config.is_in_turn(slot, proposer)
    }

    /// Get the proposer address from the beacon block.
    ///
    /// For now, we use the proposer_index as the validator index
    /// and look up the address from the validator set.
    fn get_proposer_address(&self, block: &SignedBeaconBlock) -> Address {
        let proposer_index = block.message.proposer_index as usize;
        self.config.validators.get(proposer_index).unwrap_or_default()
    }

    /// Get the block difficulty.
    ///
    /// We store difficulty in the graffiti field (first 8 bytes as u64).
    fn get_block_difficulty(&self, block: &SignedBeaconBlock) -> u64 {
        let graffiti = block.message.body.graffiti;
        // Read first 8 bytes as big-endian u64
        let bytes: [u8; 8] = graffiti[..8].try_into().unwrap_or_default();
        u64::from_be_bytes(bytes)
    }

    /// Calculate total difficulty for chain comparison.
    ///
    /// Total difficulty = sum of all block difficulties.
    /// Higher total difficulty wins in fork choice.
    pub fn calculate_total_difficulty(&self, blocks: &[SignedBeaconBlock]) -> u64 {
        blocks.iter().map(|b| self.get_block_difficulty(b)).sum()
    }

    /// Compare two chains and return which one should be canonical.
    ///
    /// Rules:
    /// 1. Longer chain wins
    /// 2. If same length, higher total difficulty wins
    pub fn compare_chains(
        &self,
        chain_a: &[SignedBeaconBlock],
        chain_b: &[SignedBeaconBlock],
    ) -> std::cmp::Ordering {
        // First compare length
        match chain_a.len().cmp(&chain_b.len()) {
            std::cmp::Ordering::Equal => {
                // Same length, compare total difficulty
                let td_a = self.calculate_total_difficulty(chain_a);
                let td_b = self.calculate_total_difficulty(chain_b);
                td_a.cmp(&td_b)
            }
            other => other,
        }
    }
}

/// Helper to set difficulty in graffiti.
pub fn set_difficulty_in_graffiti(graffiti: &mut B256, difficulty: u64) {
    let bytes = difficulty.to_be_bytes();
    graffiti[..8].copy_from_slice(&bytes);
}

/// Helper to get difficulty from graffiti.
pub fn get_difficulty_from_graffiti(graffiti: &B256) -> u64 {
    let bytes: [u8; 8] = graffiti[..8].try_into().unwrap_or_default();
    u64::from_be_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::{DIFFICULTY_IN_TURN, DIFFICULTY_OUT_OF_TURN};
    use crate::primitives::{BeaconBlock, BeaconBlockBody};
    use alloy_primitives::Bytes;

    fn test_config() -> PoaConfig {
        PoaConfig::new(
            vec![
                Address::repeat_byte(0x01),
                Address::repeat_byte(0x02),
                Address::repeat_byte(0x03),
            ],
            8,
        )
    }

    fn create_block(slot: u64, proposer_index: u64, difficulty: u64, parent_root: B256) -> SignedBeaconBlock {
        let mut graffiti = B256::ZERO;
        set_difficulty_in_graffiti(&mut graffiti, difficulty);

        let body = BeaconBlockBody {
            graffiti,
            ..Default::default()
        };

        let block = BeaconBlock::new(
            slot,
            proposer_index,
            parent_root,
            B256::ZERO,
            body,
        );

        SignedBeaconBlock::new(block, Bytes::from_static(&[0x00; 96]))
    }

    #[test]
    fn test_validate_in_turn_block() {
        let config = test_config();
        let validator = PoaValidator::new(config);

        // Slot 0, proposer 0 is in-turn
        let block = create_block(0, 0, DIFFICULTY_IN_TURN, B256::ZERO);
        assert!(validator.validate_block(&block, None).is_ok());
        assert!(validator.is_in_turn(&block));
    }

    #[test]
    fn test_validate_out_of_turn_block() {
        let config = test_config();
        let validator = PoaValidator::new(config);

        // Slot 0, proposer 1 is out-of-turn (should be proposer 0)
        let block = create_block(0, 1, DIFFICULTY_OUT_OF_TURN, B256::ZERO);
        assert!(validator.validate_block(&block, None).is_ok());
        assert!(!validator.is_in_turn(&block));
    }

    #[test]
    fn test_reject_wrong_difficulty() {
        let config = test_config();
        let validator = PoaValidator::new(config);

        // Slot 0, proposer 0 claims out-of-turn difficulty (should be in-turn)
        let block = create_block(0, 0, DIFFICULTY_OUT_OF_TURN, B256::ZERO);
        let result = validator.validate_block(&block, None);
        assert!(matches!(result, Err(PoaValidationError::InvalidDifficulty { .. })));
    }

    #[test]
    fn test_slot_increasing() {
        let config = test_config();
        let validator = PoaValidator::new(config);

        let parent = create_block(5, 2, DIFFICULTY_IN_TURN, B256::ZERO);
        let child = create_block(6, 0, DIFFICULTY_IN_TURN, parent.block_root());

        assert!(validator.validate_block(&child, Some(&parent)).is_ok());

        // Slot not increasing
        let bad_child = create_block(5, 2, DIFFICULTY_IN_TURN, parent.block_root());
        let result = validator.validate_block(&bad_child, Some(&parent));
        assert!(matches!(result, Err(PoaValidationError::SlotNotIncreasing { .. })));
    }

    #[test]
    fn test_chain_comparison() {
        let config = test_config();
        let validator = PoaValidator::new(config);

        // Chain A: 3 blocks, all in-turn (TD = 6)
        let chain_a = vec![
            create_block(0, 0, DIFFICULTY_IN_TURN, B256::ZERO),
            create_block(1, 1, DIFFICULTY_IN_TURN, B256::ZERO),
            create_block(2, 2, DIFFICULTY_IN_TURN, B256::ZERO),
        ];

        // Chain B: 3 blocks, one out-of-turn (TD = 5)
        let chain_b = vec![
            create_block(0, 0, DIFFICULTY_IN_TURN, B256::ZERO),
            create_block(1, 2, DIFFICULTY_OUT_OF_TURN, B256::ZERO), // out-of-turn
            create_block(2, 0, DIFFICULTY_IN_TURN, B256::ZERO),
        ];

        // Same length, chain_a has higher TD
        assert_eq!(
            validator.compare_chains(&chain_a, &chain_b),
            std::cmp::Ordering::Greater
        );

        // Chain C: 4 blocks (longer wins)
        let chain_c = vec![
            create_block(0, 0, DIFFICULTY_OUT_OF_TURN, B256::ZERO),
            create_block(1, 1, DIFFICULTY_OUT_OF_TURN, B256::ZERO),
            create_block(2, 2, DIFFICULTY_OUT_OF_TURN, B256::ZERO),
            create_block(3, 0, DIFFICULTY_OUT_OF_TURN, B256::ZERO),
        ];

        // chain_c is longer, wins despite lower TD
        assert_eq!(
            validator.compare_chains(&chain_c, &chain_a),
            std::cmp::Ordering::Greater
        );
    }

    #[test]
    fn test_difficulty_graffiti() {
        let mut graffiti = B256::ZERO;
        set_difficulty_in_graffiti(&mut graffiti, 12345);
        assert_eq!(get_difficulty_from_graffiti(&graffiti), 12345);
    }
}
