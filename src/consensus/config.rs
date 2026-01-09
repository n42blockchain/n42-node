//! POA configuration and validator set management.

use alloy_primitives::Address;
use std::collections::HashSet;

/// POA consensus configuration.
#[derive(Debug, Clone)]
pub struct PoaConfig {
    /// Ordered list of validators (round-robin order)
    pub validators: ValidatorSet,
    /// Block production interval in seconds
    pub block_time: u64,
    /// This node's validator address (coinbase)
    pub coinbase: Option<Address>,
}

impl PoaConfig {
    /// Create a new POA configuration.
    pub fn new(validators: Vec<Address>, block_time: u64) -> Self {
        Self {
            validators: ValidatorSet::new(validators),
            block_time,
            coinbase: None,
        }
    }

    /// Set this node's coinbase address.
    pub fn with_coinbase(mut self, coinbase: Address) -> Self {
        self.coinbase = Some(coinbase);
        self
    }

    /// Check if this node is a validator.
    pub fn is_validator(&self) -> bool {
        self.coinbase.map(|c| self.validators.contains(&c)).unwrap_or(false)
    }

    /// Get the expected validator for a given slot.
    pub fn validator_for_slot(&self, slot: u64) -> Option<Address> {
        self.validators.validator_at_slot(slot)
    }

    /// Check if the given address is the in-turn validator for the slot.
    pub fn is_in_turn(&self, slot: u64, validator: Address) -> bool {
        self.validator_for_slot(slot) == Some(validator)
    }

    /// Get the expected difficulty for a block.
    pub fn expected_difficulty(&self, slot: u64, validator: Address) -> u64 {
        if self.is_in_turn(slot, validator) {
            super::DIFFICULTY_IN_TURN
        } else {
            super::DIFFICULTY_OUT_OF_TURN
        }
    }
}

impl Default for PoaConfig {
    fn default() -> Self {
        Self {
            validators: ValidatorSet::default(),
            block_time: super::DEFAULT_BLOCK_TIME,
            coinbase: None,
        }
    }
}

/// Ordered set of validators for round-robin selection.
#[derive(Debug, Clone, Default)]
pub struct ValidatorSet {
    /// Ordered list of validator addresses
    validators: Vec<Address>,
    /// Set for O(1) membership check
    set: HashSet<Address>,
}

impl ValidatorSet {
    /// Create a new validator set.
    pub fn new(validators: Vec<Address>) -> Self {
        let set = validators.iter().copied().collect();
        Self { validators, set }
    }

    /// Check if an address is a validator.
    pub fn contains(&self, address: &Address) -> bool {
        self.set.contains(address)
    }

    /// Get the number of validators.
    pub fn len(&self) -> usize {
        self.validators.len()
    }

    /// Check if the validator set is empty.
    pub fn is_empty(&self) -> bool {
        self.validators.is_empty()
    }

    /// Get the validator at the given index.
    pub fn get(&self, index: usize) -> Option<Address> {
        self.validators.get(index).copied()
    }

    /// Get the validator for a given slot (round-robin).
    pub fn validator_at_slot(&self, slot: u64) -> Option<Address> {
        if self.is_empty() {
            return None;
        }
        let index = (slot as usize) % self.validators.len();
        self.get(index)
    }

    /// Get the index of a validator.
    pub fn index_of(&self, address: &Address) -> Option<usize> {
        self.validators.iter().position(|v| v == address)
    }

    /// Get all validators.
    pub fn validators(&self) -> &[Address] {
        &self.validators
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_validators() -> Vec<Address> {
        vec![
            Address::repeat_byte(0x01),
            Address::repeat_byte(0x02),
            Address::repeat_byte(0x03),
            Address::repeat_byte(0x04),
        ]
    }

    #[test]
    fn test_validator_set_round_robin() {
        let set = ValidatorSet::new(test_validators());

        assert_eq!(set.validator_at_slot(0), Some(Address::repeat_byte(0x01)));
        assert_eq!(set.validator_at_slot(1), Some(Address::repeat_byte(0x02)));
        assert_eq!(set.validator_at_slot(2), Some(Address::repeat_byte(0x03)));
        assert_eq!(set.validator_at_slot(3), Some(Address::repeat_byte(0x04)));
        assert_eq!(set.validator_at_slot(4), Some(Address::repeat_byte(0x01))); // wraps
        assert_eq!(set.validator_at_slot(5), Some(Address::repeat_byte(0x02)));
    }

    #[test]
    fn test_poa_config_in_turn() {
        let config = PoaConfig::new(test_validators(), 8);

        // Slot 0 -> V0 is in-turn
        assert!(config.is_in_turn(0, Address::repeat_byte(0x01)));
        assert!(!config.is_in_turn(0, Address::repeat_byte(0x02)));

        // Slot 1 -> V1 is in-turn
        assert!(config.is_in_turn(1, Address::repeat_byte(0x02)));
        assert!(!config.is_in_turn(1, Address::repeat_byte(0x01)));
    }

    #[test]
    fn test_poa_config_difficulty() {
        let config = PoaConfig::new(test_validators(), 8);

        // In-turn difficulty
        assert_eq!(
            config.expected_difficulty(0, Address::repeat_byte(0x01)),
            super::super::DIFFICULTY_IN_TURN
        );

        // Out-of-turn difficulty
        assert_eq!(
            config.expected_difficulty(0, Address::repeat_byte(0x02)),
            super::super::DIFFICULTY_OUT_OF_TURN
        );
    }

    #[test]
    fn test_is_validator() {
        let config = PoaConfig::new(test_validators(), 8)
            .with_coinbase(Address::repeat_byte(0x01));

        assert!(config.is_validator());

        let config2 = PoaConfig::new(test_validators(), 8)
            .with_coinbase(Address::repeat_byte(0xFF)); // not in list

        assert!(!config2.is_validator());
    }
}
