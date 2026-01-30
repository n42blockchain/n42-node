//! Simplified BeaconState for POA consensus with BLS signatures.
//!
//! This is a minimal beacon state implementation that only tracks
//! what's needed for POA block validation:
//! - Validator set (with BLS public keys)
//! - Latest block information
//! - Slot progression
//!
//! # Design
//!
//! Unlike Ethereum's full BeaconState which tracks attestations,
//! slashings, balances, etc., this simplified version only needs to:
//! 1. Know who can produce blocks (validator set)
//! 2. Verify signatures (validator BLS public keys)
//! 3. Track chain progression (slot, latest block)

use alloy_primitives::{keccak256, Address, B256};
use alloy_rlp::{Encodable, RlpDecodable, RlpEncodable};
use std::collections::HashMap;

use super::traits::{
    ProposerSelector, StateProvider, ValidatorInfo, ValidatorProvider, ValidatorPubkey,
};

/// BLS public key type (48 bytes).
pub type BLSPubkey = [u8; 48];

/// A validator in the beacon state.
///
/// Uses BLS public keys for signature verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BeaconValidator {
    /// Validator's Ethereum address (derived from BLS public key hash).
    pub address: Address,
    /// Validator's BLS public key (48 bytes).
    pub pubkey: BLSPubkey,
    /// Index in the validator set.
    pub index: u64,
    /// Whether this validator is active.
    pub active: bool,
}

impl BeaconValidator {
    /// Create a new validator from a BLS public key.
    pub fn new(pubkey: BLSPubkey, index: u64) -> Self {
        let address = bls_pubkey_to_address(&pubkey);
        Self { address, pubkey, index, active: true }
    }

    /// Create from address and BLS public key.
    pub fn from_address_and_pubkey(address: Address, pubkey: BLSPubkey, index: u64) -> Self {
        Self { address, pubkey, index, active: true }
    }
}

/// Convert a BLS public key to an Ethereum address.
///
/// Takes the keccak256 hash of the public key and uses the last 20 bytes.
pub fn public_key_to_address(pubkey: &BLSPubkey) -> Address {
    let hash = keccak256(pubkey);
    Address::from_slice(&hash[12..])
}

/// Alias for public_key_to_address for BLS keys.
pub fn bls_pubkey_to_address(pubkey: &BLSPubkey) -> Address {
    public_key_to_address(pubkey)
}

/// Simplified BeaconState for POA consensus.
///
/// This tracks the minimal state needed to validate beacon blocks:
/// - Validator set with BLS public keys
/// - Latest finalized/justified information
/// - Current slot
#[derive(Clone, Debug)]
pub struct BeaconState {
    /// Genesis time (unix timestamp).
    pub genesis_time: u64,
    /// Genesis validators root (for domain separation).
    pub genesis_validators_root: B256,
    /// Current slot.
    pub slot: u64,
    /// Latest block header.
    pub latest_block_header: BeaconBlockHeaderLight,
    /// Block roots history (recent blocks).
    pub block_roots: Vec<B256>,
    /// State roots history (recent states).
    pub state_roots: Vec<B256>,
    /// Validator set.
    validators: Vec<BeaconValidator>,
    /// Address to index mapping for O(1) lookup.
    validator_indices: HashMap<Address, u64>,
    /// Finalized checkpoint.
    pub finalized_checkpoint: Checkpoint,
    /// Justified checkpoint.
    pub justified_checkpoint: Checkpoint,
}

/// Lightweight block header for state tracking.
#[derive(Clone, Debug, Default, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct BeaconBlockHeaderLight {
    /// Slot number.
    pub slot: u64,
    /// Proposer index.
    pub proposer_index: u64,
    /// Parent root.
    pub parent_root: B256,
    /// State root (will be updated after state transition).
    pub state_root: B256,
    /// Body root.
    pub body_root: B256,
}

impl BeaconBlockHeaderLight {
    /// Compute the block root.
    pub fn block_root(&self) -> B256 {
        let mut buf = Vec::new();
        self.encode(&mut buf);
        keccak256(&buf)
    }
}

/// A checkpoint (epoch boundary).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Checkpoint {
    /// Epoch number.
    pub epoch: u64,
    /// Block root at this checkpoint.
    pub root: B256,
}

impl BeaconState {
    /// Create a new genesis beacon state.
    pub fn genesis(genesis_time: u64, validators: Vec<BeaconValidator>) -> Self {
        let genesis_validators_root = compute_validators_root(&validators);
        let validator_indices = validators
            .iter()
            .map(|v| (v.address, v.index))
            .collect();

        Self {
            genesis_time,
            genesis_validators_root,
            slot: 0,
            latest_block_header: BeaconBlockHeaderLight::default(),
            block_roots: vec![B256::ZERO; 8192], // SLOTS_PER_HISTORICAL_ROOT
            state_roots: vec![B256::ZERO; 8192],
            validators,
            validator_indices,
            finalized_checkpoint: Checkpoint::default(),
            justified_checkpoint: Checkpoint::default(),
        }
    }

    /// Create from existing state data.
    pub fn new(
        genesis_time: u64,
        genesis_validators_root: B256,
        slot: u64,
        latest_block_header: BeaconBlockHeaderLight,
        validators: Vec<BeaconValidator>,
        finalized_checkpoint: Checkpoint,
    ) -> Self {
        let validator_indices = validators
            .iter()
            .map(|v| (v.address, v.index))
            .collect();

        Self {
            genesis_time,
            genesis_validators_root,
            slot,
            latest_block_header,
            block_roots: vec![B256::ZERO; 8192],
            state_roots: vec![B256::ZERO; 8192],
            validators,
            validator_indices,
            justified_checkpoint: finalized_checkpoint.clone(),
            finalized_checkpoint,
        }
    }

    /// Get the number of validators.
    pub fn validator_count(&self) -> usize {
        self.validators.len()
    }

    /// Get a validator by index.
    pub fn get_validator(&self, index: u64) -> Option<&BeaconValidator> {
        self.validators.get(index as usize)
    }

    /// Get a validator by address.
    pub fn get_validator_by_address(&self, address: &Address) -> Option<&BeaconValidator> {
        self.validator_indices
            .get(address)
            .and_then(|&idx| self.get_validator(idx))
    }

    /// Get the proposer for the current slot (round-robin).
    pub fn get_proposer_index(&self) -> u64 {
        self.get_proposer_index_for_slot(self.slot)
    }

    /// Get the proposer for a specific slot (round-robin).
    pub fn get_proposer_index_for_slot(&self, slot: u64) -> u64 {
        if self.validators.is_empty() {
            return 0;
        }
        // Simple round-robin: slot % num_validators
        slot % self.validators.len() as u64
    }

    /// Get the proposer validator for the current slot.
    pub fn get_proposer(&self) -> Option<&BeaconValidator> {
        let index = self.get_proposer_index();
        self.get_validator(index)
    }

    /// Check if a validator is the proposer for a slot.
    pub fn is_proposer(&self, slot: u64, validator_index: u64) -> bool {
        self.get_proposer_index_for_slot(slot) == validator_index
    }

    /// Get all validators.
    pub fn validators(&self) -> &[BeaconValidator] {
        &self.validators
    }

    /// Update state to a new slot.
    pub fn advance_slot(&mut self) {
        self.slot += 1;
    }

    /// Set the latest block header.
    pub fn set_latest_block_header(&mut self, header: BeaconBlockHeaderLight) {
        // Store the block root in history
        let index = (self.slot as usize) % self.block_roots.len();
        self.block_roots[index] = self.latest_block_header.block_root();

        self.latest_block_header = header;
    }

    /// Compute the state root.
    pub fn compute_state_root(&self) -> B256 {
        // Simplified: hash of key state components
        let mut data = Vec::new();
        data.extend_from_slice(&self.slot.to_le_bytes());
        data.extend_from_slice(self.latest_block_header.block_root().as_slice());
        data.extend_from_slice(self.genesis_validators_root.as_slice());
        data.extend_from_slice(&(self.validators.len() as u64).to_le_bytes());
        keccak256(&data)
    }

    /// Get the signing domain for block proposals.
    ///
    /// Domain = domain_type + fork_version + genesis_validators_root
    pub fn get_domain(&self, domain_type: DomainType) -> B256 {
        compute_domain(domain_type, self.genesis_validators_root)
    }
}

// =============================================================================
// Trait Implementations for BLS-based Consensus
// =============================================================================

impl ValidatorProvider for BeaconState {
    fn validator_count(&self) -> usize {
        self.validators.len()
    }

    fn get_validator_info(&self, index: u64) -> Option<ValidatorInfo> {
        self.validators.get(index as usize).map(|v| ValidatorInfo {
            index: v.index,
            is_active: v.active,
            address: Some(v.address),
        })
    }

    fn get_validator_pubkey(&self, index: u64) -> Option<ValidatorPubkey> {
        self.validators.get(index as usize).map(|v| {
            ValidatorPubkey::new(v.pubkey)
        })
    }

    fn get_validator_by_address(&self, address: &Address) -> Option<ValidatorInfo> {
        self.validator_indices
            .get(address)
            .and_then(|&idx| self.get_validator_info(idx))
    }
}

impl ProposerSelector for BeaconState {
    fn get_proposer_index_for_slot(&self, slot: u64) -> u64 {
        if self.validators.is_empty() {
            return 0;
        }
        slot % self.validators.len() as u64
    }

    fn get_proposer_index(&self) -> u64 {
        self.get_proposer_index_for_slot(self.slot)
    }
}

impl StateProvider for BeaconState {
    fn current_slot(&self) -> u64 {
        self.slot
    }

    fn advance_slot(&mut self) {
        self.slot += 1;
    }

    fn get_domain(&self, domain_type: u32) -> B256 {
        let dt = match domain_type {
            0 => DomainType::BeaconProposer,
            1 => DomainType::BeaconAttester,
            2 => DomainType::Randao,
            _ => DomainType::BeaconProposer,
        };
        compute_domain(dt, self.genesis_validators_root)
    }

    fn compute_state_root(&self) -> B256 {
        // Simplified: hash of key state components
        let mut data = Vec::new();
        data.extend_from_slice(&self.slot.to_le_bytes());
        data.extend_from_slice(self.latest_block_header.block_root().as_slice());
        data.extend_from_slice(self.genesis_validators_root.as_slice());
        data.extend_from_slice(&(self.validators.len() as u64).to_le_bytes());
        keccak256(&data)
    }

    fn genesis_validators_root(&self) -> B256 {
        self.genesis_validators_root
    }
}

/// Domain types for signature separation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum DomainType {
    /// Beacon proposer domain.
    BeaconProposer = 0x00000000,
    /// Beacon attester domain (not used in POA).
    BeaconAttester = 0x01000000,
    /// Randao domain.
    Randao = 0x02000000,
}

impl DomainType {
    /// Get the domain type bytes.
    pub fn to_bytes(self) -> [u8; 4] {
        (self as u32).to_le_bytes()
    }
}

/// Compute the domain for signing.
pub fn compute_domain(domain_type: DomainType, genesis_validators_root: B256) -> B256 {
    let mut data = [0u8; 32];
    data[..4].copy_from_slice(&domain_type.to_bytes());
    // Fork version would go here in full implementation
    data[4..8].copy_from_slice(&[0, 0, 0, 0]); // fork version

    // Mix in genesis validators root
    let fork_data_root = keccak256(&data[..8]);
    let mut domain_data = [0u8; 64];
    domain_data[..32].copy_from_slice(fork_data_root.as_slice());
    domain_data[32..].copy_from_slice(genesis_validators_root.as_slice());

    keccak256(&domain_data)
}

/// Compute the validators root from a list of validators.
fn compute_validators_root(validators: &[BeaconValidator]) -> B256 {
    let mut data = Vec::new();
    for v in validators {
        data.extend_from_slice(&v.pubkey);
    }
    keccak256(&data)
}

/// Compute the signing root for a message.
///
/// signing_root = hash(message_root, domain)
pub fn compute_signing_root(message_root: B256, domain: B256) -> B256 {
    let mut data = [0u8; 64];
    data[..32].copy_from_slice(message_root.as_slice());
    data[32..].copy_from_slice(domain.as_slice());
    keccak256(&data)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_validators(count: usize) -> Vec<BeaconValidator> {
        (0..count)
            .map(|i| {
                // Create a deterministic BLS pubkey for testing
                let mut pubkey = [0u8; 48];
                pubkey[0] = i as u8 + 1;
                pubkey[47] = i as u8 + 1;
                BeaconValidator::new(pubkey, i as u64)
            })
            .collect()
    }

    #[test]
    fn test_genesis_state() {
        let validators = create_test_validators(4);
        let state = BeaconState::genesis(1000, validators);

        assert_eq!(state.slot, 0);
        assert_eq!(state.validator_count(), 4);
        assert_ne!(state.genesis_validators_root, B256::ZERO);
    }

    #[test]
    fn test_proposer_rotation() {
        let validators = create_test_validators(4);
        let mut state = BeaconState::genesis(1000, validators);

        // Slot 0 -> validator 0
        assert_eq!(state.get_proposer_index(), 0);

        // Slot 1 -> validator 1
        state.advance_slot();
        assert_eq!(state.get_proposer_index(), 1);

        // Slot 4 -> wraps back to validator 0
        state.slot = 4;
        assert_eq!(state.get_proposer_index(), 0);
    }

    #[test]
    fn test_validator_lookup() {
        let validators = create_test_validators(4);
        let addresses: Vec<_> = validators.iter().map(|v| v.address).collect();
        let state = BeaconState::genesis(1000, validators);

        // Lookup by index
        assert!(state.get_validator(0).is_some());
        assert!(state.get_validator(3).is_some());
        assert!(state.get_validator(4).is_none());

        // Lookup by address
        assert!(state.get_validator_by_address(&addresses[0]).is_some());
        assert!(state.get_validator_by_address(&Address::ZERO).is_none());
    }

    #[test]
    fn test_domain_computation() {
        let domain = compute_domain(DomainType::BeaconProposer, B256::ZERO);
        assert_ne!(domain, B256::ZERO);

        // Different domain types produce different domains
        let domain2 = compute_domain(DomainType::Randao, B256::ZERO);
        assert_ne!(domain, domain2);
    }

    #[test]
    fn test_signing_root() {
        let message_root = B256::repeat_byte(0x11);
        let domain = B256::repeat_byte(0x22);

        let signing_root = compute_signing_root(message_root, domain);
        assert_ne!(signing_root, B256::ZERO);

        // Same inputs produce same output
        let signing_root2 = compute_signing_root(message_root, domain);
        assert_eq!(signing_root, signing_root2);
    }

    #[test]
    fn test_public_key_to_address() {
        let pubkey = [1u8; 48];
        let address = public_key_to_address(&pubkey);
        assert_ne!(address, Address::ZERO);
    }
}
