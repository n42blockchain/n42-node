//! Consensus trait abstractions for BLS-based consensus.
//!
//! This module provides traits that abstract over consensus mechanisms
//! using BLS signatures for validator authentication.

use alloy_primitives::{Address, B256};

/// Information about a validator that can be used for consensus operations.
#[derive(Clone, Debug)]
pub struct ValidatorInfo {
    /// Validator index in the set.
    pub index: u64,
    /// Whether the validator is currently active.
    pub is_active: bool,
    /// Optional Ethereum address (derived from pubkey).
    pub address: Option<Address>,
}

/// BLS signature (96 bytes).
#[derive(Clone, Debug)]
pub struct ValidatorSignature(pub Vec<u8>);

impl ValidatorSignature {
    /// Create a new BLS signature from bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Get the signature bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// BLS public key (48 bytes).
#[derive(Clone, Debug)]
pub struct ValidatorPubkey(pub [u8; 48]);

impl ValidatorPubkey {
    /// Create a new BLS public key from bytes.
    pub fn new(bytes: [u8; 48]) -> Self {
        Self(bytes)
    }

    /// Get the public key bytes.
    pub fn as_bytes(&self) -> &[u8; 48] {
        &self.0
    }
}

/// Trait for accessing validator information.
///
/// This abstracts over different validator storage mechanisms
/// using BLS keys for authentication.
pub trait ValidatorProvider {
    /// Get the total number of validators.
    fn validator_count(&self) -> usize;

    /// Get validator info by index.
    fn get_validator_info(&self, index: u64) -> Option<ValidatorInfo>;

    /// Get validator BLS public key by index.
    fn get_validator_pubkey(&self, index: u64) -> Option<ValidatorPubkey>;

    /// Get validator by address.
    fn get_validator_by_address(&self, address: &Address) -> Option<ValidatorInfo> {
        let _ = address;
        None
    }

    /// Check if a validator is active.
    fn is_validator_active(&self, index: u64) -> bool {
        self.get_validator_info(index)
            .map(|v| v.is_active)
            .unwrap_or(false)
    }
}

/// Trait for proposer selection.
pub trait ProposerSelector {
    /// Get the proposer index for a given slot.
    fn get_proposer_index_for_slot(&self, slot: u64) -> u64;

    /// Get the proposer index for the current slot.
    fn get_proposer_index(&self) -> u64;

    /// Check if a validator is the proposer for a slot.
    fn is_proposer(&self, slot: u64, validator_index: u64) -> bool {
        self.get_proposer_index_for_slot(slot) == validator_index
    }
}

/// Trait for state operations.
pub trait StateProvider: ValidatorProvider + ProposerSelector {
    /// Get the current slot.
    fn current_slot(&self) -> u64;

    /// Advance to the next slot.
    fn advance_slot(&mut self);

    /// Get the domain for signing operations.
    fn get_domain(&self, domain_type: u32) -> B256;

    /// Compute the state root.
    fn compute_state_root(&self) -> B256;

    /// Get the genesis validators root.
    fn genesis_validators_root(&self) -> B256;
}

/// Trait for BLS signature verification.
pub trait SignatureVerifier {
    /// Verify a BLS signature against a message and public key.
    fn verify_signature(
        &self,
        pubkey: &ValidatorPubkey,
        message: &[u8],
        signature: &ValidatorSignature,
    ) -> bool;
}

/// BLS signature verifier.
#[derive(Debug, Clone, Copy, Default)]
pub struct BlsVerifier;

impl SignatureVerifier for BlsVerifier {
    fn verify_signature(
        &self,
        pubkey: &ValidatorPubkey,
        message: &[u8],
        signature: &ValidatorSignature,
    ) -> bool {
        // Use BLS verification
        let Ok(pk) = blst::min_pk::PublicKey::from_bytes(pubkey.as_bytes()) else {
            return false;
        };
        let Ok(sig) = blst::min_pk::Signature::from_bytes(signature.as_bytes()) else {
            return false;
        };
        let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
        sig.verify(true, message, dst, &[], &pk, true) == blst::BLST_ERROR::BLST_SUCCESS
    }
}
