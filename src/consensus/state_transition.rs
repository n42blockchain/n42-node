//! Beacon state transition for POA consensus.
//!
//! This module implements the state transition function that validates
//! and applies beacon blocks to the beacon state.
//!
//! # State Transition Steps
//!
//! 1. Process slots (advance state to block's slot)
//! 2. Process block header (validate proposer, parent, etc.)
//! 3. Verify block signature
//! 4. Apply state changes
//!
//! # Simplified vs Full Ethereum
//!
//! This implementation skips several Ethereum PoS features:
//! - Attestation processing (not needed for POA)
//! - Slashing processing (can be added later)
//! - Deposit processing (validators are fixed)
//! - Voluntary exits (can be added later)
//! - Sync committee (not needed for POA)

use super::state::{compute_signing_root, BeaconBlockHeaderLight, BeaconState, DomainType};
use crate::primitives::SignedBeaconBlock;
use alloy_primitives::B256;
use secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1};

/// Errors that can occur during state transition.
#[derive(Debug, Clone, thiserror::Error)]
pub enum StateTransitionError {
    /// Block slot is not greater than state slot.
    #[error("block slot {block_slot} must be greater than state slot {state_slot}")]
    SlotNotIncreasing { block_slot: u64, state_slot: u64 },

    /// Block slot is too far in the future.
    #[error("block slot {block_slot} is too far ahead of state slot {state_slot}")]
    SlotTooFarAhead { block_slot: u64, state_slot: u64 },

    /// Parent root doesn't match.
    #[error("parent root mismatch: expected {expected}, got {actual}")]
    ParentRootMismatch { expected: B256, actual: B256 },

    /// Proposer index doesn't match expected.
    #[error("proposer index mismatch at slot {slot}: expected {expected}, got {actual}")]
    ProposerIndexMismatch { slot: u64, expected: u64, actual: u64 },

    /// Proposer is not active.
    #[error("proposer {index} is not active")]
    ProposerNotActive { index: u64 },

    /// Invalid block signature.
    #[error("invalid block signature from proposer {proposer_index}")]
    InvalidSignature { proposer_index: u64 },

    /// Signature has wrong length.
    #[error("signature has wrong length: expected 64 or 65, got {length}")]
    InvalidSignatureLength { length: usize },

    /// Unknown proposer.
    #[error("unknown proposer index: {index}")]
    UnknownProposer { index: u64 },
}

/// Result type for state transitions.
pub type StateTransitionResult<T> = Result<T, StateTransitionError>;

/// Configuration for state transition.
#[derive(Debug, Clone)]
pub struct StateTransitionConfig {
    /// Maximum slots to process in one transition.
    pub max_slots_per_transition: u64,
    /// Whether to verify signatures (can be disabled for testing).
    pub verify_signatures: bool,
}

impl Default for StateTransitionConfig {
    fn default() -> Self {
        Self {
            max_slots_per_transition: 32,
            verify_signatures: true,
        }
    }
}

/// Process a beacon block and update the state.
///
/// This is the main entry point for state transitions.
///
/// # Arguments
/// * `state` - The current beacon state (will be mutated)
/// * `block` - The signed beacon block to process
/// * `config` - Configuration options
///
/// # Returns
/// * `Ok(())` if the block was successfully processed
/// * `Err(StateTransitionError)` if validation failed
pub fn process_block(
    state: &mut BeaconState,
    block: &SignedBeaconBlock,
    config: &StateTransitionConfig,
) -> StateTransitionResult<()> {
    // 1. Process slots (advance state to block's slot)
    process_slots(state, block.slot(), config)?;

    // 2. Process block header
    process_block_header(state, block)?;

    // 3. Verify block signature
    if config.verify_signatures {
        verify_block_signature(state, block)?;
    }

    // 4. Update state with new block header
    let header = BeaconBlockHeaderLight {
        slot: block.message.slot,
        proposer_index: block.message.proposer_index,
        parent_root: block.message.parent_root,
        state_root: B256::ZERO, // Will be updated after full state computation
        body_root: block.message.body.body_root(),
    };
    state.set_latest_block_header(header);

    Ok(())
}

/// Process slots to advance state to target slot.
fn process_slots(
    state: &mut BeaconState,
    target_slot: u64,
    config: &StateTransitionConfig,
) -> StateTransitionResult<()> {
    // Block must be for a future slot
    if target_slot <= state.slot {
        return Err(StateTransitionError::SlotNotIncreasing {
            block_slot: target_slot,
            state_slot: state.slot,
        });
    }

    // Don't allow skipping too many slots
    let slots_to_process = target_slot - state.slot;
    if slots_to_process > config.max_slots_per_transition {
        return Err(StateTransitionError::SlotTooFarAhead {
            block_slot: target_slot,
            state_slot: state.slot,
        });
    }

    // Advance slot by slot
    while state.slot < target_slot {
        // Store current state root in history
        let index = (state.slot as usize) % state.state_roots.len();
        state.state_roots[index] = state.compute_state_root();

        state.advance_slot();

        // In full Ethereum, epoch transitions happen here
        // For POA, we skip this complexity
    }

    Ok(())
}

/// Process and validate the block header.
fn process_block_header(
    state: &BeaconState,
    block: &SignedBeaconBlock,
) -> StateTransitionResult<()> {
    // Verify parent root matches latest block
    let expected_parent_root = state.latest_block_header.block_root();
    if block.parent_root() != expected_parent_root {
        return Err(StateTransitionError::ParentRootMismatch {
            expected: expected_parent_root,
            actual: block.parent_root(),
        });
    }

    // Verify proposer index matches expected (round-robin)
    let expected_proposer = state.get_proposer_index_for_slot(block.slot());
    if block.message.proposer_index != expected_proposer {
        return Err(StateTransitionError::ProposerIndexMismatch {
            slot: block.slot(),
            expected: expected_proposer,
            actual: block.message.proposer_index,
        });
    }

    // Verify proposer exists and is active
    let proposer = state
        .get_validator(block.message.proposer_index)
        .ok_or(StateTransitionError::UnknownProposer {
            index: block.message.proposer_index,
        })?;

    if !proposer.active {
        return Err(StateTransitionError::ProposerNotActive {
            index: block.message.proposer_index,
        });
    }

    Ok(())
}

/// Verify the block signature.
///
/// For POA, we use secp256k1 ECDSA signatures instead of BLS.
fn verify_block_signature(
    state: &BeaconState,
    block: &SignedBeaconBlock,
) -> StateTransitionResult<()> {
    let proposer_index = block.message.proposer_index;

    // Get proposer's public key
    let proposer = state
        .get_validator(proposer_index)
        .ok_or(StateTransitionError::UnknownProposer { index: proposer_index })?;

    // Compute signing root
    let block_root = block.block_root();
    let domain = state.get_domain(DomainType::BeaconProposer);
    let signing_root = compute_signing_root(block_root, domain);

    // Verify signature
    verify_secp256k1_signature(&proposer.pubkey, signing_root, &block.signature)
        .map_err(|_| StateTransitionError::InvalidSignature { proposer_index })
}

/// Verify a secp256k1 ECDSA signature.
fn verify_secp256k1_signature(
    pubkey: &PublicKey,
    message_hash: B256,
    signature_bytes: &[u8],
) -> Result<(), secp256k1::Error> {
    let secp = Secp256k1::verification_only();

    // Parse signature (64 bytes for compact format, 65 for recoverable)
    let sig = match signature_bytes.len() {
        64 => Signature::from_compact(signature_bytes)?,
        65 => Signature::from_compact(&signature_bytes[..64])?, // Ignore recovery byte
        _ => return Err(secp256k1::Error::InvalidSignature),
    };

    // Create message from hash
    let msg = Message::from_digest(message_hash.0);

    // Verify
    secp.verify_ecdsa(&msg, &sig, pubkey)
}

/// Create a signed beacon block (for testing/block production).
///
/// # Arguments
/// * `block` - The unsigned beacon block
/// * `secret_key` - The proposer's secret key
/// * `state` - The current beacon state (for domain)
pub fn sign_beacon_block(
    block: crate::primitives::BeaconBlock,
    secret_key: &secp256k1::SecretKey,
    state: &BeaconState,
) -> SignedBeaconBlock {
    let secp = Secp256k1::signing_only();

    // Compute signing root
    let block_root = block.block_root();
    let domain = state.get_domain(DomainType::BeaconProposer);
    let signing_root = compute_signing_root(block_root, domain);

    // Sign
    let msg = Message::from_digest(signing_root.0);
    let sig = secp.sign_ecdsa(&msg, secret_key);

    // Serialize signature (compact format)
    let sig_bytes = sig.serialize_compact();

    SignedBeaconBlock::new(block, alloy_primitives::Bytes::copy_from_slice(&sig_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::state::BeaconValidator;
    use crate::primitives::{BeaconBlock, BeaconBlockBody};
    use secp256k1::SecretKey;

    fn create_test_state() -> (BeaconState, Vec<SecretKey>) {
        let secp = Secp256k1::new();
        let secrets: Vec<_> = (0..4)
            .map(|i| SecretKey::from_slice(&[i as u8 + 1; 32]).unwrap())
            .collect();

        let validators: Vec<_> = secrets
            .iter()
            .enumerate()
            .map(|(i, sk)| {
                let pubkey = PublicKey::from_secret_key(&secp, sk);
                BeaconValidator::new(pubkey, i as u64)
            })
            .collect();

        let state = BeaconState::genesis(1000, validators);
        (state, secrets)
    }

    fn create_test_block(slot: u64, proposer_index: u64, parent_root: B256) -> BeaconBlock {
        BeaconBlock::new(
            slot,
            proposer_index,
            parent_root,
            B256::ZERO,
            BeaconBlockBody::default(),
        )
    }

    #[test]
    fn test_process_valid_block() {
        let (mut state, secrets) = create_test_state();
        let config = StateTransitionConfig::default();

        // Create block for slot 1, proposer 1
        let parent_root = state.latest_block_header.block_root();
        let block = create_test_block(1, 1, parent_root);
        let signed_block = sign_beacon_block(block, &secrets[1], &state);

        // Process should succeed
        let result = process_block(&mut state, &signed_block, &config);
        assert!(result.is_ok(), "Expected Ok, got {:?}", result);

        // State should be updated
        assert_eq!(state.slot, 1);
        assert_eq!(state.latest_block_header.proposer_index, 1);
    }

    #[test]
    fn test_reject_wrong_proposer() {
        let (mut state, secrets) = create_test_state();
        let config = StateTransitionConfig::default();

        // Create block with wrong proposer (should be 1, using 0)
        let parent_root = state.latest_block_header.block_root();
        let block = create_test_block(1, 0, parent_root); // Wrong proposer!
        let signed_block = sign_beacon_block(block, &secrets[0], &state);

        let result = process_block(&mut state, &signed_block, &config);
        assert!(matches!(
            result,
            Err(StateTransitionError::ProposerIndexMismatch { .. })
        ));
    }

    #[test]
    fn test_reject_wrong_parent() {
        let (mut state, secrets) = create_test_state();
        let config = StateTransitionConfig::default();

        // Create block with wrong parent root
        let block = create_test_block(1, 1, B256::repeat_byte(0xFF)); // Wrong parent!
        let signed_block = sign_beacon_block(block, &secrets[1], &state);

        let result = process_block(&mut state, &signed_block, &config);
        assert!(matches!(
            result,
            Err(StateTransitionError::ParentRootMismatch { .. })
        ));
    }

    #[test]
    fn test_reject_invalid_signature() {
        let (mut state, secrets) = create_test_state();
        let config = StateTransitionConfig::default();

        // Create block signed by wrong key
        let parent_root = state.latest_block_header.block_root();
        let block = create_test_block(1, 1, parent_root);
        let signed_block = sign_beacon_block(block, &secrets[0], &state); // Wrong key!

        let result = process_block(&mut state, &signed_block, &config);
        assert!(matches!(
            result,
            Err(StateTransitionError::InvalidSignature { .. })
        ));
    }

    #[test]
    fn test_reject_slot_not_increasing() {
        let (mut state, secrets) = create_test_state();
        let config = StateTransitionConfig::default();

        // Try to process block for current slot (0)
        let parent_root = state.latest_block_header.block_root();
        let block = create_test_block(0, 0, parent_root);
        let signed_block = sign_beacon_block(block, &secrets[0], &state);

        let result = process_block(&mut state, &signed_block, &config);
        assert!(matches!(
            result,
            Err(StateTransitionError::SlotNotIncreasing { .. })
        ));
    }

    #[test]
    fn test_skip_signature_verification() {
        let (mut state, _) = create_test_state();
        let config = StateTransitionConfig {
            verify_signatures: false, // Disable signature verification
            ..Default::default()
        };

        // Create block with invalid signature
        let parent_root = state.latest_block_header.block_root();
        let block = create_test_block(1, 1, parent_root);
        let signed_block = SignedBeaconBlock::new(block, alloy_primitives::Bytes::new());

        // Should succeed without signature verification
        let result = process_block(&mut state, &signed_block, &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_process_multiple_blocks() {
        let (mut state, secrets) = create_test_state();
        let config = StateTransitionConfig::default();

        // Process several blocks
        for slot in 1..=4 {
            let proposer_index = (slot % 4) as u64;
            let parent_root = state.latest_block_header.block_root();
            let block = create_test_block(slot, proposer_index, parent_root);
            let signed_block = sign_beacon_block(block, &secrets[proposer_index as usize], &state);

            let result = process_block(&mut state, &signed_block, &config);
            assert!(result.is_ok(), "Block {} failed: {:?}", slot, result);
        }

        assert_eq!(state.slot, 4);
    }
}
