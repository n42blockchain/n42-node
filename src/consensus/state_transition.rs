//! Beacon state transition for BLS-based consensus.
//!
//! This module implements the state transition function that validates
//! and applies beacon blocks to the beacon state.
//!
//! # State Transition Steps
//!
//! 1. Process slots (advance state to block's slot)
//! 2. Process block header (validate proposer, parent, etc.)
//! 3. Verify block signature (BLS)
//! 4. Apply state changes
//!
//! # Trait-Based Design
//!
//! This module uses trait abstractions:
//! - `StateProvider`: Access state slots, validators, domains
//! - `ValidatorProvider`: Access validator info and pubkeys
//! - `SignatureVerifier`: Verify BLS signatures
//!
//! # Simplified vs Full Ethereum
//!
//! This implementation skips several Ethereum PoS features:
//! - Attestation processing (not needed for POA)
//! - Slashing processing (can be added later)
//! - Deposit processing (validators are fixed in POA)
//! - Voluntary exits (can be added later)
//! - Sync committee (not needed for POA)

use super::state::{compute_signing_root, BeaconBlockHeaderLight, BeaconState, DomainType, BLSPubkey};
use super::traits::{
    BlsVerifier, ProposerSelector, SignatureVerifier, StateProvider, ValidatorProvider, ValidatorSignature,
};
use crate::primitives::SignedBeaconBlock;
use alloy_primitives::B256;

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
    #[error("signature has wrong length: expected 96, got {length}")]
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

/// Verify the block signature using BLS.
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

    // Verify BLS signature
    verify_bls_signature(&proposer.pubkey, signing_root, &block.signature)
        .map_err(|_| StateTransitionError::InvalidSignature { proposer_index })
}

/// Verify a BLS signature.
fn verify_bls_signature(
    pubkey: &BLSPubkey,
    message_hash: B256,
    signature_bytes: &[u8],
) -> Result<(), &'static str> {
    // Parse BLS public key
    let Ok(pk) = blst::min_pk::PublicKey::from_bytes(pubkey) else {
        return Err("Invalid public key");
    };

    // Parse BLS signature (96 bytes)
    let Ok(sig) = blst::min_pk::Signature::from_bytes(signature_bytes) else {
        return Err("Invalid signature");
    };

    // Verify
    let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
    if sig.verify(true, message_hash.as_slice(), dst, &[], &pk, true) == blst::BLST_ERROR::BLST_SUCCESS {
        Ok(())
    } else {
        Err("Signature verification failed")
    }
}

/// Create a signed beacon block using BLS (for testing/block production).
///
/// # Arguments
/// * `block` - The unsigned beacon block
/// * `secret_key` - The proposer's BLS secret key
/// * `state` - The current beacon state (for domain)
pub fn sign_beacon_block(
    block: crate::primitives::BeaconBlock,
    secret_key: &blst::min_pk::SecretKey,
    state: &BeaconState,
) -> SignedBeaconBlock {
    // Compute signing root
    let block_root = block.block_root();
    let domain = state.get_domain(DomainType::BeaconProposer);
    let signing_root = compute_signing_root(block_root, domain);

    // Sign with BLS
    let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
    let sig = secret_key.sign(signing_root.as_slice(), dst, &[]);

    // Serialize signature (96 bytes)
    let sig_bytes = sig.to_bytes();

    SignedBeaconBlock::new(block, alloy_primitives::Bytes::copy_from_slice(&sig_bytes))
}

// =============================================================================
// Trait-Based Generic Validation Functions
// =============================================================================

/// Validate a block proposer using trait abstractions.
///
/// This function works with any state that implements `ValidatorProvider` and
/// `ProposerSelector`.
///
/// # Arguments
/// * `state` - Any state implementing required traits
/// * `slot` - The slot being validated
/// * `proposer_index` - The claimed proposer index
///
/// # Returns
/// * `Ok(())` if the proposer is valid
/// * `Err(StateTransitionError)` if validation fails
pub fn validate_proposer<S>(
    state: &S,
    slot: u64,
    proposer_index: u64,
) -> StateTransitionResult<()>
where
    S: ValidatorProvider + ProposerSelector,
{
    // Verify proposer index matches expected
    let expected_proposer = state.get_proposer_index_for_slot(slot);
    if proposer_index != expected_proposer {
        return Err(StateTransitionError::ProposerIndexMismatch {
            slot,
            expected: expected_proposer,
            actual: proposer_index,
        });
    }

    // Verify proposer exists and is active
    let validator_info = state
        .get_validator_info(proposer_index)
        .ok_or(StateTransitionError::UnknownProposer { index: proposer_index })?;

    if !validator_info.is_active {
        return Err(StateTransitionError::ProposerNotActive { index: proposer_index });
    }

    Ok(())
}

/// Verify a block signature using trait abstractions.
///
/// This function works with any combination of state and signature verifier.
///
/// # Arguments
/// * `state` - Any state implementing `ValidatorProvider` and `StateProvider`
/// * `verifier` - Any signature verifier
/// * `proposer_index` - The proposer's validator index
/// * `block_root` - The block root to verify
/// * `signature` - The signature to verify
///
/// # Returns
/// * `Ok(())` if the signature is valid
/// * `Err(StateTransitionError)` if verification fails
pub fn verify_signature_generic<S, V>(
    state: &S,
    verifier: &V,
    proposer_index: u64,
    block_root: B256,
    signature: &ValidatorSignature,
) -> StateTransitionResult<()>
where
    S: ValidatorProvider + StateProvider,
    V: SignatureVerifier,
{
    // Get proposer's public key
    let pubkey = state
        .get_validator_pubkey(proposer_index)
        .ok_or(StateTransitionError::UnknownProposer { index: proposer_index })?;

    // Compute signing root
    let domain = state.get_domain(0); // BeaconProposer domain
    let signing_root = compute_signing_root(block_root, domain);

    // Verify signature
    if !verifier.verify_signature(&pubkey, signing_root.as_slice(), signature) {
        return Err(StateTransitionError::InvalidSignature { proposer_index });
    }

    Ok(())
}

/// Process slots generically for any StateProvider.
///
/// # Arguments
/// * `state` - Any mutable state implementing `StateProvider`
/// * `target_slot` - The target slot to advance to
/// * `max_slots` - Maximum slots to process
///
/// # Returns
/// * `Ok(())` if slots were processed successfully
/// * `Err(StateTransitionError)` if validation fails
pub fn process_slots_generic<S>(
    state: &mut S,
    target_slot: u64,
    max_slots: u64,
) -> StateTransitionResult<()>
where
    S: StateProvider,
{
    let current_slot = state.current_slot();

    // Block must be for a future slot
    if target_slot <= current_slot {
        return Err(StateTransitionError::SlotNotIncreasing {
            block_slot: target_slot,
            state_slot: current_slot,
        });
    }

    // Don't allow skipping too many slots
    let slots_to_process = target_slot - current_slot;
    if slots_to_process > max_slots {
        return Err(StateTransitionError::SlotTooFarAhead {
            block_slot: target_slot,
            state_slot: current_slot,
        });
    }

    // Advance slot by slot
    while state.current_slot() < target_slot {
        state.advance_slot();
    }

    Ok(())
}

/// Context for trait-based block validation.
///
/// This struct bundles together the state and verifier needed for
/// generic block validation.
pub struct ValidationContext<'a, S, V> {
    /// The current state
    pub state: &'a S,
    /// The signature verifier
    pub verifier: &'a V,
    /// Configuration options
    pub config: &'a StateTransitionConfig,
}

impl<'a, S, V> ValidationContext<'a, S, V>
where
    S: ValidatorProvider + ProposerSelector + StateProvider,
    V: SignatureVerifier,
{
    /// Create a new validation context.
    pub fn new(state: &'a S, verifier: &'a V, config: &'a StateTransitionConfig) -> Self {
        Self { state, verifier, config }
    }

    /// Validate a block header (proposer and parent).
    pub fn validate_header(
        &self,
        slot: u64,
        proposer_index: u64,
        parent_root: B256,
        expected_parent_root: B256,
    ) -> StateTransitionResult<()> {
        // Verify parent root
        if parent_root != expected_parent_root {
            return Err(StateTransitionError::ParentRootMismatch {
                expected: expected_parent_root,
                actual: parent_root,
            });
        }

        // Validate proposer
        validate_proposer(self.state, slot, proposer_index)
    }

    /// Validate a block signature.
    pub fn validate_signature(
        &self,
        proposer_index: u64,
        block_root: B256,
        signature: &ValidatorSignature,
    ) -> StateTransitionResult<()> {
        if !self.config.verify_signatures {
            return Ok(());
        }

        verify_signature_generic(
            self.state,
            self.verifier,
            proposer_index,
            block_root,
            signature,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::state::BeaconValidator;
    use crate::primitives::{BeaconBlock, BeaconBlockBody};

    fn create_test_state() -> (BeaconState, Vec<blst::min_pk::SecretKey>) {
        // Create deterministic BLS secret keys for testing
        let secrets: Vec<_> = (0..4)
            .map(|i| {
                let mut ikm = [0u8; 32];
                ikm[0] = i as u8 + 1;
                blst::min_pk::SecretKey::key_gen(&ikm, &[]).unwrap()
            })
            .collect();

        let validators: Vec<_> = secrets
            .iter()
            .enumerate()
            .map(|(i, sk)| {
                let pk = sk.sk_to_pk();
                let pubkey: BLSPubkey = pk.to_bytes();
                BeaconValidator::new(pubkey, i as u64)
            })
            .collect();

        let state = BeaconState::genesis(1000, validators);
        (state, secrets)
    }

    fn create_test_block(slot: u64, proposer_index: u64, parent_root: B256) -> BeaconBlock {
        BeaconBlock::new_without_difficulty(
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

    // =========================================================================
    // Trait-based validation tests
    // =========================================================================

    #[test]
    fn test_validate_proposer_generic() {
        let (state, _) = create_test_state();

        // Valid proposer for slot 0 is validator 0
        assert!(validate_proposer(&state, 0, 0).is_ok());

        // Valid proposer for slot 1 is validator 1
        assert!(validate_proposer(&state, 1, 1).is_ok());

        // Wrong proposer should fail
        assert!(matches!(
            validate_proposer(&state, 1, 0),
            Err(StateTransitionError::ProposerIndexMismatch { .. })
        ));

        // Unknown proposer should fail
        assert!(matches!(
            validate_proposer(&state, 0, 100),
            Err(StateTransitionError::ProposerIndexMismatch { .. })
        ));
    }

    #[test]
    fn test_process_slots_generic() {
        let (mut state, _) = create_test_state();

        // Should advance from slot 0 to slot 5
        assert!(process_slots_generic(&mut state, 5, 32).is_ok());
        assert_eq!(state.current_slot(), 5);

        // Should fail if target is not increasing
        assert!(matches!(
            process_slots_generic(&mut state, 3, 32),
            Err(StateTransitionError::SlotNotIncreasing { .. })
        ));

        // Should fail if too many slots
        assert!(matches!(
            process_slots_generic(&mut state, 100, 10),
            Err(StateTransitionError::SlotTooFarAhead { .. })
        ));
    }

    #[test]
    fn test_validation_context() {
        let (state, _) = create_test_state();
        let verifier = BlsVerifier;
        let config = StateTransitionConfig::default();

        let ctx = ValidationContext::new(&state, &verifier, &config);

        // Validate header with correct parent
        let parent_root = state.latest_block_header.block_root();
        assert!(ctx.validate_header(1, 1, parent_root, parent_root).is_ok());

        // Wrong parent should fail
        assert!(matches!(
            ctx.validate_header(1, 1, B256::ZERO, parent_root),
            Err(StateTransitionError::ParentRootMismatch { .. })
        ));

        // Wrong proposer should fail
        assert!(matches!(
            ctx.validate_header(1, 0, parent_root, parent_root),
            Err(StateTransitionError::ProposerIndexMismatch { .. })
        ));
    }
}
