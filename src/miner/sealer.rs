//! Block Sealing Module
//!
//! This module implements the seal delay calculation and block signing
//! for Clique POA consensus.
//!
//! # Seal Delay (Wiggle)
//!
//! In Clique POA, the seal delay depends on whether the validator is in-turn:
//!
//! - **In-turn**: No delay, produce immediately when timestamp is reached
//! - **Out-of-turn**: Random delay to give in-turn validator priority
//!
//! The wiggle delay formula:
//! ```text
//! wiggle_base = (num_signers / 2 + 1) * 500ms
//! delay = random(0..wiggle_base)
//! ```
//!
//! # Block Signing
//!
//! Blocks are signed using secp256k1 ECDSA with recoverable signatures (65 bytes).
//! The signature is computed over the block's seal hash (header hash without signature).

use crate::primitives::{BeaconBlock, SignedBeaconBlock};
use alloy_primitives::{Bytes, B256};
use secp256k1::rand::Rng;
use secp256k1::{ecdsa::RecoverableSignature, Message, Secp256k1, SecretKey};
use std::time::Duration;

/// Wiggle time unit (500ms) - base delay per signer position.
pub const WIGGLE_TIME_MS: u64 = 500;

/// Mining environment for seal delay calculation.
#[derive(Debug, Clone)]
pub struct MiningEnvironment {
    /// Target timestamp for the block.
    pub target_timestamp: u64,

    /// Current timestamp.
    pub current_timestamp: u64,

    /// Whether this validator is in-turn for this slot.
    pub in_turn: bool,

    /// Total number of signers/validators.
    pub num_signers: usize,
}

impl MiningEnvironment {
    /// Create a new mining environment.
    pub fn new(
        target_timestamp: u64,
        current_timestamp: u64,
        in_turn: bool,
        num_signers: usize,
    ) -> Self {
        Self {
            target_timestamp,
            current_timestamp,
            in_turn,
            num_signers,
        }
    }
}

/// Calculate the seal delay for block production.
///
/// # Returns
/// - For in-turn validators: delay until target timestamp
/// - For out-of-turn validators: delay until target timestamp + random wiggle
///
/// # Example
/// ```ignore
/// let env = MiningEnvironment::new(1700000008, 1700000000, false, 3);
/// let delay = calculate_seal_delay(&env);
/// // delay = 8 seconds + random(0..1000ms)
/// ```
pub fn calculate_seal_delay(env: &MiningEnvironment) -> Duration {
    // Base delay: wait until target timestamp
    let base_delay_secs = if env.target_timestamp > env.current_timestamp {
        env.target_timestamp - env.current_timestamp
    } else {
        0
    };

    let base_delay = Duration::from_secs(base_delay_secs);

    if env.in_turn {
        // In-turn: no wiggle, produce at exact timestamp
        base_delay
    } else {
        // Out-of-turn: add random wiggle delay
        let wiggle = calculate_wiggle_delay(env.num_signers);
        base_delay + wiggle
    }
}

/// Calculate random wiggle delay for out-of-turn validators.
///
/// Formula: random(0..(num_signers / 2 + 1) * 500ms)
fn calculate_wiggle_delay(num_signers: usize) -> Duration {
    if num_signers == 0 {
        return Duration::ZERO;
    }

    let wiggle_base_ms = ((num_signers / 2) + 1) as u64 * WIGGLE_TIME_MS;
    let random_ms = secp256k1::rand::thread_rng().gen_range(0..wiggle_base_ms);

    Duration::from_millis(random_ms)
}

/// Calculate wiggle delay deterministically (for testing).
pub fn calculate_wiggle_delay_deterministic(num_signers: usize, seed: u64) -> Duration {
    if num_signers == 0 {
        return Duration::ZERO;
    }

    let wiggle_base_ms = ((num_signers / 2) + 1) as u64 * WIGGLE_TIME_MS;
    let random_ms = seed % wiggle_base_ms;

    Duration::from_millis(random_ms)
}

/// Seal (sign) a beacon block.
///
/// Creates a signed beacon block with a secp256k1 ECDSA signature.
/// The signature is 65 bytes: [r(32) | s(32) | v(1)]
///
/// # Arguments
/// * `block` - The unsigned beacon block
/// * `secret_key` - The validator's signing key
///
/// # Returns
/// A signed beacon block with the signature field populated.
pub fn seal_block(block: BeaconBlock, secret_key: &SecretKey) -> SignedBeaconBlock {
    let secp = Secp256k1::signing_only();

    // Compute seal hash (block root without signature)
    let seal_hash = compute_seal_hash(&block);

    // Create message from hash
    let msg = Message::from_digest(seal_hash.0);

    // Sign with recoverable signature
    let sig = secp.sign_ecdsa_recoverable(&msg, secret_key);

    // Serialize to 65 bytes [r | s | v]
    let sig_bytes = serialize_recoverable_signature(&sig);

    SignedBeaconBlock::new(block, sig_bytes)
}

/// Compute the seal hash for signing.
///
/// This is the block root (hash of block contents without signature).
fn compute_seal_hash(block: &BeaconBlock) -> B256 {
    block.block_root()
}

/// Serialize a recoverable signature to 65 bytes.
///
/// Format: [r(32) | s(32) | recovery_id(1)]
fn serialize_recoverable_signature(sig: &RecoverableSignature) -> Bytes {
    let (recovery_id, sig_data) = sig.serialize_compact();

    let mut sig_bytes = [0u8; 65];
    sig_bytes[..64].copy_from_slice(&sig_data);
    // RecoveryId can be converted to i32 via Into trait
    sig_bytes[64] = i32::from(recovery_id) as u8;

    Bytes::copy_from_slice(&sig_bytes)
}

/// Verify a block signature.
///
/// # Arguments
/// * `block` - The signed beacon block to verify
/// * `expected_signer` - The expected signer's public key
///
/// # Returns
/// `true` if the signature is valid and matches the expected signer.
pub fn verify_block_signature(
    block: &SignedBeaconBlock,
    expected_signer: &secp256k1::PublicKey,
) -> bool {
    let secp = Secp256k1::verification_only();

    // Get seal hash
    let seal_hash = compute_seal_hash(&block.message);
    let msg = Message::from_digest(seal_hash.0);

    // Parse signature
    let sig_bytes = block.signature.as_ref();
    if sig_bytes.len() != 65 {
        return false;
    }

    // Try to parse as recoverable signature
    let recovery_id = match secp256k1::ecdsa::RecoveryId::try_from(sig_bytes[64] as i32) {
        Ok(id) => id,
        Err(_) => return false,
    };

    let sig = match RecoverableSignature::from_compact(&sig_bytes[..64], recovery_id) {
        Ok(s) => s,
        Err(_) => return false,
    };

    // Recover public key from signature
    let recovered_pubkey = match secp.recover_ecdsa(&msg, &sig) {
        Ok(pk) => pk,
        Err(_) => return false,
    };

    // Compare with expected signer
    recovered_pubkey == *expected_signer
}

/// Recover the signer's public key from a signed block.
///
/// # Returns
/// The public key of the signer, or None if recovery fails.
pub fn recover_signer(block: &SignedBeaconBlock) -> Option<secp256k1::PublicKey> {
    let secp = Secp256k1::verification_only();

    let seal_hash = compute_seal_hash(&block.message);
    let msg = Message::from_digest(seal_hash.0);

    let sig_bytes = block.signature.as_ref();
    if sig_bytes.len() != 65 {
        return None;
    }

    let recovery_id = secp256k1::ecdsa::RecoveryId::try_from(sig_bytes[64] as i32).ok()?;
    let sig = RecoverableSignature::from_compact(&sig_bytes[..64], recovery_id).ok()?;

    secp.recover_ecdsa(&msg, &sig).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::BeaconBlockBody;

    fn create_test_block(slot: u64) -> BeaconBlock {
        BeaconBlock::new(
            slot,
            0,
            B256::ZERO,
            B256::ZERO,
            BeaconBlockBody::default(),
            2, // in-turn difficulty
        )
    }

    #[test]
    fn test_in_turn_no_wiggle() {
        let env = MiningEnvironment::new(100, 95, true, 3);
        let delay = calculate_seal_delay(&env);

        // In-turn should have exactly 5 seconds delay (no wiggle)
        assert_eq!(delay, Duration::from_secs(5));
    }

    #[test]
    fn test_out_of_turn_has_wiggle() {
        let env = MiningEnvironment::new(100, 95, false, 3);
        let delay = calculate_seal_delay(&env);

        // Out-of-turn should have at least 5 seconds delay
        assert!(delay >= Duration::from_secs(5));

        // Maximum wiggle for 3 signers: (3/2 + 1) * 500ms = 1000ms
        assert!(delay <= Duration::from_secs(5) + Duration::from_millis(1000));
    }

    #[test]
    fn test_wiggle_formula() {
        // Test wiggle base calculation
        // num_signers=3: (3/2 + 1) * 500 = 1000ms
        let delay = calculate_wiggle_delay_deterministic(3, 500);
        assert_eq!(delay, Duration::from_millis(500));

        // num_signers=5: (5/2 + 1) * 500 = 1500ms
        let delay = calculate_wiggle_delay_deterministic(5, 1000);
        assert_eq!(delay, Duration::from_millis(1000));
    }

    #[test]
    fn test_seal_and_verify() {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let public_key = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);

        let block = create_test_block(1);
        let signed = seal_block(block, &secret_key);

        // Verify signature
        assert!(verify_block_signature(&signed, &public_key));
    }

    #[test]
    fn test_recover_signer() {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let public_key = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);

        let block = create_test_block(2);
        let signed = seal_block(block, &secret_key);

        let recovered = recover_signer(&signed).unwrap();
        assert_eq!(recovered, public_key);
    }

    #[test]
    fn test_invalid_signature_fails() {
        let secp = Secp256k1::new();
        let secret_key1 = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let secret_key2 = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let public_key2 = secp256k1::PublicKey::from_secret_key(&secp, &secret_key2);

        let block = create_test_block(3);
        // Sign with key1, verify against key2
        let signed = seal_block(block, &secret_key1);

        assert!(!verify_block_signature(&signed, &public_key2));
    }

    #[test]
    fn test_past_timestamp_no_negative_delay() {
        // If target timestamp is in the past, delay should be 0 + wiggle
        let env = MiningEnvironment::new(90, 100, true, 3);
        let delay = calculate_seal_delay(&env);

        assert_eq!(delay, Duration::ZERO);
    }
}
