//! Block Sealing Module
//!
//! This module implements the seal delay calculation and block signing
//! for POA consensus with BLS signatures.
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
//! Blocks are signed using BLS signatures (96 bytes).
//! The signature is computed over the block's seal hash (header hash without signature).

use crate::primitives::{BeaconBlock, SignedBeaconBlock};
use alloy_primitives::{Bytes, B256};
use std::time::Duration;

/// Wiggle time unit (500ms) - base delay per signer position.
pub const WIGGLE_TIME_MS: u64 = 500;

/// BLS public key type (48 bytes).
pub type BLSPubkey = [u8; 48];

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
    use std::time::{SystemTime, UNIX_EPOCH};

    if num_signers == 0 {
        return Duration::ZERO;
    }

    let wiggle_base_ms = ((num_signers / 2) + 1) as u64 * WIGGLE_TIME_MS;

    // Simple random using system time as seed
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    let random_ms = seed % wiggle_base_ms;

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

/// Seal (sign) a beacon block using BLS.
///
/// Creates a signed beacon block with a BLS signature.
/// The signature is 96 bytes.
///
/// # Arguments
/// * `block` - The unsigned beacon block
/// * `secret_key` - The validator's BLS signing key
///
/// # Returns
/// A signed beacon block with the signature field populated.
pub fn seal_block(block: BeaconBlock, secret_key: &blst::min_pk::SecretKey) -> SignedBeaconBlock {
    // Compute seal hash (block root without signature)
    let seal_hash = compute_seal_hash(&block);

    // Sign with BLS
    let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
    let sig = secret_key.sign(seal_hash.as_slice(), dst, &[]);

    // Serialize signature (96 bytes)
    let sig_bytes = sig.to_bytes();

    SignedBeaconBlock::new(block, Bytes::copy_from_slice(&sig_bytes))
}

/// Compute the seal hash for signing.
///
/// This is the block root (hash of block contents without signature).
fn compute_seal_hash(block: &BeaconBlock) -> B256 {
    block.block_root()
}

/// Verify a block signature using BLS.
///
/// # Arguments
/// * `block` - The signed beacon block to verify
/// * `expected_signer` - The expected signer's BLS public key
///
/// # Returns
/// `true` if the signature is valid and matches the expected signer.
pub fn verify_block_signature(
    block: &SignedBeaconBlock,
    expected_signer: &BLSPubkey,
) -> bool {
    // Get seal hash
    let seal_hash = compute_seal_hash(&block.message);

    // Parse BLS public key
    let Ok(pk) = blst::min_pk::PublicKey::from_bytes(expected_signer) else {
        return false;
    };

    // Parse BLS signature (96 bytes)
    let sig_bytes = block.signature.as_ref();
    let Ok(sig) = blst::min_pk::Signature::from_bytes(sig_bytes) else {
        return false;
    };

    // Verify
    let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
    sig.verify(true, seal_hash.as_slice(), dst, &[], &pk, true) == blst::BLST_ERROR::BLST_SUCCESS
}

/// Recover the signer's public key from a signed block.
///
/// Note: BLS does not support key recovery from signature like secp256k1.
/// This function returns None for BLS signatures.
/// You must have the expected public key to verify.
///
/// # Returns
/// None - BLS does not support key recovery.
pub fn recover_signer(_block: &SignedBeaconBlock) -> Option<BLSPubkey> {
    // BLS signatures do not support key recovery
    // The verifier must have the public key beforehand
    None
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

    fn create_test_keypair() -> (blst::min_pk::SecretKey, BLSPubkey) {
        let ikm = [1u8; 32];
        let sk = blst::min_pk::SecretKey::key_gen(&ikm, &[]).unwrap();
        let pk = sk.sk_to_pk();
        let pubkey: BLSPubkey = pk.to_bytes();
        (sk, pubkey)
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
        let (secret_key, public_key) = create_test_keypair();

        let block = create_test_block(1);
        let signed = seal_block(block, &secret_key);

        // Verify signature
        assert!(verify_block_signature(&signed, &public_key));
    }

    #[test]
    fn test_invalid_signature_fails() {
        let (secret_key1, _) = create_test_keypair();

        let mut ikm2 = [2u8; 32];
        ikm2[0] = 2;
        let sk2 = blst::min_pk::SecretKey::key_gen(&ikm2, &[]).unwrap();
        let pk2 = sk2.sk_to_pk();
        let public_key2: BLSPubkey = pk2.to_bytes();

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
