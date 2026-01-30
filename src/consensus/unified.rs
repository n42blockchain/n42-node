//! Unified consensus interface with BLS signatures.
//!
//! This module provides a unified interface for consensus using BLS signatures.
//!
//! # Usage
//!
//! ```ignore
//! use n42_node::consensus::unified::{ConsensusState, ConsensusVerifier};
//!
//! fn validate<S: ConsensusState, V: ConsensusVerifier>(
//!     state: &S,
//!     verifier: &V,
//!     slot: u64,
//!     proposer: u64,
//! ) -> Result<(), Error> {
//!     // Validation logic here
//! }
//! ```

use super::traits::{
    ProposerSelector, SignatureVerifier, StateProvider, ValidatorProvider,
    ValidatorPubkey, ValidatorSignature,
};

// Re-export traits for convenience
pub use super::traits::BlsVerifier;

/// Unified consensus state trait.
///
/// This is a convenience trait that combines all required state traits.
pub trait ConsensusState: ValidatorProvider + ProposerSelector + StateProvider {}

// Blanket implementation for any type that implements all required traits
impl<T> ConsensusState for T where T: ValidatorProvider + ProposerSelector + StateProvider {}

/// Unified consensus verifier trait.
///
/// This is an alias for SignatureVerifier for clarity.
pub trait ConsensusVerifier: SignatureVerifier {}

// Blanket implementation
impl<T> ConsensusVerifier for T where T: SignatureVerifier {}

/// Default verifier type (BLS).
pub type DefaultVerifier = BlsVerifier;

/// Create a default BLS verifier.
pub fn default_verifier() -> DefaultVerifier {
    DefaultVerifier::default()
}

/// Helper to create a BLS signature.
pub fn create_signature(bytes: &[u8]) -> ValidatorSignature {
    ValidatorSignature::new(bytes.to_vec())
}

/// Helper to create a BLS pubkey.
pub fn create_pubkey(bytes: &[u8]) -> Option<ValidatorPubkey> {
    if bytes.len() == 48 {
        let mut arr = [0u8; 48];
        arr.copy_from_slice(bytes);
        Some(ValidatorPubkey::new(arr))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_verifier() {
        let _verifier = default_verifier();
    }

    #[test]
    fn test_create_signature() {
        let bytes = vec![1, 2, 3, 4];
        let sig = create_signature(&bytes);
        assert_eq!(sig.as_bytes(), &[1, 2, 3, 4]);
    }

    #[test]
    fn test_create_pubkey() {
        // BLS pubkey (48 bytes)
        let bls_bytes = vec![0u8; 48];
        let pk = create_pubkey(&bls_bytes);
        assert!(pk.is_some());

        // Wrong size for BLS
        let wrong_bytes = vec![0u8; 32];
        let invalid_pk = create_pubkey(&wrong_bytes);
        assert!(invalid_pk.is_none());
    }
}
