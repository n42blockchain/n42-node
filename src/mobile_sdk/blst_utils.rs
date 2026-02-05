//! BLS12-381 key generation utilities for mobile SDK.
//!
//! Provides functions for generating BLS key pairs used by validators
//! for signing attestations and other consensus messages.

use blst::min_pk::SecretKey;
use rand::RngCore;

/// Generate a new BLS12-381 key pair.
///
/// Returns the private key and public key as hex-encoded strings.
///
/// # Returns
///
/// A tuple of (private_key_hex, public_key_hex)
///
/// # Example
///
/// ```
/// use n42_node::mobile_sdk::blst_utils::generate_bls12_381_keypair;
///
/// let (privkey, pubkey) = generate_bls12_381_keypair().unwrap();
/// assert_eq!(privkey.len(), 64);  // 32 bytes = 64 hex chars
/// assert_eq!(pubkey.len(), 96);   // 48 bytes = 96 hex chars
/// ```
pub fn generate_bls12_381_keypair() -> eyre::Result<(String, String)> {
    let mut rng = rand::thread_rng();
    let mut ikm = [0u8; 32];
    rng.fill_bytes(&mut ikm);

    let sk = SecretKey::key_gen(&ikm, &[])
        .map_err(|e| eyre::eyre!("SecretKey::key_gen() error {:?}", e))?;

    let pk = sk.sk_to_pk();

    let privkey_hex = hex::encode(sk.to_bytes());
    let pubkey_hex = hex::encode(pk.to_bytes());

    Ok((privkey_hex, pubkey_hex))
}

/// Generate a BLS12-381 key pair from a seed.
///
/// This is useful for deterministic key generation from a known seed.
///
/// # Arguments
///
/// * `seed` - A 32-byte seed for key generation
///
/// # Returns
///
/// A tuple of (private_key_hex, public_key_hex)
pub fn generate_bls12_381_keypair_from_seed(seed: &[u8; 32]) -> eyre::Result<(String, String)> {
    let sk = SecretKey::key_gen(seed, &[])
        .map_err(|e| eyre::eyre!("SecretKey::key_gen() error {:?}", e))?;

    let pk = sk.sk_to_pk();

    let privkey_hex = hex::encode(sk.to_bytes());
    let pubkey_hex = hex::encode(pk.to_bytes());

    Ok((privkey_hex, pubkey_hex))
}

/// Derive public key from a private key.
///
/// # Arguments
///
/// * `private_key_hex` - Private key as hex string (with or without 0x prefix)
///
/// # Returns
///
/// The public key as a hex-encoded string.
pub fn derive_pubkey_from_privkey(private_key_hex: &str) -> eyre::Result<String> {
    let private_key_hex = private_key_hex
        .strip_prefix("0x")
        .unwrap_or(private_key_hex);

    let sk_bytes =
        hex::decode(private_key_hex).map_err(|e| eyre::eyre!("Invalid private key hex: {}", e))?;

    let sk = SecretKey::from_bytes(&sk_bytes)
        .map_err(|e| eyre::eyre!("Failed to parse private key: {:?}", e))?;

    let pk = sk.sk_to_pk();
    Ok(hex::encode(pk.to_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::FromHex;

    #[test]
    fn test_generate_bls12_381_keypair_ok() {
        let result = generate_bls12_381_keypair();
        assert!(result.is_ok());
        let (privkey_hex, pubkey_hex) = result.unwrap();

        // Verify private key format
        let result = Vec::from_hex(&privkey_hex);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 32);

        // Verify public key format
        let result = Vec::from_hex(&pubkey_hex);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 48);

        // Verify we can reconstruct the public key
        let result = SecretKey::from_bytes(&hex::decode(&privkey_hex).unwrap());
        assert!(result.is_ok());
        let sk = result.unwrap();
        let pk = sk.sk_to_pk();
        assert_eq!(hex::encode(pk.to_bytes()), pubkey_hex);
    }

    #[test]
    fn test_generate_keypair_from_seed() {
        let seed = [1u8; 32];
        let result = generate_bls12_381_keypair_from_seed(&seed);
        assert!(result.is_ok());

        // Same seed should produce same keys
        let result2 = generate_bls12_381_keypair_from_seed(&seed);
        assert!(result2.is_ok());

        assert_eq!(result.unwrap(), result2.unwrap());
    }

    #[test]
    fn test_derive_pubkey() {
        let (privkey, pubkey) = generate_bls12_381_keypair().unwrap();
        let derived = derive_pubkey_from_privkey(&privkey).unwrap();
        assert_eq!(derived, pubkey);

        // Test with 0x prefix
        let derived_with_prefix = derive_pubkey_from_privkey(&format!("0x{}", privkey)).unwrap();
        assert_eq!(derived_with_prefix, pubkey);
    }
}
