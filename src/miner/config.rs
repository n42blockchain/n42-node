//! Miner configuration.

use alloy_primitives::{Address, Bytes};
use std::time::Duration;

/// Default recommit interval (2 seconds).
pub const DEFAULT_RECOMMIT_INTERVAL: Duration = Duration::from_secs(2);

/// Default gas ceiling.
pub const DEFAULT_GAS_CEIL: u64 = 30_000_000;

/// Default minimum gas price (1 gwei).
pub const DEFAULT_GAS_PRICE: u128 = 1_000_000_000;

/// BLS Secret Key type alias.
pub type BlsSecretKey = blst::min_pk::SecretKey;

/// Miner configuration.
#[derive(Clone)]
pub struct MinerConfig {
    /// Gas ceiling for blocks.
    pub gas_ceil: u64,

    /// Minimum gas price to accept transactions.
    pub gas_price: u128,

    /// Extra data (vanity) to include in blocks.
    /// First 32 bytes of extra_data in execution header.
    pub extra_data: Bytes,

    /// Interval for recommitting (rebuilding payload with new transactions).
    pub recommit_interval: Duration,

    /// Coinbase address (receives block rewards and fees).
    pub coinbase: Address,

    /// BLS signing key for sealing blocks.
    /// This is the private key corresponding to the validator address.
    signing_key: BlsSecretKey,
}

impl MinerConfig {
    /// Create a new miner configuration.
    pub fn new(coinbase: Address, signing_key: BlsSecretKey) -> Self {
        Self {
            gas_ceil: DEFAULT_GAS_CEIL,
            gas_price: DEFAULT_GAS_PRICE,
            extra_data: Bytes::default(),
            recommit_interval: DEFAULT_RECOMMIT_INTERVAL,
            coinbase,
            signing_key,
        }
    }

    /// Set gas ceiling.
    pub fn with_gas_ceil(mut self, gas_ceil: u64) -> Self {
        self.gas_ceil = gas_ceil;
        self
    }

    /// Set minimum gas price.
    pub fn with_gas_price(mut self, gas_price: u128) -> Self {
        self.gas_price = gas_price;
        self
    }

    /// Set extra data (vanity).
    pub fn with_extra_data(mut self, extra_data: Bytes) -> Self {
        self.extra_data = extra_data;
        self
    }

    /// Set recommit interval.
    pub fn with_recommit_interval(mut self, interval: Duration) -> Self {
        self.recommit_interval = interval;
        self
    }

    /// Get the signing key reference.
    pub fn signing_key(&self) -> &BlsSecretKey {
        &self.signing_key
    }

    /// Get the signer address derived from the signing key.
    pub fn signer_address(&self) -> Address {
        self.coinbase
    }
}

impl std::fmt::Debug for MinerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MinerConfig")
            .field("gas_ceil", &self.gas_ceil)
            .field("gas_price", &self.gas_price)
            .field("extra_data", &self.extra_data)
            .field("recommit_interval", &self.recommit_interval)
            .field("coinbase", &self.coinbase)
            .field("signing_key", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_key() -> BlsSecretKey {
        let ikm = [1u8; 32];
        BlsSecretKey::key_gen(&ikm, &[]).unwrap()
    }

    #[test]
    fn test_default_config() {
        let key = create_test_key();
        let coinbase = Address::repeat_byte(0x01);
        let config = MinerConfig::new(coinbase, key);

        assert_eq!(config.gas_ceil, DEFAULT_GAS_CEIL);
        assert_eq!(config.gas_price, DEFAULT_GAS_PRICE);
        assert_eq!(config.recommit_interval, DEFAULT_RECOMMIT_INTERVAL);
        assert_eq!(config.coinbase, coinbase);
    }

    #[test]
    fn test_config_builder() {
        let key = create_test_key();
        let coinbase = Address::repeat_byte(0x01);

        let config = MinerConfig::new(coinbase, key)
            .with_gas_ceil(50_000_000)
            .with_gas_price(2_000_000_000)
            .with_recommit_interval(Duration::from_secs(5));

        assert_eq!(config.gas_ceil, 50_000_000);
        assert_eq!(config.gas_price, 2_000_000_000);
        assert_eq!(config.recommit_interval, Duration::from_secs(5));
    }
}
