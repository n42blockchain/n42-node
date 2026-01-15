//! Payload Attributes Provider
//!
//! This module defines the `PayloadAttributesProvider` trait that supplies
//! execution payload attributes for block building. This abstraction allows
//! the miner to work with both POA and future PoS consensus mechanisms.
//!
//! # Design
//!
//! The trait provides all attributes needed by reth's `EthPayloadBuilderAttributes`:
//! - `timestamp`: Block timestamp
//! - `suggested_fee_recipient`: Address receiving block rewards/fees
//! - `prev_randao`: PoS randomness (ZERO for POA)
//! - `withdrawals`: Validator withdrawals (empty for POA)
//! - `parent_beacon_block_root`: EIP-4788 beacon block root
//!
//! # POA vs PoS
//!
//! | Attribute | POA | PoS |
//! |-----------|-----|-----|
//! | timestamp | slot * block_time | from beacon state |
//! | fee_recipient | coinbase | validator's address |
//! | prev_randao | B256::ZERO | from beacon state |
//! | withdrawals | empty | from beacon state |
//! | parent_beacon_root | computed locally | from consensus |

use alloy_eips::eip4895::Withdrawal;
use alloy_primitives::{Address, B256};

/// Trait for providing execution payload attributes.
///
/// Implementations supply the attributes needed to build execution payloads.
/// This allows the miner module to work with different consensus mechanisms
/// (POA now, PoS later) without code changes.
pub trait PayloadAttributesProvider: Send + Sync {
    /// Returns the timestamp for the given slot.
    ///
    /// For POA: `genesis_time + slot * block_time`
    /// For PoS: computed from beacon state
    fn timestamp(&self, slot: u64) -> u64;

    /// Returns the suggested fee recipient (coinbase) for the given slot.
    ///
    /// For POA: configured coinbase address
    /// For PoS: validator's withdrawal address
    fn suggested_fee_recipient(&self, slot: u64) -> Address;

    /// Returns the previous RANDAO value for randomness.
    ///
    /// For POA: B256::ZERO (not used)
    /// For PoS: mix from beacon state
    fn prev_randao(&self, slot: u64) -> B256;

    /// Returns the withdrawals to process in this block.
    ///
    /// For POA: empty vector
    /// For PoS: withdrawals from beacon state
    fn withdrawals(&self, slot: u64) -> Vec<Withdrawal>;

    /// Returns the parent beacon block root (EIP-4788).
    ///
    /// For POA: None or computed from local beacon store
    /// For PoS: from consensus layer
    fn parent_beacon_block_root(&self, slot: u64) -> Option<B256>;
}

/// POA implementation of `PayloadAttributesProvider`.
///
/// This implementation returns default/static values suitable for
/// Clique POA consensus where beacon state features are not used.
#[derive(Debug, Clone)]
pub struct PoaAttributesProvider {
    /// Coinbase address receiving block rewards and fees.
    pub coinbase: Address,

    /// Block time in seconds (e.g., 8 seconds for POA).
    pub block_time: u64,

    /// Genesis timestamp (Unix timestamp).
    pub genesis_time: u64,
}

impl PoaAttributesProvider {
    /// Create a new POA attributes provider.
    pub fn new(coinbase: Address, block_time: u64, genesis_time: u64) -> Self {
        Self {
            coinbase,
            block_time,
            genesis_time,
        }
    }

    /// Create with default genesis time (current time).
    pub fn with_current_genesis(coinbase: Address, block_time: u64) -> Self {
        let genesis_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Self::new(coinbase, block_time, genesis_time)
    }
}

impl PayloadAttributesProvider for PoaAttributesProvider {
    fn timestamp(&self, slot: u64) -> u64 {
        self.genesis_time + slot * self.block_time
    }

    fn suggested_fee_recipient(&self, _slot: u64) -> Address {
        self.coinbase
    }

    fn prev_randao(&self, _slot: u64) -> B256 {
        // POA doesn't use RANDAO
        B256::ZERO
    }

    fn withdrawals(&self, _slot: u64) -> Vec<Withdrawal> {
        // POA has no withdrawals
        vec![]
    }

    fn parent_beacon_block_root(&self, _slot: u64) -> Option<B256> {
        // For POA, this will be filled in by the worker from local beacon store
        // Return None here to indicate it should be computed
        None
    }
}

/// Wrapper that allows overriding the parent beacon block root.
///
/// Used by the worker to inject the actual parent root at build time.
#[derive(Debug)]
pub struct AttributesWithParentRoot<P: PayloadAttributesProvider> {
    inner: P,
    parent_root: Option<B256>,
}

impl<P: PayloadAttributesProvider> AttributesWithParentRoot<P> {
    /// Create a new wrapper with the given parent root.
    pub fn new(inner: P, parent_root: Option<B256>) -> Self {
        Self { inner, parent_root }
    }
}

impl<P: PayloadAttributesProvider> PayloadAttributesProvider for AttributesWithParentRoot<P> {
    fn timestamp(&self, slot: u64) -> u64 {
        self.inner.timestamp(slot)
    }

    fn suggested_fee_recipient(&self, slot: u64) -> Address {
        self.inner.suggested_fee_recipient(slot)
    }

    fn prev_randao(&self, slot: u64) -> B256 {
        self.inner.prev_randao(slot)
    }

    fn withdrawals(&self, slot: u64) -> Vec<Withdrawal> {
        self.inner.withdrawals(slot)
    }

    fn parent_beacon_block_root(&self, _slot: u64) -> Option<B256> {
        self.parent_root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poa_attributes_timestamp() {
        let coinbase = Address::repeat_byte(0x01);
        let block_time = 8;
        let genesis_time = 1700000000;

        let provider = PoaAttributesProvider::new(coinbase, block_time, genesis_time);

        assert_eq!(provider.timestamp(0), genesis_time);
        assert_eq!(provider.timestamp(1), genesis_time + 8);
        assert_eq!(provider.timestamp(10), genesis_time + 80);
    }

    #[test]
    fn test_poa_attributes_defaults() {
        let coinbase = Address::repeat_byte(0x42);
        let provider = PoaAttributesProvider::new(coinbase, 8, 1700000000);

        // Fee recipient should be coinbase
        assert_eq!(provider.suggested_fee_recipient(0), coinbase);
        assert_eq!(provider.suggested_fee_recipient(100), coinbase);

        // RANDAO should be zero
        assert_eq!(provider.prev_randao(0), B256::ZERO);

        // No withdrawals
        assert!(provider.withdrawals(0).is_empty());

        // No parent root (computed later)
        assert!(provider.parent_beacon_block_root(0).is_none());
    }

    #[test]
    fn test_attributes_with_parent_root() {
        let coinbase = Address::repeat_byte(0x01);
        let provider = PoaAttributesProvider::new(coinbase, 8, 1700000000);

        let parent_root = B256::repeat_byte(0xAB);
        let wrapped = AttributesWithParentRoot::new(provider, Some(parent_root));

        // Should return overridden parent root
        assert_eq!(wrapped.parent_beacon_block_root(0), Some(parent_root));

        // Other attributes should pass through
        assert_eq!(wrapped.suggested_fee_recipient(0), coinbase);
        assert_eq!(wrapped.prev_randao(0), B256::ZERO);
    }
}
