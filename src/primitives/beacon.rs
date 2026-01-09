//! Beacon chain block primitives.
//!
//! This module defines simplified beacon chain block types for demonstration.
//! In a production implementation, you would use full beacon chain types
//! from a library like `ethereum_consensus`.
//!
//! # Beacon Block Structure
//!
//! ```text
//! SignedBeaconBlock
//! ├── message: BeaconBlock
//! │   ├── slot: u64
//! │   ├── proposer_index: u64
//! │   ├── parent_root: B256
//! │   ├── state_root: B256
//! │   └── body: BeaconBlockBody
//! │       ├── randao_reveal: Bytes
//! │       ├── eth1_data: Eth1Data
//! │       ├── graffiti: B256
//! │       └── execution_payload_header_root: B256
//! └── signature: Bytes
//! ```

use alloy_primitives::{keccak256, Bytes, B256};
use alloy_rlp::{Encodable, RlpDecodable, RlpEncodable};

/// ETH1 data included in beacon blocks.
///
/// Contains information about the execution layer deposit contract.
#[derive(Clone, Debug, Default, PartialEq, Eq, RlpEncodable, RlpDecodable, serde::Serialize, serde::Deserialize)]
pub struct Eth1Data {
    /// Root of the deposit tree.
    pub deposit_root: B256,
    /// Number of deposits.
    pub deposit_count: u64,
    /// Block hash of the ETH1 block.
    pub block_hash: B256,
}

/// Beacon block header - the core identifying information.
///
/// This is used for:
/// - Computing block root (hash)
/// - Validating block chain linkage
/// - Cross-referencing with execution layer
#[derive(Clone, Debug, Default, PartialEq, Eq, RlpEncodable, RlpDecodable, serde::Serialize, serde::Deserialize)]
pub struct BeaconBlockHeader {
    /// Slot number (beacon chain's block height).
    pub slot: u64,
    /// Validator index of the proposer.
    pub proposer_index: u64,
    /// Root hash of the parent beacon block.
    pub parent_root: B256,
    /// Root hash of the beacon state after this block.
    pub state_root: B256,
    /// Root hash of the block body.
    pub body_root: B256,
}

impl BeaconBlockHeader {
    /// Create a new beacon block header.
    pub const fn new(
        slot: u64,
        proposer_index: u64,
        parent_root: B256,
        state_root: B256,
        body_root: B256,
    ) -> Self {
        Self { slot, proposer_index, parent_root, state_root, body_root }
    }

    /// Compute the block root (hash) of this header.
    ///
    /// In production, this would use SSZ tree hashing.
    /// For simplicity, we use RLP + keccak256.
    pub fn block_root(&self) -> B256 {
        let mut buf = Vec::new();
        self.encode(&mut buf);
        keccak256(&buf)
    }
}

/// Beacon block body - contains the block's content.
///
/// This is a simplified version. Full beacon blocks contain:
/// - Proposer slashings
/// - Attester slashings
/// - Attestations
/// - Deposits
/// - Voluntary exits
/// - Sync aggregate
/// - BLS to execution changes
#[derive(Clone, Debug, Default, PartialEq, Eq, RlpEncodable, RlpDecodable, serde::Serialize, serde::Deserialize)]
pub struct BeaconBlockBody {
    /// RANDAO reveal for randomness.
    pub randao_reveal: Bytes,
    /// ETH1 data vote.
    pub eth1_data: Eth1Data,
    /// Proposer graffiti (arbitrary 32 bytes).
    pub graffiti: B256,
    /// Root of the execution payload (links to execution layer).
    pub execution_payload_root: B256,
}

impl BeaconBlockBody {
    /// Compute the body root (hash).
    pub fn body_root(&self) -> B256 {
        let mut buf = Vec::new();
        self.encode(&mut buf);
        keccak256(&buf)
    }
}

/// A complete beacon block (header + body).
#[derive(Clone, Debug, Default, PartialEq, Eq, RlpEncodable, RlpDecodable, serde::Serialize, serde::Deserialize)]
pub struct BeaconBlock {
    /// Block slot.
    pub slot: u64,
    /// Proposer validator index.
    pub proposer_index: u64,
    /// Parent block root.
    pub parent_root: B256,
    /// State root after this block.
    pub state_root: B256,
    /// Block body.
    pub body: BeaconBlockBody,
}

impl BeaconBlock {
    /// Create a new beacon block.
    pub const fn new(
        slot: u64,
        proposer_index: u64,
        parent_root: B256,
        state_root: B256,
        body: BeaconBlockBody,
    ) -> Self {
        Self { slot, proposer_index, parent_root, state_root, body }
    }

    /// Get the header for this block.
    pub fn header(&self) -> BeaconBlockHeader {
        BeaconBlockHeader {
            slot: self.slot,
            proposer_index: self.proposer_index,
            parent_root: self.parent_root,
            state_root: self.state_root,
            body_root: self.body.body_root(),
        }
    }

    /// Compute the block root (hash).
    pub fn block_root(&self) -> B256 {
        self.header().block_root()
    }
}

/// A signed beacon block.
///
/// Contains the block and the proposer's BLS signature.
#[derive(Clone, Debug, Default, PartialEq, Eq, RlpEncodable, RlpDecodable, serde::Serialize, serde::Deserialize)]
pub struct SignedBeaconBlock {
    /// The beacon block message.
    pub message: BeaconBlock,
    /// BLS signature from the proposer.
    pub signature: Bytes,
}

impl SignedBeaconBlock {
    /// Create a new signed beacon block.
    pub fn new(message: BeaconBlock, signature: Bytes) -> Self {
        Self { message, signature }
    }

    /// Get the block root.
    pub fn block_root(&self) -> B256 {
        self.message.block_root()
    }

    /// Get the slot number.
    pub fn slot(&self) -> u64 {
        self.message.slot
    }

    /// Get the parent root.
    pub fn parent_root(&self) -> B256 {
        self.message.parent_root
    }

    /// Get the header.
    pub fn header(&self) -> BeaconBlockHeader {
        self.message.header()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_rlp::Decodable;

    #[test]
    fn test_beacon_block_header_root() {
        let header = BeaconBlockHeader::new(
            100,
            42,
            B256::ZERO,
            B256::repeat_byte(0x11),
            B256::repeat_byte(0x22),
        );

        let root = header.block_root();
        assert_ne!(root, B256::ZERO);

        // Same header should produce same root
        let root2 = header.block_root();
        assert_eq!(root, root2);
    }

    #[test]
    fn test_beacon_block_body_root() {
        let body = BeaconBlockBody {
            randao_reveal: Bytes::from_static(&[0x01, 0x02, 0x03]),
            eth1_data: Eth1Data::default(),
            graffiti: B256::repeat_byte(0xAB),
            execution_payload_root: B256::repeat_byte(0xCD),
        };

        let root = body.body_root();
        assert_ne!(root, B256::ZERO);
    }

    #[test]
    fn test_beacon_block_header_from_block() {
        let body = BeaconBlockBody::default();
        let block = BeaconBlock::new(100, 42, B256::ZERO, B256::repeat_byte(0x11), body.clone());

        let header = block.header();
        assert_eq!(header.slot, 100);
        assert_eq!(header.proposer_index, 42);
        assert_eq!(header.body_root, body.body_root());
    }

    #[test]
    fn test_signed_beacon_block() {
        let block = BeaconBlock::new(
            100,
            42,
            B256::ZERO,
            B256::repeat_byte(0x11),
            BeaconBlockBody::default(),
        );

        let signed = SignedBeaconBlock::new(block, Bytes::from_static(&[0x00; 96]));

        assert_eq!(signed.slot(), 100);
        assert_ne!(signed.block_root(), B256::ZERO);
    }

    #[test]
    fn test_rlp_roundtrip() {
        let block = BeaconBlock::new(
            100,
            42,
            B256::repeat_byte(0x01),
            B256::repeat_byte(0x02),
            BeaconBlockBody {
                randao_reveal: Bytes::from_static(&[0x01, 0x02]),
                eth1_data: Eth1Data {
                    deposit_root: B256::repeat_byte(0x03),
                    deposit_count: 1000,
                    block_hash: B256::repeat_byte(0x04),
                },
                graffiti: B256::repeat_byte(0x05),
                execution_payload_root: B256::repeat_byte(0x06),
            },
        );

        // Encode
        let mut buf = Vec::new();
        block.encode(&mut buf);

        // Decode
        let decoded = BeaconBlock::decode(&mut buf.as_slice()).unwrap();
        assert_eq!(block, decoded);
    }
}
