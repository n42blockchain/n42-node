//! Beacon sync P2P message types.
//!
//! This module defines the message types used by the `beacon_sync` subprotocol
//! for downloading beacon blocks from peers.
//!
//! # Messages
//!
//! | ID | Message | Direction | Description |
//! |----|---------|-----------|-------------|
//! | 0x00 | `GetBeaconBlocks` | Request | Request beacon blocks by slot range |
//! | 0x01 | `BeaconBlocks` | Response | Response with beacon blocks |
//!
//! # Wire Format
//!
//! All messages use RLP encoding and follow the standard RLPx message format:
//! ```text
//! message = message_id || rlp(message_data)
//! ```

use crate::primitives::SignedBeaconBlock;
use alloy_rlp::{RlpDecodable, RlpEncodable};

/// Message IDs for the beacon_sync protocol.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BeaconSyncMessageId {
    /// Request beacon blocks by slot range.
    GetBeaconBlocks = 0x00,
    /// Response with beacon blocks.
    BeaconBlocks = 0x01,
}

impl BeaconSyncMessageId {
    /// Get the message ID value.
    pub const fn id(&self) -> u8 {
        *self as u8
    }

    /// Try to parse a message ID from a byte.
    pub const fn from_id(id: u8) -> Option<Self> {
        match id {
            0x00 => Some(Self::GetBeaconBlocks),
            0x01 => Some(Self::BeaconBlocks),
            _ => None,
        }
    }
}

impl From<BeaconSyncMessageId> for u8 {
    fn from(id: BeaconSyncMessageId) -> Self {
        id as u8
    }
}

impl TryFrom<u8> for BeaconSyncMessageId {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Self::from_id(value).ok_or(value)
    }
}

/// Request for beacon blocks by slot range.
///
/// # Fields
///
/// - `request_id`: Unique identifier to match request with response
/// - `start_slot`: First slot to request (inclusive)
/// - `count`: Number of consecutive slots to request
///
/// # Example
///
/// Request slots 100-109 (10 blocks):
/// ```ignore
/// GetBeaconBlocks {
///     request_id: 1,
///     start_slot: 100,
///     count: 10,
/// }
/// ```
#[derive(Clone, Debug, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct GetBeaconBlocks {
    /// Request ID for matching response.
    pub request_id: u64,
    /// Starting slot number (inclusive).
    pub start_slot: u64,
    /// Number of slots to request.
    pub count: u64,
}

impl GetBeaconBlocks {
    /// Create a new request for beacon blocks.
    pub const fn new(request_id: u64, start_slot: u64, count: u64) -> Self {
        Self { request_id, start_slot, count }
    }

    /// Get the end slot (exclusive).
    pub const fn end_slot(&self) -> u64 {
        self.start_slot.saturating_add(self.count)
    }

    /// Check if a slot is within this request range.
    pub const fn contains_slot(&self, slot: u64) -> bool {
        slot >= self.start_slot && slot < self.end_slot()
    }

    /// Get the message ID for this message type.
    pub const fn message_id() -> BeaconSyncMessageId {
        BeaconSyncMessageId::GetBeaconBlocks
    }
}

/// Response containing beacon blocks.
///
/// # Fields
///
/// - `request_id`: Matches the request ID from `GetBeaconBlocks`
/// - `blocks`: List of signed beacon blocks (may be fewer than requested if some slots are empty)
///
/// # Notes
///
/// - Blocks are ordered by slot ascending
/// - Empty slots (no block produced) are omitted from the response
/// - The response may contain fewer blocks than requested
#[derive(Clone, Debug, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct BeaconBlocksResponse {
    /// Request ID matching the original request.
    pub request_id: u64,
    /// List of signed beacon blocks.
    pub blocks: Vec<SignedBeaconBlock>,
}

impl BeaconBlocksResponse {
    /// Create a new beacon blocks response.
    pub fn new(request_id: u64, blocks: Vec<SignedBeaconBlock>) -> Self {
        Self { request_id, blocks }
    }

    /// Create an empty response for a request.
    pub const fn empty(request_id: u64) -> Self {
        Self { request_id, blocks: Vec::new() }
    }

    /// Check if the response is empty.
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    /// Get the number of blocks in the response.
    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    /// Get the message ID for this message type.
    pub const fn message_id() -> BeaconSyncMessageId {
        BeaconSyncMessageId::BeaconBlocks
    }
}

/// Maximum number of beacon blocks that can be requested in a single message.
///
/// This limit prevents excessive memory usage and network bandwidth consumption.
pub const MAX_BEACON_BLOCKS_PER_REQUEST: u64 = 64;

/// Protocol name for beacon sync.
pub const BEACON_SYNC_PROTOCOL_NAME: &str = "beacon_sync";

/// Protocol version.
pub const BEACON_SYNC_PROTOCOL_VERSION: usize = 1;

/// Number of message types in the protocol.
pub const BEACON_SYNC_MESSAGE_COUNT: u8 = 2;

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Bytes, B256};
    use alloy_rlp::{Decodable, Encodable};
    use crate::primitives::{BeaconBlock, BeaconBlockBody};

    #[test]
    fn test_message_id_conversion() {
        assert_eq!(BeaconSyncMessageId::GetBeaconBlocks.id(), 0x00);
        assert_eq!(BeaconSyncMessageId::BeaconBlocks.id(), 0x01);

        assert_eq!(BeaconSyncMessageId::from_id(0x00), Some(BeaconSyncMessageId::GetBeaconBlocks));
        assert_eq!(BeaconSyncMessageId::from_id(0x01), Some(BeaconSyncMessageId::BeaconBlocks));
        assert_eq!(BeaconSyncMessageId::from_id(0x02), None);
    }

    #[test]
    fn test_get_beacon_blocks_range() {
        let request = GetBeaconBlocks::new(1, 100, 10);

        assert_eq!(request.end_slot(), 110);
        assert!(request.contains_slot(100));
        assert!(request.contains_slot(105));
        assert!(request.contains_slot(109));
        assert!(!request.contains_slot(99));
        assert!(!request.contains_slot(110));
    }

    #[test]
    fn test_get_beacon_blocks_rlp_roundtrip() {
        let request = GetBeaconBlocks::new(42, 1000, 64);

        let mut buf = Vec::new();
        request.encode(&mut buf);

        let decoded = GetBeaconBlocks::decode(&mut buf.as_slice()).unwrap();
        assert_eq!(request, decoded);
    }

    #[test]
    fn test_beacon_blocks_response_rlp_roundtrip() {
        let block1 = SignedBeaconBlock::new(
            BeaconBlock::new(
                100,
                1,
                B256::ZERO,
                B256::repeat_byte(0x11),
                BeaconBlockBody::default(),
            ),
            Bytes::from_static(&[0x00; 96]),
        );

        let block2 = SignedBeaconBlock::new(
            BeaconBlock::new(
                101,
                2,
                block1.block_root(),
                B256::repeat_byte(0x22),
                BeaconBlockBody::default(),
            ),
            Bytes::from_static(&[0x00; 96]),
        );

        let response = BeaconBlocksResponse::new(42, vec![block1.clone(), block2.clone()]);

        let mut buf = Vec::new();
        response.encode(&mut buf);

        let decoded = BeaconBlocksResponse::decode(&mut buf.as_slice()).unwrap();
        assert_eq!(response.request_id, decoded.request_id);
        assert_eq!(response.blocks.len(), decoded.blocks.len());
        assert_eq!(response.blocks[0].slot(), decoded.blocks[0].slot());
        assert_eq!(response.blocks[1].slot(), decoded.blocks[1].slot());
    }

    #[test]
    fn test_empty_response() {
        let response = BeaconBlocksResponse::empty(42);
        assert!(response.is_empty());
        assert_eq!(response.len(), 0);

        let mut buf = Vec::new();
        response.encode(&mut buf);

        let decoded = BeaconBlocksResponse::decode(&mut buf.as_slice()).unwrap();
        assert!(decoded.is_empty());
    }
}
