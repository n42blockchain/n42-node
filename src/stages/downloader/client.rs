//! Beacon block client trait for downloading beacon blocks from peers.
//!
//! This module defines the client trait for fetching beacon blocks from the P2P network.
//! It follows the same pattern as `BodiesClient` in reth, but uses slot ranges instead
//! of block hashes.

use crate::primitives::SignedBeaconBlock;
use reth_network_api::PeerId;
use std::{
    future::Future,
    ops::RangeInclusive,
    pin::Pin,
    task::{ready, Context, Poll},
};

/// Result type for beacon block requests.
pub type BeaconBlockResult<T> = Result<T, BeaconBlockClientError>;

/// Peer request result for beacon blocks.
pub type PeerBeaconBlockResult<T> = Result<PeerBeaconBlockResponse<T>, BeaconBlockClientError>;

/// Response with peer information.
#[derive(Debug, Clone)]
pub struct PeerBeaconBlockResponse<T> {
    /// The peer that sent the response.
    pub peer_id: PeerId,
    /// The response data.
    pub data: T,
}

impl<T> PeerBeaconBlockResponse<T> {
    /// Create a new peer response.
    pub fn new(peer_id: PeerId, data: T) -> Self {
        Self { peer_id, data }
    }

    /// Map the data.
    pub fn map<U, F: FnOnce(T) -> U>(self, f: F) -> PeerBeaconBlockResponse<U> {
        PeerBeaconBlockResponse { peer_id: self.peer_id, data: f(self.data) }
    }
}

/// Errors that can occur when fetching beacon blocks.
#[derive(Debug, Clone, thiserror::Error)]
pub enum BeaconBlockClientError {
    /// No peers available.
    #[error("no peers available")]
    NoPeers,
    /// Request timed out.
    #[error("request timed out")]
    Timeout,
    /// Request failed.
    #[error("request failed: {0}")]
    RequestFailed(String),
    /// Connection closed.
    #[error("connection closed")]
    ConnectionClosed,
    /// Channel error.
    #[error("channel error")]
    ChannelError,
}

/// The beacon blocks future type.
pub type BeaconBlocksFut =
    Pin<Box<dyn Future<Output = PeerBeaconBlockResult<Vec<SignedBeaconBlock>>> + Send + Sync>>;

/// A client capable of downloading beacon blocks.
///
/// This trait follows the same pattern as `BodiesClient` but uses slot ranges
/// instead of block hashes, since beacon blocks are identified by slot.
pub trait BeaconBlockClient: Send + Sync {
    /// The output of the request future for querying beacon blocks.
    type Output: Future<Output = PeerBeaconBlockResult<Vec<SignedBeaconBlock>>> + Send + Sync + Unpin;

    /// Fetches beacon blocks for the requested slot range.
    ///
    /// # Arguments
    ///
    /// * `range` - The inclusive range of slots to request.
    ///
    /// # Returns
    ///
    /// A future that resolves to the list of beacon blocks for the requested slots.
    /// Slots without blocks (empty slots) are omitted from the response.
    fn get_beacon_blocks(&self, range: RangeInclusive<u64>) -> Self::Output;

    /// Fetches a single beacon block by slot.
    fn get_beacon_block(&self, slot: u64) -> SingleBeaconBlockRequest<Self::Output> {
        let fut = self.get_beacon_blocks(slot..=slot);
        SingleBeaconBlockRequest { fut }
    }
}

/// A Future that resolves to a single beacon block.
#[derive(Debug)]
#[must_use = "futures do nothing unless polled"]
pub struct SingleBeaconBlockRequest<Fut> {
    fut: Fut,
}

impl<Fut> Future for SingleBeaconBlockRequest<Fut>
where
    Fut: Future<Output = PeerBeaconBlockResult<Vec<SignedBeaconBlock>>> + Send + Sync + Unpin,
{
    type Output = PeerBeaconBlockResult<Option<SignedBeaconBlock>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let resp = ready!(Pin::new(&mut self.get_mut().fut).poll(cx));
        let resp = resp.map(|res| res.map(|blocks| blocks.into_iter().next()));
        Poll::Ready(resp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_response_map() {
        let resp = PeerBeaconBlockResponse::new(PeerId::random(), vec![1, 2, 3]);
        let mapped = resp.map(|v| v.len());
        assert_eq!(mapped.data, 3);
    }
}
