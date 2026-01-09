//! Beacon sync RLPx subprotocol.
//!
//! This module implements a custom RLPx subprotocol for syncing beacon blocks
//! between peers. It complements the standard eth66 protocol by adding the
//! ability to download beacon layer data.
//!
//! # Protocol Overview
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                  beacon_sync/1 Protocol                         │
//! ├─────────────────────────────────────────────────────────────────┤
//! │                                                                 │
//! │  Peer A                              Peer B                     │
//! │    │                                   │                        │
//! │    │  GetBeaconBlocks(100..110)        │                        │
//! │    │ ─────────────────────────────────>│                        │
//! │    │                                   │                        │
//! │    │  BeaconBlocks([block100, ...])    │                        │
//! │    │ <─────────────────────────────────│                        │
//! │    │                                   │                        │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Usage
//!
//! ```ignore
//! // Create the protocol handler
//! let (tx, rx) = mpsc::unbounded_channel();
//! let handler = BeaconSyncHandler::new(tx, store);
//!
//! // Add to network
//! network.add_rlpx_sub_protocol(handler.into_rlpx_sub_protocol());
//!
//! // Handle events
//! while let Some(event) = rx.recv().await {
//!     match event {
//!         BeaconSyncEvent::Established { peer_id, to_connection } => {
//!             // Connection established, can send requests
//!         }
//!         BeaconSyncEvent::BlocksReceived { peer_id, request_id, blocks } => {
//!             // Received beacon blocks
//!         }
//!     }
//! }
//! ```

use crate::{
    network::beacon_messages::{
        BeaconBlocksResponse, BeaconSyncMessageId, GetBeaconBlocks, BEACON_SYNC_MESSAGE_COUNT,
        BEACON_SYNC_PROTOCOL_NAME, BEACON_SYNC_PROTOCOL_VERSION,
    },
    primitives::SignedBeaconBlock,
    storage::BeaconStore,
};
use alloy_primitives::bytes::{Buf, BytesMut};
use alloy_rlp::{Decodable, Encodable};
use futures::{Stream, StreamExt};
use reth_ethereum::network::{
    api::Direction,
    eth_wire::{
        capability::SharedCapabilities, multiplex::ProtocolConnection, protocol::Protocol,
        Capability,
    },
    protocol::{ConnectionHandler, OnNotSupported, ProtocolHandler},
};
use reth_network_api::PeerId;
use reth_tracing::tracing::{debug, trace, warn};
use std::{
    collections::VecDeque,
    fmt::Debug,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{ready, Context, Poll},
};
use tokio::sync::{mpsc, oneshot};
use tokio_stream::wrappers::UnboundedReceiverStream;

/// Beacon sync protocol definition.
#[derive(Debug, Clone)]
pub struct BeaconSyncProtocol;

impl BeaconSyncProtocol {
    /// Returns the capability for the beacon_sync protocol.
    pub fn capability() -> Capability {
        Capability::new_static(BEACON_SYNC_PROTOCOL_NAME, BEACON_SYNC_PROTOCOL_VERSION)
    }

    /// Returns the protocol definition.
    pub fn protocol() -> Protocol {
        Protocol::new(Self::capability(), BEACON_SYNC_MESSAGE_COUNT)
    }
}

/// Events emitted by the beacon sync protocol.
#[derive(Debug)]
pub enum BeaconSyncEvent {
    /// A new peer connection was established.
    Established {
        /// Connection direction.
        direction: Direction,
        /// The peer ID.
        peer_id: PeerId,
        /// Channel to send commands to the connection.
        to_connection: mpsc::UnboundedSender<BeaconSyncCommand>,
    },
    /// Received beacon blocks from a peer.
    BlocksReceived {
        /// The peer ID.
        peer_id: PeerId,
        /// Request ID from the original request.
        request_id: u64,
        /// The received blocks.
        blocks: Vec<SignedBeaconBlock>,
    },
    /// A peer disconnected.
    Disconnected {
        /// The peer ID.
        peer_id: PeerId,
    },
}

/// Commands that can be sent to a beacon sync connection.
#[derive(Debug)]
pub enum BeaconSyncCommand {
    /// Request beacon blocks from the peer.
    GetBeaconBlocks {
        /// Request ID.
        request_id: u64,
        /// Starting slot.
        start_slot: u64,
        /// Number of slots to request.
        count: u64,
        /// Channel to receive the response.
        response: oneshot::Sender<Result<Vec<SignedBeaconBlock>, BeaconSyncError>>,
    },
}

/// Errors that can occur during beacon sync.
#[derive(Debug, Clone, thiserror::Error)]
pub enum BeaconSyncError {
    /// The connection was closed.
    #[error("connection closed")]
    ConnectionClosed,
    /// Failed to decode a message.
    #[error("failed to decode message: {0}")]
    DecodeError(String),
    /// Request timed out.
    #[error("request timed out")]
    Timeout,
    /// Peer sent an invalid response.
    #[error("invalid response: {0}")]
    InvalidResponse(String),
}

/// The protocol handler for beacon sync.
#[derive(Debug)]
pub struct BeaconSyncHandler<S: BeaconStore> {
    /// Channel to send events to.
    events: mpsc::UnboundedSender<BeaconSyncEvent>,
    /// Beacon store for responding to requests.
    store: Arc<S>,
}

impl<S: BeaconStore> BeaconSyncHandler<S> {
    /// Create a new beacon sync handler.
    pub fn new(events: mpsc::UnboundedSender<BeaconSyncEvent>, store: Arc<S>) -> Self {
        Self { events, store }
    }
}

impl<S: BeaconStore + Send + Sync + Debug + 'static> ProtocolHandler for BeaconSyncHandler<S> {
    type ConnectionHandler = BeaconSyncConnectionHandler<S>;

    fn on_incoming(&self, _socket_addr: SocketAddr) -> Option<Self::ConnectionHandler> {
        Some(BeaconSyncConnectionHandler {
            events: self.events.clone(),
            store: self.store.clone(),
        })
    }

    fn on_outgoing(
        &self,
        _socket_addr: SocketAddr,
        _peer_id: PeerId,
    ) -> Option<Self::ConnectionHandler> {
        Some(BeaconSyncConnectionHandler {
            events: self.events.clone(),
            store: self.store.clone(),
        })
    }
}

/// Connection handler for beacon sync.
#[derive(Debug)]
pub struct BeaconSyncConnectionHandler<S: BeaconStore> {
    /// Channel to send events to.
    events: mpsc::UnboundedSender<BeaconSyncEvent>,
    /// Beacon store for responding to requests.
    store: Arc<S>,
}

impl<S: BeaconStore + Send + Sync + Debug + 'static> ConnectionHandler for BeaconSyncConnectionHandler<S> {
    type Connection = BeaconSyncConnection<S>;

    fn protocol(&self) -> Protocol {
        BeaconSyncProtocol::protocol()
    }

    fn on_unsupported_by_peer(
        self,
        _supported: &SharedCapabilities,
        _direction: Direction,
        _peer_id: PeerId,
    ) -> OnNotSupported {
        // Keep the connection alive even if peer doesn't support beacon_sync
        OnNotSupported::KeepAlive
    }

    fn into_connection(
        self,
        direction: Direction,
        peer_id: PeerId,
        conn: ProtocolConnection,
    ) -> Self::Connection {
        let (tx, rx) = mpsc::unbounded_channel();

        // Notify that connection is established
        let _ = self.events.send(BeaconSyncEvent::Established {
            direction,
            peer_id,
            to_connection: tx,
        });

        BeaconSyncConnection {
            peer_id,
            conn,
            events: self.events.clone(),
            store: self.store.clone(),
            commands: UnboundedReceiverStream::new(rx),
            pending_requests: VecDeque::new(),
            outgoing_messages: VecDeque::new(),
        }
    }
}

/// Pending request waiting for a response.
#[derive(Debug)]
struct PendingRequest {
    request_id: u64,
    response: oneshot::Sender<Result<Vec<SignedBeaconBlock>, BeaconSyncError>>,
}

/// Active beacon sync connection.
#[derive(Debug)]
pub struct BeaconSyncConnection<S: BeaconStore> {
    /// Peer ID.
    peer_id: PeerId,
    /// The underlying protocol connection.
    conn: ProtocolConnection,
    /// Channel to send events to.
    events: mpsc::UnboundedSender<BeaconSyncEvent>,
    /// Beacon store for responding to requests.
    store: Arc<S>,
    /// Incoming commands.
    commands: UnboundedReceiverStream<BeaconSyncCommand>,
    /// Pending requests waiting for responses.
    pending_requests: VecDeque<PendingRequest>,
    /// Outgoing messages to send.
    outgoing_messages: VecDeque<BytesMut>,
}

impl<S: BeaconStore + Send + Sync + 'static> BeaconSyncConnection<S> {
    /// Encode and queue a message for sending.
    #[allow(dead_code)]
    fn queue_message(&mut self, id: BeaconSyncMessageId, payload: &impl Encodable) {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&[id.id()]);
        payload.encode(&mut buf);
        self.outgoing_messages.push_back(buf);
    }

    /// Handle an incoming message.
    fn handle_message(&mut self, mut data: &[u8]) -> Option<BytesMut> {
        if data.is_empty() {
            return None;
        }

        let msg_id = data[0];
        data.advance(1);

        match BeaconSyncMessageId::from_id(msg_id) {
            Some(BeaconSyncMessageId::GetBeaconBlocks) => {
                // Decode the request
                match GetBeaconBlocks::decode(&mut data) {
                    Ok(request) => {
                        trace!(
                            peer_id = %self.peer_id,
                            request_id = request.request_id,
                            start_slot = request.start_slot,
                            count = request.count,
                            "Received GetBeaconBlocks request"
                        );

                        // Fetch blocks from store
                        let blocks = self.fetch_blocks_for_request(&request);

                        // Send response
                        let response = BeaconBlocksResponse::new(request.request_id, blocks);
                        let mut buf = BytesMut::new();
                        buf.extend_from_slice(&[BeaconSyncMessageId::BeaconBlocks.id()]);
                        response.encode(&mut buf);
                        return Some(buf);
                    }
                    Err(e) => {
                        warn!(
                            peer_id = %self.peer_id,
                            error = %e,
                            "Failed to decode GetBeaconBlocks"
                        );
                    }
                }
            }
            Some(BeaconSyncMessageId::BeaconBlocks) => {
                // Decode the response
                match BeaconBlocksResponse::decode(&mut data) {
                    Ok(response) => {
                        trace!(
                            peer_id = %self.peer_id,
                            request_id = response.request_id,
                            blocks_count = response.blocks.len(),
                            "Received BeaconBlocks response"
                        );

                        // Find matching pending request
                        if let Some(pos) = self
                            .pending_requests
                            .iter()
                            .position(|r| r.request_id == response.request_id)
                        {
                            let pending = self.pending_requests.remove(pos).unwrap();
                            let _ = pending.response.send(Ok(response.blocks.clone()));
                        }

                        // Also emit event for the downloader
                        let _ = self.events.send(BeaconSyncEvent::BlocksReceived {
                            peer_id: self.peer_id,
                            request_id: response.request_id,
                            blocks: response.blocks,
                        });
                    }
                    Err(e) => {
                        warn!(
                            peer_id = %self.peer_id,
                            error = %e,
                            "Failed to decode BeaconBlocks"
                        );
                    }
                }
            }
            None => {
                warn!(
                    peer_id = %self.peer_id,
                    msg_id = msg_id,
                    "Unknown message ID"
                );
            }
        }

        None
    }

    /// Fetch blocks from store for a request.
    fn fetch_blocks_for_request(&self, request: &GetBeaconBlocks) -> Vec<SignedBeaconBlock> {
        let mut blocks = Vec::new();
        let end_slot = request.end_slot();

        for slot in request.start_slot..end_slot {
            if let Ok(Some(block)) = self.store.block_by_slot(slot) {
                blocks.push(block);
            }
        }

        blocks
    }
}

impl<S: BeaconStore + Send + Sync + 'static> Stream for BeaconSyncConnection<S> {
    type Item = BytesMut;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        loop {
            // First, send any queued outgoing messages
            if let Some(msg) = this.outgoing_messages.pop_front() {
                return Poll::Ready(Some(msg));
            }

            // Process incoming commands
            if let Poll::Ready(Some(cmd)) = this.commands.poll_next_unpin(cx) {
                match cmd {
                    BeaconSyncCommand::GetBeaconBlocks {
                        request_id,
                        start_slot,
                        count,
                        response,
                    } => {
                        // Queue the request
                        this.pending_requests.push_back(PendingRequest {
                            request_id,
                            response,
                        });

                        // Send the request message
                        let request = GetBeaconBlocks::new(request_id, start_slot, count);
                        let mut buf = BytesMut::new();
                        buf.extend_from_slice(&[BeaconSyncMessageId::GetBeaconBlocks.id()]);
                        request.encode(&mut buf);
                        return Poll::Ready(Some(buf));
                    }
                }
            }

            // Process incoming messages from peer
            match ready!(this.conn.poll_next_unpin(cx)) {
                Some(msg) => {
                    if let Some(response) = this.handle_message(&msg) {
                        return Poll::Ready(Some(response));
                    }
                    // Continue to process more messages
                    continue;
                }
                None => {
                    // Connection closed
                    debug!(peer_id = %this.peer_id, "Beacon sync connection closed");

                    // Notify pending requests
                    for pending in this.pending_requests.drain(..) {
                        let _ = pending.response.send(Err(BeaconSyncError::ConnectionClosed));
                    }

                    // Send disconnect event
                    let _ = this.events.send(BeaconSyncEvent::Disconnected {
                        peer_id: this.peer_id,
                    });

                    return Poll::Ready(None);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_beacon_sync_protocol() {
        let cap = BeaconSyncProtocol::capability();
        assert_eq!(cap.name, BEACON_SYNC_PROTOCOL_NAME);
        assert_eq!(cap.version, BEACON_SYNC_PROTOCOL_VERSION);

        let proto = BeaconSyncProtocol::protocol();
        assert_eq!(proto.messages(), BEACON_SYNC_MESSAGE_COUNT);
    }
}
