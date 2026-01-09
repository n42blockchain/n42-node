# POA eth66 Block Propagation Detailed Documentation

This document describes the complete flow of custom block definition, broadcasting, and receiving.

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Custom Block Types](#custom-block-types)
3. [Block Broadcasting Flow](#block-broadcasting-flow)
4. [Block Receiving Flow](#block-receiving-flow)
5. [RLP Encoding/Decoding](#rlp-encodingdecoding)
6. [Key Code Locations](#key-code-locations)

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           POA eth66 Architecture                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐                │
│  │   Node 0     │     │   Node 1     │     │   Node N     │                │
│  │ (Validator)  │◄───►│ (Validator)  │◄───►│ (Validator)  │                │
│  └──────┬───────┘     └──────┬───────┘     └──────┬───────┘                │
│         │                    │                    │                         │
│         └────────────────────┼────────────────────┘                         │
│                              │                                              │
│                    eth66 Protocol (NewBlock)                                │
│                              │                                              │
│                    ┌─────────▼─────────┐                                    │
│                    │ N42BroadcastBlock │                                    │
│                    │ ┌───────────────┐ │                                    │
│                    │ │ BeaconBlock   │ │                                    │
│                    │ │ + Execution   │ │                                    │
│                    │ │   Block       │ │                                    │
│                    │ └───────────────┘ │                                    │
│                    └───────────────────┘                                    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Custom Block Types

### Type Hierarchy

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Type Hierarchy                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  N42NetworkPrimitives (NetworkPrimitives trait)                             │
│  ├── NodePrimitives: N42NodePrimitives                                      │
│  ├── BroadcastedTransaction: EthereumTxEnvelope                             │
│  └── NewBlockPayload: NewBlock<N42BroadcastBlock>  ◄── Key type             │
│                                                                             │
│  NewBlock<N42BroadcastBlock>                                                │
│  ├── block: N42BroadcastBlock                                               │
│  └── td: U128 (total difficulty)                                            │
│                                                                             │
│  N42BroadcastBlock                                                          │
│  ├── beacon: SignedBeaconBlock                                              │
│  │   ├── message: BeaconBlock                                               │
│  │   │   ├── slot: u64                                                      │
│  │   │   ├── proposer_index: u64                                            │
│  │   │   ├── parent_root: B256                                              │
│  │   │   ├── state_root: B256                                               │
│  │   │   └── body: BeaconBlockBody                                          │
│  │   └── signature: Bytes                                                   │
│  └── execution: Block (reth_ethereum_primitives)                            │
│      ├── header: Header                                                     │
│      └── body: BlockBody                                                    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Defining Custom Block (N42BroadcastBlock)

**File location**: `examples/custom-node-types/src/primitives/unified.rs`

```rust
/// Broadcast type containing beacon and execution blocks
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct N42BroadcastBlock {
    /// Signed beacon chain block
    pub beacon: SignedBeaconBlock,
    /// Execution layer block
    pub execution: Block,
}
```

### Required Trait Implementations

N42BroadcastBlock needs to implement the following traits:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    N42BroadcastBlock Required Traits                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  1. alloy_rlp::Encodable        - RLP encoding (used when sending)          │
│  2. alloy_rlp::Decodable        - RLP decoding (used when receiving)        │
│  3. reth_primitives_traits::Block - Block basic operations                  │
│  4. reth_primitives_traits::InMemorySize - Memory size calculation          │
│  5. Clone, Debug, PartialEq, Eq - Basic traits                              │
│  6. Send, Sync, Unpin, 'static  - Async safety                              │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### RLP Encoding Implementation

```rust
impl alloy_rlp::Encodable for N42BroadcastBlock {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        // Encode as RLP list: [beacon, execution]
        let beacon_len = self.beacon.length();
        let execution_len = self.execution.length();
        let list_len = beacon_len + execution_len;

        // Write list header
        alloy_rlp::Header { list: true, payload_length: list_len }.encode(out);
        // Write beacon block
        self.beacon.encode(out);
        // Write execution block
        self.execution.encode(out);
    }
}

impl alloy_rlp::Decodable for N42BroadcastBlock {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        // Read list header
        let header = alloy_rlp::Header::decode(buf)?;
        if !header.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }
        // Decode beacon block
        let beacon = SignedBeaconBlock::decode(buf)?;
        // Decode execution block
        let execution = Block::decode(buf)?;

        Ok(Self { beacon, execution })
    }
}
```

---

## Block Broadcasting Flow

### Complete Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        Block Broadcasting Flow                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────┐                                                        │
│  │ 1. Block        │  PoaNode::produce_block()                              │
│  │    Production   │  → Generate SignedBeaconBlock                          │
│  │    (POA)        │                                                        │
│  └────────┬────────┘                                                        │
│           │                                                                 │
│           ▼                                                                 │
│  ┌─────────────────┐                                                        │
│  │ 2. Create       │  create_broadcast_block()                              │
│  │    Broadcast    │  → SignedBeaconBlock + Header → N42BroadcastBlock      │
│  │    Block        │                                                        │
│  └────────┬────────┘                                                        │
│           │                                                                 │
│           ▼                                                                 │
│  ┌─────────────────┐                                                        │
│  │ 3. Wrap as      │  create_new_block_message()                            │
│  │    NewBlock     │  → NewBlock { block: N42BroadcastBlock, td }           │
│  └────────┬────────┘                                                        │
│           │                                                                 │
│           ▼                                                                 │
│  ┌─────────────────┐                                                        │
│  │ 4. Call Network │  net_handle.announce_block(new_block, hash)            │
│  │    Handle       │  → NetworkHandleMessage::AnnounceBlock                 │
│  └────────┬────────┘                                                        │
│           │                                                                 │
│           ▼                                                                 │
│  ┌─────────────────┐                                                        │
│  │ 5. NetworkMgr   │  on_handle_message()                                   │
│  │    Process Msg  │  → NewBlockMessage { hash, block: Arc<NewBlock> }      │
│  └────────┬────────┘                                                        │
│           │                                                                 │
│           ▼                                                                 │
│  ┌─────────────────┐                                                        │
│  │ 6. NetworkState │  announce_new_block()                                  │
│  │    Broadcast    │  → Select sqrt(peers) nodes                            │
│  │    Scheduling   │  → StateAction::NewBlock { peer_id, block }            │
│  └────────┬────────┘                                                        │
│           │                                                                 │
│           ▼                                                                 │
│  ┌─────────────────┐                                                        │
│  │ 7. Swarm        │  on_state_action()                                     │
│  │    Dispatch to  │  → PeerMessage::NewBlock(msg)                          │
│  │    Sessions     │  → sessions.send_message(&peer_id, msg)                │
│  └────────┬────────┘                                                        │
│           │                                                                 │
│           ▼                                                                 │
│  ┌─────────────────┐                                                        │
│  │ 8. ActiveSession│  on_internal_peer_message()                            │
│  │    Process Msg  │  → EthBroadcastMessage::NewBlock(msg.block)            │
│  │                 │  → queued_outgoing.push_back(...)                      │
│  └────────┬────────┘                                                        │
│           │                                                                 │
│           ▼                                                                 │
│  ┌─────────────────┐                                                        │
│  │ 9. RLP Encode   │  ProtocolBroadcastMessage::encode()                    │
│  │                 │  → [0x07] + NewBlock<N42BroadcastBlock>.encode()        │
│  └────────┬────────┘                                                        │
│           │                                                                 │
│           ▼                                                                 │
│  ┌─────────────────┐                                                        │
│  │ 10. Send to     │  EthStream.start_send_broadcast()                      │
│  │     Network     │  → Send bytes over P2P TCP connection                  │
│  └─────────────────┘                                                        │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Detailed Code Flow

#### Step 1-3: Block Production and Wrapping

**File**: `examples/custom-node-types/src/bin/poa_eth66.rs`

```rust
// Step 1: POA consensus produces block
let beacon_block = poa_node.produce_block(current_slot);

// Step 2: Create broadcast block
fn create_broadcast_block(beacon: &SignedBeaconBlock, block_time: u64) -> N42BroadcastBlock {
    let header = Header {
        number: beacon.slot(),
        timestamp: beacon.slot() * block_time,
        ..Default::default()
    };
    let execution = Block::new(header, BlockBody::default());
    N42BroadcastBlock::new(beacon.clone(), execution)
}

// Step 3: Wrap as NewBlock
fn create_new_block_message(beacon: &SignedBeaconBlock, block_time: u64) -> N42NewBlock {
    let block = create_broadcast_block(beacon, block_time);
    let td = U128::from(beacon.slot());
    NewBlock { block, td }
}
```

#### Step 4: Call Network Handle

**File**: `crates/net/network/src/network.rs`

```rust
impl<N: NetworkPrimitives> NetworkHandle<N> {
    /// Broadcast block to network
    pub fn announce_block(&self, block: N::NewBlockPayload, hash: B256) {
        self.send_message(NetworkHandleMessage::AnnounceBlock(block, hash))
    }
}
```

#### Step 5: NetworkManager Processing

**File**: `crates/net/network/src/manager.rs`

```rust
fn on_handle_message(&mut self, msg: NetworkHandleMessage<N>) {
    match msg {
        NetworkHandleMessage::AnnounceBlock(block, hash) => {
            // Check if in PoS mode (PoS doesn't allow broadcasting)
            if self.handle.mode().is_stake() {
                warn!("Block propagation not supported in PoS");
                return
            }
            // Wrap as internal message
            let msg = NewBlockMessage { hash, block: Arc::new(block) };
            self.swarm.state_mut().announce_new_block(msg);
        }
        // ...
    }
}
```

#### Step 6: NetworkState Broadcast Scheduling

**File**: `crates/net/network/src/state.rs`

```rust
pub fn announce_new_block(&mut self, msg: NewBlockMessage<N::NewBlockPayload>) {
    // Calculate broadcast node count: sqrt(peers) + 1
    let num_propagate = (self.active_peers.len() as f64).sqrt() as u64 + 1;

    // Randomly select nodes
    let mut peers: Vec<_> = self.active_peers.iter_mut().collect();
    peers.shuffle(&mut rand::rng());

    for (peer_id, peer) in peers {
        if peer.blocks.contains(&msg.hash) {
            continue; // Skip nodes that already know this block
        }

        if count < num_propagate {
            // Send NewBlock message
            self.queued_messages.push_back(
                StateAction::NewBlock { peer_id: *peer_id, block: msg.clone() }
            );
            peer.blocks.insert(msg.hash);
            count += 1;
        }
    }
}
```

#### Step 7-8: Swarm and ActiveSession Processing

**File**: `crates/net/network/src/swarm.rs`

```rust
fn on_state_action(&mut self, event: StateAction<N>) {
    match event {
        StateAction::NewBlock { peer_id, block: msg } => {
            let msg = PeerMessage::NewBlock(msg);
            self.sessions.send_message(&peer_id, msg);
        }
        // ...
    }
}
```

**File**: `crates/net/network/src/session/active.rs`

```rust
fn on_internal_peer_message(&mut self, msg: PeerMessage<N>) {
    match msg {
        PeerMessage::NewBlock(msg) => {
            // Convert to broadcast message and add to send queue
            self.queued_outgoing.push_back(
                EthBroadcastMessage::NewBlock(msg.block).into()
            );
        }
        // ...
    }
}
```

#### Step 9-10: RLP Encoding and Sending

**File**: `crates/net/eth-wire-types/src/message.rs`

```rust
impl<N: NetworkPrimitives> Encodable for ProtocolBroadcastMessage<N> {
    fn encode(&self, out: &mut dyn BufMut) {
        // Encode message type (0x07 = NewBlock)
        self.message_type.encode(out);
        // Encode message content
        self.message.encode(out);
    }
}

impl<N: NetworkPrimitives> Encodable for EthBroadcastMessage<N> {
    fn encode(&self, out: &mut dyn BufMut) {
        match self {
            Self::NewBlock(new_block) => new_block.encode(out),
            // ...
        }
    }
}
```

**File**: `crates/net/eth-wire/src/ethstream.rs`

```rust
pub fn start_send_broadcast(&mut self, item: EthBroadcastMessage<N>) -> Result<(), EthStreamError> {
    // RLP encode complete message
    let bytes = Bytes::from(alloy_rlp::encode(ProtocolBroadcastMessage::from(item)));
    // Send through underlying P2P connection
    self.inner.start_send_unpin(bytes)?;
    Ok(())
}
```

---

## Block Receiving Flow

### Complete Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Block Receiving Flow                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────┐                                                        │
│  │ 1. P2P Receive  │  TCP connection receives raw bytes                     │
│  │    Data         │  → BytesMut                                            │
│  └────────┬────────┘                                                        │
│           │                                                                 │
│           ▼                                                                 │
│  ┌─────────────────┐                                                        │
│  │ 2. EthStream    │  poll_next()                                           │
│  │    Poll Receive │  → Read data from P2P stream                           │
│  └────────┬────────┘                                                        │
│           │                                                                 │
│           ▼                                                                 │
│  ┌─────────────────┐                                                        │
│  │ 3. RLP Decode   │  EthStreamInner::decode_message()                      │
│  │                 │  → ProtocolMessage::decode_message()                   │
│  └────────┬────────┘                                                        │
│           │                                                                 │
│           ▼                                                                 │
│  ┌─────────────────┐                                                        │
│  │ 4. Parse Msg ID │  EthMessageID::decode()                                │
│  │                 │  → 0x07 = NewBlock                                     │
│  └────────┬────────┘                                                        │
│           │                                                                 │
│           ▼                                                                 │
│  ┌─────────────────┐                                                        │
│  │ 5. Decode       │  N::NewBlockPayload::decode()                          │
│  │    NewBlock     │  → NewBlock<N42BroadcastBlock>::decode()               │
│  │                 │  → N42BroadcastBlock::decode()                         │
│  └────────┬────────┘                                                        │
│           │                                                                 │
│           ▼                                                                 │
│  ┌─────────────────┐                                                        │
│  │ 6. ActiveSession│  on_incoming_message()                                 │
│  │    Process Msg  │  → EthMessage::NewBlock(block)                         │
│  └────────┬────────┘                                                        │
│           │                                                                 │
│           ▼                                                                 │
│  ┌─────────────────┐                                                        │
│  │ 7. Create Event │  NewBlockMessage { hash, block }                       │
│  │                 │  → PeerMessage::NewBlock(...)                          │
│  │                 │  → try_emit_broadcast()                                │
│  └────────┬────────┘                                                        │
│           │                                                                 │
│           ▼                                                                 │
│  ┌─────────────────┐                                                        │
│  │ 8. SessionMgr   │  Receive ActiveSessionMessage                          │
│  │    Forward Msg  │  → SessionEvent::IncomingPeerMessage                   │
│  └────────┬────────┘                                                        │
│           │                                                                 │
│           ▼                                                                 │
│  ┌─────────────────┐                                                        │
│  │ 9. NetworkMgr   │  on_session_event()                                    │
│  │    Process      │  → Call block_import.on_new_block()                    │
│  │    Session Evt  │                                                        │
│  └────────┬────────┘                                                        │
│           │                                                                 │
│           ▼                                                                 │
│  ┌─────────────────┐                                                        │
│  │ 10. BlockImport │  N42BlockImport::on_new_block()                        │
│  │     Process     │  → Validate, store, log                                │
│  │     Block       │                                                        │
│  └─────────────────┘                                                        │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Detailed Code Flow

#### Step 2-3: EthStream Receive and Decode

**File**: `crates/net/eth-wire/src/ethstream.rs`

```rust
impl<S, N> Stream for EthStream<S, N>
where
    S: Stream<Item = Result<BytesMut, E>> + Unpin,
    N: NetworkPrimitives,
{
    type Item = Result<EthMessage<N>, EthStreamError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        // Read data from underlying P2P stream
        let bytes = ready!(this.inner.poll_next_unpin(cx));

        match bytes {
            Some(Ok(bytes)) => {
                // Decode message
                Poll::Ready(Some(this.eth.decode_message(bytes)))
            }
            // ...
        }
    }
}
```

#### Step 3-5: RLP Decode Detailed Flow

**File**: `crates/net/eth-wire/src/ethstream.rs`

```rust
impl<N: NetworkPrimitives> EthStreamInner<N> {
    pub fn decode_message(&self, bytes: BytesMut) -> Result<EthMessage<N>, EthStreamError> {
        // Check message size
        if bytes.len() > MAX_MESSAGE_SIZE {
            return Err(EthStreamError::MessageTooBig(bytes.len()));
        }

        // Call ProtocolMessage decode
        let msg = ProtocolMessage::decode_message(self.version, &mut bytes.as_ref())?;

        Ok(msg.message)
    }
}
```

**File**: `crates/net/eth-wire-types/src/message.rs`

```rust
impl<N: NetworkPrimitives> ProtocolMessage<N> {
    pub fn decode_message(version: EthVersion, buf: &mut &[u8]) -> Result<Self, MessageError> {
        // Step 4: Decode message ID
        let message_type = EthMessageID::decode(buf)?;  // Read first byte

        let message = match message_type {
            // Step 5: Decode content based on message type
            EthMessageID::NewBlock => {
                // Call N::NewBlockPayload::decode()
                // For N42NetworkPrimitives, this is NewBlock<N42BroadcastBlock>::decode()
                EthMessage::NewBlock(Box::new(N::NewBlockPayload::decode(buf)?))
            }
            // Other message types...
        };

        Ok(Self { message_type, message })
    }
}
```

#### Step 6-7: ActiveSession Process Received Message

**File**: `crates/net/network/src/session/active.rs`

```rust
fn on_incoming_message(&mut self, msg: EthMessage<N>) -> OnIncomingMessageOutcome<N> {
    match msg {
        EthMessage::NewBlock(block) => {
            // Create NewBlockMessage
            let block = NewBlockMessage {
                hash: block.block.header().hash_slow(),
                block: Arc::new(*block),
            };
            // Send to session manager
            self.try_emit_broadcast(PeerMessage::NewBlock(block)).into()
        }
        // Other message types...
    }
}
```

#### Step 9-10: NetworkManager and BlockImport

**File**: `crates/net/network/src/manager.rs`

```rust
fn on_peer_message(&mut self, peer_id: PeerId, msg: PeerMessage<N>) {
    match msg {
        PeerMessage::NewBlock(block) => {
            // Create new block event
            let event = NewBlockEvent::Block(block.block);
            // Call BlockImport trait
            self.block_import.on_new_block(peer_id, event);
        }
        // ...
    }
}
```

**File**: `examples/custom-node-types/src/bin/poa_eth66.rs`

```rust
impl BlockImport<N42NewBlock> for N42BlockImport {
    fn on_new_block(&mut self, peer_id: PeerId, incoming_block: NewBlockEvent<N42NewBlock>) {
        match incoming_block {
            NewBlockEvent::Block(new_block_msg) => {
                let new_block = &new_block_msg.block;  // N42BroadcastBlock

                // Get beacon block
                let beacon = new_block.beacon_block();
                let slot = beacon.slot();
                let hash = beacon.block_root();

                info!(slot = slot, hash = %hash, peer = %peer_id,
                      "Received NewBlock via eth66");

                // Store block
                if let Err(e) = self.poa_node.store.insert_block(beacon.clone()) {
                    warn!(error = %e, "Failed to store received block");
                }
            }
            NewBlockEvent::Hashes(announcement) => {
                // Handle NewBlockHashes message
            }
        }
    }
}
```

---

## RLP Encoding/Decoding

### Complete Message Structure

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       RLP Encoded Message Structure                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Byte Offset    Content                                                     │
│  ───────────    ───────                                                     │
│                                                                             │
│  [0]            Message ID: 0x07 (NewBlock)                                 │
│                                                                             │
│  [1-3]          Outer list header: f9 XX XX (NewBlock list)                 │
│                 ├── payload_length = NewBlock content length                │
│                                                                             │
│  [4-...]        NewBlock content:                                           │
│                 │                                                           │
│                 ├── [4-6]     Inner list header: f9 XX XX (N42BroadcastBlock)│
│                 │             ├── payload_length = beacon + execution length│
│                 │                                                           │
│                 ├── [7-...]   SignedBeaconBlock:                            │
│                 │             ├── List header                               │
│                 │             ├── BeaconBlock (slot, proposer, roots, body) │
│                 │             └── signature (96 bytes)                      │
│                 │                                                           │
│                 ├── [...]     Block (execution):                            │
│                 │             ├── List header                               │
│                 │             ├── Header (16+ fields)                       │
│                 │             └── BlockBody (txs, ommers, withdrawals)      │
│                 │                                                           │
│                 └── [last 5]  td (U128): 84 XX XX XX XX                     │
│                               ├── 84 = string header (4 bytes)              │
│                               └── 4 bytes = total difficulty value          │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Encoding Example

```
Actual encoded bytes (example):

07                          <- Message ID (NewBlock = 0x07)
f9 03 36                    <- Outer list header (payload = 822 bytes)
  f9 03 2e                  <- N42BroadcastBlock list header (payload = 814 bytes)
    f9 01 36                <- SignedBeaconBlock list header
      f8 d2                 <- BeaconBlock list header
        84 23 1d f1 19      <- slot (u64)
        80                  <- proposer_index (0)
        a0 00...00          <- parent_root (32 bytes)
        a0 11...11          <- state_root (32 bytes)
        ...                 <- BeaconBlockBody
      b8 60 00...00         <- signature (96 bytes)
    f9 01 f0                <- Block (execution) list header
      f9 01 ed              <- Header list header
        ...                 <- Header fields
      c0                    <- transactions (empty list)
      c0                    <- ommers (empty list)
  84 23 1d f1 19            <- td (U128, 4 bytes value)
```

---

## Key Code Locations

### Custom Type Definitions

| File | Content |
|------|---------|
| `examples/custom-node-types/src/primitives/unified.rs` | N42BroadcastBlock definition and RLP implementation |
| `examples/custom-node-types/src/primitives/beacon.rs` | BeaconBlock, SignedBeaconBlock definitions |
| `examples/custom-node-types/src/network/primitives.rs` | N42NetworkPrimitives definition |

### Broadcast Path

| Step | File | Function/Struct |
|------|------|-----------------|
| 1 | `examples/.../poa_eth66.rs` | `PoaNode::produce_block()` |
| 2 | `examples/.../poa_eth66.rs` | `create_broadcast_block()` |
| 3 | `examples/.../poa_eth66.rs` | `create_new_block_message()` |
| 4 | `crates/net/network/src/network.rs` | `NetworkHandle::announce_block()` |
| 5 | `crates/net/network/src/manager.rs` | `on_handle_message()` |
| 6 | `crates/net/network/src/state.rs` | `announce_new_block()` |
| 7 | `crates/net/network/src/swarm.rs` | `on_state_action()` |
| 8 | `crates/net/network/src/session/active.rs` | `on_internal_peer_message()` |
| 9 | `crates/net/eth-wire-types/src/message.rs` | `ProtocolBroadcastMessage::encode()` |
| 10 | `crates/net/eth-wire/src/ethstream.rs` | `start_send_broadcast()` |

### Receive Path

| Step | File | Function/Struct |
|------|------|-----------------|
| 1-2 | `crates/net/eth-wire/src/ethstream.rs` | `EthStream::poll_next()` |
| 3 | `crates/net/eth-wire/src/ethstream.rs` | `EthStreamInner::decode_message()` |
| 4-5 | `crates/net/eth-wire-types/src/message.rs` | `ProtocolMessage::decode_message()` |
| 6-7 | `crates/net/network/src/session/active.rs` | `on_incoming_message()` |
| 8 | `crates/net/network/src/session/mod.rs` | `SessionManager` event handling |
| 9 | `crates/net/network/src/manager.rs` | `on_peer_message()` |
| 10 | `examples/.../poa_eth66.rs` | `N42BlockImport::on_new_block()` |

---

## Important Notes

### RLP Encoding Limitations

1. **Do not use post-Cancun Header optional fields**
   - `parent_beacon_block_root`
   - `blob_gas_used`
   - `excess_blob_gas`

   These fields will cause RLP decode failures (Overflow error).

2. **Custom types must implement complete RLP encode/decode**
   - Ensure encode/decode logic is completely symmetric
   - Use unit tests to verify roundtrip

### Network Configuration

1. **Must use `.with_pow()` configuration**
   ```rust
   NetworkConfig::builder(secret_key)
       .with_pow()  // Enable NewBlock broadcasting
   ```

2. **Types must be consistent throughout the chain**
   ```rust
   NetworkManager::<N42NetworkPrimitives>::new(config)
   ```

### Debugging Tips

1. Enable network debug logs:
   ```bash
   RUST_LOG="info,net=debug" ./poa_eth66 ...
   ```

2. Run RLP roundtrip test:
   ```bash
   cargo test test_broadcast_message_roundtrip -- --nocapture
   ```
