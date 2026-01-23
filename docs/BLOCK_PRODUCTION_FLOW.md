# Block Production Flow

This document describes the complete block production flow in N42 node, from mining trigger to block broadcast.

## Overview

N42 implements a unified block architecture combining Beacon layer and Execution layer with Clique POA consensus. The block production process involves:

1. Consensus layer scheduling
2. Payload construction
3. Seal delay calculation
4. Block sealing and signing
5. Network broadcast

## Complete Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         N42 Block Production Flow                            │
└─────────────────────────────────────────────────────────────────────────────┘

┌───────────────────┐
│  1. Mining Trigger │
│  (Consensus Layer) │
└─────────┬─────────┘
          │
          ▼
┌───────────────────────────────────────────────────────────────┐
│  2. StartMining Command                                       │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │  • parent: SignedBeaconBlock (parent block)             │  │
│  │  • slot: u64 (target slot number)                       │  │
│  │  • in_turn: bool (is it our turn to produce)            │  │
│  │  • num_validators: usize (total validator count)        │  │
│  └─────────────────────────────────────────────────────────┘  │
└─────────────────────────┬─────────────────────────────────────┘
                          │
                          ▼
┌───────────────────────────────────────────────────────────────┐
│  3. Build Initial Payload (build_payload)                     │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │  Fetch from PayloadAttributesProvider:                  │  │
│  │  • timestamp = genesis_time + slot × block_time         │  │
│  │  • fee_recipient (coinbase address)                     │  │
│  │  • prev_randao (zero in POA)                            │  │
│  │  • withdrawals                                          │  │
│  │  • graffiti (extra_data/vanity)                         │  │
│  │                                                         │  │
│  │  TODO: Select transactions from transaction pool        │  │
│  └─────────────────────────────────────────────────────────┘  │
└─────────────────────────┬─────────────────────────────────────┘
                          │
                          ▼
┌───────────────────────────────────────────────────────────────┐
│  4. Calculate Seal Delay (calculate_seal_delay)               │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │                                                         │  │
│  │   base_delay = max(0, target_timestamp - current_time)  │  │
│  │                                                         │  │
│  │   ┌──────────────┐       ┌───────────────────────────┐  │  │
│  │   │  in_turn?    │──Yes─▶│ delay = base_delay        │  │  │
│  │   └──────┬───────┘       │ (precise timing, no wiggle)│  │  │
│  │          │               └───────────────────────────┘  │  │
│  │          No                                             │  │
│  │          ▼                                              │  │
│  │   ┌─────────────────────────────────────────────────┐   │  │
│  │   │ wiggle_base = (num_signers/2 + 1) × 500ms       │   │  │
│  │   │ wiggle = random(0..wiggle_base)                 │   │  │
│  │   │ delay = base_delay + wiggle                     │   │  │
│  │   │ (gives in-turn validator priority)              │   │  │
│  │   └─────────────────────────────────────────────────┘   │  │
│  │                                                         │  │
│  └─────────────────────────────────────────────────────────┘  │
└─────────────────────────┬─────────────────────────────────────┘
                          │
                          ▼
       ┌──────────────────┴──────────────────┐
       │                                      │
       ▼                                      ▼
┌──────────────────┐                  ┌──────────────────┐
│ 5a. Recommit     │                  │ 5b. Seal Timer   │
│     Timer        │                  │     Expires      │
│ (every 2 seconds)│                  │                  │
└────────┬─────────┘                  └─────────┬────────┘
         │                                      │
         ▼                                      │
┌──────────────────┐                            │
│ Rebuild Payload  │                            │
│ (include new txs)│─────────Loop───────────────┤
└──────────────────┘                            │
                                                ▼
┌───────────────────────────────────────────────────────────────┐
│  6. Seal Block (seal_and_broadcast)                           │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │  6.1 Calculate Difficulty                               │  │
│  │      • in_turn  → difficulty = 2 (DIFF_IN_TURN)         │  │
│  │      • out_turn → difficulty = 1 (DIFF_NO_TURN)         │  │
│  │                                                         │  │
│  │  6.2 Build Complete BeaconBlock                         │  │
│  │      • slot, proposer_index, parent_root                │  │
│  │      • state_root, body, difficulty                     │  │
│  └─────────────────────────────────────────────────────────┘  │
└─────────────────────────┬─────────────────────────────────────┘
                          │
                          ▼
┌───────────────────────────────────────────────────────────────┐
│  7. Sign Block (seal_block)                                   │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │                                                         │  │
│  │   seal_hash = compute_seal_hash(block)                  │  │
│  │                      │                                  │  │
│  │                      ▼                                  │  │
│  │   msg = Message::from_digest(seal_hash)                 │  │
│  │                      │                                  │  │
│  │                      ▼                                  │  │
│  │   sig = secp256k1.sign_ecdsa_recoverable(msg, sk)       │  │
│  │                      │                                  │  │
│  │                      ▼                                  │  │
│  │   signature = [r(32) | s(32) | v(1)] (65 bytes)         │  │
│  │                      │                                  │  │
│  │                      ▼                                  │  │
│  │   SignedBeaconBlock { message: block, signature }       │  │
│  │                                                         │  │
│  └─────────────────────────────────────────────────────────┘  │
└─────────────────────────┬─────────────────────────────────────┘
                          │
                          ▼
┌───────────────────────────────────────────────────────────────┐
│  8. Emit BlockSealed Event                                    │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │  MinerEvent::BlockSealed(SealResult {                   │  │
│  │      block: SignedBeaconBlock,                          │  │
│  │      hash: B256,                                        │  │
│  │      seal_latency: Duration,                            │  │
│  │  })                                                     │  │
│  └─────────────────────────────────────────────────────────┘  │
└─────────────────────────┬─────────────────────────────────────┘
                          │
                          ▼
┌───────────────────────────────────────────────────────────────┐
│  9. Build Unified Block and Broadcast                         │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │                                                         │  │
│  │   UnifiedBlock {                                        │  │
│  │       beacon: SignedBeaconBlock,  ◄── Beacon layer      │  │
│  │       execution: SealedBlock,     ◄── Execution layer   │  │
│  │   }                                                     │  │
│  │            │                                            │  │
│  │            ▼                                            │  │
│  │   N42BroadcastBlock (for P2P broadcast)                 │  │
│  │            │                                            │  │
│  │            ▼                                            │  │
│  │   eth66 NewBlock message → Broadcast to network         │  │
│  │                                                         │  │
│  └─────────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────────┘
                          │
                          ▼
                   ┌──────────────┐
                   │ Block Done   │
                   └──────────────┘
```

## Core Data Structures

### SignedBeaconBlock

```
┌─────────────────────────────────────────────────────────────┐
│                    SignedBeaconBlock                         │
├─────────────────────────────────────────────────────────────┤
│  message: BeaconBlock                                        │
│  ├── slot: u64                                               │
│  ├── proposer_index: u64                                     │
│  ├── parent_root: B256                                       │
│  ├── state_root: B256                                        │
│  ├── difficulty: u64  (2=in-turn, 1=out-of-turn)            │
│  └── body: BeaconBlockBody                                   │
│      ├── randao_reveal: Bytes                                │
│      ├── eth1_data: Eth1Data                                 │
│      ├── graffiti: B256 (extra_data + difficulty)           │
│      └── execution_payload_root: B256 (execution block hash) │
│                                                              │
│  signature: Bytes (65 bytes: r|s|v)                          │
└─────────────────────────────────────────────────────────────┘
```

### UnifiedBlock

```
┌─────────────────────────────────────────────────────────────┐
│                      UnifiedBlock                            │
├─────────────────────────────────────────────────────────────┤
│  beacon: SignedBeaconBlock                                   │
│  ├── Contains consensus-layer information                    │
│  └── Includes signature for block authentication             │
│                                                              │
│  execution: SealedBlock                                      │
│  ├── Standard Ethereum execution block                       │
│  ├── Contains transactions                                   │
│  └── State transitions                                       │
│                                                              │
│  Cross-references:                                           │
│  • beacon.body.execution_payload_root == execution.hash()    │
│  • execution.header.parent_beacon_block_root == beacon.root  │
└─────────────────────────────────────────────────────────────┘
```

## Detailed Phase Descriptions

### Phase 1: Mining Trigger

The consensus layer determines when it's time to produce a block based on:
- Current slot number
- Validator index
- Block time configuration (default: 8 seconds)

### Phase 2: StartMining Command

The `MinerCommand::StartMining` is sent to the worker with:

```rust
pub enum MinerCommand {
    StartMining {
        parent: SignedBeaconBlock,      // Parent block
        slot: u64,                       // Target slot
        in_turn: bool,                   // Is it our turn
        num_validators: usize,           // Total validator count
    },
    Stop,
    UpdateHead(SignedBeaconBlock),
    Recommit,
}
```

### Phase 3: Build Payload

The `build_payload` function constructs the block body:

```rust
fn build_payload(&self, slot: u64, _parent: &SignedBeaconBlock) -> BeaconBlockBody {
    let timestamp = self.attributes.timestamp(slot);
    let fee_recipient = self.attributes.suggested_fee_recipient(slot);
    let prev_randao = self.attributes.prev_randao(slot);
    let withdrawals = self.attributes.withdrawals(slot);

    let mut body = BeaconBlockBody::default();

    // Store extra_data (vanity) in graffiti
    if !self.config.extra_data.is_empty() {
        body.graffiti.0[..len].copy_from_slice(&self.config.extra_data[..len]);
    }

    body
}
```

### Phase 4: Calculate Seal Delay

The delay calculation gives in-turn validators priority:

```rust
pub fn calculate_seal_delay(env: &MiningEnvironment) -> Duration {
    let base_delay_secs = if env.target_timestamp > env.current_timestamp {
        env.target_timestamp - env.current_timestamp
    } else {
        0
    };

    let base_delay = Duration::from_secs(base_delay_secs);

    if env.in_turn {
        // In-turn: no wiggle, seal at exact timestamp
        base_delay
    } else {
        // Out-of-turn: add random wiggle delay
        let wiggle = calculate_wiggle_delay(env.num_signers);
        base_delay + wiggle
    }
}

fn calculate_wiggle_delay(num_signers: usize) -> Duration {
    // wiggle_base = (num_signers / 2 + 1) * 500ms
    let wiggle_base_ms = ((num_signers / 2) + 1) as u64 * WIGGLE_TIME_MS;
    let random_ms = rand::thread_rng().gen_range(0..wiggle_base_ms);
    Duration::from_millis(random_ms)
}
```

**Wiggle Delay Example** (3 validators):
- Wiggle base = (3/2 + 1) × 500ms = 1000ms
- Out-of-turn delay = random(0..1000ms)

### Phase 5: Recommit Timer

The recommit timer fires every 2 seconds to rebuild the payload with new transactions:

```rust
pub async fn run(mut self) {
    let mut recommit_interval = interval(self.config.recommit_interval);

    loop {
        tokio::select! {
            // Recommit timer - rebuild payload for new transactions
            _ = recommit_interval.tick(), if self.state.is_some() => {
                self.rebuild_payload().await;
            }

            // Seal timer - sign and broadcast
            _ = tokio::time::sleep(seal_duration), if seal_duration.is_some() => {
                self.seal_and_broadcast().await;
            }
        }
    }
}
```

### Phase 6: Seal Block

When the seal timer expires:

```rust
async fn seal_and_broadcast(&mut self) {
    // 1. Calculate difficulty based on in-turn status
    let difficulty = if state.in_turn {
        DIFFICULTY_IN_TURN      // 2
    } else {
        DIFFICULTY_OUT_OF_TURN  // 1
    };

    // 2. Set difficulty in graffiti
    set_difficulty_in_graffiti(&mut body.graffiti, difficulty);

    // 3. Build complete BeaconBlock
    let block = BeaconBlock::new(
        state.slot,
        self.proposer_index,
        state.parent.block_root(),
        B256::ZERO,
        body,
        difficulty,
    );

    // 4. Sign block
    let signed_block = seal_block(block, self.config.signing_key());

    // 5. Emit event
    self.event_tx.send(MinerEvent::BlockSealed(result)).await;
}
```

### Phase 7: Sign Block

The `seal_block` function performs ECDSA signing:

```rust
pub fn seal_block(block: BeaconBlock, secret_key: &SecretKey) -> SignedBeaconBlock {
    let secp = Secp256k1::signing_only();

    // 1. Compute seal hash (block hash without signature)
    let seal_hash = compute_seal_hash(&block);

    // 2. Create message from hash
    let msg = Message::from_digest(seal_hash.0);

    // 3. Sign with recoverable signature
    let sig = secp.sign_ecdsa_recoverable(&msg, secret_key);

    // 4. Serialize to 65 bytes [r(32) | s(32) | v(1)]
    let sig_bytes = serialize_recoverable_signature(&sig);

    SignedBeaconBlock::new(block, sig_bytes)
}
```

### Phase 8-9: Event and Broadcast

The sealed block is emitted as an event and then broadcast:

```rust
// Build unified block
let unified = UnifiedBlock {
    beacon: signed_beacon_block,
    execution: sealed_execution_block,
};

// Convert to broadcast format
let broadcast = N42BroadcastBlock::from_unified(&unified);

// Send via eth66 NewBlock message
let new_block = NewBlock {
    block: broadcast,
    td: total_difficulty,
};

network.broadcast(new_block).await;
```

## Key Code Locations

| Phase | File | Lines |
|-------|------|-------|
| Worker main loop | `src/miner/worker.rs` | 248-296 |
| start_mining | `src/miner/worker.rs` | 300-345 |
| build_payload | `src/miner/worker.rs` | 387-410 |
| seal_and_broadcast | `src/miner/worker.rs` | 412-463 |
| calculate_seal_delay | `src/miner/sealer.rs` | 66-96 |
| seal_block | `src/miner/sealer.rs` | 124-151 |

## Constants and Configuration

```rust
// Miner Configuration
DEFAULT_RECOMMIT_INTERVAL: Duration = 2 seconds
DEFAULT_GAS_CEIL: u64 = 30,000,000
DEFAULT_GAS_PRICE: u128 = 1,000,000,000 (1 gwei)

// Clique POA
DIFF_IN_TURN: u64 = 2
DIFF_NO_TURN: u64 = 1
WIGGLE_TIME_MS: u64 = 500
EXTRA_VANITY: usize = 32         // Extra data prefix
EXTRA_SEAL: usize = 65           // Signature size

// Block Parameters
DEFAULT_BLOCK_TIME: u64 = 8 seconds
EPOCH_LENGTH: u64 = 30,000 blocks
CHECKPOINT_INTERVAL: u64 = 1,024 blocks
```

## Sequence Diagram

```
┌─────────┐     ┌────────┐     ┌────────┐     ┌─────────┐     ┌─────────┐
│Consensus│     │ Worker │     │ Sealer │     │ Network │     │  Peers  │
└────┬────┘     └───┬────┘     └───┬────┘     └────┬────┘     └────┬────┘
     │              │              │               │               │
     │ StartMining  │              │               │               │
     │─────────────▶│              │               │               │
     │              │              │               │               │
     │              │ build_payload│               │               │
     │              │─────────────▶│               │               │
     │              │              │               │               │
     │              │ calc_delay   │               │               │
     │              │─────────────▶│               │               │
     │              │◀─────────────│               │               │
     │              │              │               │               │
     │              │    [Wait for seal time]      │               │
     │              │─ ─ ─ ─ ─ ─ ─▶│               │               │
     │              │              │               │               │
     │              │ seal_block   │               │               │
     │              │─────────────▶│               │               │
     │              │◀─────────────│               │               │
     │              │              │               │               │
     │              │         broadcast            │               │
     │              │─────────────────────────────▶│               │
     │              │              │               │   NewBlock    │
     │              │              │               │──────────────▶│
     │              │              │               │               │
     │ BlockSealed  │              │               │               │
     │◀─────────────│              │               │               │
     │              │              │               │               │
```

## Related Documentation

- [Beacon Architecture](./BEACON_ARCHITECTURE.md) - System architecture overview
- [POA eth66 Block Propagation](./POA_ETH66_BLOCK_PROPAGATION.md) - Network broadcast mechanism
- [Test Scripts](./TEST_SCRIPTS.md) - Testing the block production
