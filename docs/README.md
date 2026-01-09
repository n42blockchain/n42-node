# N42 Custom Node Types

A custom POA blockchain implementation based on Reth, supporting Beacon + Execution dual-layer architecture.

## Directory Structure

```
examples/custom-node-types/
│
├── docs/                                  # Documentation
│   ├── README.md                          # This file - Project overview
│   ├── BEACON_ARCHITECTURE.md             # Architecture design document
│   ├── TEST_SCRIPTS.md                    # Test scripts usage guide
│   └── POA_ETH66_BLOCK_PROPAGATION.md     # eth66 block propagation document
│
├── src/
│   ├── bin/                               # Executable programs
│   │   ├── poa_eth66.rs                   # Validator node (produce + broadcast blocks)
│   │   ├── poa_sync_node.rs               # Sync node (download blocks only)
│   │   ├── poa_node.rs                    # Full node
│   │   └── poa_demo.rs                    # Simple demo
│   │
│   ├── consensus/                         # POA consensus layer
│   │   ├── config.rs                      # POA configuration (validators, block_time)
│   │   ├── state.rs                       # BeaconState state machine
│   │   ├── state_transition.rs            # State transition and signature verification
│   │   ├── validator.rs                   # PoaValidator block validation
│   │   ├── worker.rs                      # PoaWorker block production
│   │   └── mod.rs
│   │
│   ├── primitives/                        # Data type definitions
│   │   ├── beacon.rs                      # BeaconBlock, SignedBeaconBlock
│   │   ├── unified.rs                     # N42Block (beacon + execution)
│   │   └── mod.rs
│   │
│   ├── network/                           # P2P network layer
│   │   ├── primitives.rs                  # N42NetworkPrimitives, N42NewBlock
│   │   ├── beacon_messages.rs             # GetBeaconBlocks/BeaconBlocks messages
│   │   ├── beacon_protocol.rs             # beacon_sync custom protocol
│   │   └── mod.rs
│   │
│   ├── stages/                            # Pipeline sync stages
│   │   ├── beacon_blocks.rs               # BeaconBlocksStage (download + validate)
│   │   ├── downloader/
│   │   │   ├── client.rs                  # BeaconBlockClient trait
│   │   │   ├── downloader.rs              # BeaconBlockDownloader
│   │   │   └── mod.rs
│   │   └── mod.rs
│   │
│   ├── storage/                           # Storage layer
│   │   ├── traits.rs                      # BeaconStore traits
│   │   ├── memory.rs                      # InMemoryBeaconStore
│   │   └── mod.rs
│   │
│   ├── validation/                        # Validation logic
│   │   ├── beacon.rs                      # Beacon block validation
│   │   ├── execution.rs                   # Execution block validation
│   │   ├── cross.rs                       # Cross-layer validation
│   │   └── mod.rs
│   │
│   ├── engine/                            # Engine API
│   │   ├── types.rs
│   │   ├── validator.rs
│   │   └── mod.rs
│   │
│   ├── evm/                               # EVM configuration
│   │   ├── config.rs
│   │   └── mod.rs
│   │
│   ├── node/                              # Node builder
│   │   ├── types.rs
│   │   ├── components.rs
│   │   ├── payload.rs
│   │   ├── primitives.rs
│   │   └── mod.rs
│   │
│   ├── lib.rs                             # Library entry
│   └── main.rs
│
├── test_poa_eth66.sh                      # 3-node block propagation test
├── test_sync_node.sh                      # Sync node download test
├── run_poa_network.sh                     # Network startup script
└── Cargo.toml                             # Dependencies configuration
```

## Core Module Description

| Module | Function | Key Files |
|--------|----------|-----------|
| `consensus/` | POA consensus | `config.rs`, `validator.rs`, `worker.rs` |
| `primitives/` | Data structures | `beacon.rs` (BeaconBlock), `unified.rs` (N42Block) |
| `network/` | P2P network | `primitives.rs` (eth66), `beacon_protocol.rs` |
| `stages/` | Sync stages | `beacon_blocks.rs` (BeaconBlocksStage) |
| `storage/` | Storage | `memory.rs` (InMemoryBeaconStore) |
| `bin/` | Executables | `poa_eth66.rs`, `poa_sync_node.rs` |

## Quick Start

### Build

```bash
cargo build --release -p example-custom-node-types
```

### Run Tests

```bash
# Test block propagation between 3 validator nodes
./test_poa_eth66.sh

# Test sync node downloading blocks from validators
./test_sync_node.sh
```

### Manual Run

```bash
# Terminal 1 - Validator 0
cargo run --release -p example-custom-node-types --bin poa_eth66 -- \
    --validator-index 0 --port 30303

# Terminal 2 - Validator 1 (use enode from Terminal 1 output)
cargo run --release -p example-custom-node-types --bin poa_eth66 -- \
    --validator-index 1 --port 30304 --bootnode "enode://..."

# Terminal 3 - Sync Node
cargo run --release -p example-custom-node-types --bin poa_sync_node -- \
    --port 30400 --bootnode "enode://..."
```

## Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                   N42 Node Architecture                  │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  ┌─────────────────────────────────────────────────┐    │
│  │              Consensus Layer (POA)              │    │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────────┐   │    │
│  │  │PoaConfig │  │PoaWorker │  │PoaValidator  │   │    │
│  │  │validators│  │ produce  │  │ validate     │   │    │
│  │  └──────────┘  └──────────┘  └──────────────┘   │    │
│  └─────────────────────────────────────────────────┘    │
│                          │                              │
│                          ▼                              │
│  ┌─────────────────────────────────────────────────┐    │
│  │                 Primitives                      │    │
│  │  ┌──────────────┐      ┌──────────────────┐     │    │
│  │  │ BeaconBlock  │ ──── │ N42Block         │     │    │
│  │  │ (slot, root) │      │ (beacon + exec)  │     │    │
│  │  └──────────────┘      └──────────────────┘     │    │
│  └─────────────────────────────────────────────────┘    │
│                          │                              │
│                          ▼                              │
│  ┌─────────────────────────────────────────────────┐    │
│  │                   Network                       │    │
│  │  ┌────────────────┐    ┌────────────────────┐   │    │
│  │  │ eth66 NewBlock │    │ beacon_sync proto  │   │    │
│  │  │ broadcast      │    │ request history    │   │    │
│  │  └────────────────┘    └────────────────────┘   │    │
│  └─────────────────────────────────────────────────┘    │
│                          │                              │
│                          ▼                              │
│  ┌─────────────────────────────────────────────────┐    │
│  │                   Storage                       │    │
│  │  ┌──────────────────────────────────────────┐   │    │
│  │  │ InMemoryBeaconStore                      │   │    │
│  │  │ slot → SignedBeaconBlock                 │   │    │
│  │  └──────────────────────────────────────────┘   │    │
│  └─────────────────────────────────────────────────┘    │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

## Documentation Index

- [Architecture Design](./BEACON_ARCHITECTURE.md) - Detailed system architecture and data flow
- [Test Scripts](./TEST_SCRIPTS.md) - How to use test scripts
- [eth66 Block Propagation](./POA_ETH66_BLOCK_PROPAGATION.md) - P2P block broadcast mechanism

## Block Production Rules

- 3 Validators take turns producing blocks
- When `slot % 3 == validator_index`, it's an in-turn block
- In-turn difficulty = 2, Out-of-turn difficulty = 1
- Default block interval = 5 seconds

## Node Types

| Type | Program | Function |
|------|---------|----------|
| Validator | `poa_eth66` | Produce blocks + broadcast + validate |
| Sync Node | `poa_sync_node` | Download and validate only, no production |
