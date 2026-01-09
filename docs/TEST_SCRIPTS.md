# POA Test Scripts Usage Guide

This directory contains two test scripts for testing POA eth66 block propagation and synchronization.

## Script Overview

| Script | Purpose |
|--------|---------|
| `test_poa_eth66.sh` | Test block propagation between 3 validator nodes |
| `test_sync_node.sh` | Test sync node downloading blocks from validators |

## 1. test_poa_eth66.sh - Validator Block Propagation Test

Tests eth66 block broadcast between 3 validator nodes.

### How to Run

```bash
cd examples/custom-node-types
./test_poa_eth66.sh
```

### Test Flow

```
1. Start Validator 0 (port 30303)
2. Start Validator 1 (port 30304) → connects to Validator 0
3. Start Validator 2 (port 30305) → connects to Validator 0
4. Wait 30 seconds for nodes to connect and exchange blocks
5. Collect statistics and display results
```

### Expected Output

```
=== Peer Connections ===
  Node 0 connected peers: 2
  Node 1 connected peers: 2
  Node 2 connected peers: 2

=== Block Broadcasts ===
  Node 0 broadcasts: 3
  Node 1 broadcasts: 3
  Node 2 broadcasts: 3

=== Block Receives ===
  Node 0 received: 6 blocks
  Node 1 received: 6 blocks
  Node 2 received: 6 blocks

TEST PASSED!
```

---

## 2. test_sync_node.sh - Sync Node Download Test

Tests a non-validator node downloading blocks from 3 validators.

### How to Run

```bash
cd examples/custom-node-types
./test_sync_node.sh
```

### Test Flow

```
Phase 1: Start 3 Validators
   ├── Validator 0 (port 30303)
   ├── Validator 1 (port 30304)
   └── Validator 2 (port 30305)

Phase 2: Wait for Validators to Produce Blocks (30 seconds)
   └── Validators take turns producing blocks

Phase 3: Start Sync Node
   ├── Sync Node (port 30400)
   ├── Connect to Validators
   └── Download and validate blocks

Phase 4: Collect Statistics (after 30 seconds)
```

### Expected Output

```
=== Validator Statistics ===
  Validator 0: produced=8, received=6
  Validator 1: produced=7, received=6
  Validator 2: produced=6, received=6

=== Sync Node Statistics ===
  Peers connected: 3
  Blocks synced: 6
  Blocks rejected: 0

TEST PASSED!
Sync node successfully downloaded 6 blocks from validators.
```

---

## Manual Run

If you want to manually control each node, run them in separate terminals:

### Start Validators

```bash
# Terminal 1 - Validator 0 (Bootstrap node)
cargo run --release -p example-custom-node-types --bin poa_eth66 -- \
    --validator-index 0 \
    --port 30303 \
    --block-time 5

# Copy the enode URL from output, like:
# enode://abc123...@127.0.0.1:30303
```

```bash
# Terminal 2 - Validator 1
cargo run --release -p example-custom-node-types --bin poa_eth66 -- \
    --validator-index 1 \
    --port 30304 \
    --block-time 5 \
    --bootnode "enode://abc123...@127.0.0.1:30303"
```

```bash
# Terminal 3 - Validator 2
cargo run --release -p example-custom-node-types --bin poa_eth66 -- \
    --validator-index 2 \
    --port 30305 \
    --block-time 5 \
    --bootnode "enode://abc123...@127.0.0.1:30303"
```

### Start Sync Node

```bash
# Terminal 4 - Sync Node (non-validator)
cargo run --release -p example-custom-node-types --bin poa_sync_node -- \
    --port 30400 \
    --block-time 5 \
    --bootnode "enode://abc123...@127.0.0.1:30303"
```

---

## Command Line Arguments

### poa_eth66 (Validator Node)

| Argument | Description | Default |
|----------|-------------|---------|
| `--validator-index` | Validator index (0, 1, 2) | 0 |
| `--port` | P2P port | 30303 |
| `--block-time` | Block interval (seconds) | 5 |
| `--bootnode` | Bootstrap node enode URL | None |
| `--data-dir` | Data directory | /tmp/poa |

### poa_sync_node (Sync Node)

| Argument | Description | Default |
|----------|-------------|---------|
| `--port` | P2P port | 30400 |
| `--block-time` | Block interval for validation | 5 |
| `--bootnode` | Bootstrap node enode URL (can specify multiple) | None |

---

## Log Locations

Test scripts create temporary log directories:

```
/tmp/poa_eth66_test_<PID>/
├── node0.log    # Validator 0 log
├── node1.log    # Validator 1 log
└── node2.log    # Validator 2 log

/tmp/poa_sync_test_<PID>/
├── validator0.log
├── validator1.log
├── validator2.log
└── sync_node.log
```

### View Logs

```bash
# View block production
grep "Produced block" /tmp/poa_*/node0.log

# View block reception
grep "Received NewBlock" /tmp/poa_*/node0.log

# View sync progress
grep "Synced new block" /tmp/poa_sync_*/sync_node.log

# View sync status
grep "Sync status" /tmp/poa_sync_*/sync_node.log
```

---

## Troubleshooting

### 1. Nodes Cannot Connect

- Ensure ports are not in use
- Check firewall settings
- Verify bootnode enode URL is correct

### 2. Blocks Not Propagating

- Check `--block-time` parameter is consistent
- Look for decode errors in logs

### 3. Sync Node Not Syncing

- Sync node only receives **new** blocks, doesn't request historical blocks
- If validators have been running for a while, sync node will only receive subsequent new blocks
- Check if successfully connected to peers

### 4. Build Failure

```bash
# Make sure to build release version first
cargo build --release -p example-custom-node-types
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    POA Network Topology                  │
├─────────────────────────────────────────────────────────┤
│                                                         │
│    ┌──────────────┐                                     │
│    │ Validator 0  │◄────────────────┐                   │
│    │ (Bootstrap)  │                 │                   │
│    │ Port: 30303  │─────┐           │                   │
│    └──────────────┘     │           │                   │
│           │             │           │                   │
│           │ eth66       │ eth66     │ eth66             │
│           │ NewBlock    │ NewBlock  │ NewBlock          │
│           ▼             ▼           │                   │
│    ┌──────────────┐  ┌──────────────┐                   │
│    │ Validator 1  │◄─│ Validator 2  │                   │
│    │ Port: 30304  │  │ Port: 30305  │                   │
│    └──────────────┘  └──────────────┘                   │
│           │                   │                         │
│           └─────────┬─────────┘                         │
│                     │ eth66 NewBlock                    │
│                     ▼                                   │
│              ┌──────────────┐                           │
│              │  Sync Node   │  (download only)          │
│              │ Port: 30400  │                           │
│              └──────────────┘                           │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### Block Production Rules

- 3 Validators take turns producing blocks
- When `slot % 3 == validator_index`, it's an in-turn block
- In-turn difficulty = 2, Out-of-turn difficulty = 1
- Blocks are broadcast via eth66 NewBlock message

### Sync Node Features

- Does not participate in block production
- Connects to validators to receive broadcasts
- Validates block signatures and POA rules
- Stores blocks to local BeaconStore
