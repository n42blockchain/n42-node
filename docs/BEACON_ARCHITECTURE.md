# N42 Beacon Chain Architecture

This document describes the beacon chain architecture for the N42 POA (Proof of Authority) blockchain.

## Table of Contents

1. [Overview](#overview)
2. [Architecture Diagram](#architecture-diagram)
3. [Data Structures](#data-structures)
4. [Sync Flow](#sync-flow)
5. [Validation Flow](#validation-flow)
6. [State Transition](#state-transition)
7. [Module Structure](#module-structure)

---

## Overview

N42 implements a simplified beacon chain layer for POA consensus. Unlike Ethereum's full beacon chain with BLS signatures, attestations, and complex finality gadgets, N42 uses:

- **secp256k1 signatures** (same as Ethereum accounts)
- **Round-robin proposer selection** (no random shuffling)
- **No attestations** (POA doesn't need them)
- **Simplified state** (only validators and block history)

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        N42 Dual-Layer Architecture                       │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │                     Beacon Layer (Consensus)                     │   │
│   │                                                                 │   │
│   │   - Defines canonical chain                                     │   │
│   │   - Validates proposer signatures                               │   │
│   │   - Maintains validator set                                     │   │
│   │   - Round-robin block production                                │   │
│   │                                                                 │   │
│   │   Data: SignedBeaconBlock, BeaconState, BeaconStore            │   │
│   └─────────────────────────────────────────────────────────────────┘   │
│                              │                                          │
│                              │ execution_payload_root                   │
│                              ▼                                          │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │                   Execution Layer (EVM)                          │   │
│   │                                                                 │   │
│   │   - Executes transactions                                       │   │
│   │   - Maintains account state                                     │   │
│   │   - Computes state root                                         │   │
│   │                                                                 │   │
│   │   Data: Block, Header, Body, Receipt, ExecutionState           │   │
│   └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Architecture Diagram

### Component Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              N42 Node Components                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                           P2P Network Layer                            │  │
│  │                                                                       │  │
│  │   ┌─────────────────┐              ┌─────────────────┐                │  │
│  │   │   eth66/eth67   │              │  beacon_sync/1  │                │  │
│  │   │   (execution)   │              │   (beacon)      │                │  │
│  │   │                 │              │                 │                │  │
│  │   │ - Headers       │              │ - GetBeaconBlocks│               │  │
│  │   │ - Bodies        │              │ - BeaconBlocks  │                │  │
│  │   │ - Transactions  │              │                 │                │  │
│  │   └────────┬────────┘              └────────┬────────┘                │  │
│  │            │                                │                         │  │
│  └────────────┼────────────────────────────────┼─────────────────────────┘  │
│               │                                │                            │
│               ▼                                ▼                            │
│  ┌────────────────────────┐      ┌────────────────────────────┐            │
│  │   Execution Downloader │      │   Beacon Block Downloader  │            │
│  │                        │      │                            │            │
│  │  - HeadersDownloader   │      │  - BeaconBlockDownloader   │            │
│  │  - BodiesDownloader    │      │  - Concurrent requests     │            │
│  │                        │      │  - Ordered buffering       │            │
│  └───────────┬────────────┘      └─────────────┬──────────────┘            │
│              │                                 │                            │
│              ▼                                 ▼                            │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        Pipeline (Staged Sync)                        │   │
│  │                                                                     │   │
│  │  ┌─────────────────────────────────────────────────────────────┐    │   │
│  │  │ Stage 1: ValidatingBeaconBlocksStage (FIRST)                │    │   │
│  │  │                                                             │    │   │
│  │  │  - Downloads beacon blocks                                  │    │   │
│  │  │  - Validates signatures against BeaconState                 │    │   │
│  │  │  - Stores to BeaconStore                                    │    │   │
│  │  │  - Defines canonical chain                                  │    │   │
│  │  └──────────────────────────┬──────────────────────────────────┘    │   │
│  │                             │                                       │   │
│  │                             │ execution_payload_root                │   │
│  │                             ▼                                       │   │
│  │  ┌─────────────────────────────────────────────────────────────┐    │   │
│  │  │ Stage 2: HeadersStage                                       │    │   │
│  │  │                                                             │    │   │
│  │  │  - Downloads execution headers                              │    │   │
│  │  │  - Uses BeaconExecutionMappingProvider to know targets      │    │   │
│  │  └──────────────────────────┬──────────────────────────────────┘    │   │
│  │                             │                                       │   │
│  │                             ▼                                       │   │
│  │  ┌─────────────────────────────────────────────────────────────┐    │   │
│  │  │ Stage 3: BodiesStage                                        │    │   │
│  │  │                                                             │    │   │
│  │  │  - Downloads execution block bodies                         │    │   │
│  │  │  - Matches with headers                                     │    │   │
│  │  └──────────────────────────┬──────────────────────────────────┘    │   │
│  │                             │                                       │   │
│  │                             ▼                                       │   │
│  │  ┌─────────────────────────────────────────────────────────────┐    │   │
│  │  │ Stage 4: ExecutionStage                                     │    │   │
│  │  │                                                             │    │   │
│  │  │  - Executes transactions in EVM                             │    │   │
│  │  │  - Computes state roots                                     │    │   │
│  │  │  - Generates receipts                                       │    │   │
│  │  └─────────────────────────────────────────────────────────────┘    │   │
│  │                                                                     │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                            Storage Layer                             │   │
│  │                                                                     │   │
│  │   ┌─────────────────────┐         ┌─────────────────────┐           │   │
│  │   │    BeaconStore      │         │  Execution Database │           │   │
│  │   │                     │         │                     │           │   │
│  │   │  - Beacon blocks    │         │  - Headers          │           │   │
│  │   │  - Beacon state     │         │  - Bodies           │           │   │
│  │   │  - Checkpoints      │         │  - Receipts         │           │   │
│  │   │                     │         │  - State trie       │           │   │
│  │   └─────────────────────┘         └─────────────────────┘           │   │
│  │                                                                     │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Data Structures

### Beacon Layer

#### SignedBeaconBlock

```
┌─────────────────────────────────────────────────────────────────┐
│                      SignedBeaconBlock                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  message: BeaconBlock                                           │
│  ├── slot: u64                    // Block height (time slot)   │
│  ├── proposer_index: u64          // Validator who proposed     │
│  ├── parent_root: B256            // Hash of parent block       │
│  ├── state_root: B256             // Beacon state after block   │
│  └── body: BeaconBlockBody                                      │
│      ├── randao_reveal: Bytes     // Proposer's RANDAO          │
│      ├── eth1_data: Eth1Data      // Execution layer reference  │
│      ├── graffiti: B256           // Arbitrary proposer data    │
│      └── execution_payload_root: B256  // Links to execution    │
│                                                                 │
│  signature: Bytes                 // secp256k1 ECDSA signature  │
│                                   // (64 bytes compact format)  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

#### BeaconState

```
┌─────────────────────────────────────────────────────────────────┐
│                         BeaconState                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  genesis_time: u64                // Unix timestamp of genesis  │
│  genesis_validators_root: B256    // For signature domain       │
│  slot: u64                        // Current slot number        │
│                                                                 │
│  latest_block_header: BeaconBlockHeaderLight                    │
│  ├── slot: u64                                                  │
│  ├── proposer_index: u64                                        │
│  ├── parent_root: B256                                          │
│  ├── state_root: B256                                           │
│  └── body_root: B256                                            │
│                                                                 │
│  block_roots: Vec<B256>           // Historical block roots     │
│  state_roots: Vec<B256>           // Historical state roots     │
│                                                                 │
│  validators: Vec<BeaconValidator> // Active validator set       │
│  validator_indices: HashMap<Address, u64>  // Fast lookup       │
│                                                                 │
│  finalized_checkpoint: Checkpoint // Last finalized point       │
│  justified_checkpoint: Checkpoint // Last justified point       │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

#### BeaconValidator

```
┌─────────────────────────────────────────────────────────────────┐
│                       BeaconValidator                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  address: Address                 // Ethereum address           │
│                                   // (derived from pubkey)      │
│                                                                 │
│  pubkey: secp256k1::PublicKey     // For signature verification │
│                                   // (33 bytes compressed or    │
│                                   //  65 bytes uncompressed)    │
│                                                                 │
│  index: u64                       // Position in validator set  │
│                                                                 │
│  active: bool                     // Can propose blocks?        │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Execution Layer

#### Block Relationship

```
┌─────────────────────────────────────────────────────────────────┐
│                   Block Structure Relationship                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  SignedBeaconBlock (Slot N)                                     │
│  │                                                              │
│  │  execution_payload_root ─────────┐                           │
│  │                                  │                           │
│  │                                  ▼                           │
│  │                     ┌────────────────────────┐               │
│  │                     │   ExecutionPayload     │               │
│  │                     │                        │               │
│  │                     │  parent_hash: B256     │               │
│  │                     │  state_root: B256      │               │
│  │                     │  receipts_root: B256   │               │
│  │                     │  block_number: u64     │               │
│  │                     │  gas_used: u64         │               │
│  │                     │  timestamp: u64        │               │
│  │                     │  transactions: Vec<Tx> │               │
│  │                     │  withdrawals: Vec<W>   │               │
│  │                     │                        │               │
│  │                     └────────────────────────┘               │
│  │                                                              │
│  │  parent_root ────────────────────┐                           │
│  │                                  │                           │
│  ▼                                  ▼                           │
│  SignedBeaconBlock (Slot N-1)       SignedBeaconBlock (Parent)  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Sync Flow

### Initial Sync

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            Initial Sync Flow                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  1. DISCOVER SYNC TARGET                                                    │
│     ┌─────────────────────────────────────────────────────────────────┐     │
│     │                                                                 │     │
│     │  Peer Discovery                 Consensus Layer (if available)  │     │
│     │       │                                │                        │     │
│     │       │  highest_slot                  │  fork_choice_updated   │     │
│     │       │                                │                        │     │
│     │       └────────────┬───────────────────┘                        │     │
│     │                    │                                            │     │
│     │                    ▼                                            │     │
│     │          BeaconSyncTargetProvider                               │     │
│     │          ├── slot: 1000                                         │     │
│     │          ├── block_root: 0x...                                  │     │
│     │          └── finalized: true                                    │     │
│     │                                                                 │     │
│     └─────────────────────────────────────────────────────────────────┘     │
│                                      │                                      │
│                                      ▼                                      │
│  2. DOWNLOAD BEACON BLOCKS                                                  │
│     ┌─────────────────────────────────────────────────────────────────┐     │
│     │                                                                 │     │
│     │  Local Head: Slot 0                      Target: Slot 1000      │     │
│     │       │                                        │                │     │
│     │       │         BeaconBlockDownloader          │                │     │
│     │       │                │                       │                │     │
│     │       │                ▼                       │                │     │
│     │       │  ┌───────────────────────────────┐    │                │     │
│     │       │  │ Request: GetBeaconBlocks      │    │                │     │
│     │       │  │   start_slot: 1               │    │                │     │
│     │       │  │   count: 64                   │    │                │     │
│     │       │  └───────────────────────────────┘    │                │     │
│     │       │                │                       │                │     │
│     │       │                ▼                       │                │     │
│     │       │  ┌───────────────────────────────┐    │                │     │
│     │       │  │ Response: BeaconBlocks        │    │                │     │
│     │       │  │   blocks: [block1, block2...] │    │                │     │
│     │       │  └───────────────────────────────┘    │                │     │
│     │       │                                        │                │     │
│     │       └────────────────┬───────────────────────┘                │     │
│     │                        │                                        │     │
│     └────────────────────────┼────────────────────────────────────────┘     │
│                              │                                              │
│                              ▼                                              │
│  3. VALIDATE & STORE                                                        │
│     ┌─────────────────────────────────────────────────────────────────┐     │
│     │                                                                 │     │
│     │  For each SignedBeaconBlock:                                    │     │
│     │                                                                 │     │
│     │  ┌─────────────────────────────────────────────────────────┐    │     │
│     │  │ process_block(state, block, config)                     │    │     │
│     │  │                                                         │    │     │
│     │  │  ✓ Verify slot > state.slot                             │    │     │
│     │  │  ✓ Verify parent_root == latest_block.root              │    │     │
│     │  │  ✓ Verify proposer_index == slot % validator_count      │    │     │
│     │  │  ✓ Verify secp256k1 signature                           │    │     │
│     │  │  ✓ Update state                                         │    │     │
│     │  └─────────────────────────────────────────────────────────┘    │     │
│     │                        │                                        │     │
│     │                        ▼                                        │     │
│     │              store.insert_block(block)                          │     │
│     │                                                                 │     │
│     └─────────────────────────────────────────────────────────────────┘     │
│                              │                                              │
│                              ▼                                              │
│  4. DOWNLOAD EXECUTION BLOCKS                                               │
│     ┌─────────────────────────────────────────────────────────────────┐     │
│     │                                                                 │     │
│     │  BeaconExecutionMappingProvider                                 │     │
│     │       │                                                         │     │
│     │       │  For slot 1..1000:                                      │     │
│     │       │    - Get execution_payload_root                         │     │
│     │       │    - Download matching execution block                  │     │
│     │       │                                                         │     │
│     │       ▼                                                         │     │
│     │  HeadersStage → BodiesStage → ExecutionStage                    │     │
│     │                                                                 │     │
│     └─────────────────────────────────────────────────────────────────┘     │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Ongoing Sync (Following Head)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          Following Chain Head                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│                         Peer Network                                        │
│                              │                                              │
│                              │ NewBeaconBlock (gossip)                      │
│                              ▼                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                    Block Processing Pipeline                         │    │
│  │                                                                     │    │
│  │   ┌─────────────┐     ┌─────────────┐     ┌─────────────┐           │    │
│  │   │   Receive   │────▶│  Validate   │────▶│   Store     │           │    │
│  │   │   Block     │     │  Signature  │     │   Block     │           │    │
│  │   └─────────────┘     └─────────────┘     └─────────────┘           │    │
│  │                              │                    │                  │    │
│  │                              │                    │                  │    │
│  │                              ▼                    ▼                  │    │
│  │                       ┌─────────────┐     ┌─────────────┐           │    │
│  │                       │   Update    │     │   Notify    │           │    │
│  │                       │   State     │     │   Execution │           │    │
│  │                       └─────────────┘     └─────────────┘           │    │
│  │                                                  │                  │    │
│  │                                                  ▼                  │    │
│  │                                          ┌─────────────┐           │    │
│  │                                          │  Execute    │           │    │
│  │                                          │  Payload    │           │    │
│  │                                          └─────────────┘           │    │
│  │                                                                     │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Validation Flow

### Block Validation Sequence

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       Block Validation Sequence                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Input: SignedBeaconBlock                                                   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ Step 1: SLOT VALIDATION                                             │    │
│  │                                                                     │    │
│  │   block.slot > state.slot?                                          │    │
│  │        │                                                            │    │
│  │        ├── NO  ──▶ Error: SlotNotIncreasing                         │    │
│  │        │                                                            │    │
│  │        └── YES ──▶ Continue                                         │    │
│  │                                                                     │    │
│  │   block.slot - state.slot <= max_slots_per_transition?              │    │
│  │        │                                                            │    │
│  │        ├── NO  ──▶ Error: SlotTooFarAhead                           │    │
│  │        │                                                            │    │
│  │        └── YES ──▶ Advance state.slot to block.slot                 │    │
│  │                                                                     │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                              │                                              │
│                              ▼                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ Step 2: PARENT VALIDATION                                           │    │
│  │                                                                     │    │
│  │   block.parent_root == state.latest_block_header.block_root()?      │    │
│  │        │                                                            │    │
│  │        ├── NO  ──▶ Error: ParentRootMismatch                        │    │
│  │        │              (indicates fork or missing blocks)            │    │
│  │        │                                                            │    │
│  │        └── YES ──▶ Continue                                         │    │
│  │                                                                     │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                              │                                              │
│                              ▼                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ Step 3: PROPOSER VALIDATION                                         │    │
│  │                                                                     │    │
│  │   expected_proposer = block.slot % state.validator_count            │    │
│  │                                                                     │    │
│  │   block.proposer_index == expected_proposer?                        │    │
│  │        │                                                            │    │
│  │        ├── NO  ──▶ Error: ProposerIndexMismatch                     │    │
│  │        │              (wrong validator tried to propose)            │    │
│  │        │                                                            │    │
│  │        └── YES ──▶ Continue                                         │    │
│  │                                                                     │    │
│  │   state.validators[proposer_index].active?                          │    │
│  │        │                                                            │    │
│  │        ├── NO  ──▶ Error: ProposerNotActive                         │    │
│  │        │                                                            │    │
│  │        └── YES ──▶ Continue                                         │    │
│  │                                                                     │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                              │                                              │
│                              ▼                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ Step 4: SIGNATURE VALIDATION                                        │    │
│  │                                                                     │    │
│  │   1. Get proposer public key:                                       │    │
│  │      pubkey = state.validators[proposer_index].pubkey               │    │
│  │                                                                     │    │
│  │   2. Compute signing root:                                          │    │
│  │      block_root = keccak256(RLP(block.header))                      │    │
│  │      domain = compute_domain(BeaconProposer, genesis_validators_root)│    │
│  │      signing_root = keccak256(block_root || domain)                 │    │
│  │                                                                     │    │
│  │   3. Verify secp256k1 signature:                                    │    │
│  │      secp256k1_verify(pubkey, signing_root, block.signature)?       │    │
│  │        │                                                            │    │
│  │        ├── INVALID ──▶ Error: InvalidSignature                      │    │
│  │        │                                                            │    │
│  │        └── VALID   ──▶ Continue                                     │    │
│  │                                                                     │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                              │                                              │
│                              ▼                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ Step 5: STATE UPDATE                                                │    │
│  │                                                                     │    │
│  │   state.latest_block_header = block.header()                        │    │
│  │   state.block_roots[slot % HISTORY_SIZE] = previous_block_root      │    │
│  │                                                                     │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                              │                                              │
│                              ▼                                              │
│                        BLOCK VALID ✓                                        │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Signature Domain Computation

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      Signature Domain Computation                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Purpose: Prevent signature replay attacks across different:                 │
│           - Networks (mainnet vs testnet)                                   │
│           - Message types (proposer vs attester)                            │
│           - Forks                                                           │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                                                                     │    │
│  │  domain_type: [0x00, 0x00, 0x00, 0x00]  // BeaconProposer           │    │
│  │       │                                                             │    │
│  │       ▼                                                             │    │
│  │  fork_version: [0x00, 0x00, 0x00, 0x00]  // Genesis fork            │    │
│  │       │                                                             │    │
│  │       ▼                                                             │    │
│  │  fork_data_root = keccak256(domain_type || fork_version)            │    │
│  │       │                                                             │    │
│  │       ▼                                                             │    │
│  │  domain = keccak256(fork_data_root || genesis_validators_root)      │    │
│  │       │                                                             │    │
│  │       ▼                                                             │    │
│  │  signing_root = keccak256(block_root || domain)                     │    │
│  │       │                                                             │    │
│  │       ▼                                                             │    │
│  │  signature = secp256k1_sign(private_key, signing_root)              │    │
│  │                                                                     │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## State Transition

### State Transition Function

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        State Transition Function                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  process_block(state: &mut BeaconState, block: &SignedBeaconBlock)          │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                                                                     │    │
│  │   BeaconState (Before)                BeaconState (After)           │    │
│  │   ┌─────────────────────┐             ┌─────────────────────┐       │    │
│  │   │ slot: N             │             │ slot: N+1           │       │    │
│  │   │                     │             │                     │       │    │
│  │   │ latest_block_header:│  ────────▶  │ latest_block_header:│       │    │
│  │   │   slot: N           │             │   slot: N+1         │       │    │
│  │   │   parent_root: X    │             │   parent_root: Y    │       │    │
│  │   │   body_root: A      │             │   body_root: B      │       │    │
│  │   │                     │             │                     │       │    │
│  │   │ block_roots[N]:     │             │ block_roots[N+1]:   │       │    │
│  │   │   (empty)           │             │   hash(header_N)    │       │    │
│  │   │                     │             │                     │       │    │
│  │   │ validators:         │             │ validators:         │       │    │
│  │   │   [V0, V1, V2, V3]  │             │   [V0, V1, V2, V3]  │       │    │
│  │   │   (unchanged)       │             │   (unchanged)       │       │    │
│  │   │                     │             │                     │       │    │
│  │   └─────────────────────┘             └─────────────────────┘       │    │
│  │                                                                     │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
│  Note: In N42 POA, the validator set is static and doesn't change          │
│        during state transitions (unlike Ethereum PoS).                      │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Round-Robin Proposer Selection

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      Round-Robin Proposer Selection                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Validators: [V0, V1, V2, V3]  (4 validators)                               │
│                                                                             │
│  Formula: proposer_index = slot % validator_count                           │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                                                                     │    │
│  │  Slot    Calculation      Proposer    Difficulty                    │    │
│  │  ────    ───────────      ────────    ──────────                    │    │
│  │    0     0 % 4 = 0          V0        2 (in-turn)                   │    │
│  │    1     1 % 4 = 1          V1        2 (in-turn)                   │    │
│  │    2     2 % 4 = 2          V2        2 (in-turn)                   │    │
│  │    3     3 % 4 = 3          V3        2 (in-turn)                   │    │
│  │    4     4 % 4 = 0          V0        2 (in-turn)                   │    │
│  │    5     5 % 4 = 1          V1        2 (in-turn)                   │    │
│  │    6     6 % 4 = 2          V2        2 (in-turn)                   │    │
│  │    7     7 % 4 = 3          V3        2 (in-turn)                   │    │
│  │   ...                                                               │    │
│  │                                                                     │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
│  If in-turn proposer misses their slot:                                     │
│  - Any other validator can propose with difficulty = 1 (out-of-turn)        │
│  - Chain selection prefers higher cumulative difficulty                     │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Module Structure

```
examples/custom-node-types/src/
│
├── consensus/
│   ├── mod.rs                    # Module exports
│   ├── config.rs                 # POA configuration (validators, block time)
│   ├── validator.rs              # Execution layer POA validation
│   ├── worker.rs                 # Block production worker
│   ├── state.rs                  # BeaconState, BeaconValidator
│   └── state_transition.rs       # State transition, signature verification
│
├── stages/
│   ├── mod.rs                    # Module exports
│   ├── beacon_blocks.rs          # BeaconBlocksStage, ValidatingBeaconBlocksStage
│   └── downloader/
│       ├── mod.rs
│       ├── client.rs             # BeaconBlockClient trait
│       └── downloader.rs         # BeaconBlockDownloader (Stream)
│
├── network/
│   ├── mod.rs                    # Module exports
│   ├── primitives.rs             # N42NetworkPrimitives
│   ├── beacon_messages.rs        # GetBeaconBlocks, BeaconBlocks messages
│   └── beacon_protocol.rs        # beacon_sync/1 RLPx subprotocol
│
├── storage/
│   ├── mod.rs                    # Module exports
│   └── memory.rs                 # InMemoryBeaconStore
│
├── primitives/
│   ├── mod.rs                    # Module exports
│   ├── beacon.rs                 # SignedBeaconBlock, BeaconBlock, etc.
│   └── unified.rs                # UnifiedBlock (beacon + execution)
│
├── engine/
│   ├── mod.rs
│   ├── types.rs                  # N42EngineTypes, N42BuiltPayload
│   └── validator.rs              # Payload validation
│
├── validation/
│   ├── mod.rs
│   ├── beacon.rs                 # Beacon block validation (pre-state)
│   ├── execution.rs              # Execution block validation
│   └── cross.rs                  # Cross-layer validation
│
├── evm/
│   └── config.rs                 # EVM configuration
│
├── node/
│   ├── mod.rs
│   ├── types.rs                  # N42Node, N42NodeTypes
│   ├── primitives.rs             # N42NodePrimitives
│   ├── components.rs             # Component builders
│   └── payload.rs                # Payload builder
│
└── lib.rs                        # Crate root, re-exports
```

---

## Usage Examples

### Creating a Validating Node

```rust
use example_custom_node_types::{
    BeaconState, BeaconValidator, ValidatingBeaconBlocksStage,
    BeaconBlockDownloader, InMemoryBeaconStore, WatchSyncTargetProvider,
    StateTransitionConfig,
};
use secp256k1::{Secp256k1, SecretKey, PublicKey};

// 1. Setup validators
let secp = Secp256k1::new();
let validator_keys: Vec<SecretKey> = vec![
    SecretKey::from_slice(&[1u8; 32]).unwrap(),
    SecretKey::from_slice(&[2u8; 32]).unwrap(),
    SecretKey::from_slice(&[3u8; 32]).unwrap(),
    SecretKey::from_slice(&[4u8; 32]).unwrap(),
];

let validators: Vec<BeaconValidator> = validator_keys
    .iter()
    .enumerate()
    .map(|(i, sk)| {
        let pubkey = PublicKey::from_secret_key(&secp, sk);
        BeaconValidator::new(pubkey, i as u64)
    })
    .collect();

// 2. Create genesis beacon state
let genesis_time = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_secs();
let beacon_state = BeaconState::genesis(genesis_time, validators);

// 3. Create components
let beacon_store = Arc::new(InMemoryBeaconStore::new());
let (sync_target_tx, sync_target_provider) = WatchSyncTargetProvider::channel();
let downloader = BeaconBlockDownloader::new(client, Default::default());

// 4. Create validating stage
let stage = ValidatingBeaconBlocksStage::new(
    downloader,
    beacon_store.clone(),
    sync_target_provider,
    beacon_state,
);

// 5. Add to pipeline as FIRST stage
pipeline.push_stage(stage);

// 6. Set sync target (from peer discovery or consensus layer)
sync_target_tx.send(Some(BeaconSyncTarget::finalized(1000, block_root))).unwrap();
```

### Signing a Block (for Block Production)

```rust
use example_custom_node_types::{
    sign_beacon_block, BeaconBlock, BeaconBlockBody, BeaconState,
};
use secp256k1::SecretKey;

// Proposer's secret key
let proposer_key: SecretKey = /* ... */;

// Build the block
let block = BeaconBlock::new(
    slot,
    proposer_index,
    parent_root,
    state_root,
    BeaconBlockBody {
        randao_reveal: Bytes::new(),
        eth1_data: Eth1Data::default(),
        graffiti: B256::ZERO,
        execution_payload_root,
    },
);

// Sign it
let signed_block = sign_beacon_block(block, &proposer_key, &beacon_state);
```

---

## Comparison with Ethereum PoS

| Feature | Ethereum PoS | N42 POA |
|---------|--------------|---------|
| Signature Scheme | BLS12-381 | secp256k1 |
| Proposer Selection | Shuffled random | Round-robin |
| Attestations | Required for finality | Not used |
| Slashing | Complex rules | Simple/optional |
| Validator Set | Dynamic (staking) | Static |
| Finality | Casper FFG (2 epochs) | Immediate |
| State Size | ~100KB per validator | ~100 bytes per validator |

---

## Future Improvements

1. **State Persistence**: Store BeaconState to disk for restart recovery
2. **Checkpoint Sync**: Support syncing from trusted checkpoint
3. **Slashing**: Add basic double-proposal detection
4. **Dynamic Validators**: Support adding/removing validators
5. **Fork Choice**: Implement proper fork choice rule for reorgs
