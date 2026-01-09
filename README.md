# N42 Node

A custom POA (Proof of Authority) blockchain node based on [Reth](https://github.com/paradigmxyz/reth).

## Features

- **Dual-layer architecture**: Beacon (consensus) + Execution (EVM)
- **POA consensus**: Round-robin block production with secp256k1 signatures
- **eth66 block propagation**: P2P block broadcasting via devp2p
- **Modular design**: Separate consensus, network, storage, and validation layers

## Building

```bash
cargo build --release
```

## Running

### Validator Network (3 nodes)

```bash
# Run the test script
./test_poa_eth66.sh
```

Or manually:

```bash
# Terminal 1 - Validator 0
cargo run --release --bin poa_eth66 -- --validator-index 0 --port 30303

# Terminal 2 - Validator 1 (use enode from Terminal 1)
cargo run --release --bin poa_eth66 -- --validator-index 1 --port 30304 --bootnode "enode://..."

# Terminal 3 - Validator 2
cargo run --release --bin poa_eth66 -- --validator-index 2 --port 30305 --bootnode "enode://..."
```

### Sync Node (download only)

```bash
cargo run --release --bin poa_sync_node -- --port 30400 --bootnode "enode://..."
```

## Documentation

- [Architecture Overview](docs/README.md)
- [Beacon Architecture](docs/BEACON_ARCHITECTURE.md)
- [Test Scripts Guide](docs/TEST_SCRIPTS.md)
- [eth66 Block Propagation](docs/POA_ETH66_BLOCK_PROPAGATION.md)

## Project Structure

```
n42-node/
├── src/
│   ├── bin/           # Executables (poa_eth66, poa_sync_node, etc.)
│   ├── consensus/     # POA consensus (config, validator, worker)
│   ├── primitives/    # Data types (BeaconBlock, N42Block)
│   ├── network/       # P2P networking (eth66, beacon_sync)
│   ├── stages/        # Pipeline sync stages
│   ├── storage/       # Block storage (BeaconStore)
│   └── validation/    # Block validation
├── docs/              # Documentation
└── *.sh               # Test scripts
```

## License

MIT OR Apache-2.0
