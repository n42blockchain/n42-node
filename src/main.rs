//! N42 Node Types Example
//!
//! This example demonstrates how to create a custom node by implementing
//! reth's core customization traits.
//!
//! Run with: `cargo run -p example-custom-node-types`

use alloy_consensus::Header;
use alloy_primitives::{Bytes, B256};
use n42_node::{
    engine::N42PayloadValidator,
    evm::N42EvmConfig,
    node::N42Node,
    BeaconBlock, BeaconBlockBody, BeaconBlockValidator, CrossValidator, ExecutionValidator,
    InMemoryBeaconStore, SignedBeaconBlock, UnifiedBlock,
    UnifiedBlockValidator, N42ConsensusBuilder, N42ExecutorBuilder,
    N42NetworkBuilder, N42PayloadBuilder, N42PoolBuilder, N42NetworkPrimitives,
};
use reth_chainspec::MAINNET;
use reth_ethereum_primitives::{Block, BlockBody};
use reth_node_types::NodeTypes;
use reth_primitives_traits::SealedBlock;

fn main() -> eyre::Result<()> {
    println!("=== N42 Node Types Example ===\n");

    // Demonstrate the type hierarchy
    demonstrate_node_types();
    demonstrate_evm_config()?;
    demonstrate_payload_validator();
    demonstrate_components();
    demonstrate_beacon_blocks();
    demonstrate_beacon_storage();
    demonstrate_eth66_network();
    demonstrate_validation();

    println!("\n=== Example Complete ===");
    println!("\nTo build a full custom node, you would:");
    println!("1. Define custom primitives (Block, Header, Body, Tx, Receipt)");
    println!("2. Implement NodePrimitives for your types");
    println!("3. Create a ChainSpec with your hardfork rules");
    println!("4. Implement ConfigureEvm for custom execution");
    println!("5. Define EngineTypes for Engine API");
    println!("6. Implement PayloadValidator for block validation");
    println!("7. Configure NetworkPrimitives for eth66 with custom block type");
    println!("8. Use NodeBuilder with your custom components:");
    println!("   ```");
    println!("   NodeBuilder::new(config)");
    println!("       .with_types::<N42Node>()");
    println!("       .with_components(N42Node::components())");
    println!("       .launch()");
    println!("   ```");

    Ok(())
}

fn demonstrate_node_types() {
    println!("1. NodeTypes - Top-level type configuration\n");

    println!("   N42Node implements NodeTypes with:");
    println!(
        "   - Primitives: {}",
        std::any::type_name::<<N42Node as NodeTypes>::Primitives>()
    );
    println!(
        "   - ChainSpec:  {}",
        std::any::type_name::<<N42Node as NodeTypes>::ChainSpec>()
    );
    println!(
        "   - Storage:    {}",
        std::any::type_name::<<N42Node as NodeTypes>::Storage>()
    );
    println!(
        "   - Payload:    {}",
        std::any::type_name::<<N42Node as NodeTypes>::Payload>()
    );
    println!();
}

fn demonstrate_evm_config() -> eyre::Result<()> {
    println!("2. ConfigureEvm - EVM execution configuration\n");

    let config = N42EvmConfig::new(MAINNET.clone());
    println!("   Created N42EvmConfig with:");
    println!(
        "   - Chain: {} (ID: {})",
        MAINNET.chain.named().unwrap_or_default(),
        MAINNET.chain.id()
    );
    println!("   - Inner: {:?}", std::any::type_name_of_val(config.inner()));
    println!("   - Gas Multiplier: {}%", config.gas_multiplier());
    println!();

    Ok(())
}

fn demonstrate_payload_validator() {
    println!("3. PayloadValidator - Block validation\n");

    let validator = N42PayloadValidator::new(MAINNET.clone());
    println!("   Created N42PayloadValidator:");
    println!("   - Chain: {}", validator.chain_spec().chain);
    println!("   - Validates: newPayload, forkchoiceUpdated");
    println!();
}

fn demonstrate_components() {
    println!("4. Component Builders - Node component configuration\n");

    println!("   N42Node::components() returns a ComponentsBuilder with:");
    println!();

    // Show each builder type
    println!("   Pool Builder:");
    println!("   - Type: {}", std::any::type_name::<N42PoolBuilder>());
    println!("   - Builds: EthTransactionPool with custom configuration");
    println!();

    println!("   Executor Builder:");
    println!("   - Type: {}", std::any::type_name::<N42ExecutorBuilder>());
    println!("   - Builds: N42EvmConfig for EVM execution");
    println!();

    println!("   Payload Builder:");
    println!("   - Type: {}", std::any::type_name::<N42PayloadBuilder>());
    println!("   - Builds: EthereumPayloadBuilder for block construction");
    println!();

    println!("   Network Builder:");
    println!("   - Type: {}", std::any::type_name::<N42NetworkBuilder>());
    println!("   - Builds: P2P network stack with eth66 protocol");
    println!();

    println!("   Consensus Builder:");
    println!("   - Type: {}", std::any::type_name::<N42ConsensusBuilder>());
    println!("   - Builds: EthBeaconConsensus for consensus validation");
    println!();
}

fn demonstrate_beacon_blocks() {
    println!("5. Beacon Chain Primitives\n");

    // Create a beacon block
    let body = BeaconBlockBody {
        randao_reveal: Bytes::from_static(&[0x01, 0x02, 0x03]),
        execution_payload_root: B256::repeat_byte(0xAB),
        ..Default::default()
    };

    let block = BeaconBlock::new(
        100,                        // slot
        42,                         // proposer_index
        B256::repeat_byte(0x01),    // parent_root
        B256::repeat_byte(0x02),    // state_root
        body,
    );

    let signed = SignedBeaconBlock::new(block, Bytes::from_static(&[0x00; 96]));

    println!("   Created SignedBeaconBlock:");
    println!("   - Slot: {}", signed.slot());
    println!("   - Proposer Index: {}", signed.message.proposer_index);
    println!("   - Block Root: {:?}", signed.block_root());
    println!("   - Parent Root: {:?}", signed.parent_root());
    println!();

    println!("   UnifiedBlock combines:");
    println!("   - Type: {}", std::any::type_name::<UnifiedBlock>());
    println!("   - beacon: SignedBeaconBlock (consensus layer)");
    println!("   - execution: SealedBlock<Block> (execution layer)");
    println!("   - Validates cross-references between layers");
    println!();
}

fn demonstrate_beacon_storage() {
    use n42_node::{BeaconStoreReader, BeaconStoreWriter};

    println!("6. Beacon Storage Layer\n");

    let store = InMemoryBeaconStore::new();

    // Insert some blocks
    for slot in [100, 101, 102, 105, 110] {
        let block = BeaconBlock::new(
            slot,
            42,
            B256::repeat_byte(slot as u8),
            B256::repeat_byte(0x11),
            BeaconBlockBody::default(),
        );
        let signed = SignedBeaconBlock::new(block, Bytes::from_static(&[0x00; 96]));
        store.insert_block(signed).unwrap();
    }

    println!("   InMemoryBeaconStore:");
    println!("   - Stored {} blocks", store.len());
    println!("   - Latest slot: {:?}", store.latest_slot().unwrap());
    println!();

    // Query by slot
    if let Some(block) = store.block_by_slot(102).unwrap() {
        println!("   Retrieved block at slot 102:");
        println!("   - Block root: {:?}", block.block_root());
    }
    println!();

    // Query by root
    let block = store.block_by_slot(100).unwrap().unwrap();
    let root = block.block_root();
    if let Some(retrieved) = store.block_by_root(root).unwrap() {
        println!("   Retrieved block by root:");
        println!("   - Slot: {}", retrieved.slot());
    }
    println!();

    // Range query
    let range = store.blocks_in_range(100, 105).unwrap();
    println!("   Blocks in range 100-105: {} blocks", range.len());
    println!();
}

fn demonstrate_eth66_network() {
    println!("7. eth66 Network Protocol\n");

    println!("   N42NetworkPrimitives configures eth66 with custom block type:");
    println!("   - Type: {}", std::any::type_name::<N42NetworkPrimitives>());
    println!();

    println!("   eth66 Messages for block propagation:");
    println!("   - NewBlock: Broadcasts N42BroadcastBlock (beacon + execution)");
    println!("   - NewBlockHashes: Announces new block hashes");
    println!("   - GetBlockHeaders / BlockHeaders: Header sync");
    println!("   - GetBlockBodies / BlockBodies: Body sync");
    println!();

    println!("   N42BroadcastBlock structure:");
    println!("   ┌─────────────────────────────────────────┐");
    println!("   │          N42BroadcastBlock              │");
    println!("   │  ┌─────────────────┐ ┌───────────────┐  │");
    println!("   │  │ SignedBeacon    │ │ Execution     │  │");
    println!("   │  │ Block (CL)      │ │ Block (EL)    │  │");
    println!("   │  └─────────────────┘ └───────────────┘  │");
    println!("   └─────────────────────────────────────────┘");
    println!();
}

fn demonstrate_validation() {
    println!("8. Block Validation\n");

    // Beacon validation
    let beacon_validator = BeaconBlockValidator::new();
    println!("   BeaconBlockValidator:");
    println!("   - Validates slot ordering");
    println!("   - Validates parent linkage");
    println!("   - Validates signature length");

    let beacon = SignedBeaconBlock::new(
        BeaconBlock::new(100, 42, B256::ZERO, B256::ZERO, BeaconBlockBody::default()),
        Bytes::from_static(&[0x00; 96]),
    );
    match beacon_validator.validate(&beacon) {
        Ok(()) => println!("   - Test block: VALID"),
        Err(e) => println!("   - Test block: INVALID ({})", e),
    }
    println!();

    // Execution validation
    let exec_validator = ExecutionValidator::new();
    println!("   ExecutionValidator:");
    println!("   - Validates gas limits");
    println!("   - Validates block number sequence");
    println!("   - Validates parent hash linkage");

    let header = Header { number: 100, gas_used: 1000, gas_limit: 10000, ..Default::default() };
    let execution = SealedBlock::seal_slow(Block::new(header, BlockBody::default()));
    match exec_validator.validate(&execution) {
        Ok(()) => println!("   - Test block: VALID"),
        Err(e) => println!("   - Test block: INVALID ({})", e),
    }
    println!();

    // Cross-reference validation
    let _cross_validator = CrossValidator::new();
    println!("   CrossValidator:");
    println!("   - Validates beacon_root in execution header");
    println!("   - Validates execution_payload_root in beacon body");
    println!();

    // Unified validation
    let unified_validator = UnifiedBlockValidator::new();
    println!("   UnifiedBlockValidator:");
    println!("   - Combines all validation stages");
    println!("   - Beacon -> Cross-reference -> Execution");
    println!("   - Ready for production use: {:?}", unified_validator);
    println!();
}
