//! POA Node using eth66 protocol for P2P communication.
//!
//! This implements a Proof-of-Authority node that:
//! - Uses reth's NetworkManager with eth66/67/68 protocols
//! - Broadcasts blocks via eth66's NewBlock message using N42NetworkPrimitives
//! - Uses PoaWorker for round-robin block production
//! - Validates incoming blocks with PoaValidator
//!
//! Run with:
//! ```sh
//! # Terminal 1 - Validator 0
//! cargo run -p example-custom-node-types --bin poa_eth66 --release -- \
//!     --validator-index 0 --port 30303 --data-dir /tmp/poa0
//!
//! # Terminal 2 - Validator 1 (copy enode from Terminal 1)
//! cargo run -p example-custom-node-types --bin poa_eth66 --release -- \
//!     --validator-index 1 --port 30304 --data-dir /tmp/poa1 \
//!     --bootnode enode://...@127.0.0.1:30303
//!
//! # Terminal 3 - Validator 2 (copy enode from Terminal 1)
//! cargo run -p example-custom-node-types --bin poa_eth66 --release -- \
//!     --validator-index 2 --port 30305 --data-dir /tmp/poa2 \
//!     --bootnode enode://...@127.0.0.1:30303
//! ```

use alloy_primitives::{Address, Bytes, B256, U128};
use n42_node::{
    BeaconBlock, BeaconBlockBody, BeaconStoreReader, BeaconStoreWriter, InMemoryBeaconStore,
    N42BroadcastBlock, N42NetworkPrimitives, N42NewBlock, PoaConfig, PoaValidator,
    SignedBeaconBlock, DIFFICULTY_IN_TURN, DIFFICULTY_OUT_OF_TURN, DEFAULT_BLOCK_TIME,
    get_difficulty_from_graffiti, set_difficulty_in_graffiti,
};
use reth_chainspec::MAINNET;
use reth_discv4::Discv4ConfigBuilder;
use reth_network::{
    import::{BlockImport, BlockImportEvent, BlockImportOutcome, BlockValidation, NewBlockEvent},
    NetworkConfig, NetworkEvent, NetworkEventListenerProvider, NetworkManager, PeersInfo,
};
use reth_network_peers::{pk2id, NodeRecord, PeerId};
use reth_provider::noop::NoopProvider;
use reth_tracing::{
    tracing_subscriber::filter::LevelFilter, LayerInfo, LogFormat, RethTracer, Tracer,
};
use reth_tracing::tracing::{info, warn, debug};
use secp256k1::{rand, SecretKey, SECP256K1};
use std::{
    collections::HashSet,
    fmt,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    str::FromStr,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::mpsc;
use tokio_stream::StreamExt;

/// Command line arguments
struct Args {
    /// This validator's index (0, 1, or 2)
    validator_index: usize,
    /// P2P port
    port: u16,
    /// Data directory
    #[allow(dead_code)]
    data_dir: String,
    /// Bootnode enode URL
    bootnode: Option<String>,
    /// Block time in seconds
    block_time: u64,
}

impl Args {
    fn parse() -> Self {
        let args: Vec<String> = std::env::args().collect();
        let mut validator_index = 0;
        let mut port = 30303;
        let mut data_dir = "/tmp/poa".to_string();
        let mut bootnode = None;
        let mut block_time = DEFAULT_BLOCK_TIME;

        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "--validator-index" => {
                    validator_index = args[i + 1].parse().expect("Invalid validator index");
                    i += 2;
                }
                "--port" => {
                    port = args[i + 1].parse().expect("Invalid port");
                    i += 2;
                }
                "--data-dir" => {
                    data_dir = args[i + 1].clone();
                    i += 2;
                }
                "--bootnode" => {
                    bootnode = Some(args[i + 1].clone());
                    i += 2;
                }
                "--block-time" => {
                    block_time = args[i + 1].parse().expect("Invalid block time");
                    i += 2;
                }
                _ => i += 1,
            }
        }

        Self { validator_index, port, data_dir, bootnode, block_time }
    }
}

/// POA node state
struct PoaNode {
    /// Validator configuration
    config: PoaConfig,
    /// Block validator
    validator: PoaValidator,
    /// Block storage
    store: Arc<InMemoryBeaconStore>,
    /// This validator's index
    validator_index: usize,
    /// This validator's address
    validator_address: Address,
    /// Last produced slot
    last_produced_slot: Mutex<Option<u64>>,
    /// Known block hashes (to avoid re-processing)
    known_blocks: Mutex<HashSet<B256>>,
    /// Block time in seconds
    block_time: u64,
}

impl PoaNode {
    fn new(validators: Vec<Address>, validator_index: usize, block_time: u64) -> Self {
        let config = PoaConfig::new(validators.clone(), block_time);
        let validator = PoaValidator::new(config.clone());
        let validator_address = validators[validator_index];

        Self {
            config,
            validator,
            store: Arc::new(InMemoryBeaconStore::new()),
            validator_index,
            validator_address,
            last_produced_slot: Mutex::new(None),
            known_blocks: Mutex::new(HashSet::new()),
            block_time,
        }
    }

    /// Calculate current slot from timestamp
    fn current_slot(&self) -> u64 {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        now / self.block_time
    }

    /// Check if this validator should produce at the given slot
    fn should_produce(&self, slot: u64) -> bool {
        self.config.validator_for_slot(slot) == Some(self.validator_address)
    }

    /// Check if this is an in-turn slot for this validator
    fn is_in_turn(&self, slot: u64) -> bool {
        self.should_produce(slot)
    }

    /// Produce a block for the given slot
    fn produce_block(&self, slot: u64) -> Option<SignedBeaconBlock> {
        // Check if we already produced for this slot
        let mut last_slot = self.last_produced_slot.lock().unwrap();
        if *last_slot == Some(slot) {
            return None;
        }

        // Get parent block
        let parent = self.store.latest_block().ok().flatten();
        let parent_root = parent.as_ref().map(|b| b.block_root()).unwrap_or_default();
        let parent_slot = parent.as_ref().map(|b| b.slot()).unwrap_or(0);

        // Only produce if slot is after parent
        if slot <= parent_slot {
            return None;
        }

        // Calculate difficulty
        let difficulty = if self.is_in_turn(slot) {
            DIFFICULTY_IN_TURN
        } else {
            DIFFICULTY_OUT_OF_TURN
        };

        // Create graffiti with difficulty
        let mut graffiti = B256::ZERO;
        set_difficulty_in_graffiti(&mut graffiti, difficulty);

        // Create block body
        let body = BeaconBlockBody {
            graffiti,
            ..Default::default()
        };

        // Create block
        let block = BeaconBlock::new(
            slot,
            self.validator_index as u64,
            parent_root,
            B256::random(), // state_root (simplified)
            body,
        );

        // Sign block (simplified - just use validator index as signature)
        let sig = Bytes::from(vec![self.validator_index as u8; 96]);
        let signed = SignedBeaconBlock::new(block, sig);

        *last_slot = Some(slot);

        info!(
            slot = slot,
            difficulty = difficulty,
            in_turn = self.is_in_turn(slot),
            parent_slot = parent_slot,
            "Produced block"
        );

        Some(signed)
    }

    /// Process a received block from the network
    fn process_block(&self, block: &SignedBeaconBlock, peer_id: PeerId) -> Result<bool, String> {
        let block_root = block.block_root();

        // Check if we've seen this block
        {
            let mut known = self.known_blocks.lock().unwrap();
            if known.contains(&block_root) {
                debug!(hash = %block_root, "Block already known");
                return Ok(false);
            }
            known.insert(block_root);
        }

        // Get parent for validation
        let parent = self.store.latest_block().ok().flatten();

        // Validate block
        self.validator
            .validate_block(block, parent.as_ref())
            .map_err(|e| e.to_string())?;

        // Check if this extends our chain
        let our_tip_slot = parent.map(|b| b.slot()).unwrap_or(0);

        if block.slot() > our_tip_slot {
            self.store.insert_block(block.clone()).map_err(|e| e.to_string())?;

            let difficulty = get_difficulty_from_graffiti(&block.message.body.graffiti);
            info!(
                slot = block.slot(),
                proposer = block.message.proposer_index,
                difficulty = difficulty,
                peer = %peer_id,
                "Accepted block from network"
            );
            Ok(true)
        } else {
            debug!(
                slot = block.slot(),
                our_tip = our_tip_slot,
                "Block does not extend chain"
            );
            Ok(false)
        }
    }
}

/// Block import handler for N42 network
struct N42BlockImport {
    /// POA node state
    poa_node: Arc<PoaNode>,
    /// Pending import events
    pending_events: Mutex<Vec<BlockImportEvent<N42NewBlock>>>,
}

impl N42BlockImport {
    fn new(poa_node: Arc<PoaNode>) -> Self {
        Self {
            poa_node,
            pending_events: Mutex::new(Vec::new()),
        }
    }
}

impl BlockImport<N42NewBlock> for N42BlockImport {
    fn on_new_block(&mut self, peer_id: PeerId, incoming_block: NewBlockEvent<N42NewBlock>) {
        match incoming_block {
            NewBlockEvent::Block(new_block_msg) => {
                // Access the block through the NewBlockMessage wrapper
                let new_block = &new_block_msg.block;
                let hash = new_block_msg.hash;

                info!(
                    slot = new_block.block.slot(),
                    hash = %hash,
                    peer = %peer_id,
                    "Received NewBlock via eth66"
                );

                // Process the beacon block
                match self.poa_node.process_block(new_block.block.beacon_block(), peer_id) {
                    Ok(accepted) => {
                        let validation = if accepted {
                            BlockValidation::ValidBlock { block: new_block_msg.clone() }
                        } else {
                            // Block already known, but still valid
                            BlockValidation::ValidHeader { block: new_block_msg.clone() }
                        };

                        let outcome = BlockImportOutcome {
                            peer: peer_id,
                            result: Ok(validation),
                        };
                        self.pending_events.lock().unwrap().push(
                            BlockImportEvent::Outcome(outcome)
                        );
                    }
                    Err(e) => {
                        warn!(
                            slot = new_block.block.slot(),
                            hash = %hash,
                            error = %e,
                            "Block validation failed"
                        );
                        let outcome = BlockImportOutcome {
                            peer: peer_id,
                            result: Err(reth_network::import::BlockImportError::Consensus(
                                reth_consensus::ConsensusError::BaseFeeMissing
                            )),
                        };
                        self.pending_events.lock().unwrap().push(
                            BlockImportEvent::Outcome(outcome)
                        );
                    }
                }
            }
            NewBlockEvent::Hashes(announcement) => {
                debug!(
                    hashes = ?announcement.0,
                    peer = %peer_id,
                    "Received NewBlockHashes announcement"
                );
                // We could request blocks here, but for simplicity we just log
            }
        }
    }

    fn poll(&mut self, _cx: &mut Context<'_>) -> Poll<BlockImportEvent<N42NewBlock>> {
        let mut events = self.pending_events.lock().unwrap();
        if let Some(event) = events.pop() {
            Poll::Ready(event)
        } else {
            Poll::Pending
        }
    }
}

impl fmt::Debug for N42BlockImport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("N42BlockImport").finish()
    }
}

/// Create N42BroadcastBlock from SignedBeaconBlock
fn create_broadcast_block(beacon: &SignedBeaconBlock, block_time: u64) -> N42BroadcastBlock {
    use alloy_consensus::Header;
    use reth_ethereum_primitives::{Block, BlockBody};

    // Create a minimal execution block that matches the beacon block
    // Note: Don't set parent_beacon_block_root as it causes RLP encoding issues
    // with post-Cancun Header fields. The beacon block is included in the unified
    // N42BroadcastBlock anyway, so cross-reference is still possible.
    let header = Header {
        number: beacon.slot(),
        timestamp: beacon.slot() * block_time,
        ..Default::default()
    };

    let execution = Block::new(header, BlockBody::default());
    N42BroadcastBlock::new(beacon.clone(), execution)
}

/// Create N42NewBlock for broadcasting
fn create_new_block_message(beacon: &SignedBeaconBlock, block_time: u64) -> N42NewBlock {
    use reth_ethereum::network::eth_wire::NewBlock;

    let block = create_broadcast_block(beacon, block_time);
    // Total difficulty - use slot as proxy (fits in U128)
    let td = U128::from(beacon.slot());

    NewBlock { block, td }
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    // Initialize tracing - DEBUG for network to see message handling
    let _ = RethTracer::new()
        .with_stdout(LayerInfo::new(
            LogFormat::Terminal,
            LevelFilter::DEBUG.to_string(),
            "reth_network=debug,net=debug".to_string(),
            Some("always".to_string()),
        ))
        .init();

    let args = Args::parse();

    info!(
        validator_index = args.validator_index,
        port = args.port,
        block_time = args.block_time,
        "Starting POA eth66 node"
    );

    // Define validators (using simple addresses)
    let validators: Vec<Address> = (0..3)
        .map(|i| Address::repeat_byte(i as u8 + 1))
        .collect();

    info!(
        validators = ?validators,
        this_validator = ?validators[args.validator_index],
        "Validator set"
    );

    // Create POA node
    let poa_node = Arc::new(PoaNode::new(
        validators,
        args.validator_index,
        args.block_time,
    ));

    // Create block import handler
    let block_import = Box::new(N42BlockImport::new(poa_node.clone()));

    // Generate secret key for this node
    let secret_key = SecretKey::new(&mut rand::thread_rng());
    let peer_id = pk2id(&secret_key.public_key(SECP256K1));

    info!(peer_id = %peer_id, "Node identity");

    // Build network configuration
    let local_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, args.port));

    // Create custom HelloMessage with only eth68 (avoid eth69 which may have decode issues)
    use reth_network::HelloMessageWithProtocols;
    use reth_ethereum::network::eth_wire::{EthVersion, protocol::Protocol};
    let hello_message = HelloMessageWithProtocols::builder(peer_id)
        // Use only eth66/67/68, not eth69
        .protocols([
            Protocol::eth(EthVersion::Eth66),
            Protocol::eth(EthVersion::Eth67),
            Protocol::eth(EthVersion::Eth68),
        ])
        .build();

    // Explicitly specify N42NetworkPrimitives to ensure BlockImport<N42NewBlock> is used
    let mut net_builder: reth_network::NetworkConfigBuilder<N42NetworkPrimitives> =
        NetworkConfig::builder(secret_key)
            .with_pow()  // Enable NewBlock broadcasting (not PoS)
            .set_addrs(local_addr)  // Set both listener and discovery to same port
            .hello_message(hello_message)  // Use our custom protocol list
            .block_import(block_import);

    // Add bootnode if specified
    if let Some(bootnode_str) = &args.bootnode {
        match NodeRecord::from_str(bootnode_str) {
            Ok(bootnode) => {
                info!(bootnode = %bootnode, "Adding bootnode");
                net_builder = net_builder.boot_nodes(vec![bootnode.clone()]);
            }
            Err(e) => {
                warn!(error = %e, bootnode = bootnode_str, "Failed to parse bootnode");
            }
        }
    }

    // Build network config with MAINNET chain spec
    let net_cfg = net_builder.build(NoopProvider::eth(MAINNET.clone()));

    // Configure discovery
    let net_cfg = net_cfg.set_discovery_v4(
        Discv4ConfigBuilder::default()
            .lookup_interval(Duration::from_secs(1))
            .build(),
    );

    // Create network manager with N42NetworkPrimitives
    let net_manager = NetworkManager::<N42NetworkPrimitives>::new(net_cfg).await?;
    let net_handle = net_manager.handle().clone();

    // Get our enode URL for other nodes to connect
    let local_enode = net_handle.local_node_record();
    info!(enode = %local_enode, "Local enode URL (share with other validators)");

    // Subscribe to network events
    let mut events = net_handle.event_listener();

    // Spawn network manager
    tokio::spawn(net_manager);

    // Channel for new blocks to broadcast
    let (block_tx, mut block_rx) = mpsc::channel::<SignedBeaconBlock>(32);

    // Spawn block producer
    let poa_clone = poa_node.clone();
    let block_tx_clone = block_tx.clone();
    let block_time = args.block_time;
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        let mut last_checked_slot = 0u64;

        loop {
            interval.tick().await;

            let current_slot = poa_clone.current_slot();

            // Only check once per slot
            if current_slot == last_checked_slot {
                continue;
            }
            last_checked_slot = current_slot;

            // Try to produce if it's our turn
            if poa_clone.should_produce(current_slot) {
                if let Some(block) = poa_clone.produce_block(current_slot) {
                    // Store locally
                    let _ = poa_clone.store.insert_block(block.clone());

                    // Send to broadcast channel
                    let _ = block_tx_clone.send(block).await;
                }
            } else {
                // Out-of-turn production after delay (for liveness)
                let slot_time = Duration::from_secs(block_time);
                let delay = slot_time / 2;

                tokio::time::sleep(delay).await;

                // Check if we still need to produce
                let latest_slot = poa_clone.store.latest_slot().ok().flatten().unwrap_or(0);

                if latest_slot < current_slot {
                    let maybe_block = poa_clone.produce_block(current_slot);

                    if let Some(block) = maybe_block {
                        let _ = poa_clone.store.insert_block(block.clone());
                        let _ = block_tx_clone.send(block).await;
                    }
                }
            }
        }
    });

    // Spawn block broadcaster
    let net_handle_clone = net_handle.clone();
    let block_time_clone = args.block_time;
    tokio::spawn(async move {
        while let Some(block) = block_rx.recv().await {
            let new_block = create_new_block_message(&block, block_time_clone);
            let hash = block.block_root();

            let peer_count = net_handle_clone.num_connected_peers();
            info!(
                slot = block.slot(),
                hash = %hash,
                peers = peer_count,
                "Broadcasting block via eth66 NewBlock"
            );

            // Broadcast via eth66 NewBlock message
            net_handle_clone.announce_block(new_block, hash);
        }
    });

    // Handle network events
    info!("Node running. Waiting for peers...");
    info!("Copy the enode URL above and use it as --bootnode for other validators");

    while let Some(evt) = events.next().await {
        match evt {
            NetworkEvent::ActivePeerSession { info, .. } => {
                info!(
                    peers = net_handle.num_connected_peers(),
                    peer_id = %info.peer_id,
                    chain = %info.status.chain,
                    client = ?info.client_version,
                    "Peer connected"
                );
            }
            NetworkEvent::Peer(reth_network_api::events::PeerEvent::SessionClosed { peer_id, reason }) => {
                info!(
                    peers = net_handle.num_connected_peers(),
                    peer_id = %peer_id,
                    reason = ?reason,
                    "Peer disconnected"
                );
            }
            _ => {}
        }
    }

    Ok(())
}
