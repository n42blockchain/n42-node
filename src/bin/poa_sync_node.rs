//! POA Sync Node - Downloads blocks from validators.
//!
//! This node:
//! - Does NOT produce blocks (not a validator)
//! - Connects to validator nodes and downloads blocks via eth66
//! - Validates and stores received blocks
//! - Tracks sync progress
//!
//! Run with:
//! ```sh
//! # First start the validator nodes, then connect sync node:
//! cargo run -p example-custom-node-types --bin poa_sync_node --release -- \
//!     --port 30400 --bootnode enode://...@127.0.0.1:30303
//! ```

use alloy_primitives::{keccak256, Address, B256};
use n42_node::{
    BeaconStoreReader, BeaconStoreWriter, InMemoryBeaconStore, N42NetworkPrimitives,
    N42NewBlock, PoaConfig, PoaValidator, SignedBeaconBlock, DEFAULT_BLOCK_TIME,
    get_difficulty_from_graffiti,
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
use reth_tracing::tracing::{info, warn, debug, error};
// secp256k1 for P2P identity (required by devp2p protocol)
use secp256k1::{SecretKey, SECP256K1};
use std::{
    collections::HashSet,
    fmt,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    str::FromStr,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};
use tokio_stream::StreamExt;

/// BLS public key type (48 bytes)
type BLSPubkey = [u8; 48];

/// Command line arguments
struct Args {
    /// P2P port
    port: u16,
    /// Bootnode enode URL(s) - comma separated
    bootnodes: Vec<String>,
    /// Block time in seconds (for validation)
    block_time: u64,
}

impl Args {
    fn parse() -> Self {
        let args: Vec<String> = std::env::args().collect();
        let mut port = 30400;
        let mut bootnodes = Vec::new();
        let mut block_time = DEFAULT_BLOCK_TIME;

        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "--port" => {
                    port = args[i + 1].parse().expect("Invalid port");
                    i += 2;
                }
                "--bootnode" => {
                    bootnodes.push(args[i + 1].clone());
                    i += 2;
                }
                "--block-time" => {
                    block_time = args[i + 1].parse().expect("Invalid block time");
                    i += 2;
                }
                _ => i += 1,
            }
        }

        Self { port, bootnodes, block_time }
    }
}

/// Generate deterministic BLS-derived addresses for validators (must match poa_eth66.rs)
fn generate_validator_addresses(count: usize) -> Vec<Address> {
    (0..count)
        .map(|i| {
            // Deterministic seed for demo purposes (same as poa_eth66.rs)
            let mut ikm = [0u8; 32];
            ikm[0] = i as u8 + 1;
            ikm[31] = 0x42;

            let sk = blst::min_pk::SecretKey::key_gen(&ikm, &[]).unwrap();
            let pk = sk.sk_to_pk();
            let pubkey: BLSPubkey = pk.to_bytes();

            // Derive address from BLS public key (keccak256 of pubkey, last 20 bytes)
            let hash = keccak256(&pubkey);
            Address::from_slice(&hash[12..])
        })
        .collect()
}

/// Generate deterministic secp256k1 key for P2P identity
fn generate_p2p_key() -> SecretKey {
    // Use a different seed for sync node
    let mut seed = [0u8; 32];
    seed[0] = 200; // Different from validator keys
    seed[31] = 0xAA;
    SecretKey::from_slice(&seed).unwrap()
}

/// Sync node state - only tracks downloaded blocks, never produces
struct SyncNode {
    /// Validator configuration (for validation)
    #[allow(dead_code)]
    config: PoaConfig,
    /// Block validator
    validator: PoaValidator,
    /// Block storage
    store: Arc<InMemoryBeaconStore>,
    /// Known block hashes (to avoid re-processing)
    known_blocks: Mutex<HashSet<B256>>,
    /// Sync statistics
    stats: Mutex<SyncStats>,
}

/// Sync statistics
#[derive(Default)]
struct SyncStats {
    /// Total blocks received
    blocks_received: u64,
    /// Blocks accepted
    blocks_accepted: u64,
    /// Blocks rejected (invalid)
    blocks_rejected: u64,
    /// Blocks skipped (already known)
    blocks_skipped: u64,
}

impl SyncNode {
    fn new(validators: Vec<Address>, block_time: u64) -> Self {
        let config = PoaConfig::new(validators, block_time);
        let validator = PoaValidator::new(config.clone());

        Self {
            config,
            validator,
            store: Arc::new(InMemoryBeaconStore::new()),
            known_blocks: Mutex::new(HashSet::new()),
            stats: Mutex::new(SyncStats::default()),
        }
    }

    /// Get current sync stats
    fn get_stats(&self) -> (u64, u64, u64, u64) {
        let stats = self.stats.lock().unwrap();
        (stats.blocks_received, stats.blocks_accepted, stats.blocks_rejected, stats.blocks_skipped)
    }

    /// Get highest synced slot
    fn highest_slot(&self) -> Option<u64> {
        self.store.latest_slot().ok().flatten()
    }

    /// Process a received block from the network
    fn process_block(&self, block: &SignedBeaconBlock, peer_id: PeerId) -> Result<bool, String> {
        let block_root = block.block_root();

        // Update stats
        {
            let mut stats = self.stats.lock().unwrap();
            stats.blocks_received += 1;
        }

        // Check if we've seen this block
        {
            let mut known = self.known_blocks.lock().unwrap();
            if known.contains(&block_root) {
                debug!(hash = %block_root, "Block already known");
                let mut stats = self.stats.lock().unwrap();
                stats.blocks_skipped += 1;
                return Ok(false);
            }
            known.insert(block_root);
        }

        // Get parent for validation
        let parent = self.store.latest_block().ok().flatten();

        // Validate block
        match self.validator.validate_block(block, parent.as_ref()) {
            Ok(()) => {}
            Err(e) => {
                let mut stats = self.stats.lock().unwrap();
                stats.blocks_rejected += 1;
                return Err(e.to_string());
            }
        }

        // Check if this extends our chain
        let our_tip_slot = parent.map(|b| b.slot()).unwrap_or(0);

        if block.slot() > our_tip_slot {
            self.store.insert_block(block.clone()).map_err(|e| e.to_string())?;

            let difficulty = get_difficulty_from_graffiti(&block.message.body.graffiti);
            let mut stats = self.stats.lock().unwrap();
            stats.blocks_accepted += 1;

            info!(
                slot = block.slot(),
                proposer = block.message.proposer_index,
                difficulty = difficulty,
                peer = %peer_id,
                total_synced = stats.blocks_accepted,
                "✓ Synced new block"
            );
            Ok(true)
        } else {
            debug!(
                slot = block.slot(),
                our_tip = our_tip_slot,
                "Block does not extend chain"
            );
            let mut stats = self.stats.lock().unwrap();
            stats.blocks_skipped += 1;
            Ok(false)
        }
    }
}

/// Block import handler for sync node
struct SyncBlockImport {
    /// Sync node state
    sync_node: Arc<SyncNode>,
    /// Pending import events
    pending_events: Mutex<Vec<BlockImportEvent<N42NewBlock>>>,
}

impl SyncBlockImport {
    fn new(sync_node: Arc<SyncNode>) -> Self {
        Self {
            sync_node,
            pending_events: Mutex::new(Vec::new()),
        }
    }
}

impl BlockImport<N42NewBlock> for SyncBlockImport {
    fn on_new_block(&mut self, peer_id: PeerId, incoming_block: NewBlockEvent<N42NewBlock>) {
        match incoming_block {
            NewBlockEvent::Block(new_block_msg) => {
                let new_block = &new_block_msg.block;
                let hash = new_block_msg.hash;

                debug!(
                    slot = new_block.block.slot(),
                    hash = %hash,
                    peer = %peer_id,
                    "Received NewBlock via eth66"
                );

                // Process the beacon block
                match self.sync_node.process_block(new_block.block.beacon_block(), peer_id) {
                    Ok(accepted) => {
                        let validation = if accepted {
                            BlockValidation::ValidBlock { block: new_block_msg.clone() }
                        } else {
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
                        error!(
                            slot = new_block.block.slot(),
                            hash = %hash,
                            error = %e,
                            peer = %peer_id,
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

impl fmt::Debug for SyncBlockImport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SyncBlockImport").finish()
    }
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    // Initialize tracing
    let _ = RethTracer::new()
        .with_stdout(LayerInfo::new(
            LogFormat::Terminal,
            LevelFilter::INFO.to_string(),
            "".to_string(),
            Some("always".to_string()),
        ))
        .init();

    let args = Args::parse();

    info!(
        port = args.port,
        bootnodes = args.bootnodes.len(),
        block_time = args.block_time,
        "Starting POA sync node (non-validator)"
    );

    if args.bootnodes.is_empty() {
        warn!("No bootnodes specified! Use --bootnode <enode> to connect to validators");
    }

    // Generate validator addresses (must match poa_eth66.rs)
    let validators = generate_validator_addresses(3);

    info!(validators = ?validators, "Known validator set (BLS-derived addresses)");

    // Create sync node
    let sync_node = Arc::new(SyncNode::new(validators, args.block_time));

    // Create block import handler
    let block_import = Box::new(SyncBlockImport::new(sync_node.clone()));

    // Generate secp256k1 key for P2P identity (required by devp2p)
    let secret_key = generate_p2p_key();
    let peer_id = pk2id(&secret_key.public_key(SECP256K1));

    info!(peer_id = %peer_id, "Sync node P2P identity (secp256k1)");

    // Build network configuration
    let local_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, args.port));

    // Create HelloMessage with eth66/67/68
    use reth_network::HelloMessageWithProtocols;
    use reth_ethereum::network::eth_wire::{EthVersion, protocol::Protocol};
    let hello_message = HelloMessageWithProtocols::builder(peer_id)
        .protocols([
            Protocol::eth(EthVersion::Eth66),
            Protocol::eth(EthVersion::Eth67),
            Protocol::eth(EthVersion::Eth68),
        ])
        .build();

    // Parse bootnodes
    let mut boot_nodes = Vec::new();
    for bootnode_str in &args.bootnodes {
        match NodeRecord::from_str(bootnode_str) {
            Ok(bootnode) => {
                info!(bootnode = %bootnode, "Adding bootnode");
                boot_nodes.push(bootnode);
            }
            Err(e) => {
                warn!(error = %e, bootnode = bootnode_str, "Failed to parse bootnode");
            }
        }
    }

    let mut net_builder: reth_network::NetworkConfigBuilder<N42NetworkPrimitives> =
        NetworkConfig::builder(secret_key)
            .with_pow()
            .set_addrs(local_addr)
            .hello_message(hello_message)
            .block_import(block_import);

    if !boot_nodes.is_empty() {
        net_builder = net_builder.boot_nodes(boot_nodes);
    }

    // Build network config
    let net_cfg = net_builder.build(NoopProvider::eth(MAINNET.clone()));

    // Configure discovery - more aggressive for sync node
    let net_cfg = net_cfg.set_discovery_v4(
        Discv4ConfigBuilder::default()
            .lookup_interval(Duration::from_secs(1))
            .build(),
    );

    // Create network manager
    let net_manager = NetworkManager::<N42NetworkPrimitives>::new(net_cfg).await?;
    let net_handle = net_manager.handle().clone();

    // Get our enode URL
    let local_enode = net_handle.local_node_record();
    info!(enode = %local_enode, "Sync node enode URL");

    // Subscribe to network events
    let mut events = net_handle.event_listener();

    // Spawn network manager
    tokio::spawn(net_manager);

    // Spawn status reporter
    let sync_node_clone = sync_node.clone();
    let net_handle_clone = net_handle.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(10));
        loop {
            interval.tick().await;
            let (received, accepted, rejected, skipped) = sync_node_clone.get_stats();
            let highest = sync_node_clone.highest_slot().unwrap_or(0);
            let peers = net_handle_clone.num_connected_peers();

            info!(
                peers = peers,
                highest_slot = highest,
                received = received,
                accepted = accepted,
                rejected = rejected,
                skipped = skipped,
                "Sync status"
            );
        }
    });

    // Handle network events
    info!("Sync node running. Waiting for peers...");
    info!("This node will only download and validate blocks, not produce them.");

    while let Some(evt) = events.next().await {
        match evt {
            NetworkEvent::ActivePeerSession { info, .. } => {
                info!(
                    peers = net_handle.num_connected_peers(),
                    peer_id = %info.peer_id,
                    chain = %info.status.chain,
                    client = ?info.client_version,
                    "Connected to peer"
                );
            }
            NetworkEvent::Peer(reth_network_api::events::PeerEvent::SessionClosed { peer_id, reason }) => {
                warn!(
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
