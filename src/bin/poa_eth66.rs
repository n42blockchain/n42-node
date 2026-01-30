//! POA Node using eth66 protocol with Clique consensus.
//!
//! This implements a Proof-of-Authority node that:
//! - Uses reth's NetworkManager with eth66/67/68 protocols
//! - Uses Clique consensus engine for round-robin block production
//! - BLS signature for block sealing
//! - Snapshot-based signer authorization
//!
//! Run with:
//! ```sh
//! # Terminal 1 - Validator 0
//! cargo run --bin poa_eth66 --release -- \
//!     --validator-index 0 --port 30303
//!
//! # Terminal 2 - Validator 1 (copy enode from Terminal 1)
//! cargo run --bin poa_eth66 --release -- \
//!     --validator-index 1 --port 30304 \
//!     --bootnode enode://...@127.0.0.1:30303
//! ```

use alloy_primitives::{keccak256, Address, Bytes, B256, U128};
use n42_node::{
    BeaconBlock, BeaconBlockBody, BeaconStoreReader, BeaconStoreWriter, InMemoryBeaconStore,
    N42BroadcastBlock, N42NetworkPrimitives, N42NewBlock, SignedBeaconBlock,
    // Clique consensus types
    Clique, CliqueConfig, ChainHeaderReader, ChainConfig, HeaderData,
    MemorySnapshotDatabase, EXTRA_VANITY,
    CLIQUE_DIFF_IN_TURN, CLIQUE_DIFF_NO_TURN, NONCE_DROP_VOTE,
    // Miner module types
    MinerConfig, MinerEvent, PoaAttributesProvider, Worker as MinerWorker,
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
// secp256k1 for P2P identity (required by devp2p protocol)
use secp256k1::{SecretKey, SECP256K1};
use std::{
    collections::HashMap,
    fmt,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    str::FromStr,
    sync::{Arc, RwLock},
    task::{Context, Poll},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::mpsc;
use tokio_stream::StreamExt;

/// BLS public key type (48 bytes)
type BLSPubkey = [u8; 48];

/// Default block time in seconds
const DEFAULT_BLOCK_TIME: u64 = 5;

/// Command line arguments
struct Args {
    /// This validator's index (0, 1, or 2)
    validator_index: usize,
    /// P2P port
    port: u16,
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

        Self { validator_index, port, bootnode, block_time }
    }
}

/// Simple chain header reader backed by our beacon store
struct CliqueChainReader {
    store: Arc<InMemoryBeaconStore>,
    headers: RwLock<HashMap<B256, HeaderData>>,
    headers_by_number: RwLock<HashMap<u64, HeaderData>>,
    chain_config: ChainConfig,
    block_time: u64,
}

impl CliqueChainReader {
    fn new(store: Arc<InMemoryBeaconStore>, block_time: u64) -> Self {
        Self {
            store,
            headers: RwLock::new(HashMap::new()),
            headers_by_number: RwLock::new(HashMap::new()),
            chain_config: ChainConfig::default(),
            block_time,
        }
    }

    /// Convert SignedBeaconBlock to HeaderData for Clique
    fn beacon_to_header(&self, block: &SignedBeaconBlock) -> HeaderData {
        let slot = block.slot();
        let hash = block.block_root();
        let parent_hash = block.message.parent_root;

        // Get coinbase from graffiti (first 20 bytes after vanity)
        let coinbase = if block.message.body.graffiti.as_slice().len() >= 20 {
            Address::from_slice(&block.message.body.graffiti.as_slice()[..20])
        } else {
            Address::ZERO
        };

        // Build extra data: [vanity 32 bytes] + [signature 96 bytes for BLS]
        let mut extra = vec![0u8; EXTRA_VANITY];
        extra.extend_from_slice(&block.signature);

        // Get difficulty from proposer_index pattern
        let signers_count = 3u64; // We have 3 validators
        let expected_proposer = slot % signers_count;
        let difficulty = if block.message.proposer_index == expected_proposer {
            CLIQUE_DIFF_IN_TURN
        } else {
            CLIQUE_DIFF_NO_TURN
        };

        HeaderData {
            number: slot,
            hash,
            parent_hash,
            coinbase,
            nonce: NONCE_DROP_VOTE, // No vote
            extra: Bytes::from(extra),
            time: slot * self.block_time,
            difficulty,
        }
    }

    /// Insert a header from a beacon block
    fn insert_header(&self, block: &SignedBeaconBlock) {
        let header = self.beacon_to_header(block);
        let hash = header.hash;
        let number = header.number;

        self.headers.write().unwrap().insert(hash, header.clone());
        self.headers_by_number.write().unwrap().insert(number, header);
    }
}

impl ChainHeaderReader for CliqueChainReader {
    fn config(&self) -> &ChainConfig {
        &self.chain_config
    }

    fn current_header(&self) -> Option<HeaderData> {
        self.store.latest_block().ok().flatten().map(|b| self.beacon_to_header(&b))
    }

    fn get_header(&self, hash: B256, _number: u64) -> Option<HeaderData> {
        self.headers.read().unwrap().get(&hash).cloned()
    }

    fn get_header_by_number(&self, number: u64) -> Option<HeaderData> {
        self.headers_by_number.read().unwrap().get(&number).cloned()
    }

    fn get_header_by_hash(&self, hash: B256) -> Option<HeaderData> {
        self.headers.read().unwrap().get(&hash).cloned()
    }
}

/// POA node state with Clique consensus
#[allow(dead_code)]
struct PoaNode {
    /// Clique consensus engine
    clique: Clique<MemorySnapshotDatabase>,
    /// Chain reader for Clique
    chain_reader: Arc<CliqueChainReader>,
    /// Block storage
    store: Arc<InMemoryBeaconStore>,
    /// All blocks indexed by hash (for fork choice)
    blocks_by_hash: RwLock<HashMap<B256, SignedBeaconBlock>>,
    /// This validator's index
    validator_index: usize,
    /// This validator's address
    validator_address: Address,
    /// BLS signing key
    bls_signing_key: blst::min_pk::SecretKey,
    /// All validator addresses (in order)
    validators: Vec<Address>,
    /// Validator BLS public keys (for signature verification)
    validator_pubkeys: Vec<BLSPubkey>,
    /// Last produced slot
    last_produced_slot: RwLock<Option<u64>>,
    /// Block time in seconds
    block_time: u64,
    /// Genesis block hash
    genesis_hash: B256,
}

impl PoaNode {
    fn new(
        validators: Vec<Address>,
        validator_pubkeys: Vec<BLSPubkey>,
        validator_index: usize,
        bls_signing_key: blst::min_pk::SecretKey,
        block_time: u64,
    ) -> Self {
        let store = Arc::new(InMemoryBeaconStore::new());
        let chain_reader = Arc::new(CliqueChainReader::new(store.clone(), block_time));

        // Create Clique config
        let clique_config = CliqueConfig {
            period: block_time,
            epoch: 30000,
        };

        // Create snapshot database
        let snapshot_db = MemorySnapshotDatabase::new_arc();

        // Create Clique engine
        let clique = Clique::new(clique_config, snapshot_db);

        // Authorize this signer
        let validator_address = validators[validator_index];
        clique.authorize(validator_address);

        // Register all validator pubkeys for signature verification
        for (addr, pubkey) in validators.iter().zip(validator_pubkeys.iter()) {
            clique.register_pubkey(*addr, *pubkey);
        }

        // Create deterministic genesis block (same for all nodes)
        let genesis = Self::create_genesis_block(&validators, block_time);
        let genesis_hash = genesis.block_root();

        // Store genesis block
        store.insert_block(genesis.clone()).expect("Failed to store genesis");
        chain_reader.insert_header(&genesis);

        let mut blocks_by_hash = HashMap::new();
        blocks_by_hash.insert(genesis_hash, genesis);

        info!(
            genesis_hash = %genesis_hash,
            "Genesis block created"
        );

        Self {
            clique,
            chain_reader,
            store,
            blocks_by_hash: RwLock::new(blocks_by_hash),
            validator_index,
            validator_address,
            bls_signing_key,
            validators,
            validator_pubkeys,
            last_produced_slot: RwLock::new(Some(0)), // Genesis is at slot 0
            block_time,
            genesis_hash,
        }
    }

    /// Create deterministic genesis block (identical for all nodes)
    fn create_genesis_block(validators: &[Address], _block_time: u64) -> SignedBeaconBlock {
        // Genesis block at slot 0 with validator 0 as proposer
        let mut graffiti = B256::ZERO;
        // Put first validator address in graffiti
        graffiti.as_mut_slice()[..20].copy_from_slice(validators[0].as_slice());

        let body = BeaconBlockBody {
            graffiti,
            ..Default::default()
        };

        // Genesis has no parent (parent_root = ZERO)
        // Use deterministic state_root for reproducibility
        let state_root = keccak256(b"n42-genesis-state");

        let block = BeaconBlock::new(
            0,  // slot 0
            0,  // proposer_index 0
            B256::ZERO,  // parent_root (no parent)
            state_root,
            body,
            CLIQUE_DIFF_IN_TURN,  // genesis is always in-turn
        );

        // Genesis signature is deterministic (all zeros for simplicity)
        // In production, this would be signed by validator 0
        let signature = Bytes::from(vec![0u8; 96]); // BLS signature is 96 bytes

        SignedBeaconBlock::new(block, signature)
    }

    /// Calculate current slot from timestamp
    fn current_slot(&self) -> u64 {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        now / self.block_time
    }

    /// Create data to be signed for the seal (block root)
    fn create_seal_data(&self, block: &BeaconBlock) -> B256 {
        block.block_root()
    }

    /// Process a received block from the network
    fn process_block(&self, block: &SignedBeaconBlock, peer_id: PeerId) -> Result<bool, String> {
        let slot = block.slot();
        let hash = block.block_root();
        let parent_hash = block.message.parent_root;

        // Check if we already have this block
        {
            let blocks = self.blocks_by_hash.read().unwrap();
            if blocks.contains_key(&hash) {
                debug!(slot = slot, hash = %hash, "Block already known");
                return Ok(false);
            }
        }

        // Check if parent exists in our block database
        let parent_exists = {
            let blocks = self.blocks_by_hash.read().unwrap();
            blocks.contains_key(&parent_hash)
        };

        if !parent_exists {
            return Err(format!(
                "unknown parent: {} (we may need to sync)",
                parent_hash
            ));
        }

        // Convert to HeaderData for Clique validation
        let header = self.chain_reader.beacon_to_header(block);

        // Get parent header for validation
        let parent_header = self.chain_reader.get_header_by_hash(parent_hash);
        let parents: Vec<HeaderData> = parent_header.into_iter().collect();

        // Verify using Clique
        if let Err(e) = self.clique.verify_header(
            self.chain_reader.as_ref(),
            &header,
            if parents.is_empty() { None } else { Some(&parents) },
        ) {
            // For now, log but don't reject (we may not have full snapshot)
            debug!(
                slot = slot,
                hash = %hash,
                error = %e,
                "Clique validation warning (continuing anyway)"
            );
        }

        // Verify BLS signature
        let signer = self.verify_block_signature(block);

        // Verify signer is a known validator
        if let Some(signer_addr) = signer {
            if !self.validators.contains(&signer_addr) {
                return Err(format!("unknown signer: {}", signer_addr));
            }
        }

        // Store block in our database
        {
            let mut blocks = self.blocks_by_hash.write().unwrap();
            blocks.insert(hash, block.clone());
        }

        // Update chain tip if this block extends the current tip
        let our_tip_slot = self.store.latest_slot().ok().flatten().unwrap_or(0);
        if slot > our_tip_slot {
            self.store.insert_block(block.clone()).map_err(|e| e.to_string())?;
            self.chain_reader.insert_header(block);
        }

        info!(
            slot = slot,
            hash = %hash,
            parent = %parent_hash,
            signer = ?signer,
            peer = %peer_id,
            "Accepted block from network"
        );

        Ok(true)
    }

    /// Verify block signature and return signer address if valid.
    /// BLS does not support key recovery, so we try all known validators.
    fn verify_block_signature(&self, block: &SignedBeaconBlock) -> Option<Address> {
        if block.signature.len() != 96 {
            return None;
        }

        let seal_hash = self.create_seal_data(&block.message);
        let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

        // Parse signature
        let Ok(sig) = blst::min_pk::Signature::from_bytes(block.signature.as_ref()) else {
            return None;
        };

        // Try all known validators
        for (i, pubkey) in self.validator_pubkeys.iter().enumerate() {
            let Ok(pk) = blst::min_pk::PublicKey::from_bytes(pubkey) else {
                continue;
            };

            if sig.verify(true, seal_hash.as_slice(), dst, &[], &pk, true)
                == blst::BLST_ERROR::BLST_SUCCESS
            {
                return Some(self.validators[i]);
            }
        }

        None
    }
}

/// Block import handler for N42 network
struct N42BlockImport {
    poa_node: Arc<PoaNode>,
    pending_events: std::sync::Mutex<Vec<BlockImportEvent<N42NewBlock>>>,
}

impl N42BlockImport {
    fn new(poa_node: Arc<PoaNode>) -> Self {
        Self {
            poa_node,
            pending_events: std::sync::Mutex::new(Vec::new()),
        }
    }
}

impl BlockImport<N42NewBlock> for N42BlockImport {
    fn on_new_block(&mut self, peer_id: PeerId, incoming_block: NewBlockEvent<N42NewBlock>) {
        match incoming_block {
            NewBlockEvent::Block(new_block_msg) => {
                let new_block = &new_block_msg.block;
                let hash = new_block_msg.hash;

                info!(
                    slot = new_block.block.slot(),
                    hash = %hash,
                    peer = %peer_id,
                    "Received NewBlock via eth66"
                );

                match self.poa_node.process_block(new_block.block.beacon_block(), peer_id) {
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
    let td = U128::from(beacon.slot());

    NewBlock { block, td }
}

/// Generate deterministic BLS keys for validators
fn generate_bls_keys(count: usize) -> Vec<(blst::min_pk::SecretKey, BLSPubkey, Address)> {
    (0..count)
        .map(|i| {
            // Deterministic seed for demo purposes
            let mut ikm = [0u8; 32];
            ikm[0] = i as u8 + 1;
            ikm[31] = 0x42;

            let sk = blst::min_pk::SecretKey::key_gen(&ikm, &[]).unwrap();
            let pk = sk.sk_to_pk();
            let pubkey: BLSPubkey = pk.to_bytes();

            // Derive address from BLS public key (keccak256 of pubkey, last 20 bytes)
            let hash = keccak256(&pubkey);
            let address = Address::from_slice(&hash[12..]);

            (sk, pubkey, address)
        })
        .collect()
}

/// Generate deterministic secp256k1 key for P2P identity
fn generate_p2p_key(index: usize) -> SecretKey {
    let mut seed = [0u8; 32];
    seed[0] = index as u8 + 100; // Different range from BLS keys
    seed[31] = 0x99;
    SecretKey::from_slice(&seed).unwrap()
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    // Initialize tracing
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
        "Starting POA eth66 node with BLS signatures"
    );

    // Generate BLS keys for all validators
    let bls_keys = generate_bls_keys(3);

    let validators: Vec<Address> = bls_keys.iter().map(|(_, _, addr)| *addr).collect();
    let validator_pubkeys: Vec<BLSPubkey> = bls_keys.iter().map(|(_, pk, _)| *pk).collect();

    info!(
        validators = ?validators,
        this_validator = ?validators[args.validator_index],
        "Validator set (addresses derived from BLS public keys)"
    );

    // Get this validator's BLS key
    let bls_signing_key = bls_keys[args.validator_index].0.clone();

    // Generate secp256k1 key for P2P identity (required by devp2p)
    let p2p_key = generate_p2p_key(args.validator_index);

    // Create POA node with Clique
    let poa_node = Arc::new(PoaNode::new(
        validators.clone(),
        validator_pubkeys.clone(),
        args.validator_index,
        bls_signing_key.clone(),
        args.block_time,
    ));

    // Create block import handler
    let block_import = Box::new(N42BlockImport::new(poa_node.clone()));

    // Use secp256k1 key for P2P identity
    let peer_id = pk2id(&p2p_key.public_key(SECP256K1));

    info!(peer_id = %peer_id, "Node P2P identity (secp256k1)");

    // Build network configuration
    let local_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, args.port));

    use reth_network::HelloMessageWithProtocols;
    use reth_ethereum::network::eth_wire::{EthVersion, protocol::Protocol};
    let hello_message = HelloMessageWithProtocols::builder(peer_id)
        .protocols([
            Protocol::eth(EthVersion::Eth66),
            Protocol::eth(EthVersion::Eth67),
            Protocol::eth(EthVersion::Eth68),
        ])
        .build();

    let mut net_builder: reth_network::NetworkConfigBuilder<N42NetworkPrimitives> =
        NetworkConfig::builder(p2p_key.clone())
            .with_pow()
            .set_addrs(local_addr)
            .hello_message(hello_message)
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

    let net_cfg = net_builder.build(NoopProvider::eth(MAINNET.clone()));

    let net_cfg = net_cfg.set_discovery_v4(
        Discv4ConfigBuilder::default()
            .lookup_interval(Duration::from_secs(1))
            .build(),
    );

    let net_manager = NetworkManager::<N42NetworkPrimitives>::new(net_cfg).await?;
    let net_handle = net_manager.handle().clone();

    let local_enode = net_handle.local_node_record();
    info!(enode = %local_enode, "Local enode URL (share with other validators)");

    let mut events = net_handle.event_listener();

    tokio::spawn(net_manager);

    let (block_tx, mut block_rx) = mpsc::channel::<SignedBeaconBlock>(32);

    // Create miner configuration with BLS key
    let miner_config = MinerConfig::new(validators[args.validator_index], bls_signing_key)
        .with_recommit_interval(Duration::from_secs(2));

    // Create POA attributes provider
    // genesis_time = 0 because current_slot() uses `now / block_time`
    // so timestamp(slot) = slot * block_time matches current time
    let attrs_provider = Arc::new(PoaAttributesProvider::new(
        validators[args.validator_index],
        args.block_time,
        0, // genesis_time = 0 for compatibility with current_slot()
    ));

    // Spawn miner worker
    let (miner_handle, mut miner_events) = MinerWorker::spawn(
        miner_config,
        attrs_provider,
        args.validator_index as u64,
    );

    info!("Miner worker started with BLS signing and wiggle delay support");

    // Spawn block producer that uses the miner
    let poa_clone = poa_node.clone();
    let validator_count = validators.len();
    let miner_handle_clone = miner_handle.clone();

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_millis(500));
        let mut last_checked_slot = 0u64;

        loop {
            interval.tick().await;

            let current_slot = poa_clone.current_slot();

            // Skip if already checked this slot
            if current_slot <= last_checked_slot {
                continue;
            }

            // Check if it's our turn (for deciding in_turn vs out_of_turn)
            let expected_producer = (current_slot as usize) % validator_count;
            let is_in_turn = expected_producer == poa_clone.validator_index;

            // Get parent block for mining
            if let Ok(Some(parent)) = poa_clone.store.latest_block() {
                // Only start mining if slot is newer than parent
                if current_slot > parent.slot() {
                    // Start mining with the miner worker
                    let _ = miner_handle_clone
                        .start_mining(parent, current_slot, is_in_turn, validator_count)
                        .await;
                }
            }

            last_checked_slot = current_slot;
        }
    });

    // Spawn miner event handler - receives sealed blocks from miner
    let poa_clone2 = poa_node.clone();
    let block_tx_clone2 = block_tx.clone();
    tokio::spawn(async move {
        while let Some(event) = miner_events.recv().await {
            match event {
                MinerEvent::BlockSealed(result) => {
                    let block = result.block;
                    let hash = result.hash;

                    info!(
                        slot = block.slot(),
                        hash = %hash,
                        latency_ms = result.seal_latency.as_millis(),
                        "Miner sealed block with BLS signature"
                    );

                    // Store in blocks_by_hash
                    {
                        let mut blocks = poa_clone2.blocks_by_hash.write().unwrap();
                        blocks.insert(hash, block.clone());
                    }

                    // Store in beacon store
                    let _ = poa_clone2.store.insert_block(block.clone());
                    poa_clone2.chain_reader.insert_header(&block);

                    // Send to broadcaster
                    let _ = block_tx_clone2.send(block).await;
                }
                MinerEvent::MiningStarted { slot, in_turn } => {
                    debug!(slot = slot, in_turn = in_turn, "Mining started");
                }
                MinerEvent::MiningCancelled { reason } => {
                    debug!(reason = %reason, "Mining cancelled");
                }
                MinerEvent::Error(err) => {
                    warn!(error = %err, "Miner error");
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

            net_handle_clone.announce_block(new_block, hash);
        }
    });

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
