//! POA Node - Multi-node POA consensus network
//!
//! Run 3 nodes with:
//! ```bash
//! GENESIS=$(($(date +%s) + 15))
//!
//! # Terminal 1
//! poa_node -p 30303 -c 0x0101010101010101010101010101010101010101 -g $GENESIS
//!
//! # Terminal 2
//! poa_node -p 30304 -c 0x0202020202020202020202020202020202020202 -g $GENESIS \
//!   -b 127.0.0.1:30303
//!
//! # Terminal 3
//! poa_node -p 30305 -c 0x0303030303030303030303030303030303030303 -g $GENESIS \
//!   -b 127.0.0.1:30303
//! ```

use alloy_primitives::{Address, B256};
use n42_node::{
    get_difficulty_from_graffiti, set_difficulty_in_graffiti, BeaconBlock, BeaconBlockBody,
    BeaconStoreReader, BeaconStoreWriter, InMemoryBeaconStore, PoaConfig, PoaValidator,
    SignedBeaconBlock,
};
use std::{
    collections::HashSet,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    str::FromStr,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const DEFAULT_VALIDATORS: [&str; 3] = [
    "0x0101010101010101010101010101010101010101",
    "0x0202020202020202020202020202020202020202",
    "0x0303030303030303030303030303030303030303",
];

const BLOCK_TIME: u64 = 8;

// Message types
const MSG_BLOCK: u8 = 0x01;
const MSG_HELLO: u8 = 0x02;
const MSG_PEERS: u8 = 0x03;

fn encode_block(block: &SignedBeaconBlock) -> Vec<u8> {
    let encoded = alloy_rlp::encode(block);
    let mut data = vec![MSG_BLOCK];
    data.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
    data.extend_from_slice(&encoded);
    data
}

fn encode_hello(port: u16) -> Vec<u8> {
    vec![MSG_HELLO, (port >> 8) as u8, port as u8]
}

fn encode_peers(peers: &[String]) -> Vec<u8> {
    let mut data = vec![MSG_PEERS, peers.len() as u8];
    for peer in peers {
        let bytes = peer.as_bytes();
        data.push(bytes.len() as u8);
        data.extend_from_slice(bytes);
    }
    data
}

struct PoaNode {
    coinbase: Address,
    config: PoaConfig,
    validator: PoaValidator,
    store: Arc<Mutex<InMemoryBeaconStore>>,
    peers: Arc<Mutex<HashSet<String>>>,
    genesis_time: u64,
    last_produced_slot: Mutex<Option<u64>>,
    my_port: u16,
}

impl PoaNode {
    fn current_slot(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if now < self.genesis_time {
            0
        } else {
            (now - self.genesis_time) / BLOCK_TIME
        }
    }

    fn try_produce_block(&self) -> Option<SignedBeaconBlock> {
        let slot = self.current_slot();

        let mut last_slot = self.last_produced_slot.lock().unwrap();
        if *last_slot == Some(slot) {
            return None;
        }

        let store = self.store.lock().unwrap();
        let parent = store.latest_block().ok().flatten();
        let parent_slot = parent.as_ref().map(|b| b.slot()).unwrap_or(0);

        if slot <= parent_slot && parent.is_some() {
            return None;
        }

        if !self.config.validators.contains(&self.coinbase) {
            return None;
        }

        let parent_root = parent.as_ref().map(|b| b.block_root()).unwrap_or(B256::ZERO);
        let proposer_index = self.config.validators.index_of(&self.coinbase)? as u64;
        let difficulty = self.config.expected_difficulty(slot, self.coinbase);

        let mut graffiti = B256::ZERO;
        set_difficulty_in_graffiti(&mut graffiti, difficulty);

        let body = BeaconBlockBody {
            graffiti,
            ..Default::default()
        };

        let block = BeaconBlock::new(slot, proposer_index, parent_root, B256::ZERO, body);

        let mut sig = vec![0u8; 96];
        sig[..20].copy_from_slice(self.coinbase.as_slice());
        let signed = SignedBeaconBlock::new(block, sig.into());

        *last_slot = Some(slot);
        Some(signed)
    }

    fn receive_block(&self, block: &SignedBeaconBlock) -> Result<bool, String> {
        let store = self.store.lock().unwrap();
        let parent = store.latest_block().ok().flatten();

        self.validator
            .validate_block(block, parent.as_ref())
            .map_err(|e| e.to_string())?;

        let our_tip_slot = parent.map(|b| b.slot()).unwrap_or(0);

        if block.slot() > our_tip_slot {
            store.insert_block(block.clone()).map_err(|e| e.to_string())?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn broadcast_block(&self, block: &SignedBeaconBlock) {
        let data = encode_block(block);
        let peers: Vec<String> = self.peers.lock().unwrap().iter().cloned().collect();

        for peer in peers {
            if let Ok(mut stream) = TcpStream::connect_timeout(
                &peer.parse().unwrap(),
                Duration::from_secs(2),
            ) {
                stream.set_write_timeout(Some(Duration::from_secs(2))).ok();
                let _ = stream.write_all(&data);
            }
        }
    }

    fn add_peer(&self, peer: String) {
        if !peer.contains(&format!(":{}", self.my_port)) {
            let mut peers = self.peers.lock().unwrap();
            if peers.insert(peer.clone()) {
                println!("[NET] Added peer: {}", peer);
            }
        }
    }

    fn chain_len(&self) -> usize {
        self.store.lock().unwrap().len()
    }

    fn tip_slot(&self) -> u64 {
        self.store
            .lock()
            .unwrap()
            .latest_block()
            .ok()
            .flatten()
            .map(|b| b.slot())
            .unwrap_or(0)
    }

    fn peer_count(&self) -> usize {
        self.peers.lock().unwrap().len()
    }

    fn get_peers(&self) -> Vec<String> {
        self.peers.lock().unwrap().iter().cloned().collect()
    }
}

fn handle_connection(
    mut stream: TcpStream,
    node: Arc<PoaNode>,
) {
    let peer_addr = match stream.peer_addr() {
        Ok(addr) => addr.to_string(),
        Err(_) => return,
    };

    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();

    let mut buf = vec![0u8; 65536];
    match stream.read(&mut buf) {
        Ok(0) => return,
        Ok(n) => {
            if n == 0 {
                return;
            }

            match buf[0] {
                MSG_BLOCK => {
                    if n >= 5 {
                        let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
                        if n >= 5 + len {
                            if let Ok(block) = alloy_rlp::Decodable::decode(&mut &buf[5..5 + len]) {
                                let block: SignedBeaconBlock = block;
                                let slot = block.slot();
                                let difficulty = get_difficulty_from_graffiti(&block.message.body.graffiti);

                                match node.receive_block(&block) {
                                    Ok(true) => {
                                        println!(
                                            "📥 RECEIVED block: slot={}, proposer=V{}, difficulty={} ✓",
                                            slot, block.message.proposer_index, difficulty
                                        );
                                    }
                                    Ok(false) => {}
                                    Err(e) => {
                                        println!("❌ REJECTED block slot={}: {}", slot, e);
                                    }
                                }
                            }
                        }
                    }
                }
                MSG_HELLO => {
                    if n >= 3 {
                        let peer_port = ((buf[1] as u16) << 8) | (buf[2] as u16);
                        // Extract IP from peer_addr
                        if let Some(ip) = peer_addr.split(':').next() {
                            let peer = format!("{}:{}", ip, peer_port);
                            node.add_peer(peer);

                            // Send back our peer list
                            let peers = node.get_peers();
                            let response = encode_peers(&peers);
                            let _ = stream.write_all(&response);
                        }
                    }
                }
                MSG_PEERS => {
                    if n >= 2 {
                        let count = buf[1] as usize;
                        let mut offset = 2;
                        for _ in 0..count {
                            if offset >= n {
                                break;
                            }
                            let len = buf[offset] as usize;
                            offset += 1;
                            if offset + len <= n {
                                if let Ok(peer) = std::str::from_utf8(&buf[offset..offset + len]) {
                                    node.add_peer(peer.to_string());
                                }
                                offset += len;
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        Err(_) => {}
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let mut port: u16 = 30303;
    let mut coinbase: Option<Address> = None;
    let mut bootnodes: Vec<String> = Vec::new();
    let mut genesis_time: Option<u64> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--port" | "-p" => {
                if i + 1 < args.len() {
                    port = args[i + 1].parse().unwrap_or(30303);
                    i += 1;
                }
            }
            "--coinbase" | "-c" => {
                if i + 1 < args.len() {
                    coinbase = Address::from_str(&args[i + 1]).ok();
                    i += 1;
                }
            }
            "--bootnode" | "-b" => {
                if i + 1 < args.len() {
                    bootnodes.push(args[i + 1].clone());
                    i += 1;
                }
            }
            "--genesis-time" | "-g" => {
                if i + 1 < args.len() {
                    genesis_time = args[i + 1].parse().ok();
                    i += 1;
                }
            }
            "--help" | "-h" => {
                println!("POA Node\n");
                println!("Usage: poa_node [OPTIONS]\n");
                println!("Options:");
                println!("  -p, --port <PORT>           P2P port (default: 30303)");
                println!("  -c, --coinbase <ADDRESS>    Validator address");
                println!("  -b, --bootnode <ADDR:PORT>  Bootnode (can use multiple times)");
                println!("  -g, --genesis-time <UNIX>   Genesis timestamp");
                println!("  -h, --help                  Show help\n");
                println!("Example (3 nodes):");
                println!("  GENESIS=$(($(date +%s) + 15))");
                println!("  poa_node -p 30303 -c 0x01..01 -g $GENESIS");
                println!("  poa_node -p 30304 -c 0x02..02 -g $GENESIS -b 127.0.0.1:30303");
                println!("  poa_node -p 30305 -c 0x03..03 -g $GENESIS -b 127.0.0.1:30303");
                return;
            }
            _ => {}
        }
        i += 1;
    }

    let coinbase = coinbase.unwrap_or_else(|| Address::from_str(DEFAULT_VALIDATORS[0]).unwrap());
    let genesis_time = genesis_time.unwrap_or_else(|| {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + 15
    });

    let validators: Vec<Address> = DEFAULT_VALIDATORS
        .iter()
        .map(|s| Address::from_str(s).unwrap())
        .collect();

    let config = PoaConfig::new(validators.clone(), BLOCK_TIME).with_coinbase(coinbase);

    // Initialize peers with bootnodes
    let peers: HashSet<String> = bootnodes.iter().cloned().collect();

    let node = Arc::new(PoaNode {
        coinbase,
        validator: PoaValidator::new(config.clone()),
        config,
        store: Arc::new(Mutex::new(InMemoryBeaconStore::new())),
        peers: Arc::new(Mutex::new(peers)),
        genesis_time,
        last_produced_slot: Mutex::new(None),
        my_port: port,
    });

    println!("╔════════════════════════════════════════════╗");
    println!("║            POA Node Starting               ║");
    println!("╠════════════════════════════════════════════╣");
    println!("║ Port:       {:>28} ║", port);
    println!("║ Genesis:    {:>28} ║", genesis_time);
    println!("║ Block time: {:>27}s ║", BLOCK_TIME);
    println!("╠════════════════════════════════════════════╣");
    for (i, v) in validators.iter().enumerate() {
        let marker = if *v == coinbase { " ← YOU" } else { "" };
        println!("║ V{}: {:?}{:>8} ║", i, v, marker);
    }
    println!("╠════════════════════════════════════════════╣");
    println!("║ Bootnodes: {:>30} ║", bootnodes.len());
    for bn in &bootnodes {
        println!("║   - {:>37} ║", bn);
    }
    println!("╚════════════════════════════════════════════╝\n");

    // TCP Listener
    let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).expect("Failed to bind");
    listener.set_nonblocking(true).ok();
    println!("[NET] Listening on 0.0.0.0:{}", port);

    // Connect to bootnodes and announce ourselves
    for bootnode in &bootnodes {
        println!("[NET] Connecting to bootnode {}...", bootnode);
        if let Ok(mut stream) = TcpStream::connect_timeout(
            &bootnode.parse().unwrap(),
            Duration::from_secs(5),
        ) {
            let hello = encode_hello(port);
            if stream.write_all(&hello).is_ok() {
                println!("[NET] Sent HELLO to {}", bootnode);

                // Read peer list response
                stream.set_read_timeout(Some(Duration::from_secs(2))).ok();
                let mut buf = vec![0u8; 4096];
                if let Ok(n) = stream.read(&mut buf) {
                    if n > 2 && buf[0] == MSG_PEERS {
                        let count = buf[1] as usize;
                        let mut offset = 2;
                        for _ in 0..count {
                            if offset >= n {
                                break;
                            }
                            let len = buf[offset] as usize;
                            offset += 1;
                            if offset + len <= n {
                                if let Ok(peer) = std::str::from_utf8(&buf[offset..offset + len]) {
                                    node.add_peer(peer.to_string());
                                }
                                offset += len;
                            }
                        }
                    }
                }
            }
        } else {
            println!("[NET] Failed to connect to {}", bootnode);
        }
    }

    // Listener thread
    let node_for_listener = Arc::clone(&node);
    thread::spawn(move || {
        loop {
            match listener.accept() {
                Ok((stream, _)) => {
                    let n = Arc::clone(&node_for_listener);
                    thread::spawn(move || handle_connection(stream, n));
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });

    // Wait for genesis
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    if now < genesis_time {
        let wait = genesis_time - now;
        println!("\n⏳ Waiting {} seconds for genesis...", wait);
        println!("   Peers: {}\n", node.peer_count());
        thread::sleep(Duration::from_secs(wait));
    }

    println!("\n🚀 GENESIS! Consensus starting...\n");

    // Main loop
    let mut last_slot = 0u64;

    loop {
        let current_slot = node.current_slot();

        if current_slot != last_slot && current_slot > 0 {
            last_slot = current_slot;

            let in_turn_idx = (current_slot as usize) % validators.len();
            let in_turn_addr = validators[in_turn_idx];
            let is_my_turn = in_turn_addr == coinbase;

            println!("\n═══════════════════════════════════════════");
            println!("📦 SLOT {} | In-turn: V{} {}",
                current_slot,
                in_turn_idx,
                if is_my_turn { "← YOUR TURN!" } else { "" }
            );
            println!("   Chain: {} blocks | Tip: slot {} | Peers: {}",
                node.chain_len(),
                node.tip_slot(),
                node.peer_count()
            );
            println!("═══════════════════════════════════════════");

            if is_my_turn {
                if let Some(block) = node.try_produce_block() {
                    let difficulty = get_difficulty_from_graffiti(&block.message.body.graffiti);
                    println!(
                        "📤 PRODUCED: slot={}, difficulty={} (IN-TURN)",
                        block.slot(), difficulty
                    );
                    let _ = node.receive_block(&block);
                    node.broadcast_block(&block);
                }
            } else {
                println!("   ⏳ Waiting {}s for in-turn validator...", BLOCK_TIME / 2);
                thread::sleep(Duration::from_secs(BLOCK_TIME / 2));

                if node.tip_slot() < current_slot {
                    println!("   ⚠️  No block received, producing OUT-OF-TURN...");
                    if let Some(block) = node.try_produce_block() {
                        let difficulty = get_difficulty_from_graffiti(&block.message.body.graffiti);
                        println!(
                            "📤 PRODUCED: slot={}, difficulty={} (OUT-OF-TURN)",
                            block.slot(), difficulty
                        );
                        let _ = node.receive_block(&block);
                        node.broadcast_block(&block);
                    }
                }
            }
        }

        thread::sleep(Duration::from_millis(100));
    }
}
