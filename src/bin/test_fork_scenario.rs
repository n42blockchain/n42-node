//! Fork Scenario Integration Test
//!
//! This test simulates a network partition scenario where:
//! - Two groups of validators operate independently for N slots
//! - Each group builds its own chain (creating two long forks)
//! - Then the partition heals and fork choice determines the winner
//!
//! Run with: `cargo run --bin test_fork_scenario`

use alloy_primitives::{Address, B256};
use n42_node::{
    BeaconBlock, BeaconBlockBody, PoaConfig, PoaValidator, SignedBeaconBlock,
    DIFFICULTY_IN_TURN, DIFFICULTY_OUT_OF_TURN,
};
use std::collections::HashMap;

/// Simulated validator node with simple chain management
struct ValidatorNode {
    address: Address,
    index: usize,
    validator: PoaValidator,
    /// Local chain (ordered list of blocks)
    chain: Vec<SignedBeaconBlock>,
    /// All blocks indexed by hash (including forks)
    blocks_by_hash: HashMap<B256, SignedBeaconBlock>,
    /// Last produced slot
    last_produced_slot: Option<u64>,
}

impl ValidatorNode {
    fn new(index: usize, address: Address, config: PoaConfig) -> Self {
        Self {
            address,
            index,
            validator: PoaValidator::new(config),
            chain: Vec::new(),
            blocks_by_hash: HashMap::new(),
            last_produced_slot: None,
        }
    }

    fn is_in_turn(&self, slot: u64) -> bool {
        self.validator.config().is_in_turn(slot, self.address)
    }

    fn get_difficulty(&self, slot: u64) -> u64 {
        self.validator.config().expected_difficulty(slot, self.address)
    }

    /// Get the tip of our canonical chain
    fn chain_tip(&self) -> Option<&SignedBeaconBlock> {
        self.chain.last()
    }

    /// Calculate total difficulty of our chain
    fn total_difficulty(&self) -> u64 {
        self.chain.iter().map(|b| b.message.difficulty).sum()
    }

    /// Produce a block for the given slot
    fn produce_block(&mut self, slot: u64) -> Option<SignedBeaconBlock> {
        if self.last_produced_slot == Some(slot) {
            return None;
        }

        let parent = self.chain_tip()?;
        let parent_slot = parent.slot();
        let parent_root = parent.block_root();

        if slot <= parent_slot {
            return None;
        }

        let difficulty = self.get_difficulty(slot);

        let mut graffiti = B256::ZERO;
        n42_node::set_difficulty_in_graffiti(&mut graffiti, difficulty);

        let body = BeaconBlockBody {
            graffiti,
            ..Default::default()
        };

        // Use unique state_root to distinguish blocks at same slot from different producers
        let state_root = {
            let mut data = Vec::new();
            data.extend_from_slice(&slot.to_be_bytes());
            data.extend_from_slice(self.address.as_slice());
            data.extend_from_slice(&difficulty.to_be_bytes());
            alloy_primitives::keccak256(&data)
        };

        let block = BeaconBlock::new(
            slot,
            self.index as u64,
            parent_root,
            state_root,
            body,
            difficulty,
        );

        let mut sig = vec![0u8; 96];
        sig[..20].copy_from_slice(self.address.as_slice());
        let signed = SignedBeaconBlock::new(block, sig.into());

        self.last_produced_slot = Some(slot);
        Some(signed)
    }

    /// Insert genesis block
    fn insert_genesis(&mut self, genesis: SignedBeaconBlock) {
        let hash = genesis.block_root();
        self.chain.push(genesis.clone());
        self.blocks_by_hash.insert(hash, genesis);
    }

    /// Receive a block and add to our chain if it extends it
    fn receive_block(&mut self, block: &SignedBeaconBlock) -> bool {
        let hash = block.block_root();
        let parent_hash = block.message.parent_root;

        // Already have this block?
        if self.blocks_by_hash.contains_key(&hash) {
            return false;
        }

        // Store the block regardless
        self.blocks_by_hash.insert(hash, block.clone());

        // Does it extend our current chain?
        if let Some(tip) = self.chain_tip() {
            if parent_hash == tip.block_root() && block.slot() > tip.slot() {
                self.chain.push(block.clone());
                return true;
            }
        }

        false
    }

    /// Try to switch to a better chain (simple reorg)
    /// Returns true if reorg happened
    fn try_reorg(&mut self, other_chain: &[SignedBeaconBlock]) -> bool {
        let our_td = self.total_difficulty();
        let other_td: u64 = other_chain.iter().map(|b| b.message.difficulty).sum();

        if other_td > our_td {
            // Store all blocks
            for block in other_chain {
                self.blocks_by_hash.insert(block.block_root(), block.clone());
            }
            // Switch chain
            self.chain = other_chain.to_vec();
            true
        } else if other_td == our_td && !other_chain.is_empty() {
            // Tie-breaker: lower tip hash wins
            let our_tip = self.chain_tip().map(|b| b.block_root()).unwrap_or_default();
            let other_tip = other_chain.last().map(|b| b.block_root()).unwrap_or_default();
            if other_tip < our_tip {
                for block in other_chain {
                    self.blocks_by_hash.insert(block.block_root(), block.clone());
                }
                self.chain = other_chain.to_vec();
                true
            } else {
                false
            }
        } else {
            false
        }
    }

    fn print_status(&self, prefix: &str) {
        let tip = self.chain_tip();
        let tip_slot = tip.map(|b| b.slot()).unwrap_or(0);
        let tip_hash = tip.map(|b| b.block_root()).unwrap_or_default();
        let td = self.total_difficulty();
        println!(
            "{}V{}: tip_slot={}, chain_len={}, TD={}, head={}",
            prefix,
            self.index,
            tip_slot,
            self.chain.len(),
            td,
            &format!("{:?}", tip_hash)[..14]
        );
    }
}

/// Create a deterministic genesis block
fn create_genesis(validators: &[Address]) -> SignedBeaconBlock {
    let mut graffiti = B256::ZERO;
    graffiti.as_mut_slice()[..20].copy_from_slice(validators[0].as_slice());
    n42_node::set_difficulty_in_graffiti(&mut graffiti, DIFFICULTY_IN_TURN);

    let body = BeaconBlockBody {
        graffiti,
        ..Default::default()
    };

    let state_root = alloy_primitives::keccak256(b"fork-test-genesis");

    let block = BeaconBlock::new(
        0,
        0,
        B256::ZERO,
        state_root,
        body,
        DIFFICULTY_IN_TURN,
    );

    SignedBeaconBlock::new(block, vec![0u8; 96].into())
}

fn main() {
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║          Fork Scenario Integration Test                      ║");
    println!("╚══════════════════════════════════════════════════════════════╝\n");

    // Configuration - make forks long!
    let common_prefix_slots = 5;   // Slots before partition
    let partition_slots = 30;      // Slots during partition (long forks!)

    // Create 3 validators
    let validators = vec![
        Address::repeat_byte(0x01),  // V0
        Address::repeat_byte(0x02),  // V1
        Address::repeat_byte(0x03),  // V2
    ];

    println!("Validators:");
    for (i, v) in validators.iter().enumerate() {
        println!("  V{}: {:?}", i, v);
    }
    println!();

    let config = PoaConfig::new(validators.clone(), 1);

    println!("┌─────────────────────────────────────────────────────────────┐");
    println!("│ Test Configuration                                          │");
    println!("├─────────────────────────────────────────────────────────────┤");
    println!("│  Common prefix:      {:>3} slots                             │", common_prefix_slots);
    println!("│  Partition duration: {:>3} slots (fork length)               │", partition_slots);
    println!("│  In-turn difficulty:   {}                                    │", DIFFICULTY_IN_TURN);
    println!("│  Out-of-turn diff:     {}                                    │", DIFFICULTY_OUT_OF_TURN);
    println!("└─────────────────────────────────────────────────────────────┘\n");

    // Create nodes
    let mut nodes: Vec<ValidatorNode> = validators
        .iter()
        .enumerate()
        .map(|(i, &addr)| ValidatorNode::new(i, addr, config.clone()))
        .collect();

    // Genesis block
    let genesis = create_genesis(&validators);
    println!("Genesis: hash={}\n", &format!("{:?}", genesis.block_root())[..18]);

    for node in &mut nodes {
        node.insert_genesis(genesis.clone());
    }

    // ========================================
    // Phase 1: Build common prefix
    // ========================================
    println!("═══════════════════════════════════════════════════════════════");
    println!(" Phase 1: Building Common Prefix ({} slots)", common_prefix_slots);
    println!("═══════════════════════════════════════════════════════════════\n");

    for slot in 1..=common_prefix_slots {
        let in_turn_idx = (slot as usize) % validators.len();
        let is_in_turn = nodes[in_turn_idx].is_in_turn(slot);
        let diff = if is_in_turn { DIFFICULTY_IN_TURN } else { DIFFICULTY_OUT_OF_TURN };

        if let Some(block) = nodes[in_turn_idx].produce_block(slot) {
            let hash = block.block_root();
            println!(
                "  Slot {:>2}: V{} produced (in_turn={}, diff={}) hash={}",
                slot,
                in_turn_idx,
                is_in_turn,
                diff,
                &format!("{:?}", hash)[..10]
            );

            // Broadcast to all nodes
            for (i, node) in nodes.iter_mut().enumerate() {
                if i == in_turn_idx {
                    node.chain.push(block.clone());
                    node.blocks_by_hash.insert(hash, block.clone());
                } else {
                    node.receive_block(&block);
                }
            }
        }
    }

    println!("\nCommon prefix built:");
    for node in &nodes {
        node.print_status("  ");
    }

    let common_td: u64 = nodes[0].total_difficulty();
    println!("\n  Common prefix TD: {}\n", common_td);

    // ========================================
    // Phase 2: Network Partition - Two Forks
    // ========================================
    println!("═══════════════════════════════════════════════════════════════");
    println!(" Phase 2: Network Partition ({} slots)", partition_slots);
    println!("═══════════════════════════════════════════════════════════════\n");

    println!("  ┌─────────────────┐     ┌─────────────────┐");
    println!("  │  Partition A    │     │  Partition B    │");
    println!("  │    V0 + V1      │ X X │      V2         │");
    println!("  │  (cooperating)  │     │   (isolated)    │");
    println!("  └─────────────────┘     └─────────────────┘\n");

    let partition_start = common_prefix_slots + 1;
    let partition_end = common_prefix_slots + partition_slots;

    // Track blocks produced in each partition
    let mut partition_a_blocks: Vec<SignedBeaconBlock> = nodes[0].chain.clone();
    let mut partition_b_blocks: Vec<SignedBeaconBlock> = nodes[2].chain.clone();

    println!("Building Fork A (V0 + V1):");
    let mut fork_a_in_turn = 0;
    let mut fork_a_out_turn = 0;

    for slot in partition_start..=partition_end {
        let in_turn_idx = (slot as usize) % validators.len();

        // Partition A: V0 and V1 cooperate
        // When it's V0 or V1's turn, they produce in-turn
        // When it's V2's turn, V0 produces out-of-turn (V2 is isolated)
        let partition_a_producer = if in_turn_idx == 0 || in_turn_idx == 1 {
            in_turn_idx  // V0 or V1 is in-turn
        } else {
            0  // V2's turn, but V2 is isolated, so V0 produces out-of-turn
        };

        if let Some(block) = nodes[partition_a_producer].produce_block(slot) {
            let hash = block.block_root();
            let is_in_turn = nodes[partition_a_producer].is_in_turn(slot);
            if is_in_turn { fork_a_in_turn += 1; } else { fork_a_out_turn += 1; }

            // Only V0 and V1 receive
            for i in 0..2 {
                if i == partition_a_producer {
                    nodes[i].chain.push(block.clone());
                    nodes[i].blocks_by_hash.insert(hash, block.clone());
                } else {
                    nodes[i].receive_block(&block);
                }
            }
            partition_a_blocks.push(block);
        }
    }

    println!("  Produced {} blocks ({} in-turn, {} out-of-turn)",
             partition_slots, fork_a_in_turn, fork_a_out_turn);

    println!("\nBuilding Fork B (V2 alone):");
    let mut fork_b_in_turn = 0;
    let mut fork_b_out_turn = 0;

    for slot in partition_start..=partition_end {
        // V2 produces every slot
        if let Some(block) = nodes[2].produce_block(slot) {
            let hash = block.block_root();
            let is_in_turn = nodes[2].is_in_turn(slot);
            if is_in_turn { fork_b_in_turn += 1; } else { fork_b_out_turn += 1; }

            nodes[2].chain.push(block.clone());
            nodes[2].blocks_by_hash.insert(hash, block.clone());
            partition_b_blocks.push(block);
        }
    }

    println!("  Produced {} blocks ({} in-turn, {} out-of-turn)",
             partition_slots, fork_b_in_turn, fork_b_out_turn);

    // Calculate chain statistics
    let chain_a_td = nodes[0].total_difficulty();
    let chain_a_tip = nodes[0].chain_tip().unwrap().slot();
    let chain_a_hash = nodes[0].chain_tip().unwrap().block_root();

    let chain_b_td = nodes[2].total_difficulty();
    let chain_b_tip = nodes[2].chain_tip().unwrap().slot();
    let chain_b_hash = nodes[2].chain_tip().unwrap().block_root();

    println!("\n┌─────────────────────────────────────────────────────────────┐");
    println!("│ Fork Statistics                                             │");
    println!("├─────────────────────────────────────────────────────────────┤");
    println!("│ Fork A (V0+V1):                                             │");
    println!("│   Length: {} blocks, Tip slot: {}, TD: {:>4}                 │",
             nodes[0].chain.len(), chain_a_tip, chain_a_td);
    println!("│   In-turn: {}, Out-of-turn: {} (during partition)           │",
             fork_a_in_turn, fork_a_out_turn);
    println!("│   Tip: {}                              │", &format!("{:?}", chain_a_hash)[..42]);
    println!("├─────────────────────────────────────────────────────────────┤");
    println!("│ Fork B (V2):                                                │");
    println!("│   Length: {} blocks, Tip slot: {}, TD: {:>4}                 │",
             nodes[2].chain.len(), chain_b_tip, chain_b_td);
    println!("│   In-turn: {}, Out-of-turn: {} (during partition)          │",
             fork_b_in_turn, fork_b_out_turn);
    println!("│   Tip: {}                              │", &format!("{:?}", chain_b_hash)[..42]);
    println!("└─────────────────────────────────────────────────────────────┘\n");

    // ========================================
    // Phase 3: Partition Heals - Fork Resolution
    // ========================================
    println!("═══════════════════════════════════════════════════════════════");
    println!(" Phase 3: Partition Heals - Fork Resolution");
    println!("═══════════════════════════════════════════════════════════════\n");

    // Determine winner BEFORE reorg
    let winner_before = if chain_a_td > chain_b_td {
        "Fork A"
    } else if chain_b_td > chain_a_td {
        "Fork B"
    } else {
        if chain_a_hash < chain_b_hash { "Fork A" } else { "Fork B" }
    };

    println!("Predicted winner (by TD): {} (TD={})\n",
             winner_before,
             if winner_before == "Fork A" { chain_a_td } else { chain_b_td });

    // Try reorg on all nodes
    println!("Attempting fork resolution...");

    // V0 and V1 see Fork B
    let reorg_v0 = nodes[0].try_reorg(&partition_b_blocks);
    let reorg_v1 = nodes[1].try_reorg(&partition_b_blocks);

    // V2 sees Fork A
    let reorg_v2 = nodes[2].try_reorg(&partition_a_blocks);

    println!("  V0 reorg to Fork B: {}", if reorg_v0 { "YES" } else { "NO" });
    println!("  V1 reorg to Fork B: {}", if reorg_v1 { "YES" } else { "NO" });
    println!("  V2 reorg to Fork A: {}", if reorg_v2 { "YES" } else { "NO" });

    println!("\nFinal chain status after merge:");
    for node in &nodes {
        node.print_status("  ");
    }

    // ========================================
    // Results
    // ========================================
    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║                      TEST RESULTS                            ║");
    println!("╠══════════════════════════════════════════════════════════════╣");

    let final_heads: Vec<B256> = nodes.iter()
        .map(|n| n.chain_tip().map(|b| b.block_root()).unwrap_or_default())
        .collect();
    let all_converged = final_heads.windows(2).all(|w| w[0] == w[1]);

    let final_td = nodes[0].total_difficulty();
    let final_winner = if nodes[0].chain_tip().unwrap().block_root() == chain_a_hash {
        "Fork A"
    } else {
        "Fork B"
    };

    println!("║ Winner: {:>7} (TD: {:>4})                                  ║", final_winner, final_td);
    println!("║ Convergence: {:>3}                                           ║",
             if all_converged { "YES" } else { "NO" });
    println!("║ Fork depth: {} blocks                                       ║", partition_slots);
    println!("╚══════════════════════════════════════════════════════════════╝\n");

    if all_converged {
        println!("✓ SUCCESS: All nodes converged to the same canonical chain!");
        println!("  Final head: {}", &format!("{:?}", final_heads[0])[..42]);
    } else {
        println!("✗ FAILURE: Nodes have different canonical heads!");
        for (i, hash) in final_heads.iter().enumerate() {
            println!("  V{}: {}", i, &format!("{:?}", hash)[..42]);
        }
    }

    // Print detailed block-by-block comparison
    println!("\n═══════════════════════════════════════════════════════════════");
    println!(" Detailed Fork Comparison (partition period)");
    println!("═══════════════════════════════════════════════════════════════\n");

    println!("Slot | Fork A (V0+V1)                    | Fork B (V2)");
    println!("-----+-----------------------------------+----------------------------------");

    for slot in partition_start..=partition_end.min(partition_start + 14) {
        let a_block = partition_a_blocks.iter()
            .find(|b| b.slot() == slot);
        let b_block = partition_b_blocks.iter()
            .find(|b| b.slot() == slot);

        let a_str = a_block
            .map(|b| format!("diff={} {}", b.message.difficulty, &format!("{:?}", b.block_root())[..10]))
            .unwrap_or_else(|| "---".to_string());

        let b_str = b_block
            .map(|b| format!("diff={} {}", b.message.difficulty, &format!("{:?}", b.block_root())[..10]))
            .unwrap_or_else(|| "---".to_string());

        println!("{:>4} | {:>33} | {:>32}", slot, a_str, b_str);
    }

    if partition_slots > 15 {
        println!(" ... | ... ({} more slots) ...         | ...", partition_slots - 15);
    }

    println!("\n=== Fork Scenario Test Complete ===\n");
}
