//! POA Consensus Demo
//!
//! This demo simulates 3 validators running POA consensus with:
//! - Round-robin block production (8 second intervals)
//! - In-turn difficulty = 2, out-of-turn difficulty = 1
//! - Longest chain + highest difficulty fork choice
//!
//! Run with: `cargo run -p example-custom-node-types --bin poa_demo`

use alloy_primitives::{Address, B256};
use n42_node::{
    get_difficulty_from_graffiti, BeaconBlock, BeaconBlockBody, PoaConfig, PoaValidationError,
    PoaValidator, SignedBeaconBlock, DIFFICULTY_IN_TURN, DIFFICULTY_OUT_OF_TURN,
};
use std::time::Duration;

/// Simulated validator node
struct ValidatorNode {
    /// Validator address (coinbase)
    address: Address,
    /// Node index (for display)
    index: usize,
    /// POA validator for block validation
    validator: PoaValidator,
    /// Local chain (blocks)
    chain: Vec<SignedBeaconBlock>,
    /// Last produced slot (avoid double production)
    last_produced_slot: Option<u64>,
}

impl ValidatorNode {
    fn new(index: usize, address: Address, config: PoaConfig) -> Self {
        Self {
            address,
            index,
            validator: PoaValidator::new(config),
            chain: Vec::new(),
            last_produced_slot: None,
        }
    }

    /// Check if this node is the in-turn validator for the slot
    fn is_in_turn(&self, slot: u64) -> bool {
        self.validator.config().is_in_turn(slot, self.address)
    }

    /// Get expected difficulty for this node at given slot
    fn get_difficulty(&self, slot: u64) -> u64 {
        self.validator.config().expected_difficulty(slot, self.address)
    }

    /// Try to produce a block for the given slot
    fn produce_block(&mut self, slot: u64) -> Option<SignedBeaconBlock> {
        // Don't produce twice for same slot
        if self.last_produced_slot == Some(slot) {
            return None;
        }

        // Check slot is ahead of our chain tip
        let parent_slot = self.chain.last().map(|b| b.slot()).unwrap_or(0);
        if slot <= parent_slot && !self.chain.is_empty() {
            return None;
        }

        let parent_root = self
            .chain
            .last()
            .map(|b| b.block_root())
            .unwrap_or(B256::ZERO);

        let difficulty = self.get_difficulty(slot);
        let proposer_index = self.index as u64;

        // Build block with difficulty in graffiti
        let mut graffiti = B256::ZERO;
        n42_node::set_difficulty_in_graffiti(&mut graffiti, difficulty);

        let body = BeaconBlockBody {
            graffiti,
            ..Default::default()
        };

        let block = BeaconBlock::new(slot, proposer_index, parent_root, B256::ZERO, body, difficulty);

        // Create signed block (placeholder signature with validator address)
        let mut sig = vec![0u8; 96];
        sig[..20].copy_from_slice(self.address.as_slice());
        let signed = SignedBeaconBlock::new(block, sig.into());

        self.last_produced_slot = Some(slot);

        Some(signed)
    }

    /// Validate and potentially accept a new block
    fn receive_block(&mut self, block: &SignedBeaconBlock) -> Result<bool, PoaValidationError> {
        let parent = self.chain.last();

        // Validate the block
        self.validator.validate_block(block, parent)?;

        // Check if this block extends our chain
        let block_slot = block.slot();
        let our_tip_slot = self.chain.last().map(|b| b.slot()).unwrap_or(0);

        if block_slot > our_tip_slot {
            // Block extends our chain
            self.chain.push(block.clone());
            Ok(true)
        } else {
            // Block doesn't extend (fork or old)
            Ok(false)
        }
    }

    /// Get total difficulty of our chain
    fn total_difficulty(&self) -> u64 {
        self.validator.calculate_total_difficulty(&self.chain)
    }

    /// Print chain status
    fn print_status(&self) {
        let tip_slot = self.chain.last().map(|b| b.slot()).unwrap_or(0);
        let td = self.total_difficulty();
        println!(
            "  Node {} ({}): chain length={}, tip_slot={}, total_difficulty={}",
            self.index,
            &format!("{:?}", self.address)[..10],
            self.chain.len(),
            tip_slot,
            td
        );
    }
}

fn main() {
    println!("=== POA Consensus Demo ===\n");

    // Create 3 validators
    let validators = vec![
        Address::repeat_byte(0x01),
        Address::repeat_byte(0x02),
        Address::repeat_byte(0x03),
    ];

    println!("Validators:");
    for (i, v) in validators.iter().enumerate() {
        println!("  V{}: {:?}", i, v);
    }
    println!();

    // POA config: 3 validators, 1 second block time (for faster demo)
    let config = PoaConfig::new(validators.clone(), 1);

    println!("POA Configuration:");
    println!("  Block time: {} second", config.block_time);
    println!("  In-turn difficulty: {}", DIFFICULTY_IN_TURN);
    println!("  Out-of-turn difficulty: {}", DIFFICULTY_OUT_OF_TURN);
    println!();

    // Create validator nodes
    let mut nodes: Vec<ValidatorNode> = validators
        .iter()
        .enumerate()
        .map(|(i, &addr)| ValidatorNode::new(i, addr, config.clone()))
        .collect();

    println!("=== Starting Consensus Simulation ===\n");
    println!("Simulating 10 slots with round-robin block production...\n");

    // Simulate 10 slots
    for slot in 1..=10 {
        println!("--- Slot {} ---", slot);

        // Determine who is in-turn
        let in_turn_idx = (slot as usize) % validators.len();
        println!(
            "In-turn validator: V{} ({})",
            in_turn_idx,
            &format!("{:?}", validators[in_turn_idx])[..10]
        );

        // Simulate block production
        // In real POA: in-turn produces immediately, others wait then may produce if in-turn fails

        // Scenario: in-turn validator produces (normal case)
        let block = nodes[in_turn_idx].produce_block(slot);

        if let Some(ref b) = block {
            let difficulty = get_difficulty_from_graffiti(&b.message.body.graffiti);
            println!(
                "V{} produced block: slot={}, difficulty={} (in-turn={})",
                in_turn_idx,
                b.slot(),
                difficulty,
                nodes[in_turn_idx].is_in_turn(slot)
            );

            // Broadcast to all nodes (including self)
            for (i, node) in nodes.iter_mut().enumerate() {
                match node.receive_block(b) {
                    Ok(accepted) => {
                        if accepted {
                            println!("  V{}: accepted block", i);
                        }
                    }
                    Err(e) => {
                        println!("  V{}: rejected block - {}", i, e);
                    }
                }
            }
        }

        // Print chain status
        println!("\nChain Status:");
        for node in &nodes {
            node.print_status();
        }
        println!();

        // Small delay for readability
        std::thread::sleep(Duration::from_millis(200));
    }

    println!("=== Fork Scenario Demo ===\n");
    println!("Simulating a fork where V1 misses slot 11, V2 produces out-of-turn...\n");

    // Reset chains for fork demo
    for node in &mut nodes {
        node.chain.clear();
        node.last_produced_slot = None;
    }

    // Build a common prefix (slots 1-10)
    for slot in 1..=10 {
        let in_turn_idx = (slot as usize) % validators.len();
        if let Some(block) = nodes[in_turn_idx].produce_block(slot) {
            for node in &mut nodes {
                let _ = node.receive_block(&block);
            }
        }
    }

    println!("Common prefix built (slots 1-10)");
    println!("Chain status:");
    for node in &nodes {
        node.print_status();
    }
    println!();

    // Fork scenario: V2 (in-turn for slot 11) doesn't produce
    // V0 produces out-of-turn
    println!("--- Slot 11 (Fork) ---");
    println!("V2 is in-turn but fails to produce...");
    println!("V0 produces out-of-turn block\n");

    // V0 produces out-of-turn for slot 11
    if let Some(block) = nodes[0].produce_block(11) {
        let difficulty = get_difficulty_from_graffiti(&block.message.body.graffiti);
        println!(
            "V0 produced: slot=11, difficulty={} (out-of-turn)",
            difficulty
        );

        // Only V0 and V1 receive this block (network partition)
        for i in 0..2 {
            match nodes[i].receive_block(&block) {
                Ok(accepted) => {
                    if accepted {
                        println!("  V{}: accepted block", i);
                    }
                }
                Err(e) => println!("  V{}: rejected - {}", i, e),
            }
        }
    }

    println!();

    // Meanwhile V2 finally produces (late)
    println!("V2 finally produces in-turn block for slot 11...\n");

    // Create V2's in-turn block manually
    let parent_root = nodes[2].chain.last().unwrap().block_root();
    let mut graffiti = B256::ZERO;
    n42_node::set_difficulty_in_graffiti(&mut graffiti, DIFFICULTY_IN_TURN);

    let v2_block = SignedBeaconBlock::new(
        BeaconBlock::new(
            11,
            2,
            parent_root,
            B256::ZERO,
            BeaconBlockBody {
                graffiti,
                ..Default::default()
            },
            DIFFICULTY_IN_TURN,
        ),
        vec![0u8; 96].into(),
    );

    println!(
        "V2 produced: slot=11, difficulty={} (in-turn)",
        DIFFICULTY_IN_TURN
    );

    // V2 accepts its own block
    let _ = nodes[2].receive_block(&v2_block);
    println!("  V2: accepted block");

    println!("\nFork created!");
    println!("Chain A (V0, V1): 11 blocks, last slot=11, out-of-turn");
    println!("Chain B (V2): 11 blocks, last slot=11, in-turn");
    println!();

    // Compare chains
    println!("Chain comparison:");
    let chain_a = &nodes[0].chain;
    let chain_b = &nodes[2].chain;

    let td_a = nodes[0].total_difficulty();
    let td_b = nodes[2].total_difficulty();

    println!("  Chain A: length={}, total_difficulty={}", chain_a.len(), td_a);
    println!("  Chain B: length={}, total_difficulty={}", chain_b.len(), td_b);

    // Fork choice: same length, higher TD wins
    if chain_a.len() == chain_b.len() {
        if td_a > td_b {
            println!("\n  Result: Chain A wins (same length, higher TD)");
        } else if td_b > td_a {
            println!("\n  Result: Chain B wins (same length, higher TD)");
        } else {
            println!("\n  Result: Tie (needs tie-breaker)");
        }
    } else if chain_a.len() > chain_b.len() {
        println!("\n  Result: Chain A wins (longer chain)");
    } else {
        println!("\n  Result: Chain B wins (longer chain)");
    }

    println!();
    println!("=== Demo Complete ===");
    println!("\nPOA consensus rules demonstrated:");
    println!("1. Round-robin validator selection (slot % num_validators)");
    println!("2. In-turn validators produce with difficulty=2");
    println!("3. Out-of-turn validators produce with difficulty=1");
    println!("4. Fork choice: longest chain wins, ties broken by total difficulty");
}
