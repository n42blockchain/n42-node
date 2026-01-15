//! POA block production worker.
//!
//! This module implements the block production logic for POA consensus.
//! The worker monitors the current time, calculates slots, and produces
//! blocks when it's this node's turn.

use super::{PoaConfig, DIFFICULTY_IN_TURN, DIFFICULTY_OUT_OF_TURN};
use crate::primitives::{BeaconBlock, BeaconBlockBody, Eth1Data, SignedBeaconBlock};
use alloy_primitives::{Address, Bytes, B256};
use reth_tracing::tracing::{debug, info, trace};
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::mpsc;

/// Configuration for the POA worker.
#[derive(Debug, Clone)]
pub struct PoaWorkerConfig {
    /// POA consensus configuration.
    pub poa_config: PoaConfig,
    /// Genesis time (UNIX timestamp).
    pub genesis_time: u64,
    /// Delay before producing out-of-turn blocks (allows in-turn validator to produce first).
    pub out_of_turn_delay: Duration,
}

impl PoaWorkerConfig {
    /// Create a new worker configuration.
    pub fn new(poa_config: PoaConfig, genesis_time: u64) -> Self {
        // Get block_time before moving poa_config
        let out_of_turn_delay = Duration::from_secs(poa_config.block_time / 2);
        Self {
            poa_config,
            genesis_time,
            // Out-of-turn validators wait half a block time before producing
            out_of_turn_delay,
        }
    }

    /// Set custom out-of-turn delay.
    pub fn with_out_of_turn_delay(mut self, delay: Duration) -> Self {
        self.out_of_turn_delay = delay;
        self
    }
}

/// Events emitted by the POA worker.
#[derive(Debug, Clone)]
pub enum PoaWorkerEvent {
    /// A new beacon block was produced.
    NewBlock(Arc<SignedBeaconBlock>),
    /// Slot changed.
    SlotChange {
        /// Previous slot number.
        old_slot: u64,
        /// New slot number.
        new_slot: u64,
    },
    /// Worker started.
    Started,
    /// Worker stopped.
    Stopped,
}

/// Commands that can be sent to the POA worker.
#[derive(Debug, Clone)]
pub enum PoaWorkerCommand {
    /// Stop the worker.
    Stop,
    /// Update the parent block for the next production.
    UpdateParent(Arc<SignedBeaconBlock>),
    /// Update execution payload root for next block.
    SetExecutionPayloadRoot(B256),
}

/// POA block production worker.
///
/// Produces beacon blocks at regular intervals when it's this node's turn.
///
/// # Block Production Logic
///
/// ```text
/// ┌────────────────────────────────────────────────────────────┐
/// │                 POA Worker Flow                            │
/// ├────────────────────────────────────────────────────────────┤
/// │                                                            │
/// │  1. Calculate current slot from time                       │
/// │     slot = (current_time - genesis_time) / block_time      │
/// │                                                            │
/// │  2. Check if we should produce                             │
/// │     - In-turn: produce immediately                         │
/// │     - Out-of-turn: wait out_of_turn_delay first            │
/// │                                                            │
/// │  3. Build beacon block                                     │
/// │     - Set slot, proposer_index                             │
/// │     - Set parent_root from last known block                │
/// │     - Set difficulty in graffiti field                     │
/// │     - Sign with placeholder signature                      │
/// │                                                            │
/// │  4. Emit NewBlock event                                    │
/// │                                                            │
/// └────────────────────────────────────────────────────────────┘
/// ```
#[derive(Debug)]
pub struct PoaWorker {
    /// Worker configuration.
    config: PoaWorkerConfig,
    /// Current parent block root.
    parent_root: B256,
    /// Current parent slot.
    parent_slot: u64,
    /// Execution payload root for next block.
    execution_payload_root: B256,
    /// Last produced slot (to avoid double production).
    last_produced_slot: Option<u64>,
}

impl PoaWorker {
    /// Create a new POA worker.
    pub fn new(config: PoaWorkerConfig) -> Self {
        Self {
            config,
            parent_root: B256::ZERO,
            parent_slot: 0,
            execution_payload_root: B256::ZERO,
            last_produced_slot: None,
        }
    }

    /// Set the initial parent block.
    pub fn with_parent(mut self, parent: &SignedBeaconBlock) -> Self {
        self.parent_root = parent.block_root();
        self.parent_slot = parent.slot();
        self
    }

    /// Get the current slot based on time.
    pub fn current_slot(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if now < self.config.genesis_time {
            return 0;
        }

        (now - self.config.genesis_time) / self.config.poa_config.block_time
    }

    /// Get the time until the next slot starts.
    pub fn time_until_next_slot(&self) -> Duration {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if now < self.config.genesis_time {
            return Duration::from_secs(self.config.genesis_time - now);
        }

        let elapsed_in_slot = (now - self.config.genesis_time) % self.config.poa_config.block_time;
        Duration::from_secs(self.config.poa_config.block_time - elapsed_in_slot)
    }

    /// Check if this node should produce a block for the given slot.
    pub fn should_produce(&self, slot: u64) -> bool {
        // Check if we have a coinbase configured
        let Some(coinbase) = self.config.poa_config.coinbase else {
            return false;
        };

        // Check if coinbase is a validator
        if !self.config.poa_config.validators.contains(&coinbase) {
            return false;
        }

        // Check if we already produced for this slot
        if self.last_produced_slot == Some(slot) {
            return false;
        }

        // Slot must be greater than parent slot
        if slot <= self.parent_slot {
            return false;
        }

        true
    }

    /// Check if we are the in-turn validator for the slot.
    pub fn is_in_turn(&self, slot: u64) -> bool {
        let Some(coinbase) = self.config.poa_config.coinbase else {
            return false;
        };
        self.config.poa_config.is_in_turn(slot, coinbase)
    }

    /// Update the parent block.
    pub fn update_parent(&mut self, parent: &SignedBeaconBlock) {
        let new_slot = parent.slot();
        // Only update if the new block is ahead
        if new_slot > self.parent_slot {
            self.parent_root = parent.block_root();
            self.parent_slot = new_slot;
            debug!(target: "poa::worker", slot = new_slot, root = ?self.parent_root, "Updated parent block");
        }
    }

    /// Set the execution payload root for the next block.
    pub fn set_execution_payload_root(&mut self, root: B256) {
        self.execution_payload_root = root;
    }

    /// Build a new beacon block for the given slot.
    pub fn build_block(&mut self, slot: u64) -> Option<SignedBeaconBlock> {
        if !self.should_produce(slot) {
            return None;
        }

        let coinbase = self.config.poa_config.coinbase?;
        let proposer_index = self.config.poa_config.validators.index_of(&coinbase)? as u64;

        // Determine difficulty based on in-turn status
        let difficulty = if self.is_in_turn(slot) {
            DIFFICULTY_IN_TURN
        } else {
            DIFFICULTY_OUT_OF_TURN
        };

        // Build graffiti with difficulty
        let mut graffiti = B256::ZERO;
        super::validator::set_difficulty_in_graffiti(&mut graffiti, difficulty);

        let body = BeaconBlockBody {
            randao_reveal: Bytes::default(),
            eth1_data: Eth1Data::default(),
            graffiti,
            execution_payload_root: self.execution_payload_root,
        };

        let block = BeaconBlock::new_without_difficulty(slot, proposer_index, self.parent_root, B256::ZERO, body);

        // Create signature placeholder (in production, this would be a real BLS signature)
        let signature = create_placeholder_signature(&coinbase);

        let signed_block = SignedBeaconBlock::new(block, signature);

        // Update state
        self.last_produced_slot = Some(slot);
        self.parent_root = signed_block.block_root();
        self.parent_slot = slot;

        info!(
            target: "poa::worker",
            slot,
            proposer = ?coinbase,
            in_turn = self.is_in_turn(slot),
            difficulty,
            block_root = ?self.parent_root,
            "Produced new beacon block"
        );

        Some(signed_block)
    }

    /// Run the worker loop.
    ///
    /// This spawns a task that continuously monitors slots and produces blocks.
    pub async fn run(
        mut self,
        mut cmd_rx: mpsc::Receiver<PoaWorkerCommand>,
        event_tx: mpsc::Sender<PoaWorkerEvent>,
    ) {
        info!(target: "poa::worker", "Starting POA worker");
        let _ = event_tx.send(PoaWorkerEvent::Started).await;

        let mut current_slot = self.current_slot();

        loop {
            // Check for commands
            tokio::select! {
                biased;

                cmd = cmd_rx.recv() => {
                    match cmd {
                        Some(PoaWorkerCommand::Stop) | None => {
                            info!(target: "poa::worker", "Stopping POA worker");
                            let _ = event_tx.send(PoaWorkerEvent::Stopped).await;
                            return;
                        }
                        Some(PoaWorkerCommand::UpdateParent(parent)) => {
                            self.update_parent(&parent);
                        }
                        Some(PoaWorkerCommand::SetExecutionPayloadRoot(root)) => {
                            self.set_execution_payload_root(root);
                        }
                    }
                }

                _ = tokio::time::sleep(Duration::from_millis(100)) => {
                    let new_slot = self.current_slot();

                    // Slot changed
                    if new_slot > current_slot {
                        trace!(target: "poa::worker", old_slot = current_slot, new_slot, "Slot changed");
                        let _ = event_tx.send(PoaWorkerEvent::SlotChange {
                            old_slot: current_slot,
                            new_slot,
                        }).await;

                        current_slot = new_slot;

                        // Try to produce block
                        if self.should_produce(current_slot) {
                            let is_in_turn = self.is_in_turn(current_slot);

                            // Out-of-turn validators wait before producing
                            if !is_in_turn {
                                debug!(
                                    target: "poa::worker",
                                    slot = current_slot,
                                    delay = ?self.config.out_of_turn_delay,
                                    "Out-of-turn, waiting before producing"
                                );
                                tokio::time::sleep(self.config.out_of_turn_delay).await;

                                // Re-check if we should still produce (parent might have been updated)
                                if !self.should_produce(current_slot) {
                                    debug!(target: "poa::worker", "Skipping production, parent was updated");
                                    continue;
                                }
                            }

                            if let Some(block) = self.build_block(current_slot) {
                                let _ = event_tx.send(PoaWorkerEvent::NewBlock(Arc::new(block))).await;
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Create a placeholder signature for demo purposes.
///
/// In production, this would create a real BLS signature.
fn create_placeholder_signature(proposer: &Address) -> Bytes {
    // 96 bytes for BLS signature, include proposer address for identification
    let mut sig = vec![0u8; 96];
    sig[..20].copy_from_slice(proposer.as_slice());
    Bytes::from(sig)
}

/// Builder for creating and starting a POA worker.
#[derive(Debug)]
pub struct PoaWorkerBuilder {
    config: PoaWorkerConfig,
    parent: Option<SignedBeaconBlock>,
    execution_payload_root: Option<B256>,
}

impl PoaWorkerBuilder {
    /// Create a new worker builder.
    pub fn new(config: PoaWorkerConfig) -> Self {
        Self { config, parent: None, execution_payload_root: None }
    }

    /// Set the initial parent block.
    pub fn with_parent(mut self, parent: SignedBeaconBlock) -> Self {
        self.parent = Some(parent);
        self
    }

    /// Set the initial execution payload root.
    pub fn with_execution_payload_root(mut self, root: B256) -> Self {
        self.execution_payload_root = Some(root);
        self
    }

    /// Build and return the worker along with command/event channels.
    pub fn build(self) -> (PoaWorkerHandle, mpsc::Receiver<PoaWorkerEvent>) {
        let (cmd_tx, cmd_rx) = mpsc::channel(16);
        let (event_tx, event_rx) = mpsc::channel(64);

        let mut worker = PoaWorker::new(self.config);

        if let Some(parent) = &self.parent {
            worker = worker.with_parent(parent);
        }

        if let Some(root) = self.execution_payload_root {
            worker.set_execution_payload_root(root);
        }

        // Spawn the worker task
        tokio::spawn(async move {
            worker.run(cmd_rx, event_tx).await;
        });

        (PoaWorkerHandle { cmd_tx }, event_rx)
    }

    /// Start the worker and return handles for interaction.
    pub fn start(
        self,
    ) -> (PoaWorkerHandle, mpsc::Receiver<PoaWorkerEvent>) {
        let (cmd_tx, cmd_rx) = mpsc::channel(16);
        let (event_tx, event_rx) = mpsc::channel(64);

        let mut worker = PoaWorker::new(self.config);

        if let Some(parent) = &self.parent {
            worker = worker.with_parent(parent);
        }

        if let Some(root) = self.execution_payload_root {
            worker.set_execution_payload_root(root);
        }

        // Spawn the worker task
        tokio::spawn(async move {
            worker.run(cmd_rx, event_tx).await;
        });

        (PoaWorkerHandle { cmd_tx }, event_rx)
    }
}

/// Handle for interacting with a running POA worker.
#[derive(Debug, Clone)]
pub struct PoaWorkerHandle {
    cmd_tx: mpsc::Sender<PoaWorkerCommand>,
}

impl PoaWorkerHandle {
    /// Stop the worker.
    pub async fn stop(&self) -> Result<(), mpsc::error::SendError<PoaWorkerCommand>> {
        self.cmd_tx.send(PoaWorkerCommand::Stop).await
    }

    /// Update the parent block.
    pub async fn update_parent(
        &self,
        parent: Arc<SignedBeaconBlock>,
    ) -> Result<(), mpsc::error::SendError<PoaWorkerCommand>> {
        self.cmd_tx.send(PoaWorkerCommand::UpdateParent(parent)).await
    }

    /// Set execution payload root.
    pub async fn set_execution_payload_root(
        &self,
        root: B256,
    ) -> Result<(), mpsc::error::SendError<PoaWorkerCommand>> {
        self.cmd_tx.send(PoaWorkerCommand::SetExecutionPayloadRoot(root)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> PoaWorkerConfig {
        let poa_config = PoaConfig::new(
            vec![
                Address::repeat_byte(0x01),
                Address::repeat_byte(0x02),
                Address::repeat_byte(0x03),
            ],
            2, // 2 second block time for faster tests
        )
        .with_coinbase(Address::repeat_byte(0x01));

        // Set genesis time to now
        let genesis_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        PoaWorkerConfig::new(poa_config, genesis_time)
    }

    #[test]
    fn test_slot_calculation() {
        let mut config = test_config();
        // Set genesis to 10 seconds ago
        config.genesis_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 10;

        let worker = PoaWorker::new(config.clone());
        let slot = worker.current_slot();

        // With 2 second blocks and 10 seconds elapsed, we should be at slot 5
        assert!(slot >= 4 && slot <= 6, "Expected slot around 5, got {}", slot);
    }

    #[test]
    fn test_should_produce() {
        let config = test_config();
        let worker = PoaWorker::new(config);

        // Worker should produce for slot 0 (greater than parent_slot which is 0 initially? no, 0 <= 0)
        // Actually slot must be > parent_slot (which is 0), so slot 1 should work
        assert!(!worker.should_produce(0)); // 0 <= 0
        assert!(worker.should_produce(1)); // 1 > 0
    }

    #[test]
    fn test_is_in_turn() {
        let config = test_config();
        let worker = PoaWorker::new(config);

        // Validator 0x01 is coinbase
        // Slot 0 -> validator[0] = 0x01 (in-turn)
        // Slot 1 -> validator[1] = 0x02 (out-of-turn for 0x01)
        // Slot 2 -> validator[2] = 0x03 (out-of-turn for 0x01)
        // Slot 3 -> validator[0] = 0x01 (in-turn again)
        assert!(worker.is_in_turn(0));
        assert!(!worker.is_in_turn(1));
        assert!(!worker.is_in_turn(2));
        assert!(worker.is_in_turn(3));
    }

    #[test]
    fn test_build_block_in_turn() {
        let config = test_config();
        let mut worker = PoaWorker::new(config);

        // Build block for slot 3 (in-turn for validator 0x01)
        // But first we need parent_slot < 3
        worker.parent_slot = 2;

        let block = worker.build_block(3).expect("Should produce block");

        assert_eq!(block.slot(), 3);
        assert_eq!(block.message.proposer_index, 0); // First validator

        // Check difficulty in graffiti
        let difficulty =
            super::super::validator::get_difficulty_from_graffiti(&block.message.body.graffiti);
        assert_eq!(difficulty, DIFFICULTY_IN_TURN);
    }

    #[test]
    fn test_build_block_out_of_turn() {
        let config = test_config();
        let mut worker = PoaWorker::new(config);

        // Build block for slot 1 (out-of-turn for validator 0x01)
        let block = worker.build_block(1).expect("Should produce block");

        assert_eq!(block.slot(), 1);

        // Check difficulty in graffiti
        let difficulty =
            super::super::validator::get_difficulty_from_graffiti(&block.message.body.graffiti);
        assert_eq!(difficulty, DIFFICULTY_OUT_OF_TURN);
    }

    #[test]
    fn test_no_double_production() {
        let config = test_config();
        let mut worker = PoaWorker::new(config);

        // Build first block
        let block1 = worker.build_block(1);
        assert!(block1.is_some());

        // Try to build again for same slot
        let block2 = worker.build_block(1);
        assert!(block2.is_none(), "Should not produce twice for same slot");
    }

    #[test]
    fn test_update_parent() {
        let config = test_config();
        let mut worker = PoaWorker::new(config);

        // Create a parent block
        let parent_block = SignedBeaconBlock::new(
            BeaconBlock::new_without_difficulty(5, 0, B256::ZERO, B256::ZERO, BeaconBlockBody::default()),
            Bytes::from_static(&[0; 96]),
        );

        worker.update_parent(&parent_block);

        assert_eq!(worker.parent_slot, 5);
        assert_eq!(worker.parent_root, parent_block.block_root());
    }

    #[tokio::test]
    async fn test_worker_handle() {
        let config = test_config();
        let builder = PoaWorkerBuilder::new(config);

        let (handle, mut event_rx) = builder.start();

        // Wait for started event
        let event = tokio::time::timeout(Duration::from_secs(1), event_rx.recv())
            .await
            .expect("Timeout waiting for event")
            .expect("Channel closed");

        assert!(matches!(event, PoaWorkerEvent::Started));

        // Stop the worker
        handle.stop().await.expect("Failed to send stop command");

        // Wait for stopped event
        let event = tokio::time::timeout(Duration::from_secs(1), event_rx.recv())
            .await
            .expect("Timeout waiting for event")
            .expect("Channel closed");

        assert!(matches!(event, PoaWorkerEvent::Stopped));
    }
}
