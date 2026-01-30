//! Miner Worker Module
//!
//! This module implements the main mining worker that orchestrates block production
//! for Clique POA consensus.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    Worker::run()                             │
//! │                                                              │
//! │  ┌─────────────┐  ┌───────────────┐  ┌──────────────┐       │
//! │  │ cmd_rx      │  │recommit_timer │  │ seal_timer   │       │
//! │  │ (commands)  │  │(rebuild payload)│  │(sign block) │       │
//! │  └──────┬──────┘  └───────┬───────┘  └──────┬───────┘       │
//! │         │                 │                  │               │
//! │         └────────────┬────┴──────────────────┘               │
//! │                      ↓                                       │
//! │  ┌─────────────────────────────────────────────────┐        │
//! │  │ tokio::select! {                                │        │
//! │  │   cmd => handle_command(),                      │        │
//! │  │   recommit_tick => rebuild_payload(),           │        │
//! │  │   seal_time => seal_and_broadcast(),            │        │
//! │  │ }                                               │        │
//! │  └─────────────────────────────────────────────────┘        │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Workflow
//!
//! 1. Receive `StartMining` command with parent block and timestamp
//! 2. Build initial payload using `PayloadBuilder`
//! 3. Schedule recommit timer (default: 2 seconds)
//! 4. Calculate seal delay (in-turn: 0, out-of-turn: wiggle)
//! 5. When seal timer fires, sign and emit block

use super::attributes::PayloadAttributesProvider;
use super::config::MinerConfig;
use super::error::{MinerError, MinerResult};
use super::sealer::{calculate_seal_delay, seal_block, MiningEnvironment};
use crate::primitives::{BeaconBlock, BeaconBlockBody, SignedBeaconBlock};
use alloy_primitives::B256;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::time::interval;
use reth_tracing::tracing;

/// Commands sent to the miner worker.
#[derive(Debug, Clone)]
pub enum MinerCommand {
    /// Start mining on top of the given parent block.
    StartMining {
        /// Parent block to build on.
        parent: SignedBeaconBlock,
        /// Target slot for the new block.
        slot: u64,
        /// Whether this miner is in-turn for this slot.
        in_turn: bool,
        /// Total number of validators.
        num_validators: usize,
    },

    /// Stop current mining operation.
    Stop,

    /// Update the chain head (may cancel current mining if parent changed).
    UpdateHead(SignedBeaconBlock),

    /// Trigger manual recommit.
    Recommit,
}

/// Events emitted by the miner worker.
#[derive(Debug, Clone)]
pub enum MinerEvent {
    /// Block has been sealed and is ready for broadcast.
    BlockSealed(SealResult),

    /// Mining has started for a slot.
    MiningStarted {
        /// Slot being mined.
        slot: u64,
        /// Whether in-turn.
        in_turn: bool,
    },

    /// Mining was cancelled.
    MiningCancelled {
        /// Reason for cancellation.
        reason: String,
    },

    /// Error occurred during mining.
    Error(String),
}

/// Result of sealing a block.
#[derive(Debug, Clone)]
pub struct SealResult {
    /// The sealed block.
    pub block: SignedBeaconBlock,
    /// Block hash.
    pub hash: B256,
    /// Seal latency (time from start to seal).
    pub seal_latency: Duration,
}

/// Handle for sending commands to the miner worker.
#[derive(Clone)]
pub struct MinerHandle {
    cmd_tx: mpsc::Sender<MinerCommand>,
}

impl MinerHandle {
    /// Start mining on top of the given parent block.
    pub async fn start_mining(
        &self,
        parent: SignedBeaconBlock,
        slot: u64,
        in_turn: bool,
        num_validators: usize,
    ) -> MinerResult<()> {
        self.cmd_tx
            .send(MinerCommand::StartMining {
                parent,
                slot,
                in_turn,
                num_validators,
            })
            .await
            .map_err(|e| MinerError::ChannelError(e.to_string()))
    }

    /// Stop current mining operation.
    pub async fn stop(&self) -> MinerResult<()> {
        self.cmd_tx
            .send(MinerCommand::Stop)
            .await
            .map_err(|e| MinerError::ChannelError(e.to_string()))
    }

    /// Update the chain head.
    pub async fn update_head(&self, block: SignedBeaconBlock) -> MinerResult<()> {
        self.cmd_tx
            .send(MinerCommand::UpdateHead(block))
            .await
            .map_err(|e| MinerError::ChannelError(e.to_string()))
    }

    /// Trigger manual recommit.
    pub async fn recommit(&self) -> MinerResult<()> {
        self.cmd_tx
            .send(MinerCommand::Recommit)
            .await
            .map_err(|e| MinerError::ChannelError(e.to_string()))
    }
}

/// Current mining state.
#[derive(Debug)]
struct MiningState {
    /// Parent block we're building on.
    parent: SignedBeaconBlock,
    /// Target slot.
    slot: u64,
    /// Whether in-turn.
    in_turn: bool,
    /// Number of validators.
    num_validators: usize,
    /// Current payload (block body).
    payload: BeaconBlockBody,
    /// Time mining started.
    started_at: Instant,
    /// Scheduled seal time.
    seal_at: Instant,
}

/// Miner worker that runs the main mining loop.
pub struct Worker<A: PayloadAttributesProvider> {
    /// Miner configuration.
    config: MinerConfig,

    /// Payload attributes provider.
    attributes: Arc<A>,

    /// Current mining state (if mining).
    state: Option<MiningState>,

    /// Command receiver.
    cmd_rx: mpsc::Receiver<MinerCommand>,

    /// Event sender.
    event_tx: mpsc::Sender<MinerEvent>,

    /// Proposer index (our position in validator list).
    proposer_index: u64,
}

impl<A: PayloadAttributesProvider + 'static> Worker<A> {
    /// Create a new miner worker and return its handle.
    ///
    /// # Arguments
    /// * `config` - Miner configuration
    /// * `attributes` - Payload attributes provider
    /// * `proposer_index` - Our index in the validator list
    ///
    /// # Returns
    /// A tuple of (handle, event_receiver)
    pub fn new(
        config: MinerConfig,
        attributes: Arc<A>,
        proposer_index: u64,
    ) -> (MinerHandle, mpsc::Receiver<MinerEvent>, Self) {
        let (cmd_tx, cmd_rx) = mpsc::channel(16);
        let (event_tx, event_rx) = mpsc::channel(16);

        let worker = Self {
            config,
            attributes,
            state: None,
            cmd_rx,
            event_tx,
            proposer_index,
        };

        let handle = MinerHandle { cmd_tx };
        (handle, event_rx, worker)
    }

    /// Spawn the worker as a background task.
    pub fn spawn(
        config: MinerConfig,
        attributes: Arc<A>,
        proposer_index: u64,
    ) -> (MinerHandle, mpsc::Receiver<MinerEvent>) {
        let (handle, event_rx, worker) = Self::new(config, attributes, proposer_index);

        tokio::spawn(async move {
            worker.run().await;
        });

        (handle, event_rx)
    }

    /// Run the main mining loop.
    pub async fn run(mut self) {
        let mut recommit_interval = interval(self.config.recommit_interval);
        recommit_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            // Calculate time until seal (if mining)
            let seal_duration = self.state.as_ref().map(|s| {
                let now = Instant::now();
                if s.seal_at > now {
                    s.seal_at - now
                } else {
                    Duration::ZERO
                }
            });

            tokio::select! {
                // Handle incoming commands
                Some(cmd) = self.cmd_rx.recv() => {
                    match cmd {
                        MinerCommand::StartMining { parent, slot, in_turn, num_validators } => {
                            self.start_mining(parent, slot, in_turn, num_validators).await;
                        }
                        MinerCommand::Stop => {
                            self.stop_mining("manual stop").await;
                        }
                        MinerCommand::UpdateHead(block) => {
                            self.handle_head_update(block).await;
                        }
                        MinerCommand::Recommit => {
                            self.rebuild_payload().await;
                        }
                    }
                }

                // Recommit timer (rebuild payload with new transactions)
                _ = recommit_interval.tick(), if self.state.is_some() => {
                    self.rebuild_payload().await;
                }

                // Seal timer (time to sign and broadcast)
                _ = tokio::time::sleep(seal_duration.unwrap_or(Duration::from_secs(3600))), if seal_duration.is_some() => {
                    self.seal_and_broadcast().await;
                }

                else => {
                    // Channel closed, exit
                    break;
                }
            }
        }
    }

    /// Start mining on a new parent block.
    async fn start_mining(
        &mut self,
        parent: SignedBeaconBlock,
        slot: u64,
        in_turn: bool,
        num_validators: usize,
    ) {
        // Build initial payload
        let payload = self.build_payload(slot, &parent);

        // Calculate seal delay
        let now = Instant::now();
        let current_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let target_timestamp = self.attributes.timestamp(slot);

        let env = MiningEnvironment::new(target_timestamp, current_timestamp, in_turn, num_validators);
        let delay = calculate_seal_delay(&env);

        let seal_at = now + delay;

        self.state = Some(MiningState {
            parent,
            slot,
            in_turn,
            num_validators,
            payload,
            started_at: now,
            seal_at,
        });

        // Emit event
        let _ = self
            .event_tx
            .send(MinerEvent::MiningStarted { slot, in_turn })
            .await;

        tracing::info!(
            slot = slot,
            in_turn = in_turn,
            delay_ms = delay.as_millis(),
            "Started mining"
        );
    }

    /// Stop current mining operation.
    async fn stop_mining(&mut self, reason: &str) {
        if self.state.take().is_some() {
            let _ = self
                .event_tx
                .send(MinerEvent::MiningCancelled {
                    reason: reason.to_string(),
                })
                .await;
        }
    }

    /// Handle chain head update.
    async fn handle_head_update(&mut self, new_head: SignedBeaconBlock) {
        if let Some(ref state) = self.state {
            // If new head is different from our parent, cancel mining
            if new_head.block_root() != state.parent.block_root() {
                self.stop_mining("head updated").await;
            }
        }
    }

    /// Rebuild payload (called on recommit).
    async fn rebuild_payload(&mut self) {
        // Extract needed values first to avoid borrow issues
        let (slot, parent) = match &self.state {
            Some(state) => (state.slot, state.parent.clone()),
            None => return,
        };

        // Build new payload
        let new_payload = self.build_payload(slot, &parent);

        // Update state
        if let Some(ref mut state) = self.state {
            state.payload = new_payload;
            tracing::debug!(slot = state.slot, "Rebuilt payload on recommit");
        }
    }

    /// Build a payload for the given slot.
    ///
    /// In a full implementation, this would use reth's PayloadBuilder
    /// to pack transactions from the mempool. For now, we create an
    /// empty payload.
    fn build_payload(&self, slot: u64, _parent: &SignedBeaconBlock) -> BeaconBlockBody {
        // Get attributes from provider
        let _timestamp = self.attributes.timestamp(slot);
        let _fee_recipient = self.attributes.suggested_fee_recipient(slot);
        let _prev_randao = self.attributes.prev_randao(slot);
        let _withdrawals = self.attributes.withdrawals(slot);

        // TODO: Use reth PayloadBuilder to pack transactions
        // For now, return empty body with config's extra_data in graffiti
        let mut body = BeaconBlockBody::default();

        // Store extra_data in graffiti (first 32 bytes)
        if !self.config.extra_data.is_empty() {
            let len = std::cmp::min(self.config.extra_data.len(), 32);
            body.graffiti.0[..len].copy_from_slice(&self.config.extra_data[..len]);
        }

        body
    }

    /// Seal the current block and broadcast.
    async fn seal_and_broadcast(&mut self) {
        let state = match self.state.take() {
            Some(s) => s,
            None => return,
        };

        // Calculate difficulty based on in-turn status
        let difficulty = if state.in_turn {
            crate::consensus::DIFFICULTY_IN_TURN
        } else {
            crate::consensus::DIFFICULTY_OUT_OF_TURN
        };

        // Set difficulty in graffiti for compatibility
        let mut body = state.payload.clone();
        crate::consensus::set_difficulty_in_graffiti(&mut body.graffiti, difficulty);

        // Build the beacon block
        let block = BeaconBlock::new(
            state.slot,
            self.proposer_index,
            state.parent.block_root(),
            B256::ZERO, // State root will be computed later
            body,
            difficulty,
        );

        // Seal (sign) the block
        let signed_block = seal_block(block, self.config.signing_key());
        let hash = signed_block.block_root();
        let seal_latency = state.started_at.elapsed();

        tracing::info!(
            slot = state.slot,
            hash = %hash,
            in_turn = state.in_turn,
            difficulty = difficulty,
            latency_ms = seal_latency.as_millis(),
            "Sealed block"
        );

        // Emit sealed block event
        let _ = self
            .event_tx
            .send(MinerEvent::BlockSealed(SealResult {
                block: signed_block,
                hash,
                seal_latency,
            }))
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::miner::PoaAttributesProvider;
    use alloy_primitives::Address;

    fn create_test_config() -> MinerConfig {
        let ikm = [1u8; 32];
        let key = blst::min_pk::SecretKey::key_gen(&ikm, &[]).unwrap();
        let coinbase = Address::repeat_byte(0x01);
        MinerConfig::new(coinbase, key).with_recommit_interval(Duration::from_millis(100))
    }

    fn create_test_parent() -> SignedBeaconBlock {
        let block = BeaconBlock::new(
            0,
            0,
            B256::ZERO,
            B256::ZERO,
            BeaconBlockBody::default(),
            2,
        );
        SignedBeaconBlock::new(block, alloy_primitives::Bytes::new())
    }

    #[tokio::test]
    async fn test_worker_start_mining() {
        let config = create_test_config();
        let coinbase = config.coinbase;
        let attrs = Arc::new(PoaAttributesProvider::new(coinbase, 8, 1700000000));

        let (handle, mut event_rx) = Worker::spawn(config, attrs, 0);

        // Start mining
        let parent = create_test_parent();
        handle.start_mining(parent, 1, true, 3).await.unwrap();

        // Should receive MiningStarted event
        let event = tokio::time::timeout(Duration::from_secs(1), event_rx.recv())
            .await
            .unwrap()
            .unwrap();

        match event {
            MinerEvent::MiningStarted { slot, in_turn } => {
                assert_eq!(slot, 1);
                assert!(in_turn);
            }
            _ => panic!("Expected MiningStarted event"),
        }

        // Stop mining
        handle.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_worker_stop_mining() {
        let config = create_test_config();
        let coinbase = config.coinbase;
        let attrs = Arc::new(PoaAttributesProvider::new(coinbase, 8, 1700000000));

        let (handle, mut event_rx) = Worker::spawn(config, attrs, 0);

        // Start mining
        let parent = create_test_parent();
        handle.start_mining(parent, 1, true, 3).await.unwrap();

        // Wait for MiningStarted
        let _ = event_rx.recv().await;

        // Stop mining
        handle.stop().await.unwrap();

        // Should receive MiningCancelled event
        let event = tokio::time::timeout(Duration::from_secs(1), event_rx.recv())
            .await
            .unwrap()
            .unwrap();

        match event {
            MinerEvent::MiningCancelled { reason } => {
                assert_eq!(reason, "manual stop");
            }
            _ => panic!("Expected MiningCancelled event"),
        }
    }
}
