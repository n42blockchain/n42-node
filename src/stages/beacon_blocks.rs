//! Beacon blocks download stage.
//!
//! This stage downloads beacon blocks from the P2P network and stores them
//! in the beacon store. It runs as the **FIRST** stage in the pipeline,
//! defining the canonical chain for subsequent stages.
//!
//! # Pipeline Position
//!
//! ```text
//! BeaconBlocks Stage  ← This stage (FIRST - defines canonical chain)
//!     │
//!     │ (provides execution_payload_root for each slot)
//!     ▼
//! Headers Stage
//!     │
//!     ▼
//! Bodies Stage
//!     │
//!     ▼
//! Execution Stage
//! ```
//!
//! # Design Rationale
//!
//! In a PoS system, the beacon chain defines the canonical chain:
//! - Beacon blocks contain `execution_payload_root` which references execution blocks
//! - By downloading beacon blocks first, we know which execution blocks to download
//! - This prevents downloading execution blocks that aren't part of the canonical chain
//!
//! # Sync Target
//!
//! The stage uses a `BeaconSyncTarget` to determine what to sync:
//! - Can be set by consensus layer (fork choice)
//! - Can be discovered from peers (highest finalized/head)

use super::downloader::{BeaconBlockDownloaderLike, BeaconDownloadError};
use crate::{primitives::SignedBeaconBlock, storage::BeaconStore};
use alloy_primitives::B256;
use reth_stages_api::{
    ExecInput, ExecOutput, Stage, StageCheckpoint, StageError, StageId, UnwindInput, UnwindOutput,
};
use reth_tracing::tracing::{debug, info, trace, warn};
use std::{
    sync::Arc,
    task::{ready, Context, Poll},
};
use tokio::sync::watch;

/// Sync target for beacon blocks.
///
/// This determines what the beacon blocks stage should sync to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BeaconSyncTarget {
    /// The target slot to sync to.
    pub slot: u64,
    /// The expected block root at the target slot (optional, for validation).
    pub block_root: Option<B256>,
    /// Whether this target is finalized.
    pub finalized: bool,
}

impl BeaconSyncTarget {
    /// Create a new sync target.
    pub fn new(slot: u64) -> Self {
        Self { slot, block_root: None, finalized: false }
    }

    /// Create a finalized sync target.
    pub fn finalized(slot: u64, block_root: B256) -> Self {
        Self { slot, block_root: Some(block_root), finalized: true }
    }

    /// Create a head sync target.
    pub fn head(slot: u64) -> Self {
        Self { slot, block_root: None, finalized: false }
    }
}

/// Provider for beacon sync target.
///
/// This trait allows different sources of sync target:
/// - From consensus layer (fork choice updated)
/// - From peer discovery (highest advertised slot)
/// - From configuration (for testing)
pub trait BeaconSyncTargetProvider: Send + Sync {
    /// Get the current sync target.
    fn sync_target(&self) -> Option<BeaconSyncTarget>;

    /// Get the current finalized slot.
    fn finalized_slot(&self) -> Option<u64>;
}

/// Simple sync target provider using a watch channel.
///
/// This can be updated externally (e.g., from consensus layer or peer discovery).
#[derive(Debug, Clone)]
pub struct WatchSyncTargetProvider {
    receiver: watch::Receiver<Option<BeaconSyncTarget>>,
}

impl WatchSyncTargetProvider {
    /// Create a new provider with the given receiver.
    pub fn new(receiver: watch::Receiver<Option<BeaconSyncTarget>>) -> Self {
        Self { receiver }
    }

    /// Create a provider and sender pair.
    pub fn channel() -> (watch::Sender<Option<BeaconSyncTarget>>, Self) {
        let (tx, rx) = watch::channel(None);
        (tx, Self::new(rx))
    }
}

impl BeaconSyncTargetProvider for WatchSyncTargetProvider {
    fn sync_target(&self) -> Option<BeaconSyncTarget> {
        self.receiver.borrow().clone()
    }

    fn finalized_slot(&self) -> Option<u64> {
        self.receiver.borrow().as_ref().filter(|t| t.finalized).map(|t| t.slot)
    }
}

/// The beacon blocks stage downloads beacon blocks and stores them in the beacon store.
///
/// This is the **FIRST** stage in the N42 pipeline. It:
/// 1. Determines the sync target from the beacon sync target provider
/// 2. Downloads beacon blocks from peers
/// 3. Stores them in the beacon store
/// 4. Provides the canonical chain for subsequent stages
///
/// # Sync Strategy
///
/// The stage syncs in two phases:
/// 1. **Finalized sync**: Sync to the finalized checkpoint first
/// 2. **Head sync**: Then sync to the head
///
/// This ensures we have a stable base before chasing the head.
#[derive(Debug)]
pub struct BeaconBlocksStage<D, S, T> {
    /// The beacon block downloader.
    downloader: D,
    /// The beacon store.
    store: Arc<S>,
    /// Sync target provider.
    sync_target_provider: T,
    /// Buffer for downloaded blocks.
    buffer: Option<Vec<SignedBeaconBlock>>,
    /// Current sync target.
    current_target: Option<BeaconSyncTarget>,
}

impl<D, S, T> BeaconBlocksStage<D, S, T>
where
    D: BeaconBlockDownloaderLike,
    S: BeaconStore,
    T: BeaconSyncTargetProvider,
{
    /// Create a new beacon blocks stage.
    pub fn new(downloader: D, store: Arc<S>, sync_target_provider: T) -> Self {
        Self {
            downloader,
            store,
            sync_target_provider,
            buffer: None,
            current_target: None,
        }
    }

    /// Get the local beacon head slot.
    fn local_head_slot(&self) -> u64 {
        self.store.latest_slot().ok().flatten().unwrap_or(0)
    }

    /// Determine the download range based on sync target.
    fn get_download_range(&self, checkpoint: u64) -> Option<(u64, u64)> {
        let target = self.sync_target_provider.sync_target()?;
        let local_head = self.local_head_slot();

        // Start from the higher of checkpoint or local head
        let start = checkpoint.max(local_head).saturating_add(1);

        if start > target.slot {
            // Already synced
            return None;
        }

        Some((start, target.slot))
    }
}

/// Custom stage ID for beacon blocks.
pub const BEACON_BLOCKS_STAGE_ID: &str = "BeaconBlocks";

/// Error when beacon block root doesn't match expected value.
#[derive(Debug, Clone, thiserror::Error)]
#[error("beacon block root mismatch at slot {slot}: expected {expected}, got {actual}")]
pub struct BeaconBlockRootMismatch {
    /// The slot where mismatch occurred.
    pub slot: u64,
    /// Expected block root.
    pub expected: B256,
    /// Actual block root.
    pub actual: B256,
}

impl<Provider, D, S, T> Stage<Provider> for BeaconBlocksStage<D, S, T>
where
    D: BeaconBlockDownloaderLike,
    S: BeaconStore + Send + Sync + 'static,
    T: BeaconSyncTargetProvider,
{
    fn id(&self) -> StageId {
        StageId::Other(BEACON_BLOCKS_STAGE_ID)
    }

    fn poll_execute_ready(
        &mut self,
        cx: &mut Context<'_>,
        input: ExecInput,
    ) -> Poll<Result<(), StageError>> {
        // If we have a buffer, we're ready
        if self.buffer.is_some() {
            return Poll::Ready(Ok(()));
        }

        // Get sync target
        let target = match self.sync_target_provider.sync_target() {
            Some(t) => t,
            None => {
                // No sync target yet, wait
                debug!(
                    target: "sync::stages::beacon_blocks",
                    "No beacon sync target available, waiting..."
                );
                // Return pending to wait for sync target
                // In a real implementation, we'd register a waker
                return Poll::Pending;
            }
        };

        // Store current target for execute phase
        self.current_target = Some(target.clone());

        // Determine download range
        let checkpoint = input.checkpoint().block_number;
        let (from_slot, to_slot) = match self.get_download_range(checkpoint) {
            Some(range) => range,
            None => {
                // Already synced to target
                debug!(
                    target: "sync::stages::beacon_blocks",
                    checkpoint = checkpoint,
                    target_slot = target.slot,
                    "Already synced to beacon target"
                );
                self.buffer = Some(Vec::new());
                return Poll::Ready(Ok(()));
            }
        };

        debug!(
            target: "sync::stages::beacon_blocks",
            from_slot = from_slot,
            to_slot = to_slot,
            target_finalized = target.finalized,
            "Setting beacon block download range"
        );

        // Set the download range
        if let Err(e) = self.downloader.set_download_range(from_slot..=to_slot) {
            return Poll::Ready(Err(beacon_download_to_stage_error(e)));
        }

        // Poll the downloader
        use futures::StreamExt;
        match ready!(self.downloader.poll_next_unpin(cx)) {
            Some(Ok(blocks)) => {
                trace!(
                    target: "sync::stages::beacon_blocks",
                    blocks_count = blocks.len(),
                    "Downloaded beacon blocks"
                );
                self.buffer = Some(blocks);
                Poll::Ready(Ok(()))
            }
            Some(Err(e)) => Poll::Ready(Err(beacon_download_to_stage_error(e))),
            None => {
                // Stream ended
                self.buffer = Some(Vec::new());
                Poll::Ready(Ok(()))
            }
        }
    }

    fn execute(&mut self, _provider: &Provider, input: ExecInput) -> Result<ExecOutput, StageError> {
        let checkpoint = input.checkpoint().block_number;

        // Get current target
        let target = match &self.current_target {
            Some(t) => t.clone(),
            None => {
                // No target, nothing to do
                return Ok(ExecOutput::done(input.checkpoint()));
            }
        };

        // Check if already synced
        if checkpoint >= target.slot {
            debug!(
                target: "sync::stages::beacon_blocks",
                checkpoint = checkpoint,
                target_slot = target.slot,
                "Beacon blocks stage already synced"
            );
            return Ok(ExecOutput::done(input.checkpoint()));
        }

        // Take the buffer
        let buffer = self.buffer.take().ok_or(StageError::MissingDownloadBuffer)?;

        if buffer.is_empty() {
            debug!(
                target: "sync::stages::beacon_blocks",
                "No beacon blocks downloaded"
            );
            return Ok(ExecOutput {
                checkpoint: StageCheckpoint::new(checkpoint),
                done: false, // Not done, just no blocks in this batch
            });
        }

        trace!(
            target: "sync::stages::beacon_blocks",
            blocks_count = buffer.len(),
            "Writing beacon blocks to store"
        );

        // Track the highest slot
        let mut highest_slot = checkpoint;

        // Validate and store blocks
        for block in &buffer {
            let slot = block.slot();

            // Validate block root if we have target root and this is the target slot
            if slot == target.slot {
                if let Some(expected_root) = target.block_root {
                    let actual_root = block.block_root();
                    if actual_root != expected_root {
                        warn!(
                            target: "sync::stages::beacon_blocks",
                            slot = slot,
                            expected = %expected_root,
                            actual = %actual_root,
                            "Block root mismatch at target slot"
                        );
                        return Err(StageError::Fatal(Box::new(BeaconBlockRootMismatch {
                            slot,
                            expected: expected_root,
                            actual: actual_root,
                        })));
                    }
                }
            }

            // Store the block
            self.store
                .insert_block(block.clone())
                .map_err(|e| StageError::Fatal(Box::new(e)))?;

            if slot > highest_slot {
                highest_slot = slot;
            }
        }

        info!(
            target: "sync::stages::beacon_blocks",
            blocks_stored = buffer.len(),
            highest_slot = highest_slot,
            target_slot = target.slot,
            "Beacon blocks stored successfully"
        );

        // Check if we've reached the target
        let done = highest_slot >= target.slot;

        Ok(ExecOutput {
            checkpoint: StageCheckpoint::new(highest_slot),
            done,
        })
    }

    fn unwind(
        &mut self,
        _provider: &Provider,
        input: UnwindInput,
    ) -> Result<UnwindOutput, StageError> {
        // Clear buffers
        self.buffer.take();
        self.current_target.take();

        debug!(
            target: "sync::stages::beacon_blocks",
            unwind_to = input.unwind_to,
            "Unwinding beacon blocks stage"
        );

        // Remove blocks from the beacon store
        self.store
            .remove_blocks_from(input.unwind_to + 1)
            .map_err(|e| StageError::Fatal(Box::new(e)))?;

        info!(
            target: "sync::stages::beacon_blocks",
            unwind_to = input.unwind_to,
            "Beacon blocks unwound successfully"
        );

        Ok(UnwindOutput { checkpoint: StageCheckpoint::new(input.unwind_to) })
    }
}

/// Convert a beacon download error to a stage error.
fn beacon_download_to_stage_error(error: BeaconDownloadError) -> StageError {
    match error {
        BeaconDownloadError::NoPeers => StageError::Fatal(Box::new(error)),
        BeaconDownloadError::Aborted => StageError::Fatal(Box::new(error)),
        BeaconDownloadError::RequestFailed(_) => StageError::Recoverable(Box::new(error)),
    }
}

/// Mapping from beacon slot to execution block.
///
/// This is used by subsequent stages (Headers, Bodies) to know which
/// execution blocks correspond to which beacon slots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BeaconExecutionMapping {
    /// Beacon slot.
    pub slot: u64,
    /// Beacon block root.
    pub beacon_root: B256,
    /// Execution payload root from the beacon block.
    pub execution_payload_root: B256,
}

/// Provider for beacon-to-execution mapping.
///
/// Headers stage can use this to determine which execution blocks to download.
pub trait BeaconExecutionMappingProvider: Send + Sync {
    /// Get the execution payload root for a slot.
    fn execution_payload_root(&self, slot: u64) -> Option<B256>;

    /// Get mappings for a range of slots.
    fn mappings_in_range(&self, start: u64, end: u64) -> Vec<BeaconExecutionMapping>;
}

/// Implementation using BeaconStore.
impl<S: BeaconStore + Send + Sync> BeaconExecutionMappingProvider for S {
    fn execution_payload_root(&self, slot: u64) -> Option<B256> {
        self.block_by_slot(slot)
            .ok()
            .flatten()
            .map(|b| b.message.body.execution_payload_root)
    }

    fn mappings_in_range(&self, start: u64, end: u64) -> Vec<BeaconExecutionMapping> {
        let mut mappings = Vec::new();
        for slot in start..=end {
            if let Ok(Some(block)) = self.block_by_slot(slot) {
                mappings.push(BeaconExecutionMapping {
                    slot,
                    beacon_root: block.block_root(),
                    execution_payload_root: block.message.body.execution_payload_root,
                });
            }
        }
        mappings
    }
}

// =============================================================================
// Validating Beacon Blocks Stage (with BeaconState)
// =============================================================================

use crate::consensus::{
    state_transition::{process_block, StateTransitionConfig, StateTransitionError},
    BeaconState,
};
use parking_lot::RwLock;

/// Error during beacon block validation.
#[derive(Debug, Clone, thiserror::Error)]
pub enum BeaconValidationStageError {
    /// State transition failed.
    #[error("state transition failed: {0}")]
    StateTransition(#[from] StateTransitionError),
    /// Block root mismatch.
    #[error("block root mismatch at slot {slot}: expected {expected}, got {actual}")]
    BlockRootMismatch {
        /// Slot where mismatch occurred.
        slot: u64,
        /// Expected root.
        expected: B256,
        /// Actual root.
        actual: B256,
    },
}

/// Beacon blocks stage with full state validation.
///
/// This stage validates each beacon block against the beacon state before
/// storing it, ensuring only valid blocks enter the store.
///
/// # Validation
///
/// For each block:
/// 1. Verify proposer index matches expected (round-robin)
/// 2. Verify parent root matches previous block
/// 3. Verify proposer signature
/// 4. Apply state transition
///
/// # Usage
///
/// ```ignore
/// let beacon_state = BeaconState::genesis(genesis_time, validators);
/// let stage = ValidatingBeaconBlocksStage::new(
///     downloader,
///     store,
///     sync_target_provider,
///     beacon_state,
/// );
/// ```
#[derive(Debug)]
pub struct ValidatingBeaconBlocksStage<D, S, T> {
    /// The beacon block downloader.
    downloader: D,
    /// The beacon store.
    store: Arc<S>,
    /// Sync target provider.
    sync_target_provider: T,
    /// Buffer for downloaded blocks.
    buffer: Option<Vec<SignedBeaconBlock>>,
    /// Current sync target.
    current_target: Option<BeaconSyncTarget>,
    /// Beacon state (shared, mutable).
    beacon_state: Arc<RwLock<BeaconState>>,
    /// State transition configuration.
    state_config: StateTransitionConfig,
}

impl<D, S, T> ValidatingBeaconBlocksStage<D, S, T>
where
    D: BeaconBlockDownloaderLike,
    S: BeaconStore,
    T: BeaconSyncTargetProvider,
{
    /// Create a new validating beacon blocks stage.
    pub fn new(
        downloader: D,
        store: Arc<S>,
        sync_target_provider: T,
        beacon_state: BeaconState,
    ) -> Self {
        Self {
            downloader,
            store,
            sync_target_provider,
            buffer: None,
            current_target: None,
            beacon_state: Arc::new(RwLock::new(beacon_state)),
            state_config: StateTransitionConfig::default(),
        }
    }

    /// Create with custom state transition config.
    pub fn with_config(
        downloader: D,
        store: Arc<S>,
        sync_target_provider: T,
        beacon_state: BeaconState,
        state_config: StateTransitionConfig,
    ) -> Self {
        Self {
            downloader,
            store,
            sync_target_provider,
            buffer: None,
            current_target: None,
            beacon_state: Arc::new(RwLock::new(beacon_state)),
            state_config,
        }
    }

    /// Get shared access to the beacon state.
    pub fn beacon_state(&self) -> Arc<RwLock<BeaconState>> {
        self.beacon_state.clone()
    }

    /// Get the local beacon head slot.
    fn local_head_slot(&self) -> u64 {
        self.store.latest_slot().ok().flatten().unwrap_or(0)
    }

    /// Determine the download range based on sync target.
    fn get_download_range(&self, checkpoint: u64) -> Option<(u64, u64)> {
        let target = self.sync_target_provider.sync_target()?;
        let local_head = self.local_head_slot();

        let start = checkpoint.max(local_head).saturating_add(1);

        if start > target.slot {
            return None;
        }

        Some((start, target.slot))
    }

    /// Validate and process a single block.
    fn validate_and_store_block(
        &self,
        block: &SignedBeaconBlock,
        target: &BeaconSyncTarget,
    ) -> Result<(), StageError> {
        let slot = block.slot();

        // Validate block root at target slot
        if slot == target.slot {
            if let Some(expected_root) = target.block_root {
                let actual_root = block.block_root();
                if actual_root != expected_root {
                    warn!(
                        target: "sync::stages::beacon_blocks",
                        slot = slot,
                        expected = %expected_root,
                        actual = %actual_root,
                        "Block root mismatch at target slot"
                    );
                    return Err(StageError::Fatal(Box::new(BeaconValidationStageError::BlockRootMismatch {
                        slot,
                        expected: expected_root,
                        actual: actual_root,
                    })));
                }
            }
        }

        // Validate against beacon state
        {
            let mut state = self.beacon_state.write();
            process_block(&mut state, block, &self.state_config)
                .map_err(|e| StageError::Fatal(Box::new(BeaconValidationStageError::StateTransition(e))))?;
        }

        // Store the validated block
        self.store
            .insert_block(block.clone())
            .map_err(|e| StageError::Fatal(Box::new(e)))?;

        trace!(
            target: "sync::stages::beacon_blocks",
            slot = slot,
            block_root = %block.block_root(),
            "Validated and stored beacon block"
        );

        Ok(())
    }
}

/// Stage ID for validating beacon blocks.
pub const VALIDATING_BEACON_BLOCKS_STAGE_ID: &str = "ValidatingBeaconBlocks";

impl<Provider, D, S, T> Stage<Provider> for ValidatingBeaconBlocksStage<D, S, T>
where
    D: BeaconBlockDownloaderLike,
    S: BeaconStore + Send + Sync + 'static,
    T: BeaconSyncTargetProvider,
{
    fn id(&self) -> StageId {
        StageId::Other(VALIDATING_BEACON_BLOCKS_STAGE_ID)
    }

    fn poll_execute_ready(
        &mut self,
        cx: &mut Context<'_>,
        input: ExecInput,
    ) -> Poll<Result<(), StageError>> {
        // If we have a buffer, we're ready
        if self.buffer.is_some() {
            return Poll::Ready(Ok(()));
        }

        // Get sync target
        let target = match self.sync_target_provider.sync_target() {
            Some(t) => t,
            None => {
                debug!(
                    target: "sync::stages::beacon_blocks",
                    "No beacon sync target available, waiting..."
                );
                return Poll::Pending;
            }
        };

        self.current_target = Some(target.clone());

        // Determine download range
        let checkpoint = input.checkpoint().block_number;
        let (from_slot, to_slot) = match self.get_download_range(checkpoint) {
            Some(range) => range,
            None => {
                debug!(
                    target: "sync::stages::beacon_blocks",
                    checkpoint = checkpoint,
                    target_slot = target.slot,
                    "Already synced to beacon target"
                );
                self.buffer = Some(Vec::new());
                return Poll::Ready(Ok(()));
            }
        };

        debug!(
            target: "sync::stages::beacon_blocks",
            from_slot = from_slot,
            to_slot = to_slot,
            target_finalized = target.finalized,
            "Setting beacon block download range (validating)"
        );

        if let Err(e) = self.downloader.set_download_range(from_slot..=to_slot) {
            return Poll::Ready(Err(beacon_download_to_stage_error(e)));
        }

        use futures::StreamExt;
        match ready!(self.downloader.poll_next_unpin(cx)) {
            Some(Ok(blocks)) => {
                trace!(
                    target: "sync::stages::beacon_blocks",
                    blocks_count = blocks.len(),
                    "Downloaded beacon blocks for validation"
                );
                self.buffer = Some(blocks);
                Poll::Ready(Ok(()))
            }
            Some(Err(e)) => Poll::Ready(Err(beacon_download_to_stage_error(e))),
            None => {
                self.buffer = Some(Vec::new());
                Poll::Ready(Ok(()))
            }
        }
    }

    fn execute(&mut self, _provider: &Provider, input: ExecInput) -> Result<ExecOutput, StageError> {
        let checkpoint = input.checkpoint().block_number;

        let target = match &self.current_target {
            Some(t) => t.clone(),
            None => {
                return Ok(ExecOutput::done(input.checkpoint()));
            }
        };

        if checkpoint >= target.slot {
            debug!(
                target: "sync::stages::beacon_blocks",
                checkpoint = checkpoint,
                target_slot = target.slot,
                "Validating beacon blocks stage already synced"
            );
            return Ok(ExecOutput::done(input.checkpoint()));
        }

        let buffer = self.buffer.take().ok_or(StageError::MissingDownloadBuffer)?;

        if buffer.is_empty() {
            debug!(
                target: "sync::stages::beacon_blocks",
                "No beacon blocks downloaded"
            );
            return Ok(ExecOutput {
                checkpoint: StageCheckpoint::new(checkpoint),
                done: false,
            });
        }

        info!(
            target: "sync::stages::beacon_blocks",
            blocks_count = buffer.len(),
            "Validating beacon blocks"
        );

        let mut highest_slot = checkpoint;

        // Validate and store each block
        for block in &buffer {
            self.validate_and_store_block(block, &target)?;

            let slot = block.slot();
            if slot > highest_slot {
                highest_slot = slot;
            }
        }

        info!(
            target: "sync::stages::beacon_blocks",
            blocks_validated = buffer.len(),
            highest_slot = highest_slot,
            target_slot = target.slot,
            "Beacon blocks validated and stored successfully"
        );

        let done = highest_slot >= target.slot;

        Ok(ExecOutput {
            checkpoint: StageCheckpoint::new(highest_slot),
            done,
        })
    }

    fn unwind(
        &mut self,
        _provider: &Provider,
        input: UnwindInput,
    ) -> Result<UnwindOutput, StageError> {
        self.buffer.take();
        self.current_target.take();

        debug!(
            target: "sync::stages::beacon_blocks",
            unwind_to = input.unwind_to,
            "Unwinding validating beacon blocks stage"
        );

        // Remove blocks from store
        self.store
            .remove_blocks_from(input.unwind_to + 1)
            .map_err(|e| StageError::Fatal(Box::new(e)))?;

        // Reset beacon state to the unwind target
        // In a full implementation, we'd reload the state from a checkpoint
        // For now, we just log a warning
        warn!(
            target: "sync::stages::beacon_blocks",
            unwind_to = input.unwind_to,
            "Beacon state should be reset to slot {} (not implemented)",
            input.unwind_to
        );

        info!(
            target: "sync::stages::beacon_blocks",
            unwind_to = input.unwind_to,
            "Validating beacon blocks unwound successfully"
        );

        Ok(UnwindOutput { checkpoint: StageCheckpoint::new(input.unwind_to) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stage_id() {
        assert_eq!(BEACON_BLOCKS_STAGE_ID, "BeaconBlocks");
    }

    #[test]
    fn test_sync_target() {
        let target = BeaconSyncTarget::new(100);
        assert_eq!(target.slot, 100);
        assert!(!target.finalized);

        let finalized = BeaconSyncTarget::finalized(200, B256::ZERO);
        assert_eq!(finalized.slot, 200);
        assert!(finalized.finalized);
    }

    #[test]
    fn test_watch_provider() {
        let (tx, provider) = WatchSyncTargetProvider::channel();

        // Initially no target
        assert!(provider.sync_target().is_none());

        // Set target
        tx.send(Some(BeaconSyncTarget::new(100))).unwrap();
        assert_eq!(provider.sync_target().unwrap().slot, 100);

        // Finalized slot
        assert!(provider.finalized_slot().is_none()); // Not finalized

        tx.send(Some(BeaconSyncTarget::finalized(200, B256::ZERO))).unwrap();
        assert_eq!(provider.finalized_slot(), Some(200));
    }
}
