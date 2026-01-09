//! Beacon block downloader.
//!
//! Downloads beacon blocks from peers in a streaming fashion.
//! Unlike body downloading, beacon blocks are complete and don't need
//! to be matched with headers.

use super::client::{BeaconBlockClient, BeaconBlockClientError, PeerBeaconBlockResult};
use crate::primitives::SignedBeaconBlock;
use futures::{stream::FuturesUnordered, Future, Stream, StreamExt};
use std::{
    cmp::Ordering,
    collections::BinaryHeap,
    ops::RangeInclusive,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use reth_tracing::tracing::{debug, trace};

/// Result type for beacon block downloads.
pub type BeaconDownloadResult = Result<Vec<SignedBeaconBlock>, BeaconDownloadError>;

/// Errors that can occur during beacon block download.
#[derive(Debug, Clone, thiserror::Error)]
pub enum BeaconDownloadError {
    /// Request failed.
    #[error("request failed: {0}")]
    RequestFailed(#[from] BeaconBlockClientError),
    /// No more peers available.
    #[error("no more peers available")]
    NoPeers,
    /// Download was aborted.
    #[error("download aborted")]
    Aborted,
}

/// Configuration for the beacon block downloader.
#[derive(Debug, Clone)]
pub struct BeaconDownloaderConfig {
    /// Maximum number of slots to request per request.
    pub request_limit: u64,
    /// Maximum number of blocks to buffer before yielding.
    pub batch_size: usize,
    /// Maximum concurrent requests.
    pub max_concurrent_requests: usize,
}

impl Default for BeaconDownloaderConfig {
    fn default() -> Self {
        Self {
            request_limit: 64,
            batch_size: 256,
            max_concurrent_requests: 10,
        }
    }
}

/// A downloader that fetches beacon blocks from the P2P network.
///
/// This downloader implements the `Stream` trait and yields batches of
/// beacon blocks ordered by slot.
#[derive(Debug)]
#[must_use = "Stream does nothing unless polled"]
pub struct BeaconBlockDownloader<C: BeaconBlockClient> {
    /// The beacon block client.
    client: Arc<C>,
    /// Configuration.
    config: BeaconDownloaderConfig,
    /// The range of slots to download.
    download_range: RangeInclusive<u64>,
    /// The next slot to request.
    next_request_slot: u64,
    /// Requests in progress.
    in_progress: FuturesUnordered<BeaconBlockRequestFuture>,
    /// Buffered responses waiting to be ordered.
    buffered: BinaryHeap<OrderedBeaconResponse>,
    /// Queued blocks ready to be yielded.
    queued: Vec<SignedBeaconBlock>,
    /// The next expected slot for ordering.
    next_expected_slot: u64,
    /// Whether the download has finished.
    finished: bool,
}

impl<C: BeaconBlockClient + 'static> BeaconBlockDownloader<C> {
    /// Create a new beacon block downloader.
    pub fn new(client: Arc<C>, config: BeaconDownloaderConfig) -> Self {
        Self {
            client,
            config,
            download_range: 1..=0, // Empty range
            next_request_slot: 0,
            in_progress: FuturesUnordered::new(),
            buffered: BinaryHeap::new(),
            queued: Vec::new(),
            next_expected_slot: 0,
            finished: true,
        }
    }

    /// Set the download range.
    ///
    /// This resets the downloader state and prepares it to download
    /// blocks in the specified slot range.
    pub fn set_download_range(&mut self, range: RangeInclusive<u64>) -> Result<(), BeaconDownloadError> {
        self.clear();

        if range.is_empty() {
            self.finished = true;
            return Ok(());
        }

        self.download_range = range.clone();
        self.next_request_slot = *range.start();
        self.next_expected_slot = *range.start();
        self.finished = false;

        debug!(
            start = *range.start(),
            end = *range.end(),
            "Set beacon block download range"
        );

        Ok(())
    }

    /// Clear all state.
    fn clear(&mut self) {
        self.download_range = 1..=0;
        self.next_request_slot = 0;
        self.in_progress = FuturesUnordered::new();
        self.buffered.clear();
        self.queued.clear();
        self.next_expected_slot = 0;
        self.finished = true;
    }

    /// Check if we can submit more requests.
    fn can_submit_request(&self) -> bool {
        !self.finished
            && self.in_progress.len() < self.config.max_concurrent_requests
            && self.next_request_slot <= *self.download_range.end()
    }

    /// Submit the next request.
    fn submit_next_request(&mut self) {
        if !self.can_submit_request() {
            return;
        }

        let start_slot = self.next_request_slot;
        let end_slot = (*self.download_range.end())
            .min(start_slot + self.config.request_limit - 1);

        let range = start_slot..=end_slot;
        self.next_request_slot = end_slot + 1;

        trace!(
            start = start_slot,
            end = end_slot,
            "Submitting beacon block request"
        );

        let fut = self.client.get_beacon_blocks(range.clone());
        self.in_progress.push(BeaconBlockRequestFuture {
            start_slot,
            end_slot,
            fut: Box::pin(async move { fut.await }),
        });
    }

    /// Try to move buffered responses to the queue in order.
    fn try_queue_buffered(&mut self) {
        while let Some(response) = self.buffered.peek() {
            // Only process if this is the next expected slot range
            if response.start_slot > self.next_expected_slot {
                // Gap in the sequence, wait for missing blocks
                break;
            }

            let response = self.buffered.pop().unwrap();

            // Update next expected slot
            self.next_expected_slot = response.end_slot + 1;

            // Add blocks to queue
            self.queued.extend(response.blocks);
        }
    }

    /// Check if we should yield the current queue.
    fn should_yield(&self) -> bool {
        // Yield if we have enough blocks or if we're done
        self.queued.len() >= self.config.batch_size
            || (self.is_done() && !self.queued.is_empty())
    }

    /// Check if download is complete.
    fn is_done(&self) -> bool {
        self.finished
            || (self.next_request_slot > *self.download_range.end()
                && self.in_progress.is_empty()
                && self.buffered.is_empty())
    }
}

impl<C: BeaconBlockClient + 'static> Stream for BeaconBlockDownloader<C> {
    type Item = BeaconDownloadResult;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        loop {
            // Check if we're done
            if this.finished && this.queued.is_empty() {
                return Poll::Ready(None);
            }

            // Check if we should yield current queue
            if this.should_yield() {
                let blocks = std::mem::take(&mut this.queued);
                return Poll::Ready(Some(Ok(blocks)));
            }

            // Submit new requests if possible
            while this.can_submit_request() {
                this.submit_next_request();
            }

            // Poll in-progress requests
            match this.in_progress.poll_next_unpin(cx) {
                Poll::Ready(Some(result)) => {
                    match result.result {
                        Ok(response) => {
                            trace!(
                                start_slot = result.start_slot,
                                end_slot = result.end_slot,
                                blocks_count = response.data.len(),
                                "Received beacon blocks"
                            );

                            // Buffer the response
                            this.buffered.push(OrderedBeaconResponse {
                                start_slot: result.start_slot,
                                end_slot: result.end_slot,
                                blocks: response.data,
                            });

                            // Try to move to queue
                            this.try_queue_buffered();
                        }
                        Err(e) => {
                            debug!(
                                start_slot = result.start_slot,
                                end_slot = result.end_slot,
                                error = %e,
                                "Beacon block request failed"
                            );
                            // For now, fail on any error
                            // A production implementation would retry
                            return Poll::Ready(Some(Err(BeaconDownloadError::RequestFailed(e))));
                        }
                    }
                    continue;
                }
                Poll::Ready(None) => {
                    // No more in-progress requests
                    if this.is_done() {
                        this.finished = true;
                        // Yield remaining blocks if any
                        if !this.queued.is_empty() {
                            let blocks = std::mem::take(&mut this.queued);
                            return Poll::Ready(Some(Ok(blocks)));
                        }
                        return Poll::Ready(None);
                    }
                }
                Poll::Pending => {
                    return Poll::Pending;
                }
            }
        }
    }
}

/// A pending beacon block request.
struct BeaconBlockRequestFuture {
    start_slot: u64,
    end_slot: u64,
    fut: Pin<Box<dyn Future<Output = PeerBeaconBlockResult<Vec<SignedBeaconBlock>>> + Send + Sync>>,
}

impl Future for BeaconBlockRequestFuture {
    type Output = BeaconBlockRequestResult;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.fut.as_mut().poll(cx) {
            Poll::Ready(result) => Poll::Ready(BeaconBlockRequestResult {
                start_slot: self.start_slot,
                end_slot: self.end_slot,
                result,
            }),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Result of a beacon block request.
struct BeaconBlockRequestResult {
    start_slot: u64,
    end_slot: u64,
    result: PeerBeaconBlockResult<Vec<SignedBeaconBlock>>,
}

/// A response ordered by start slot.
#[derive(Debug)]
struct OrderedBeaconResponse {
    start_slot: u64,
    end_slot: u64,
    blocks: Vec<SignedBeaconBlock>,
}

impl Eq for OrderedBeaconResponse {}

impl PartialEq for OrderedBeaconResponse {
    fn eq(&self, other: &Self) -> bool {
        self.start_slot == other.start_slot
    }
}

impl Ord for OrderedBeaconResponse {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse ordering for min-heap behavior
        other.start_slot.cmp(&self.start_slot)
    }
}

impl PartialOrd for OrderedBeaconResponse {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Trait for beacon block downloaders.
///
/// This trait allows the stage to work with different downloader implementations.
pub trait BeaconBlockDownloaderLike: Stream<Item = BeaconDownloadResult> + Send + Sync + Unpin {
    /// Set the download range.
    fn set_download_range(&mut self, range: RangeInclusive<u64>) -> Result<(), BeaconDownloadError>;
}

impl<C: BeaconBlockClient + 'static> BeaconBlockDownloaderLike for BeaconBlockDownloader<C> {
    fn set_download_range(&mut self, range: RangeInclusive<u64>) -> Result<(), BeaconDownloadError> {
        BeaconBlockDownloader::set_download_range(self, range)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ordered_response_ordering() {
        let mut heap = BinaryHeap::new();

        heap.push(OrderedBeaconResponse {
            start_slot: 100,
            end_slot: 110,
            blocks: vec![],
        });
        heap.push(OrderedBeaconResponse {
            start_slot: 50,
            end_slot: 60,
            blocks: vec![],
        });
        heap.push(OrderedBeaconResponse {
            start_slot: 75,
            end_slot: 85,
            blocks: vec![],
        });

        // Should pop in ascending order (min-heap)
        assert_eq!(heap.pop().unwrap().start_slot, 50);
        assert_eq!(heap.pop().unwrap().start_slot, 75);
        assert_eq!(heap.pop().unwrap().start_slot, 100);
    }

    #[test]
    fn test_config_defaults() {
        let config = BeaconDownloaderConfig::default();
        assert_eq!(config.request_limit, 64);
        assert_eq!(config.batch_size, 256);
        assert_eq!(config.max_concurrent_requests, 10);
    }
}
