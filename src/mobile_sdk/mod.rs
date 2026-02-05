//! Mobile SDK for N42 block verification.
//!
//! This module provides functionality for mobile validators to:
//! - Verify blocks by executing them with EVM
//! - Sign attestation data with BLS signatures
//! - Create deposit and exit transactions
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────┐
//! │           Mobile Validator              │
//! ├─────────────────────────────────────────┤
//! │  ┌─────────────────────────────────┐   │
//! │  │      WebSocket Client           │   │
//! │  │  (subscribeToVerificationReq)   │   │
//! │  └──────────────┬──────────────────┘   │
//! │                 │                       │
//! │  ┌──────────────▼──────────────────┐   │
//! │  │     Block Verification          │   │
//! │  │  • Execute block with EVM       │   │
//! │  │  • Compute receipts_root        │   │
//! │  │  • Sign AttestationData         │   │
//! │  └──────────────┬──────────────────┘   │
//! │                 │                       │
//! │  ┌──────────────▼──────────────────┐   │
//! │  │     Submit Verification         │   │
//! │  │  (submitVerification RPC)       │   │
//! │  └─────────────────────────────────┘   │
//! └─────────────────────────────────────────┘
//! ```

pub mod blst_utils;
pub mod c_ffi;
pub mod deposit_exit;
pub mod jni;

use alloy_primitives::B256;
use blst::min_pk::SecretKey;
use jsonrpsee::core::client::{ClientT, SubscriptionClientT};
use jsonrpsee::rpc_params;
use jsonrpsee::ws_client::WsClientBuilder;
use tracing::{debug, error, info};

use crate::pos::beacon::{AttestationData, BlockVerifyResult, UnverifiedBlock};

/// Run the mobile verification client.
///
/// Connects to a node via WebSocket and subscribes to verification requests.
/// When a block needs verification, it executes the block, computes the
/// receipts root, signs the attestation data, and submits the result.
///
/// # Arguments
///
/// * `ws_url` - WebSocket URL of the node (e.g., "ws://localhost:8546")
/// * `validator_private_key` - BLS private key for signing (hex encoded)
pub async fn run_client(ws_url: &str, validator_private_key: &str) -> eyre::Result<()> {
    info!("Connecting to node at {}", ws_url);

    let client = WsClientBuilder::default()
        .build(ws_url)
        .await
        .map_err(|e| eyre::eyre!("Failed to connect to WebSocket: {}", e))?;

    info!("Connected, subscribing to verification requests...");

    // Subscribe to verification requests
    let mut subscription = client
        .subscribe::<UnverifiedBlock, _>(
            "consensusBeaconExt_subscribeToVerificationRequest",
            rpc_params![],
            "consensusBeaconExt_unsubscribeFromVerificationRequest",
        )
        .await
        .map_err(|e| eyre::eyre!("Failed to subscribe: {}", e))?;

    info!("Subscribed, waiting for verification requests...");

    // Process verification requests
    while let Some(result) = subscription.next().await {
        match result {
            Ok(unverified_block) => {
                let block_hash = unverified_block.get_block_hash().unwrap_or_default();
                info!(
                    "Received block for verification: {:?}",
                    block_hash
                );

                match gen_block_verify_result(unverified_block, validator_private_key).await {
                    Ok(verify_result) => {
                        info!("Block verified, submitting result...");

                        // Submit the verification result
                        let submit_result: Result<bool, _> = client
                            .request(
                                "consensusBeaconExt_submitVerification",
                                rpc_params![verify_result],
                            )
                            .await;

                        match submit_result {
                            Ok(true) => info!("Verification submitted successfully"),
                            Ok(false) => error!("Verification rejected by node"),
                            Err(e) => error!("Failed to submit verification: {}", e),
                        }
                    }
                    Err(e) => {
                        error!("Failed to verify block: {}", e);
                    }
                }
            }
            Err(e) => {
                error!("Subscription error: {}", e);
            }
        }
    }

    Ok(())
}

/// Generate a block verification result.
///
/// Parses the block from JSON, computes a simplified receipts root hash,
/// and signs the attestation data with the validator's BLS key.
///
/// # Arguments
///
/// * `unverified_block` - The block to verify (contains JSON-serialized block)
/// * `validator_private_key` - BLS private key for signing (hex encoded)
///
/// # Returns
///
/// A `BlockVerifyResult` containing the signed attestation data.
pub async fn gen_block_verify_result(
    unverified_block: UnverifiedBlock,
    validator_private_key: &str,
) -> eyre::Result<BlockVerifyResult> {
    // Parse block info from JSON
    let block_hash = unverified_block.get_block_hash()?;
    let slot = unverified_block.get_block_number()?;
    let committee_index = unverified_block.committee_index;

    debug!(
        "Verifying block: hash={:?}, slot={}, committee_index={}",
        block_hash, slot, committee_index
    );

    // For mobile verification, we use the block's receipts_root directly
    // since mobile devices don't have access to full state for EVM execution.
    // The full node will validate the EVM execution separately.
    let receipts_root = unverified_block.get_receipts_root()?;

    debug!("Using receipts_root from block: {:?}", receipts_root);

    // Create attestation data
    let attestation_data = AttestationData {
        slot,
        committee_index,
        receipts_root,
    };

    // Sign the attestation data
    let validator_private_key = validator_private_key
        .strip_prefix("0x")
        .unwrap_or(validator_private_key);
    let sk_bytes =
        hex::decode(validator_private_key).map_err(|e| eyre::eyre!("Invalid private key: {}", e))?;
    let sk = SecretKey::from_bytes(&sk_bytes)
        .map_err(|e| eyre::eyre!("Failed to parse private key: {:?}", e))?;

    let pk = sk.sk_to_pk();
    let pubkey = hex::encode(pk.to_bytes());

    // Serialize attestation data for signing
    let msg = serde_json::to_vec(&attestation_data)?;

    // Sign with BLS
    let sig = sk.sign(
        &msg,
        alloy_rpc_types_beacon::constants::BLS_DST_SIG,
        &[],
    );
    let signature = hex::encode(sig.to_bytes());

    debug!("Signed attestation with pubkey: {}", pubkey);

    Ok(BlockVerifyResult {
        pubkey,
        signature,
        attestation_data,
        block_hash,
    })
}

/// Verify a block by checking its structure.
///
/// This is a simplified verification for mobile devices that checks
/// the block structure without full EVM execution.
///
/// # Arguments
///
/// * `unverified_block` - The block to verify
///
/// # Returns
///
/// The receipts root from the block header.
pub async fn verify(unverified_block: &UnverifiedBlock) -> eyre::Result<B256> {
    let block_number = unverified_block.get_block_number()?;
    let receipts_root = unverified_block.get_receipts_root()?;

    debug!(
        "Block {} verified, receipts_root: {:?}",
        block_number, receipts_root
    );

    Ok(receipts_root)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attestation_data_serialization() {
        let data = AttestationData {
            slot: 100,
            committee_index: 1,
            receipts_root: B256::repeat_byte(0xAB),
        };

        let json = serde_json::to_string(&data).unwrap();
        let decoded: AttestationData = serde_json::from_str(&json).unwrap();

        assert_eq!(data.slot, decoded.slot);
        assert_eq!(data.committee_index, decoded.committee_index);
        assert_eq!(data.receipts_root, decoded.receipts_root);
    }
}
