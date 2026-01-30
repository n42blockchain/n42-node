//! Clique proof-of-authority consensus engine implementation with BLS signatures.

use super::{
    database::SnapshotDatabase,
    error::CliqueError,
    snapshot::{CliqueConfig, HeaderData, Snapshot},
    CHECKPOINT_INTERVAL, DIFF_IN_TURN, DIFF_NO_TURN, EXTRA_SEAL, EXTRA_VANITY,
    INMEMORY_SIGNATURES, INMEMORY_SNAPSHOTS, NONCE_AUTH_VOTE, NONCE_DROP_VOTE,
};
use alloy_primitives::{keccak256, Address, B256};
use lru::LruCache;
use parking_lot::RwLock;
use std::{collections::HashMap, num::NonZeroUsize, sync::Arc, time::SystemTime};

/// BLS public key type (48 bytes).
pub type BLSPubkey = [u8; 48];

/// Chain header reader trait for accessing blockchain headers.
pub trait ChainHeaderReader: Send + Sync {
    /// Get the current chain configuration.
    fn config(&self) -> &ChainConfig;

    /// Get the current header.
    fn current_header(&self) -> Option<HeaderData>;

    /// Get header by hash and number.
    fn get_header(&self, hash: B256, number: u64) -> Option<HeaderData>;

    /// Get header by number.
    fn get_header_by_number(&self, number: u64) -> Option<HeaderData>;

    /// Get header by hash.
    fn get_header_by_hash(&self, hash: B256) -> Option<HeaderData>;
}

/// Minimal chain configuration for Clique.
#[derive(Debug, Clone, Default)]
pub struct ChainConfig {
    /// Maximum gas limit.
    pub max_gas_limit: u64,
}

/// Clique proof-of-authority consensus engine with BLS signatures.
pub struct Clique<DB: SnapshotDatabase> {
    /// Consensus engine configuration.
    config: CliqueConfig,

    /// Database to store and retrieve snapshot checkpoints.
    db: Arc<DB>,

    /// Snapshots for recent blocks to speed up reorgs.
    recents: RwLock<LruCache<B256, Snapshot>>,

    /// Signatures of recent blocks to speed up mining.
    signatures: RwLock<LruCache<B256, Address>>,

    /// Current list of proposals we are pushing.
    proposals: RwLock<HashMap<Address, bool>>,

    /// Ethereum address of the signing key.
    signer: RwLock<Option<Address>>,

    /// Mapping of addresses to BLS public keys for signature verification.
    pubkey_map: RwLock<HashMap<Address, BLSPubkey>>,

    /// Skip difficulty verifications (for testing).
    fake_diff: bool,
}

impl<DB: SnapshotDatabase> Clique<DB> {
    /// Create a new Clique consensus engine.
    pub fn new(config: CliqueConfig, db: Arc<DB>) -> Self {
        Self {
            config,
            db,
            recents: RwLock::new(LruCache::new(
                NonZeroUsize::new(INMEMORY_SNAPSHOTS).unwrap(),
            )),
            signatures: RwLock::new(LruCache::new(
                NonZeroUsize::new(INMEMORY_SIGNATURES).unwrap(),
            )),
            proposals: RwLock::new(HashMap::new()),
            signer: RwLock::new(None),
            pubkey_map: RwLock::new(HashMap::new()),
            fake_diff: false,
        }
    }

    /// Create a new Clique engine with fake difficulty (for testing).
    pub fn new_fake_diff(config: CliqueConfig, db: Arc<DB>) -> Self {
        let mut engine = Self::new(config, db);
        engine.fake_diff = true;
        engine
    }

    /// Get the configuration.
    pub fn config(&self) -> &CliqueConfig {
        &self.config
    }

    /// Authorize a signer.
    pub fn authorize(&self, signer: Address) {
        *self.signer.write() = Some(signer);
    }

    /// Register a validator's BLS public key.
    pub fn register_pubkey(&self, address: Address, pubkey: BLSPubkey) {
        self.pubkey_map.write().insert(address, pubkey);
    }

    /// Get the current signer.
    pub fn signer(&self) -> Option<Address> {
        *self.signer.read()
    }

    /// Propose to authorize or deauthorize an address.
    pub fn propose(&self, address: Address, authorize: bool) {
        self.proposals.write().insert(address, authorize);
    }

    /// Remove a proposal.
    pub fn discard(&self, address: Address) {
        self.proposals.write().remove(&address);
    }

    /// Verify the signature on a header and return the signer address.
    ///
    /// With BLS signatures, we cannot recover the signer from the signature.
    /// Instead, we try each known signer's public key until we find a match.
    pub fn ecrecover(&self, header: &HeaderData) -> Result<Address, CliqueError> {
        let hash = header.hash;

        // Check signature cache
        if let Some(address) = self.signatures.write().get(&hash) {
            return Ok(*address);
        }

        // Retrieve signature from extra-data
        let signature = header.signature()?;

        // Calculate seal hash (header hash without signature)
        let seal_hash = self.seal_hash(header);

        // Try to verify against known signers
        let pubkey_map = self.pubkey_map.read();
        for (address, pubkey) in pubkey_map.iter() {
            if self.verify_bls_signature(&seal_hash, signature, pubkey) {
                // Cache and return
                self.signatures.write().put(hash, *address);
                return Ok(*address);
            }
        }

        // If we have the coinbase address, try that as a hint
        if let Some(pubkey) = pubkey_map.get(&header.coinbase) {
            if self.verify_bls_signature(&seal_hash, signature, pubkey) {
                self.signatures.write().put(hash, header.coinbase);
                return Ok(header.coinbase);
            }
        }

        Err(CliqueError::SignatureRecoveryFailed {
            message: "No matching signer found for BLS signature".to_string(),
        })
    }

    /// Calculate the seal hash (hash of header without signature).
    pub fn seal_hash(&self, header: &HeaderData) -> B256 {
        // In go-ethereum, this is RLP encoding of header fields without signature
        // For simplicity, we'll hash the essential fields
        let mut data = Vec::new();
        data.extend_from_slice(header.parent_hash.as_slice());
        data.extend_from_slice(&header.number.to_be_bytes());
        data.extend_from_slice(&header.time.to_be_bytes());
        data.extend_from_slice(header.coinbase.as_slice());
        data.extend_from_slice(&header.difficulty.to_be_bytes());

        // Extra data without signature
        if header.extra.len() >= EXTRA_SEAL {
            data.extend_from_slice(&header.extra[..header.extra.len() - EXTRA_SEAL]);
        }

        keccak256(&data)
    }

    /// Verify a BLS signature.
    fn verify_bls_signature(&self, hash: &B256, signature: &[u8], pubkey: &BLSPubkey) -> bool {
        // Parse BLS public key
        let Ok(pk) = blst::min_pk::PublicKey::from_bytes(pubkey) else {
            return false;
        };

        // Parse BLS signature (96 bytes)
        let Ok(sig) = blst::min_pk::Signature::from_bytes(signature) else {
            return false;
        };

        // Verify
        let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
        sig.verify(true, hash.as_slice(), dst, &[], &pk, true) == blst::BLST_ERROR::BLST_SUCCESS
    }

    /// Retrieve the snapshot at a given point.
    pub fn snapshot<C: ChainHeaderReader>(
        &self,
        chain: &C,
        number: u64,
        hash: B256,
        parents: Option<&[HeaderData]>,
    ) -> Result<Snapshot, CliqueError> {
        let mut headers: Vec<HeaderData> = Vec::new();
        let mut current_number = number;
        let mut current_hash = hash;
        let mut snap: Option<Snapshot> = None;

        while snap.is_none() {
            // Check in-memory cache
            if let Some(s) = self.recents.write().get(&current_hash) {
                snap = Some(s.clone());
                break;
            }

            // Check on-disk checkpoint
            if current_number % CHECKPOINT_INTERVAL == 0 {
                if let Ok(Some(s)) = self.db.load_snapshot(current_hash) {
                    let mut loaded = s;
                    loaded.config = self.config;
                    snap = Some(loaded);
                    break;
                }
            }

            // At genesis or checkpoint, create new snapshot
            if current_number == 0
                || (current_number % self.config.epoch == 0 && headers.len() > 90000)
            {
                if let Some(checkpoint) = chain.get_header_by_number(current_number) {
                    let signers = checkpoint.checkpoint_signers()?;
                    let new_snap = Snapshot::new(
                        self.config,
                        current_number,
                        checkpoint.hash,
                        signers,
                    );

                    // Store to disk
                    let _ = self.db.store_snapshot(&new_snap);
                    snap = Some(new_snap);
                    break;
                }
            }

            // No snapshot found, gather header and move backward
            let header = if let Some(p) = parents {
                p.iter()
                    .find(|h| h.hash == current_hash && h.number == current_number)
                    .cloned()
            } else {
                chain.get_header(current_hash, current_number)
            };

            let Some(header) = header else {
                return Err(CliqueError::UnknownAncestor);
            };

            headers.push(header.clone());
            current_number = current_number.saturating_sub(1);
            current_hash = header.parent_hash;
        }

        let mut snap = snap.ok_or(CliqueError::UnknownBlock)?;

        // Apply headers in reverse order
        headers.reverse();
        if !headers.is_empty() {
            snap = snap.apply(&headers, |h| self.ecrecover(h))?;
        }

        // Cache the snapshot
        self.recents.write().put(snap.hash, snap.clone());

        // Store checkpoint to disk
        if snap.number % CHECKPOINT_INTERVAL == 0 && !headers.is_empty() {
            let _ = self.db.store_snapshot(&snap);
        }

        Ok(snap)
    }

    /// Verify a header conforms to consensus rules.
    pub fn verify_header<C: ChainHeaderReader>(
        &self,
        chain: &C,
        header: &HeaderData,
        parents: Option<&[HeaderData]>,
    ) -> Result<(), CliqueError> {
        // Don't waste time checking blocks from the future
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if header.time > now {
            return Err(CliqueError::FutureBlock {
                block_time: header.time,
                current_time: now,
            });
        }

        // Checkpoint blocks need to enforce zero beneficiary
        let checkpoint = (header.number % self.config.epoch) == 0;
        if checkpoint && header.coinbase != Address::ZERO {
            return Err(CliqueError::InvalidCheckpointBeneficiary);
        }

        // Nonces must be 0x00..0 or 0xff..f, zeroes enforced on checkpoints
        if header.nonce != NONCE_AUTH_VOTE && header.nonce != NONCE_DROP_VOTE {
            return Err(CliqueError::InvalidVote);
        }
        if checkpoint && header.nonce != NONCE_DROP_VOTE {
            return Err(CliqueError::InvalidCheckpointVote);
        }

        // Check extra-data contains vanity and signature
        if header.extra.len() < EXTRA_VANITY {
            return Err(CliqueError::MissingVanity);
        }
        if header.extra.len() < EXTRA_VANITY + EXTRA_SEAL {
            return Err(CliqueError::MissingSignature);
        }

        // Ensure extra-data contains signer list on checkpoint, but none otherwise
        let signers_bytes = header.extra.len() - EXTRA_VANITY - EXTRA_SEAL;
        if !checkpoint && signers_bytes != 0 {
            return Err(CliqueError::ExtraSigners);
        }
        if checkpoint && signers_bytes % 20 != 0 {
            return Err(CliqueError::InvalidCheckpointSigners);
        }

        // Ensure difficulty is valid
        if header.number > 0 {
            if header.difficulty != DIFF_IN_TURN && header.difficulty != DIFF_NO_TURN {
                return Err(CliqueError::InvalidDifficulty {
                    difficulty: header.difficulty,
                });
            }
        }

        // All basic checks passed, verify cascading fields
        self.verify_cascading_fields(chain, header, parents)
    }

    /// Verify cascading header fields.
    fn verify_cascading_fields<C: ChainHeaderReader>(
        &self,
        chain: &C,
        header: &HeaderData,
        parents: Option<&[HeaderData]>,
    ) -> Result<(), CliqueError> {
        let number = header.number;

        // Genesis block is always valid
        if number == 0 {
            return Ok(());
        }

        // Get parent header
        let parent = if let Some(p) = parents {
            p.last().cloned()
        } else {
            chain.get_header(header.parent_hash, number - 1)
        };

        let parent = parent.ok_or(CliqueError::UnknownAncestor)?;

        // Ensure timestamp is correct
        if parent.time + self.config.period > header.time {
            return Err(CliqueError::InvalidTimestamp {
                parent_time: parent.time,
                period: self.config.period,
                block_time: header.time,
            });
        }

        // Retrieve snapshot for validation
        let snap = self.snapshot(chain, number - 1, header.parent_hash, parents)?;

        // If checkpoint, verify signer list
        if number % self.config.epoch == 0 {
            let expected_signers = snap.signers_list();
            let checkpoint_signers = header.checkpoint_signers()?;

            if expected_signers != checkpoint_signers {
                return Err(CliqueError::MismatchingCheckpointSigners);
            }
        }

        // Verify seal
        self.verify_seal(&snap, header)
    }

    /// Verify the seal (signature) of a header.
    fn verify_seal(&self, snap: &Snapshot, header: &HeaderData) -> Result<(), CliqueError> {
        let number = header.number;

        // Genesis block has no seal
        if number == 0 {
            return Err(CliqueError::UnknownBlock);
        }

        // Resolve signer and check authorization
        let signer = self.ecrecover(header)?;

        if !snap.is_signer(&signer) {
            return Err(CliqueError::UnauthorizedSigner { signer });
        }

        // Check recent signers for spam protection
        for (&recent_block, &recent_signer) in &snap.recents {
            if recent_signer == signer {
                let limit = (snap.signer_count() / 2 + 1) as u64;
                if recent_block > number.saturating_sub(limit) {
                    return Err(CliqueError::RecentlySigned {
                        signer,
                        recent_block,
                    });
                }
            }
        }

        // Verify difficulty matches turn
        if !self.fake_diff {
            let inturn = snap.inturn(number, signer);
            let expected_diff = if inturn { DIFF_IN_TURN } else { DIFF_NO_TURN };

            if header.difficulty != expected_diff {
                return Err(CliqueError::WrongDifficulty {
                    signer,
                    block: number,
                    expected: expected_diff,
                    actual: header.difficulty,
                });
            }
        }

        Ok(())
    }

    /// Calculate difficulty for a new block.
    pub fn calc_difficulty<C: ChainHeaderReader>(
        &self,
        chain: &C,
        _time: u64,
        parent: &HeaderData,
    ) -> Result<u64, CliqueError> {
        let snap = self.snapshot(chain, parent.number, parent.hash, None)?;
        let signer = self.signer().ok_or(CliqueError::UnauthorizedSigner {
            signer: Address::ZERO,
        })?;

        Ok(snap.calc_difficulty(snap.number + 1, signer))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::clique::MemorySnapshotDatabase;

    fn test_config() -> CliqueConfig {
        CliqueConfig {
            period: 15,
            epoch: 30000,
        }
    }

    #[test]
    fn test_clique_creation() {
        let db = MemorySnapshotDatabase::new_arc();
        let engine = Clique::new(test_config(), db);

        assert_eq!(engine.config().period, 15);
        assert_eq!(engine.config().epoch, 30000);
        assert!(engine.signer().is_none());
    }

    #[test]
    fn test_authorize() {
        let db = MemorySnapshotDatabase::new_arc();
        let engine = Clique::new(test_config(), db);

        let signer = Address::repeat_byte(0x01);
        engine.authorize(signer);

        assert_eq!(engine.signer(), Some(signer));
    }

    #[test]
    fn test_proposals() {
        let db = MemorySnapshotDatabase::new_arc();
        let engine = Clique::new(test_config(), db);

        let addr = Address::repeat_byte(0x01);
        engine.propose(addr, true);

        {
            let proposals = engine.proposals.read();
            assert_eq!(proposals.get(&addr), Some(&true));
        }

        engine.discard(addr);

        {
            let proposals = engine.proposals.read();
            assert!(proposals.get(&addr).is_none());
        }
    }
}
