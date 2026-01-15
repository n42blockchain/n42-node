//! Clique snapshot - authorization voting state at a given point in time.

use super::{
    CliqueError, DIFF_IN_TURN, DIFF_NO_TURN, EXTRA_SEAL, EXTRA_VANITY,
    NONCE_AUTH_VOTE, NONCE_DROP_VOTE,
};
use alloy_primitives::{Address, B256, Bytes};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};

/// Clique configuration parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CliqueConfig {
    /// Number of seconds between blocks to enforce.
    pub period: u64,
    /// Epoch length to reset votes and checkpoint.
    pub epoch: u64,
}

impl Default for CliqueConfig {
    fn default() -> Self {
        Self {
            period: 15,
            epoch: 30000,
        }
    }
}

/// A single vote that an authorized signer made to modify the list of authorizations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vote {
    /// Authorized signer that cast this vote.
    pub signer: Address,
    /// Block number the vote was cast in.
    pub block: u64,
    /// Account being voted on to change its authorization.
    pub address: Address,
    /// Whether to authorize or deauthorize the voted account.
    pub authorize: bool,
}

/// Vote tally to keep the current score of votes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Tally {
    /// Whether the vote is about authorizing or kicking someone.
    pub authorize: bool,
    /// Number of votes wanting to pass the proposal.
    pub votes: usize,
}

/// Snapshot is the state of the authorization voting at a given point in time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    /// Consensus engine configuration.
    #[serde(skip)]
    pub config: CliqueConfig,

    /// Block number where the snapshot was created.
    pub number: u64,

    /// Block hash where the snapshot was created.
    pub hash: B256,

    /// Set of authorized signers at this moment.
    pub signers: BTreeSet<Address>,

    /// Set of recent signers for spam protection (block number -> signer).
    pub recents: HashMap<u64, Address>,

    /// List of votes cast in chronological order.
    pub votes: Vec<Vote>,

    /// Current vote tally to avoid recalculating.
    pub tally: HashMap<Address, Tally>,
}

impl Snapshot {
    /// Create a new snapshot with the specified startup parameters.
    ///
    /// This method does not initialize the set of recent signers,
    /// so only use it for the genesis block.
    pub fn new(
        config: CliqueConfig,
        number: u64,
        hash: B256,
        signers: Vec<Address>,
    ) -> Self {
        Self {
            config,
            number,
            hash,
            signers: signers.into_iter().collect(),
            recents: HashMap::new(),
            votes: Vec::new(),
            tally: HashMap::new(),
        }
    }

    /// Create a deep copy of the snapshot.
    pub fn copy(&self) -> Self {
        Self {
            config: self.config,
            number: self.number,
            hash: self.hash,
            signers: self.signers.clone(),
            recents: self.recents.clone(),
            votes: self.votes.clone(),
            tally: self.tally.clone(),
        }
    }

    /// Get the list of authorized signers in ascending order.
    pub fn signers_list(&self) -> Vec<Address> {
        self.signers.iter().copied().collect()
    }

    /// Check if an address is an authorized signer.
    pub fn is_signer(&self, address: &Address) -> bool {
        self.signers.contains(address)
    }

    /// Get the number of signers.
    pub fn signer_count(&self) -> usize {
        self.signers.len()
    }

    /// Check if a signer at a given block height is in-turn.
    pub fn inturn(&self, number: u64, signer: Address) -> bool {
        let signers: Vec<_> = self.signers.iter().copied().collect();
        if signers.is_empty() {
            return false;
        }

        let offset = signers.iter().position(|s| *s == signer).unwrap_or(0);
        (number % signers.len() as u64) == offset as u64
    }

    /// Calculate the expected difficulty for a signer at a given block.
    pub fn calc_difficulty(&self, number: u64, signer: Address) -> u64 {
        if self.inturn(number, signer) {
            DIFF_IN_TURN
        } else {
            DIFF_NO_TURN
        }
    }

    /// Check if it makes sense to cast the specified vote.
    pub fn valid_vote(&self, address: &Address, authorize: bool) -> bool {
        let is_signer = self.signers.contains(address);
        // Can only authorize non-signers or deauthorize signers
        (is_signer && !authorize) || (!is_signer && authorize)
    }

    /// Add a new vote into the tally.
    ///
    /// Returns true if the vote was counted.
    pub fn cast(&mut self, address: Address, authorize: bool) -> bool {
        if !self.valid_vote(&address, authorize) {
            return false;
        }

        let tally = self.tally.entry(address).or_insert(Tally {
            authorize,
            votes: 0,
        });
        tally.votes += 1;
        true
    }

    /// Remove a previously cast vote from the tally.
    ///
    /// Returns true if the vote was removed.
    pub fn uncast(&mut self, address: Address, authorize: bool) -> bool {
        let Some(tally) = self.tally.get_mut(&address) else {
            return false;
        };

        // Ensure we only revert counted votes
        if tally.authorize != authorize {
            return false;
        }

        if tally.votes > 1 {
            tally.votes -= 1;
        } else {
            self.tally.remove(&address);
        }
        true
    }

    /// Apply a list of headers to create a new snapshot.
    ///
    /// The `recover_signer` function is used to extract the signer from each header.
    pub fn apply<F>(
        &self,
        headers: &[HeaderData],
        recover_signer: F,
    ) -> Result<Snapshot, CliqueError>
    where
        F: Fn(&HeaderData) -> Result<Address, CliqueError>,
    {
        if headers.is_empty() {
            return Ok(self.clone());
        }

        // Sanity check that headers can be applied
        for i in 0..headers.len() - 1 {
            if headers[i + 1].number != headers[i].number + 1 {
                return Err(CliqueError::InvalidVotingChain);
            }
        }

        if headers[0].number != self.number + 1 {
            return Err(CliqueError::InvalidVotingChain);
        }

        let mut snap = self.copy();

        for header in headers {
            let number = header.number;

            // Remove any votes on checkpoint blocks
            if number % self.config.epoch == 0 {
                snap.votes.clear();
                snap.tally.clear();
            }

            // Delete the oldest signer from the recent list to allow it signing again
            let limit = (snap.signers.len() / 2 + 1) as u64;
            if number >= limit {
                snap.recents.remove(&(number - limit));
            }

            // Resolve the authorization key and check against signers
            let signer = recover_signer(header)?;

            if !snap.signers.contains(&signer) {
                return Err(CliqueError::UnauthorizedSigner { signer });
            }

            // Check if signer recently signed
            for (&recent_block, &recent_signer) in &snap.recents {
                if recent_signer == signer {
                    return Err(CliqueError::RecentlySigned {
                        signer,
                        recent_block,
                    });
                }
            }

            snap.recents.insert(number, signer);

            // Header authorized, discard any previous votes from the signer
            // First collect votes to uncast (to avoid borrow issues)
            let votes_to_uncast: Vec<_> = snap
                .votes
                .iter()
                .filter(|vote| vote.signer == signer && vote.address == header.coinbase)
                .map(|vote| (vote.address, vote.authorize))
                .collect();

            for (address, authorize) in votes_to_uncast {
                snap.uncast(address, authorize);
            }

            snap.votes
                .retain(|vote| !(vote.signer == signer && vote.address == header.coinbase));

            // Tally up the new vote from the signer
            let authorize = if header.nonce == NONCE_AUTH_VOTE {
                true
            } else if header.nonce == NONCE_DROP_VOTE {
                false
            } else {
                return Err(CliqueError::InvalidVote);
            };

            if snap.cast(header.coinbase, authorize) {
                snap.votes.push(Vote {
                    signer,
                    block: number,
                    address: header.coinbase,
                    authorize,
                });
            }

            // If the vote passed, update the list of signers
            if let Some(tally) = snap.tally.get(&header.coinbase) {
                if tally.votes > snap.signers.len() / 2 {
                    if tally.authorize {
                        snap.signers.insert(header.coinbase);
                    } else {
                        snap.signers.remove(&header.coinbase);

                        // Signer list shrunk, delete any leftover recent caches
                        let new_limit = (snap.signers.len() / 2 + 1) as u64;
                        if number >= new_limit {
                            snap.recents.remove(&(number - new_limit));
                        }

                        // Discard any previous votes the deauthorized signer cast
                        let removed_signer = header.coinbase;
                        let votes_to_uncast: Vec<_> = snap
                            .votes
                            .iter()
                            .filter(|vote| vote.signer == removed_signer)
                            .map(|vote| (vote.address, vote.authorize))
                            .collect();

                        for (address, authorize) in votes_to_uncast {
                            snap.uncast(address, authorize);
                        }

                        snap.votes.retain(|vote| vote.signer != removed_signer);
                    }

                    // Discard any previous votes around the just changed account
                    snap.votes.retain(|vote| vote.address != header.coinbase);
                    snap.tally.remove(&header.coinbase);
                }
            }
        }

        snap.number += headers.len() as u64;
        snap.hash = headers.last().unwrap().hash;

        Ok(snap)
    }
}

/// Minimal header data needed for snapshot processing.
#[derive(Debug, Clone)]
pub struct HeaderData {
    pub number: u64,
    pub hash: B256,
    pub parent_hash: B256,
    pub coinbase: Address,
    pub nonce: [u8; 8],
    pub extra: Bytes,
    pub time: u64,
    pub difficulty: u64,
}

impl HeaderData {
    /// Extract signers from checkpoint block extra-data.
    pub fn checkpoint_signers(&self) -> Result<Vec<Address>, CliqueError> {
        if self.extra.len() < EXTRA_VANITY + EXTRA_SEAL {
            return Err(CliqueError::MissingSignature);
        }

        let signers_bytes = &self.extra[EXTRA_VANITY..self.extra.len() - EXTRA_SEAL];
        if signers_bytes.len() % 20 != 0 {
            return Err(CliqueError::InvalidCheckpointSigners);
        }

        let signers: Vec<Address> = signers_bytes
            .chunks(20)
            .map(|chunk| Address::from_slice(chunk))
            .collect();

        Ok(signers)
    }

    /// Get the signature from extra-data.
    pub fn signature(&self) -> Result<&[u8], CliqueError> {
        if self.extra.len() < EXTRA_SEAL {
            return Err(CliqueError::MissingSignature);
        }
        Ok(&self.extra[self.extra.len() - EXTRA_SEAL..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> CliqueConfig {
        CliqueConfig {
            period: 15,
            epoch: 30000,
        }
    }

    #[test]
    fn test_snapshot_inturn() {
        let signers = vec![
            Address::repeat_byte(0x01),
            Address::repeat_byte(0x02),
            Address::repeat_byte(0x03),
        ];
        let snap = Snapshot::new(test_config(), 0, B256::ZERO, signers.clone());

        // Block 0: signer 0 is in-turn
        assert!(snap.inturn(0, signers[0]));
        assert!(!snap.inturn(0, signers[1]));
        assert!(!snap.inturn(0, signers[2]));

        // Block 1: signer 1 is in-turn
        assert!(!snap.inturn(1, signers[0]));
        assert!(snap.inturn(1, signers[1]));
        assert!(!snap.inturn(1, signers[2]));

        // Block 2: signer 2 is in-turn
        assert!(!snap.inturn(2, signers[0]));
        assert!(!snap.inturn(2, signers[1]));
        assert!(snap.inturn(2, signers[2]));

        // Block 3: signer 0 is in-turn (wraps around)
        assert!(snap.inturn(3, signers[0]));
    }

    #[test]
    fn test_snapshot_voting() {
        let signers = vec![
            Address::repeat_byte(0x01),
            Address::repeat_byte(0x02),
            Address::repeat_byte(0x03),
        ];
        let mut snap = Snapshot::new(test_config(), 0, B256::ZERO, signers);

        let new_signer = Address::repeat_byte(0x04);

        // Valid vote to add new signer
        assert!(snap.valid_vote(&new_signer, true));
        assert!(snap.cast(new_signer, true));
        assert_eq!(snap.tally.get(&new_signer).unwrap().votes, 1);

        // Second vote
        assert!(snap.cast(new_signer, true));
        assert_eq!(snap.tally.get(&new_signer).unwrap().votes, 2);

        // Uncast one vote
        assert!(snap.uncast(new_signer, true));
        assert_eq!(snap.tally.get(&new_signer).unwrap().votes, 1);

        // Invalid: can't deauthorize non-signer
        assert!(!snap.valid_vote(&new_signer, false));
    }

    #[test]
    fn test_calc_difficulty() {
        let signers = vec![
            Address::repeat_byte(0x01),
            Address::repeat_byte(0x02),
        ];
        let snap = Snapshot::new(test_config(), 0, B256::ZERO, signers.clone());

        // Signer 0 at block 0 is in-turn
        assert_eq!(snap.calc_difficulty(0, signers[0]), DIFF_IN_TURN);
        assert_eq!(snap.calc_difficulty(0, signers[1]), DIFF_NO_TURN);

        // Signer 1 at block 1 is in-turn
        assert_eq!(snap.calc_difficulty(1, signers[0]), DIFF_NO_TURN);
        assert_eq!(snap.calc_difficulty(1, signers[1]), DIFF_IN_TURN);
    }
}
