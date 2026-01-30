//! POS (Proof of Stake) implementation for N42.
//!
//! This module provides a complete POS consensus implementation with:
//! - BeaconState with VecTree storage for efficient validator management
//! - BLS signature verification
//! - Committee shuffling and attestation handling
//! - Withdrawal processing
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    POS Module Structure                      │
//! ├─────────────────────────────────────────────────────────────┤
//! │  beacon.rs       - BeaconState, PosBeaconBlock, Attestation │
//! │  validator.rs    - Validator struct with BLS pubkey         │
//! │  committee_cache - Committee shuffling and caching          │
//! │  shuffle_list    - Shuffling algorithm                      │
//! │  safe_arith      - Safe arithmetic operations               │
//! └─────────────────────────────────────────────────────────────┘
//! ```

pub mod beacon;
pub mod validator;
pub mod committee_cache;
pub mod shuffle_list;
pub mod beacon_committee;
pub mod attestation_duty;
pub mod activation_queue;
pub mod safe_arith;

// Re-export commonly used types
pub use beacon::{
    BeaconState,
    PosBeaconBlock,
    PosBeaconBlockBody,
    Attestation,
    AttestationData,
    Deposit,
    DepositData,
    DepositMessage,
    VoluntaryExit,
    VoluntaryExitWithSig,
    Eth1Data,
    ChainSpec,
    beacon_chain_spec,
    Epoch,
    Gwei,
    BLSPubkey,
    BLSSignature,
    SLOTS_PER_EPOCH,
    DOMAIN_CONSTANT_BEACON_ATTESTER,
    SignedRoot,
    is_compounding_withdrawal_credential,
    RelativeEpoch,
};

pub use validator::{
    Validator,
    ValidatorInfo,
    ValidatorBeforeTx,
    ValidatorChangeset,
    ValidatorRevert,
};

pub use committee_cache::CommitteeCache;
pub use beacon_committee::{BeaconCommittee, OwnedBeaconCommittee};
pub use attestation_duty::AttestationDuty;
pub use activation_queue::ActivationQueue;

// Type aliases
pub type Hash256 = alloy_primitives::B256;
pub type Slot = u64;
pub type CommitteeIndex = u64;
