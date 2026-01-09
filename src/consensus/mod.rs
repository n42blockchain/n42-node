//! POA (Proof of Authority) Consensus for N42.
//!
//! This module implements a round-robin POA consensus algorithm:
//!
//! # Algorithm
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    POA Round-Robin                          │
//! ├─────────────────────────────────────────────────────────────┤
//! │                                                             │
//! │  Validators: [V0, V1, V2, V3]                               │
//! │  Block Interval: 8 seconds                                  │
//! │                                                             │
//! │  Slot 0 → V0 (in-turn, difficulty=2)                        │
//! │  Slot 1 → V1 (in-turn, difficulty=2)                        │
//! │  Slot 2 → V2 (in-turn, difficulty=2)                        │
//! │  Slot 3 → V3 (in-turn, difficulty=2)                        │
//! │  Slot 4 → V0 (in-turn, difficulty=2)                        │
//! │  ...                                                        │
//! │                                                             │
//! │  If V1 misses slot 1:                                       │
//! │  - V2 can produce with difficulty=1 (out-of-turn)           │
//! │  - Chain follows longest chain + highest difficulty         │
//! │                                                             │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Components
//!
//! - [`PoaConfig`]: Configuration (validators, block time)
//! - [`PoaValidator`]: Validates block authority and difficulty
//! - [`PoaWorker`]: Produces blocks when it's our turn
//! - [`BeaconState`]: Simplified beacon state for POA
//! - [`state_transition`]: State transition and block validation

mod config;
pub mod state;
pub mod state_transition;
mod validator;
mod worker;

pub use config::{PoaConfig, ValidatorSet};
pub use state::{
    compute_domain, compute_signing_root, public_key_to_address, BeaconBlockHeaderLight,
    BeaconState, BeaconValidator, Checkpoint, DomainType,
};
pub use state_transition::{
    process_block, sign_beacon_block, StateTransitionConfig, StateTransitionError,
    StateTransitionResult,
};
pub use validator::{
    get_difficulty_from_graffiti, set_difficulty_in_graffiti, PoaValidationError, PoaValidator,
};
pub use worker::{
    PoaWorker, PoaWorkerBuilder, PoaWorkerCommand, PoaWorkerConfig, PoaWorkerEvent,
    PoaWorkerHandle,
};

/// In-turn difficulty value (when it's the validator's assigned slot)
pub const DIFFICULTY_IN_TURN: u64 = 2;

/// Out-of-turn difficulty value (backup validator)
pub const DIFFICULTY_OUT_OF_TURN: u64 = 1;

/// Default block time in seconds
pub const DEFAULT_BLOCK_TIME: u64 = 8;
