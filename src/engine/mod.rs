//! Engine API types and validation.
//!
//! This module implements custom Engine API types for N42 unified blocks:
//! - [`N42EngineTypes`]: Custom engine types without Block type restriction
//! - [`N42BuiltPayload`]: Built payload with unified block support
//! - [`PayloadValidator`]: Validates execution payloads from consensus layer

mod types;
mod validator;

pub use types::{N42BuiltPayload, N42EngineTypes, N42PayloadConversionError};
pub use validator::N42PayloadValidator;
