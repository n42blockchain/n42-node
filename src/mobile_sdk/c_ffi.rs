//! iOS C FFI bindings for mobile SDK.
//!
//! Provides C-compatible functions for iOS apps (Swift/Objective-C) to:
//! - Generate BLS key pairs
//! - Create deposit and exit transactions
//! - Run the verification client
//! - Generate block verification results
//!
//! # Swift Usage
//!
//! ```swift
//! // Generate keypair
//! var error: UnsafeMutablePointer<CChar>?
//! let keypair = generate_bls12_381_keypair_c(&error)
//! if keypair != nil {
//!     let result = String(cString: keypair!)
//!     rust_free_string(keypair)
//! } else if error != nil {
//!     let errorMsg = String(cString: error!)
//!     rust_free_string(error)
//! }
//! ```

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;

use alloy_primitives::U256;

use crate::mobile_sdk::blst_utils::generate_bls12_381_keypair;
use crate::mobile_sdk::deposit_exit::{
    create_deposit_unsigned_tx, create_exit_unsigned_tx, create_get_exit_fee_unsigned_tx,
};
use crate::mobile_sdk::{gen_block_verify_result, run_client};
use crate::pos::beacon::UnverifiedBlock;

// ============================================================================
// Helper functions
// ============================================================================

/// Convert a C string to a Rust String.
fn cstr_to_string(c: *const c_char) -> Result<String, String> {
    if c.is_null() {
        return Err("null pointer".into());
    }
    unsafe {
        CStr::from_ptr(c)
            .to_str()
            .map(|s| s.to_owned())
            .map_err(|e| format!("utf8 error: {}", e))
    }
}

/// Convert a Rust String to a C string (caller must free with rust_free_string).
fn make_c_string(s: String) -> *mut c_char {
    CString::new(s).unwrap().into_raw()
}

/// Free a string allocated by Rust.
///
/// Call this function to free any string returned by the Rust functions.
///
/// # Safety
///
/// The pointer must have been allocated by Rust (returned from one of these functions).
#[unsafe(no_mangle)]
pub extern "C" fn rust_free_string(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    unsafe {
        drop(CString::from_raw(s));
    }
}

// ============================================================================
// Client functions
// ============================================================================

/// Run the verification client (blocking).
///
/// # Arguments
///
/// * `ws_url` - WebSocket URL (C string)
/// * `validator_private_key` - BLS private key (C string, hex)
/// * `out_error` - Output pointer for error message (caller must free with rust_free_string)
///
/// # Returns
///
/// 0 on success, -1 on error.
///
/// # Safety
///
/// All pointers must be valid C strings or null.
#[unsafe(no_mangle)]
pub extern "C" fn run_client_c(
    ws_url: *const c_char,
    validator_private_key: *const c_char,
    out_error: *mut *mut c_char,
) -> i32 {
    let set_error = |msg: String| {
        if !out_error.is_null() {
            unsafe {
                *out_error = make_c_string(msg);
            }
        }
    };

    let ws = match cstr_to_string(ws_url) {
        Ok(s) => s,
        Err(e) => {
            set_error(e);
            return -1;
        }
    };

    let pk = match cstr_to_string(validator_private_key) {
        Ok(s) => s,
        Err(e) => {
            set_error(e);
            return -1;
        }
    };

    // Run the async function blocking
    let res = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(run_client(&ws, &pk));

    match res {
        Ok(()) => 0,
        Err(e) => {
            set_error(format!("{}", e));
            -1
        }
    }
}

/// Generate a block verification result (blocking).
///
/// # Arguments
///
/// * `block` - Block JSON (C string)
/// * `validator_private_key` - BLS private key (C string, hex)
/// * `out_error` - Output pointer for error message
///
/// # Returns
///
/// JSON string of BlockVerifyResult (caller must free), or null on error.
///
/// # Safety
///
/// All pointers must be valid C strings or null.
#[unsafe(no_mangle)]
pub extern "C" fn gen_block_verify_result_c(
    block: *const c_char,
    validator_private_key: *const c_char,
    out_error: *mut *mut c_char,
) -> *mut c_char {
    let set_error = |msg: String| {
        if !out_error.is_null() {
            unsafe {
                *out_error = make_c_string(msg);
            }
        }
    };

    let block_json = match cstr_to_string(block) {
        Ok(s) => s,
        Err(e) => {
            set_error(e);
            return ptr::null_mut();
        }
    };

    let block: UnverifiedBlock = match serde_json::from_str(&block_json) {
        Ok(v) => v,
        Err(e) => {
            set_error(format!("{}", e));
            return ptr::null_mut();
        }
    };

    let pk = match cstr_to_string(validator_private_key) {
        Ok(s) => s,
        Err(e) => {
            set_error(e);
            return ptr::null_mut();
        }
    };

    // Run the async function blocking
    let res = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(gen_block_verify_result(block, &pk));

    match res {
        Ok(block_verify_result) => match serde_json::to_string(&block_verify_result) {
            Ok(v) => make_c_string(v),
            Err(e) => {
                set_error(format!("{}", e));
                ptr::null_mut()
            }
        },
        Err(e) => {
            set_error(format!("{}", e));
            ptr::null_mut()
        }
    }
}

// ============================================================================
// Key generation
// ============================================================================

/// Generate a BLS12-381 key pair.
///
/// # Arguments
///
/// * `out_error` - Output pointer for error message
///
/// # Returns
///
/// JSON string of (private_key, public_key) tuple (caller must free), or null on error.
///
/// # Safety
///
/// out_error can be null.
#[unsafe(no_mangle)]
pub extern "C" fn generate_bls12_381_keypair_c(out_error: *mut *mut c_char) -> *mut c_char {
    let set_error = |msg: String| {
        if !out_error.is_null() {
            unsafe {
                *out_error = make_c_string(msg);
            }
        }
    };

    match generate_bls12_381_keypair() {
        Ok(keypair) => match serde_json::to_string(&keypair) {
            Ok(v) => make_c_string(v),
            Err(e) => {
                set_error(format!("{}", e));
                ptr::null_mut()
            }
        },
        Err(e) => {
            set_error(format!("{}", e));
            ptr::null_mut()
        }
    }
}

// ============================================================================
// Transaction builders
// ============================================================================

/// Create an unsigned deposit transaction.
///
/// # Arguments
///
/// * `deposit_contract_address` - Contract address (C string, hex)
/// * `validator_private_key` - BLS private key (C string, hex)
/// * `withdrawal_address` - Withdrawal address (C string, hex)
/// * `deposit_value_in_wei` - Deposit amount (C string, hex or decimal)
/// * `out_error` - Output pointer for error message
///
/// # Returns
///
/// JSON string of transaction request (caller must free), or null on error.
///
/// # Safety
///
/// All pointers must be valid C strings or null.
#[unsafe(no_mangle)]
pub extern "C" fn create_deposit_unsigned_tx_c(
    deposit_contract_address: *const c_char,
    validator_private_key: *const c_char,
    withdrawal_address: *const c_char,
    deposit_value_in_wei: *const c_char,
    out_error: *mut *mut c_char,
) -> *mut c_char {
    let set_error = |msg: String| {
        if !out_error.is_null() {
            unsafe {
                *out_error = make_c_string(msg);
            }
        }
    };

    let addr = match cstr_to_string(deposit_contract_address) {
        Ok(s) => s,
        Err(e) => {
            set_error(e);
            return ptr::null_mut();
        }
    };

    let pk = match cstr_to_string(validator_private_key) {
        Ok(s) => s,
        Err(e) => {
            set_error(e);
            return ptr::null_mut();
        }
    };

    let wd = match cstr_to_string(withdrawal_address) {
        Ok(s) => s,
        Err(e) => {
            set_error(e);
            return ptr::null_mut();
        }
    };

    let val_str = match cstr_to_string(deposit_value_in_wei) {
        Ok(s) => s,
        Err(e) => {
            set_error(e);
            return ptr::null_mut();
        }
    };

    let value: U256 = match val_str.parse() {
        Ok(v) => v,
        Err(e) => {
            set_error(format!("invalid deposit value: {}", e));
            return ptr::null_mut();
        }
    };

    match create_deposit_unsigned_tx(&addr, &pk, &wd, &value) {
        Ok(tx) => match serde_json::to_string(&tx) {
            Ok(v) => make_c_string(v),
            Err(e) => {
                set_error(format!("{}", e));
                ptr::null_mut()
            }
        },
        Err(e) => {
            set_error(format!("{}", e));
            ptr::null_mut()
        }
    }
}

/// Create an unsigned transaction to query exit fee.
///
/// # Arguments
///
/// * `out_error` - Output pointer for error message
///
/// # Returns
///
/// JSON string of transaction request (caller must free), or null on error.
///
/// # Safety
///
/// out_error can be null.
#[unsafe(no_mangle)]
pub extern "C" fn create_get_exit_fee_unsigned_tx_c(out_error: *mut *mut c_char) -> *mut c_char {
    let set_error = |msg: String| {
        if !out_error.is_null() {
            unsafe {
                *out_error = make_c_string(msg);
            }
        }
    };

    match create_get_exit_fee_unsigned_tx() {
        Ok(tx) => match serde_json::to_string(&tx) {
            Ok(v) => make_c_string(v),
            Err(e) => {
                set_error(format!("{}", e));
                ptr::null_mut()
            }
        },
        Err(e) => {
            set_error(format!("{}", e));
            ptr::null_mut()
        }
    }
}

/// Create an unsigned exit transaction.
///
/// # Arguments
///
/// * `validator_public_key` - BLS public key (C string, hex)
/// * `fee_in_wei_or_empty` - Exit fee (C string, hex or decimal), or null/empty for default
/// * `out_error` - Output pointer for error message
///
/// # Returns
///
/// JSON string of transaction request (caller must free), or null on error.
///
/// # Safety
///
/// All pointers must be valid C strings or null.
#[unsafe(no_mangle)]
pub extern "C" fn create_exit_unsigned_tx_c(
    validator_public_key: *const c_char,
    fee_in_wei_or_empty: *const c_char,
    out_error: *mut *mut c_char,
) -> *mut c_char {
    let set_error = |msg: String| {
        if !out_error.is_null() {
            unsafe {
                *out_error = make_c_string(msg);
            }
        }
    };

    let pubkey = match cstr_to_string(validator_public_key) {
        Ok(s) => s,
        Err(e) => {
            set_error(e);
            return ptr::null_mut();
        }
    };

    let fee_opt = if fee_in_wei_or_empty.is_null() {
        None
    } else {
        match cstr_to_string(fee_in_wei_or_empty) {
            Ok(s) if s.is_empty() => None,
            Ok(s) => match s.parse::<U256>() {
                Ok(v) => Some(v),
                Err(e) => {
                    set_error(format!("invalid fee: {}", e));
                    return ptr::null_mut();
                }
            },
            Err(e) => {
                set_error(e);
                return ptr::null_mut();
            }
        }
    };

    match create_exit_unsigned_tx(&pubkey, &fee_opt) {
        Ok(tx) => match serde_json::to_string(&tx) {
            Ok(v) => make_c_string(v),
            Err(e) => {
                set_error(format!("{}", e));
                ptr::null_mut()
            }
        },
        Err(e) => {
            set_error(format!("{}", e));
            ptr::null_mut()
        }
    }
}

// ============================================================================
// C Header generation (for cbindgen)
// ============================================================================

/// C header declarations for the mobile SDK.
///
/// These can be used with cbindgen to generate a C header file:
/// ```bash
/// cbindgen --config cbindgen.toml --crate n42-node --output n42_mobile.h
/// ```
#[cfg(feature = "cbindgen")]
pub mod cbindgen_header {
    //! Header declarations for C/Swift interop.
    //!
    //! ```c
    //! // n42_mobile.h
    //! void rust_free_string(char *s);
    //!
    //! int run_client_c(const char *ws_url, const char *validator_private_key, char **out_error);
    //!
    //! char *gen_block_verify_result_c(const char *block, const char *validator_private_key, char **out_error);
    //!
    //! char *generate_bls12_381_keypair_c(char **out_error);
    //!
    //! char *create_deposit_unsigned_tx_c(
    //!     const char *deposit_contract_address,
    //!     const char *validator_private_key,
    //!     const char *withdrawal_address,
    //!     const char *deposit_value_in_wei,
    //!     char **out_error
    //! );
    //!
    //! char *create_get_exit_fee_unsigned_tx_c(char **out_error);
    //!
    //! char *create_exit_unsigned_tx_c(
    //!     const char *validator_public_key,
    //!     const char *fee_in_wei_or_empty,
    //!     char **out_error
    //! );
    //! ```
}
