//! Android JNI bindings for mobile SDK.
//!
//! Provides native methods for Android apps to:
//! - Generate BLS key pairs
//! - Create deposit and exit transactions
//! - Run the verification client
//! - Generate block verification results
//!
//! # Java Interface
//!
//! ```java
//! package com.mobileSdk;
//!
//! public class NativeBindings {
//!     static { System.loadLibrary("n42_mobile"); }
//!
//!     public static native String createDepositUnsignedTx(
//!         String depositContractAddress,
//!         String validatorPrivateKey,
//!         String withdrawalAddress,
//!         String depositValueWeiHex
//!     );
//!
//!     public static native String generateBls12381Keypair();
//!     public static native String createGetExitFeeUnsignedTx();
//!     public static native String createExitUnsignedTx(String validatorPublicKey, String feeInWeiHex);
//!     public static native CompletableFuture<Void> runClient(String wsUrl, String validatorPrivateKey);
//!     public static native CompletableFuture<String> genBlockVerifyResult(String blockJson, String validatorPrivateKey);
//! }
//! ```

use alloy_primitives::U256;
use jni::objects::{GlobalRef, JClass, JObject, JString, JValue};
use jni::sys::{jobject, jstring};
use jni::JNIEnv;
use once_cell::sync::Lazy;
use tokio::runtime::Runtime;

use crate::mobile_sdk::blst_utils::generate_bls12_381_keypair;
use crate::mobile_sdk::deposit_exit::{
    create_deposit_unsigned_tx, create_exit_unsigned_tx, create_get_exit_fee_unsigned_tx,
};
use crate::mobile_sdk::{gen_block_verify_result, run_client};
use crate::pos::beacon::UnverifiedBlock;

/// Global Tokio runtime for async operations
static RUNTIME: Lazy<Runtime> =
    Lazy::new(|| Runtime::new().expect("Failed to create Tokio runtime"));

/// Create an unsigned deposit transaction.
///
/// # Safety
///
/// This function is called from Java via JNI.
#[unsafe(no_mangle)]
pub extern "C" fn Java_com_mobileSdk_NativeBindings_createDepositUnsignedTx(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    deposit_contract_address: JString<'_>,
    validator_private_key: JString<'_>,
    withdrawal_address: JString<'_>,
    deposit_value_wei_in_hex: JString<'_>,
) -> jstring {
    let deposit_contract_address: String = match env.get_string(&deposit_contract_address) {
        Ok(s) => s.into(),
        Err(e) => {
            let _ = env.throw_new("java/lang/Exception", e.to_string());
            return std::ptr::null_mut();
        }
    };

    let validator_private_key: String = match env.get_string(&validator_private_key) {
        Ok(s) => s.into(),
        Err(e) => {
            let _ = env.throw_new("java/lang/Exception", e.to_string());
            return std::ptr::null_mut();
        }
    };

    let withdrawal_address: String = match env.get_string(&withdrawal_address) {
        Ok(s) => s.into(),
        Err(e) => {
            let _ = env.throw_new("java/lang/Exception", e.to_string());
            return std::ptr::null_mut();
        }
    };

    let deposit_value_wei_in_hex: String = match env.get_string(&deposit_value_wei_in_hex) {
        Ok(s) => s.into(),
        Err(e) => {
            let _ = env.throw_new("java/lang/Exception", e.to_string());
            return std::ptr::null_mut();
        }
    };

    let deposit_value_wei: U256 = match deposit_value_wei_in_hex.parse() {
        Ok(v) => v,
        Err(e) => {
            let _ = env.throw_new("java/lang/Exception", e.to_string());
            return std::ptr::null_mut();
        }
    };

    let transaction_request = match create_deposit_unsigned_tx(
        &deposit_contract_address,
        &validator_private_key,
        &withdrawal_address,
        &deposit_value_wei,
    ) {
        Ok(v) => v,
        Err(e) => {
            let _ = env.throw_new("java/lang/Exception", e.to_string());
            return std::ptr::null_mut();
        }
    };

    let json_string = match serde_json::to_string(&transaction_request) {
        Ok(v) => v,
        Err(e) => {
            let _ = env.throw_new("java/lang/Exception", e.to_string());
            return std::ptr::null_mut();
        }
    };

    match env.new_string(&json_string) {
        Ok(s) => s.into_raw(),
        Err(e) => {
            let _ = env.throw_new("java/lang/Exception", e.to_string());
            std::ptr::null_mut()
        }
    }
}

/// Generate a new BLS12-381 key pair.
///
/// # Safety
///
/// This function is called from Java via JNI.
#[unsafe(no_mangle)]
pub extern "C" fn Java_com_mobileSdk_NativeBindings_generateBls12381Keypair(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jstring {
    let key_pair = match generate_bls12_381_keypair() {
        Ok(v) => v,
        Err(e) => {
            let _ = env.throw_new("java/lang/Exception", e.to_string());
            return std::ptr::null_mut();
        }
    };

    let json_string = match serde_json::to_string(&key_pair) {
        Ok(v) => v,
        Err(e) => {
            let _ = env.throw_new("java/lang/Exception", e.to_string());
            return std::ptr::null_mut();
        }
    };

    match env.new_string(&json_string) {
        Ok(s) => s.into_raw(),
        Err(e) => {
            let _ = env.throw_new("java/lang/Exception", e.to_string());
            std::ptr::null_mut()
        }
    }
}

/// Create an unsigned transaction to query exit fee.
///
/// # Safety
///
/// This function is called from Java via JNI.
#[unsafe(no_mangle)]
pub extern "C" fn Java_com_mobileSdk_NativeBindings_createGetExitFeeUnsignedTx(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jstring {
    let transaction_request = match create_get_exit_fee_unsigned_tx() {
        Ok(v) => v,
        Err(e) => {
            let _ = env.throw_new("java/lang/Exception", e.to_string());
            return std::ptr::null_mut();
        }
    };

    let json_string = match serde_json::to_string(&transaction_request) {
        Ok(v) => v,
        Err(e) => {
            let _ = env.throw_new("java/lang/Exception", e.to_string());
            return std::ptr::null_mut();
        }
    };

    match env.new_string(&json_string) {
        Ok(s) => s.into_raw(),
        Err(e) => {
            let _ = env.throw_new("java/lang/Exception", e.to_string());
            std::ptr::null_mut()
        }
    }
}

/// Create an unsigned exit transaction.
///
/// # Safety
///
/// This function is called from Java via JNI.
#[unsafe(no_mangle)]
pub extern "C" fn Java_com_mobileSdk_NativeBindings_createExitUnsignedTx(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    validator_public_key: JString<'_>,
    exit_fee_in_wei_in_hex: JString<'_>,
) -> jstring {
    let validator_public_key: String = match env.get_string(&validator_public_key) {
        Ok(s) => s.into(),
        Err(e) => {
            let _ = env.throw_new("java/lang/Exception", e.to_string());
            return std::ptr::null_mut();
        }
    };

    let fee = if !exit_fee_in_wei_in_hex.is_null() {
        let exit_fee_in_wei_in_hex: String = match env.get_string(&exit_fee_in_wei_in_hex) {
            Ok(s) => s.into(),
            Err(e) => {
                let _ = env.throw_new("java/lang/Exception", e.to_string());
                return std::ptr::null_mut();
            }
        };

        match exit_fee_in_wei_in_hex.parse::<U256>() {
            Ok(v) => Some(v),
            Err(e) => {
                let _ = env.throw_new("java/lang/Exception", e.to_string());
                return std::ptr::null_mut();
            }
        }
    } else {
        None
    };

    let transaction_request = match create_exit_unsigned_tx(&validator_public_key, &fee) {
        Ok(v) => v,
        Err(e) => {
            let _ = env.throw_new("java/lang/Exception", e.to_string());
            return std::ptr::null_mut();
        }
    };

    let json_string = match serde_json::to_string(&transaction_request) {
        Ok(v) => v,
        Err(e) => {
            let _ = env.throw_new("java/lang/Exception", e.to_string());
            return std::ptr::null_mut();
        }
    };

    match env.new_string(&json_string) {
        Ok(s) => s.into_raw(),
        Err(e) => {
            let _ = env.throw_new("java/lang/Exception", e.to_string());
            std::ptr::null_mut()
        }
    }
}

/// Run the verification client.
///
/// Returns a CompletableFuture that completes when the client stops.
///
/// # Safety
///
/// This function is called from Java via JNI.
#[unsafe(no_mangle)]
pub extern "C" fn Java_com_mobileSdk_NativeBindings_runClient(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    ws_url: JString<'_>,
    validator_private_key: JString<'_>,
) -> jobject {
    let ws_url: String = match env.get_string(&ws_url) {
        Ok(s) => s.into(),
        Err(e) => {
            let _ = env.throw_new("java/lang/Exception", e.to_string());
            return std::ptr::null_mut();
        }
    };

    let validator_private_key: String = match env.get_string(&validator_private_key) {
        Ok(s) => s.into(),
        Err(e) => {
            let _ = env.throw_new("java/lang/Exception", e.to_string());
            return std::ptr::null_mut();
        }
    };

    // Create a new CompletableFuture object in Java
    let cf_class = match env.find_class("java/util/concurrent/CompletableFuture") {
        Ok(c) => c,
        Err(e) => {
            let _ = env.throw_new("java/lang/Exception", e.to_string());
            return std::ptr::null_mut();
        }
    };

    let cf_obj = match env.new_object(cf_class, "()V", &[]) {
        Ok(o) => o,
        Err(e) => {
            let _ = env.throw_new("java/lang/Exception", e.to_string());
            return std::ptr::null_mut();
        }
    };

    // Promote CompletableFuture to a global ref so it outlives this JNI call
    let global_cf: GlobalRef = match env.new_global_ref(&cf_obj) {
        Ok(g) => g,
        Err(e) => {
            let _ = env.throw_new("java/lang/Exception", e.to_string());
            return std::ptr::null_mut();
        }
    };

    let jvm = match env.get_java_vm() {
        Ok(v) => v,
        Err(e) => {
            let _ = env.throw_new("java/lang/Exception", e.to_string());
            return std::ptr::null_mut();
        }
    };

    // Spawn async task
    RUNTIME.spawn(async move {
        let result = run_client(&ws_url, &validator_private_key).await;

        // Attach thread to JVM to call back into Java
        let mut env = match jvm.attach_current_thread() {
            Ok(e) => e,
            Err(_) => return,
        };

        match result {
            Ok(()) => {
                let _ = env.call_method(
                    &global_cf,
                    "complete",
                    "(Ljava/lang/Object;)Z",
                    &[(&JObject::null()).into()],
                );
            }
            Err(e) => {
                if let Ok(jmsg) = env.new_string(e.to_string()) {
                    if let Ok(ex_class) = env.find_class("java/lang/RuntimeException") {
                        if let Ok(ex_obj) = env.new_object(
                            ex_class,
                            "(Ljava/lang/String;)V",
                            &[(&jmsg).into()],
                        ) {
                            let _ = env.call_method(
                                &global_cf,
                                "completeExceptionally",
                                "(Ljava/lang/Throwable;)Z",
                                &[(&JObject::from(ex_obj)).into()],
                            );
                        }
                    }
                }
            }
        }
    });

    cf_obj.into_raw()
}

/// Generate a block verification result.
///
/// Returns a CompletableFuture that resolves to JSON string of BlockVerifyResult.
///
/// # Safety
///
/// This function is called from Java via JNI.
#[unsafe(no_mangle)]
pub extern "C" fn Java_com_mobileSdk_NativeBindings_genBlockVerifyResult(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    block: JString<'_>,
    validator_private_key: JString<'_>,
) -> jobject {
    let block_json: String = match env.get_string(&block) {
        Ok(s) => s.into(),
        Err(e) => {
            let _ = env.throw_new("java/lang/Exception", e.to_string());
            return std::ptr::null_mut();
        }
    };

    let block: UnverifiedBlock = match serde_json::from_str(&block_json) {
        Ok(v) => v,
        Err(e) => {
            let _ = env.throw_new("java/lang/Exception", e.to_string());
            return std::ptr::null_mut();
        }
    };

    let validator_private_key: String = match env.get_string(&validator_private_key) {
        Ok(s) => s.into(),
        Err(e) => {
            let _ = env.throw_new("java/lang/Exception", e.to_string());
            return std::ptr::null_mut();
        }
    };

    // Create CompletableFuture
    let cf_class = match env.find_class("java/util/concurrent/CompletableFuture") {
        Ok(c) => c,
        Err(e) => {
            let _ = env.throw_new("java/lang/Exception", e.to_string());
            return std::ptr::null_mut();
        }
    };

    let cf_obj = match env.new_object(cf_class, "()V", &[]) {
        Ok(o) => o,
        Err(e) => {
            let _ = env.throw_new("java/lang/Exception", e.to_string());
            return std::ptr::null_mut();
        }
    };

    let global_cf: GlobalRef = match env.new_global_ref(&cf_obj) {
        Ok(g) => g,
        Err(e) => {
            let _ = env.throw_new("java/lang/Exception", e.to_string());
            return std::ptr::null_mut();
        }
    };

    let jvm = match env.get_java_vm() {
        Ok(v) => v,
        Err(e) => {
            let _ = env.throw_new("java/lang/Exception", e.to_string());
            return std::ptr::null_mut();
        }
    };

    // Spawn async task
    RUNTIME.spawn(async move {
        let result = gen_block_verify_result(block, &validator_private_key).await;

        let mut env = match jvm.attach_current_thread() {
            Ok(e) => e,
            Err(_) => return,
        };

        match result {
            Ok(block_verify_result) => {
                let json_string = match serde_json::to_string(&block_verify_result) {
                    Ok(v) => v,
                    Err(e) => {
                        if let Ok(jmsg) = env.new_string(e.to_string()) {
                            if let Ok(ex_class) = env.find_class("java/lang/RuntimeException") {
                                if let Ok(ex_obj) = env.new_object(
                                    ex_class,
                                    "(Ljava/lang/String;)V",
                                    &[(&jmsg).into()],
                                ) {
                                    let _ = env.call_method(
                                        &global_cf,
                                        "completeExceptionally",
                                        "(Ljava/lang/Throwable;)Z",
                                        &[(&JObject::from(ex_obj)).into()],
                                    );
                                }
                            }
                        }
                        return;
                    }
                };

                if let Ok(java_string) = env.new_string(&json_string) {
                    let _ = env.call_method(
                        &global_cf,
                        "complete",
                        "(Ljava/lang/Object;)Z",
                        &[JValue::Object(&java_string.into())],
                    );
                }
            }
            Err(e) => {
                if let Ok(jmsg) = env.new_string(e.to_string()) {
                    if let Ok(ex_class) = env.find_class("java/lang/RuntimeException") {
                        if let Ok(ex_obj) = env.new_object(
                            ex_class,
                            "(Ljava/lang/String;)V",
                            &[(&jmsg).into()],
                        ) {
                            let _ = env.call_method(
                                &global_cf,
                                "completeExceptionally",
                                "(Ljava/lang/Throwable;)Z",
                                &[(&JObject::from(ex_obj)).into()],
                            );
                        }
                    }
                }
            }
        }
    });

    cf_obj.into_raw()
}
