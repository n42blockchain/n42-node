//! Deposit and exit transaction builders for mobile SDK.
//!
//! Provides functions for creating unsigned transactions for:
//! - Validator deposits to the deposit contract
//! - Validator exits via the EIP-7002 withdrawal request contract
//!
//! These transactions are returned unsigned so the mobile app can
//! sign them with the user's wallet.

use alloy_primitives::{Address, Bytes, FixedBytes, B256, U256};
use blst::min_pk::SecretKey;
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::pos::beacon::DepositData;

/// Default deposit contract addresses
pub const DEVNET_DEPOSIT_CONTRACT_ADDRESS: &str = "0x5FbDB2315678afecb367f032d93F642f64180aa3";
pub const TESTNET_DEPOSIT_CONTRACT_ADDRESS: &str = "0x4242424242424242424242424242424242424242";

/// EIP-7002 withdrawal request contract address
pub const EIP7002_CONTRACT_ADDRESS: &str = "0x00000961Ef480Eb55e80D19ad83579A64c007002";

/// Unsigned transaction request.
///
/// This struct contains all the data needed to build a transaction,
/// but without the signature. The mobile app should sign this
/// with the user's wallet.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UnsignedTransactionRequest {
    /// Destination address
    pub to: Option<Address>,
    /// Transaction data (calldata)
    pub data: Option<Bytes>,
    /// ETH value to send
    pub value: Option<U256>,
    /// Gas limit
    pub gas: Option<u64>,
}

/// Create an unsigned deposit transaction.
///
/// Creates a transaction that deposits ETH to the deposit contract
/// to register a new validator.
///
/// # Arguments
///
/// * `deposit_contract_address` - Address of the deposit contract
/// * `validator_private_key` - BLS private key for the validator (hex)
/// * `withdrawal_address` - ETH1 address for withdrawals (hex)
/// * `deposit_value_in_wei` - Amount to deposit in wei
///
/// # Returns
///
/// An unsigned transaction request to be signed by the user's wallet.
pub fn create_deposit_unsigned_tx(
    deposit_contract_address: &str,
    validator_private_key: &str,
    withdrawal_address: &str,
    deposit_value_in_wei: &U256,
) -> eyre::Result<UnsignedTransactionRequest> {
    // Parse withdrawal address
    let addr_hex = withdrawal_address
        .strip_prefix("0x")
        .unwrap_or(withdrawal_address);
    let addr_bytes = hex::decode(addr_hex)
        .map_err(|e| eyre::eyre!("invalid withdrawal_address: {}", e))?;
    if addr_bytes.len() != 20 {
        return Err(eyre::eyre!(
            "withdrawal_address must be 20 bytes, got {} bytes",
            addr_bytes.len()
        ));
    }
    let addr = Address::from_slice(&addr_bytes);

    // Create withdrawal credentials (ETH1 style: 0x01 prefix)
    let creds = withdrawal_credentials(&addr);
    debug!("withdrawal_credentials: 0x{}", hex::encode(&creds));

    // Parse validator private key
    let validator_private_key = validator_private_key
        .strip_prefix("0x")
        .unwrap_or(validator_private_key);
    let sk = SecretKey::from_bytes(&hex::decode(validator_private_key)?)
        .map_err(|e| eyre::eyre!("SecretKey::from_bytes() error {:?}", e))?;
    let pk = sk.sk_to_pk();

    debug!("pubkey: {:?}", hex::encode(pk.to_bytes()));

    // Create deposit data
    let mut deposit_data = DepositData {
        pubkey: FixedBytes(pk.to_bytes()),
        withdrawal_credentials: creds,
        signature: Default::default(),
        // Amount in Gwei (divide wei by 10^9)
        amount: (*deposit_value_in_wei / U256::from(1_000_000_000u64))
            .try_into()
            .unwrap_or(0),
    };

    // Sign the deposit data
    deposit_data.signature = deposit_data.create_signature(&sk);

    debug!("signed deposit: {:?}", deposit_data);

    // Compute deposit data root using tree hash
    let root = tree_hash::TreeHash::tree_hash_root(&deposit_data);
    debug!("deposit_data_root: {:?}", root);

    // Encode function call: deposit(bytes,bytes,bytes,bytes32)
    let selector = &alloy_primitives::keccak256(b"deposit(bytes,bytes,bytes,bytes32)")[0..4];

    // ABI encode parameters
    let mut calldata = selector.to_vec();

    // Encode each parameter with offset headers
    let pubkey_bytes = pk.to_bytes().to_vec();
    let creds_bytes = deposit_data.withdrawal_credentials.to_vec();
    let sig_bytes = deposit_data.signature.to_vec();
    let root_bytes = root.to_vec();

    // Calculate offsets (4 params * 32 bytes each = 128 bytes header)
    let header_size = 128u64;
    let pubkey_offset = header_size;
    let creds_offset = pubkey_offset + 32 + ((pubkey_bytes.len() + 31) / 32 * 32) as u64;
    let sig_offset = creds_offset + 32 + ((creds_bytes.len() + 31) / 32 * 32) as u64;

    // Write offsets
    calldata.extend_from_slice(&encode_u256(U256::from(pubkey_offset)));
    calldata.extend_from_slice(&encode_u256(U256::from(creds_offset)));
    calldata.extend_from_slice(&encode_u256(U256::from(sig_offset)));
    calldata.extend_from_slice(&root_bytes);

    // Write dynamic data
    calldata.extend_from_slice(&encode_bytes(&pubkey_bytes));
    calldata.extend_from_slice(&encode_bytes(&creds_bytes));
    calldata.extend_from_slice(&encode_bytes(&sig_bytes));

    // Parse contract address
    let contract_address: Address = deposit_contract_address.parse()?;

    debug!("deposit_value_in_wei: {:?}", deposit_value_in_wei);

    let tx = UnsignedTransactionRequest {
        to: Some(contract_address),
        data: Some(Bytes::from(calldata)),
        value: Some(*deposit_value_in_wei),
        gas: Some(300_000),
    };

    debug!("deposit Unsigned tx: {:?}", tx);

    Ok(tx)
}

/// Create an unsigned transaction to query the exit fee.
///
/// # Returns
///
/// An unsigned transaction request that can be used with eth_call
/// to get the current exit fee from the EIP-7002 contract.
pub fn create_get_exit_fee_unsigned_tx() -> eyre::Result<UnsignedTransactionRequest> {
    let contract_address: Address = EIP7002_CONTRACT_ADDRESS.parse()?;

    let tx = UnsignedTransactionRequest {
        to: Some(contract_address),
        data: Some(Bytes::new()),
        value: None,
        gas: None,
    };

    debug!("get_exit_fee Unsigned tx: {:?}", tx);

    Ok(tx)
}

/// Create an unsigned exit transaction.
///
/// Creates a transaction that requests a validator exit via the
/// EIP-7002 withdrawal request contract.
///
/// # Arguments
///
/// * `validator_public_key` - BLS public key of the validator (hex)
/// * `fee` - Optional exit fee in wei (query with create_get_exit_fee_unsigned_tx)
///
/// # Returns
///
/// An unsigned transaction request to be signed by the user's wallet.
pub fn create_exit_unsigned_tx(
    validator_public_key: &str,
    fee: &Option<U256>,
) -> eyre::Result<UnsignedTransactionRequest> {
    let contract_address: Address = EIP7002_CONTRACT_ADDRESS.parse()?;

    // Parse public key
    let pubkey_hex = validator_public_key
        .strip_prefix("0x")
        .unwrap_or(validator_public_key);
    let pubkey_bytes =
        hex::decode(pubkey_hex).map_err(|e| eyre::eyre!("invalid validator_public_key: {}", e))?;

    // Build calldata: pubkey (48 bytes) + amount (8 bytes, 0 for full exit)
    let mut data = Vec::with_capacity(56);
    data.extend_from_slice(&pubkey_bytes);
    data.extend_from_slice(&0u64.to_be_bytes()); // amount = 0 for full exit

    let tx = UnsignedTransactionRequest {
        to: Some(contract_address),
        data: Some(Bytes::from(data)),
        value: Some(fee.unwrap_or(U256::from(1))),
        gas: None,
    };

    debug!("exit Unsigned tx: {:?}", tx);

    Ok(tx)
}

/// Create withdrawal credentials from an address.
///
/// Uses ETH1 withdrawal credentials format (0x01 prefix).
fn withdrawal_credentials(withdrawal_address: &Address) -> B256 {
    let mut credentials = [0u8; 32];
    credentials[0] = 0x01;
    credentials[12..].copy_from_slice(withdrawal_address.as_slice());
    B256::from(credentials)
}

/// ABI encode a U256 as 32 bytes.
fn encode_u256(value: U256) -> [u8; 32] {
    value.to_be_bytes()
}

/// ABI encode bytes with length prefix and padding.
fn encode_bytes(data: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::new();

    // Length as U256
    encoded.extend_from_slice(&encode_u256(U256::from(data.len())));

    // Data with padding to 32 bytes
    encoded.extend_from_slice(data);
    let padding = (32 - (data.len() % 32)) % 32;
    encoded.extend(vec![0u8; padding]);

    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_deposit_unsigned_tx_0x_prefix_hex_inputs_ok() {
        let deposit_contract_address = DEVNET_DEPOSIT_CONTRACT_ADDRESS;
        let validator_private_key =
            "0x6be6c38a5986be6c7094e92017af0d15da0af6857362e2ba0c2103c3eb893eec";
        let withdrawal_address = "0xa0Ee7A142d267C1f36714E4a8F75612F20a79720";
        let deposit_value_in_wei = U256::from(32_000_000_000_000_000_000u128); // 32 ETH

        let result = create_deposit_unsigned_tx(
            deposit_contract_address,
            validator_private_key,
            withdrawal_address,
            &deposit_value_in_wei,
        );
        assert!(result.is_ok());

        let tx = result.unwrap();
        assert!(tx.to.is_some());
        assert!(tx.data.is_some());
        assert_eq!(tx.value, Some(deposit_value_in_wei));
        assert_eq!(tx.gas, Some(300_000));
    }

    #[test]
    fn test_create_exit_unsigned_tx_0x_prefix_hex_inputs_ok() {
        let validator_public_key =
            "0x8a2470d8ccb2e43b3b5295cfee71508f8808e166e5f152d5af9fe022d95e300dc7c5814f2c9eb71e2da8412beb61c53a";
        let exit_fee_in_wei = U256::from(1);

        let result = create_exit_unsigned_tx(validator_public_key, &Some(exit_fee_in_wei));
        assert!(result.is_ok());

        let tx = result.unwrap();
        assert!(tx.to.is_some());
        assert!(tx.data.is_some());
        assert_eq!(tx.value, Some(exit_fee_in_wei));
    }

    #[test]
    fn test_create_deposit_unsigned_tx_no_0x_prefix_hex_inputs_ok() {
        let deposit_contract_address = "5FbDB2315678afecb367f032d93F642f64180aa3";
        let validator_private_key =
            "6be6c38a5986be6c7094e92017af0d15da0af6857362e2ba0c2103c3eb893eec";
        let withdrawal_address = "a0Ee7A142d267C1f36714E4a8F75612F20a79720";
        let deposit_value_in_wei = U256::from(32_000_000_000_000_000_000u128);

        let result = create_deposit_unsigned_tx(
            deposit_contract_address,
            validator_private_key,
            withdrawal_address,
            &deposit_value_in_wei,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_create_exit_unsigned_tx_no_0x_prefix_hex_inputs_ok() {
        let validator_public_key =
            "8a2470d8ccb2e43b3b5295cfee71508f8808e166e5f152d5af9fe022d95e300dc7c5814f2c9eb71e2da8412beb61c53a";
        let exit_fee_in_wei = U256::from(1);

        let result = create_exit_unsigned_tx(validator_public_key, &Some(exit_fee_in_wei));
        assert!(result.is_ok());
    }

    #[test]
    fn test_create_deposit_invalid_inputs_no_panic() {
        let result = create_deposit_unsigned_tx("x", "", "", &U256::ZERO);
        assert!(result.is_err());

        let result = create_deposit_unsigned_tx(
            DEVNET_DEPOSIT_CONTRACT_ADDRESS,
            "invalid_key",
            "",
            &U256::ZERO,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_create_exit_unsigned_tx_invalid_inputs_no_panic() {
        let result = create_exit_unsigned_tx("invalid_pubkey", &None);
        assert!(result.is_err());
    }

    #[test]
    fn test_get_exit_fee_tx() {
        let result = create_get_exit_fee_unsigned_tx();
        assert!(result.is_ok());

        let tx = result.unwrap();
        assert!(tx.to.is_some());
        assert_eq!(tx.data, Some(Bytes::new()));
    }

    #[test]
    fn test_withdrawal_credentials() {
        let addr = Address::repeat_byte(0xAB);
        let creds = withdrawal_credentials(&addr);

        assert_eq!(creds[0], 0x01);
        assert_eq!(&creds[12..], addr.as_slice());
    }
}
