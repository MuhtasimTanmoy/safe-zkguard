// SPDX-License-Identifier: MIT

use alloy::{
    network::{EthereumWallet, TransactionBuilder},
    primitives::{Address, Bytes, U256},
    providers::{Provider, ProviderBuilder},
    rpc::types::TransactionRequest,
    signers::local::PrivateKeySigner,
    sol,
};
use alloy_sol_types::{SolCall, SolValue};
use anyhow::{Context, Result};
use tracing::{error, info};
use url::Url;
use zkguard_core::UserAction;

sol! {
    #[sol(rpc)]
    // Should match the interface of the ZKGuard Safe Module contract
    interface IZKGuardSafeModule {
        event VerifiedAndExecuted(
            address indexed safe,
            address indexed to,
            uint256 value,
            uint8 operation,
            bytes32 actionHash,
            bytes32 journalDigest
        );

        function verifyAndExec(
            bytes calldata userAction,
            bytes calldata seal,
            bytes calldata journal,
            uint8 operation
        ) external returns (bytes memory returnData);
    }
}

// Sends a transaction to the ZKGuard Safe Module contract to verify and execute
// a user action using the provided on-chain seal and journal.
pub async fn verify_onchain(
    private_key: &str,
    eth_rpc_url: &str,
    contract_address: &str,
    onchain_seal: Vec<u8>,
    onchain_journal: Vec<u8>,
    user_action: &UserAction,
) -> Result<(), anyhow::Error> {
    let private_key_signer = private_key.parse::<PrivateKeySigner>()?;
    let wallet = EthereumWallet::from(private_key_signer.clone());
    let rpc_url: Url = eth_rpc_url.parse()?;
    let provider = ProviderBuilder::new().wallet(wallet).on_http(rpc_url);

    let safe_address_str = std::env::var("SAFE_ADDRESS").expect("SAFE_ADDRESS must be set");
    let safe_address = safe_address_str.parse::<Address>()?;
    let from_addr = Address::from_slice(&user_action.from);
    let to_addr = Address::from_slice(&user_action.to);
    let val_u256 = U256::from(user_action.value);
    let nonce_u256 = U256::from(user_action.nonce);

    let abi_encoded_user_action = (
        from_addr,
        to_addr,
        val_u256,
        nonce_u256,
        Bytes::from(user_action.data.clone()),
    )
        .abi_encode_params();

    let calldata = IZKGuardSafeModule::verifyAndExecCall {
        userAction: abi_encoded_user_action.into(),
        seal: onchain_seal.into(),
        journal: onchain_journal.into(),
        operation: 0, // 0 = Call
    };

    info!("ZKGuard Module Address: {}", contract_address);
    let address_contract = contract_address.parse::<Address>()?;

    info!("Safe Address: {}", safe_address);

    let tx = TransactionRequest::default()
        .with_to(address_contract)
        .with_input(calldata.abi_encode());

    let estimate = provider.estimate_gas(tx.clone()).await?;
    let tx = tx.with_gas_limit((estimate as f64 * 1.125) as u64); // add 12.5% buffer

    let transaction_result = provider
        .send_transaction(tx)
        .await
        .context("Failed to send transaction")?;

    let tx_hash = transaction_result.tx_hash();
    info!("\nTransaction sent with hash: {} \n", tx_hash);

    let receipt = transaction_result.get_receipt().await?;
    info!("Transaction receipt: {:?}", receipt);

    // Check if the transaction was successful
    if receipt.status() {
        info!("Transaction succeeded");
    } else {
        error!("Transaction failed");
    }

    // Decode and log the VerifiedAndExecuted event
    if let Some(event) = receipt.decoded_log::<IZKGuardSafeModule::VerifiedAndExecuted>() {
        info!("VerifiedAndExecuted event found:");

        let IZKGuardSafeModule::VerifiedAndExecuted {
            safe,
            to,
            value,
            operation,
            actionHash,
            journalDigest,
        } = event.data;

        info!("  Safe: {}", safe);
        info!("  To: {}", to);
        info!("  Value: {}", value);
        info!("  Operation: {}", operation);
        info!("  ActionHash: {:?}", actionHash);
        info!("  JournalDigest: {:?}", journalDigest);
    } else {
        error!("VerifiedAndExecuted event not found in receipt logs");
    }

    Ok(())
}
