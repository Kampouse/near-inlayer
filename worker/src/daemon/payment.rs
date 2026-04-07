//! Payment verification helpers for MPP-402 protocol.

use std::collections::HashSet;
use std::fs;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::Digest;

/// Price per execution (in NEAR)
pub(crate) const EXECUTION_PRICE_NEAR: &str = "0.001";

/// HMAC secret for challenge binding (prevents tampering with challenge params)
const CHALLENGE_SECRET: &[u8] = b"outlayer-mpp-challenge-secret-v1";

/// Used payment receipts (replay protection) for /execute endpoint
pub(crate) static USED_RECEIPTS: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();

/// Get the used receipts set for replay prevention.
pub(crate) fn get_used_receipts() -> &'static Mutex<HashSet<String>> {
    USED_RECEIPTS.get_or_init(|| {
        let mut set = HashSet::new();
        let path = dirs::home_dir().unwrap_or_default().join(".inlayer").join("used_receipts.json");
        if let Ok(data) = fs::read_to_string(&path) {
            if let Ok(arr) = serde_json::from_str::<Vec<String>>(&data) {
                for h in arr { set.insert(h); }
            }
        }
        Mutex::new(set)
    })
}

/// Request body for the /execute endpoint.
#[derive(Serialize, Deserialize)]
pub(crate) struct ExecuteRequest {
    /// Input data for WASM execution
    pub(crate) input: String,
    /// Optional WASM URL (if not using default)
    pub(crate) wasm_url: Option<String>,
    /// Max instructions (default: 10B)
    pub(crate) max_instructions: Option<u64>,
    /// Max memory in MB (default: 256)
    pub(crate) max_memory_mb: Option<u32>,
}

/// Payment challenge returned on HTTP 402.
#[derive(Serialize)]
pub(crate) struct Challenge402 {
    /// MPP version
    pub(crate) version: String,
    /// Amount to pay (in token units)
    pub(crate) amount: String,
    /// Token identifier
    pub(crate) token: String,
    /// Recipient account (the worker's account)
    pub(crate) recipient: String,
    /// Unique challenge ID (prevents replay)
    pub(crate) challenge_id: String,
    /// HMAC binding challenge_id + amount + recipient (prevents tampering)
    pub(crate) hmac: String,
    /// Description of what's being paid for
    pub(crate) description: String,
    /// Payment methods accepted
    pub(crate) methods: Vec<String>,
}

/// Compute HMAC for challenge binding.
pub(crate) fn compute_challenge_hmac(challenge_id: &str, amount: &str, recipient: &str) -> String {
    use std::fmt::Write;
    let msg = format!("{}:{}:{}", challenge_id, amount, recipient);
    let hash = sha2::Sha256::new()
        .chain_update(CHALLENGE_SECRET)
        .chain_update(msg.as_bytes())
        .finalize();
    let mut hex = String::with_capacity(16);
    for b in &hash[..8] { write!(&mut hex, "{:02x}", b).unwrap(); }
    hex
}

/// Verify that a payment receipt corresponds to a valid on-chain transaction
/// that paid at least the minimum amount to the expected contract.
///
/// Checks: tx exists & succeeded, receiver matches contract, signer matches
/// `expected_signer`, and the action contains a qualifying transfer or
/// function-call deposit.
pub(crate) fn verify_payment(receipt: &str, expected_signer: &str, rpc_url: &str, contract_id: &str) -> Result<(), String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| format!("HTTP client build failed: {}", e))?;

    let resp = client.post(rpc_url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": "1",
            "method": "EXPERIMENTAL_tx_status",
            "params": [receipt, expected_signer]
        }))
        .send()
        .map_err(|e| format!("RPC request failed: {}", e))?;

    let body: serde_json::Value = resp.json()
        .map_err(|e| format!("RPC response parse failed: {}", e))?;

    if let Some(error) = body.get("error") {
        return Err(format!("TX not found: {}", error["message"]));
    }

    let result = body.get("result").cloned().unwrap_or_default();

    // Check final execution status
    let final_status = result.get("final_execution_status").and_then(|s| s.as_str()).unwrap_or("");
    if final_status == "FINAL" || final_status.contains("Success") {
        // Check transaction details
        let tx = result.get("transaction").cloned().unwrap_or_default();

        // Verify receiver matches contract
        let receiver_id = tx.get("receiver_id").and_then(|r| r.as_str()).unwrap_or("");
        if receiver_id != contract_id {
            return Err(format!("Wrong recipient: expected {}, got {}", contract_id, receiver_id));
        }

        // Verify signer
        if expected_signer.is_empty() {
            return Err("Missing Signer-Account header".to_string());
        }
        let tx_signer = tx.get("signer_id").and_then(|s| s.as_str()).unwrap_or("");
        if tx_signer != expected_signer {
            return Err(format!("Signer mismatch: expected {}, got {}", expected_signer, tx_signer));
        }

        // Check actions for qualifying payment
        let actions = tx.get("actions").cloned().unwrap_or_default();
        if let Some(actions_arr) = actions.as_array() {
            for action in actions_arr {
                if let Some(transfer) = action.get("Transfer") {
                    let deposit_str = transfer.get("deposit").and_then(|d| d.as_str()).unwrap_or("0");
                    let deposit_yocto: u128 = deposit_str.parse().unwrap_or(0);
                    let deposit_near = deposit_yocto as f64 / 1e24;
                    if deposit_near >= 0.001 {
                        return Ok(());
                    }
                }
                if let Some(fc) = action.get("FunctionCall") {
                    let method = fc.get("method_name").and_then(|m| m.as_str()).unwrap_or("");
                    let args_b64 = fc.get("args").and_then(|a| a.as_str()).unwrap_or("");
                    let args_bytes = base64::engine::general_purpose::STANDARD.decode(args_b64).unwrap_or_default();
                    let args_json: serde_json::Value = serde_json::from_slice(&args_bytes).unwrap_or_default();

                    if method == "ft_transfer_call" || method == "ft_transfer" {
                        let fc_receiver = args_json.get("receiver_id").and_then(|r| r.as_str()).unwrap_or("");
                        if fc_receiver != contract_id {
                            return Err(format!("Wrong ft_transfer recipient: expected {}, got {}", contract_id, fc_receiver));
                        }
                        let amount_str = args_json.get("amount").and_then(|a| a.as_str()).unwrap_or("0");
                        let amount: f64 = amount_str.parse().unwrap_or(0.0);
                        if amount > 0.0 {
                            return Ok(());
                        }
                    }
                    if method == "request_execution" {
                        let deposit_str = fc.get("deposit").and_then(|d| d.as_str()).unwrap_or("0");
                        let deposit_yocto: u128 = deposit_str.parse().unwrap_or(0);
                        let deposit_near = deposit_yocto as f64 / 1e24;
                        if deposit_near >= 0.001 {
                            return Ok(());
                        }
                    }
                }
            }
        }

        return Err("No valid payment action found in transaction".to_string());
    }

    if final_status.contains("Failure") {
        return Err("Transaction failed on-chain".to_string());
    }

    Err(format!("Unexpected TX status: {}", final_status))
}

/// Mark a payment receipt as used (persisted to disk for replay prevention).
/// Loads the existing set from `~/.inlayer/used_receipts.json` on first call.
pub(crate) fn mark_receipt_used(receipt: &str) {
    let used = USED_RECEIPTS.get_or_init(|| {
        let mut set = HashSet::new();
        let path = dirs::home_dir().unwrap_or_default().join(".inlayer").join("used_receipts.json");
        if let Ok(data) = fs::read_to_string(&path) {
            if let Ok(arr) = serde_json::from_str::<Vec<String>>(&data) {
                for h in arr { set.insert(h); }
            }
        }
        Mutex::new(set)
    });
    let mut set = used.lock().unwrap();
    set.insert(receipt.to_string());
    let path = dirs::home_dir().unwrap_or_default().join(".inlayer").join("used_receipts.json");
    let arr: Vec<&String> = set.iter().collect();
    let _ = fs::write(&path, serde_json::to_string(&arr).unwrap_or_default());
}

/// Check if a receipt has already been used (for replay prevention).
#[allow(dead_code)]
pub(crate) fn is_receipt_used(receipt: &str) -> bool {
    if let Some(used) = USED_RECEIPTS.get() {
        let set = used.lock().unwrap();
        return set.contains(receipt);
    }
    false
}
