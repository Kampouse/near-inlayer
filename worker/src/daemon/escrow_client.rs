//! Escrow client — claims tasks, writes results to FastNear KV,
//! submits KV references to the escrow contract, and waits for settlement.
//!
//! The escrow contract is the payment arbiter. It knows nothing about WASM,
//! KV, or inlayer. This module is the bridge: it reads escrow state, claims
//! open jobs, writes work results to KV, and submits the KV reference back
//! to the escrow contract for verification.

use std::time::Duration;

use anyhow::{bail, Context, Result};
use near_crypto::InMemorySigner;

use super::nonce::NonceCache;
use super::{rpc_pool, send_function_call};

// ── Constants ───────────────────────────────────────────────────────────

/// Gas for claim() — simple state transition, no cross-contract call.
const GAS_CLAIM: u64 = 50_000_000_000_000; // 50 Tgas

/// Gas for submit_result() — triggers yield/resume, needs more headroom.
const GAS_SUBMIT_RESULT: u64 = 100_000_000_000_000; // 100 Tgas

/// Default worker stake: 0.1 NEAR in yoctoNEAR.
const DEFAULT_WORKER_STAKE_YOCTO: u128 = 100_000_000_000_000_000_000_000;

/// How long to wait between poll attempts.
const POLL_INTERVAL: Duration = Duration::from_secs(10);

// ── Escrow status strings (must match contract's EscrowStatus enum) ─────

mod status {
    pub const PENDING_FUNDING: &str = "PendingFunding";
    pub const OPEN: &str = "Open";
    pub const IN_PROGRESS: &str = "InProgress";
    pub const VERIFYING: &str = "Verifying";
    pub const CLAIMED: &str = "Claimed";
    pub const REFUNDED: &str = "Refunded";
    pub const CANCELLED: &str = "Cancelled";
    pub const SETTLEMENT_FAILED: &str = "SettlementFailed";
}

/// Terminal statuses — job is done, no more polling needed.
pub(crate) fn is_terminal(status: &str) -> bool {
    matches!(
        status,
        status::CLAIMED | status::REFUNDED | status::CANCELLED | status::SETTLEMENT_FAILED
    )
}

// ── Escrow view (from get_escrow) ───────────────────────────────────────

#[derive(Debug, Clone, serde::Deserialize)]
pub struct EscrowView {
    pub job_id: String,
    pub status: String,
    pub task_description: String,
    pub criteria: String,
    pub result: Option<String>,
    #[serde(default = "default_threshold")]
    pub score_threshold: u8,
}

pub(crate) fn default_threshold() -> u8 {
    80
}

// ── KV reference (stored in escrow result field) ────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KvReference {
    /// Account that received the __fastdata_kv call (e.g. "kv.kampouse.near")
    pub kv_account: String,
    /// Account that made the __fastdata_kv call (the daemon's NEAR account)
    pub kv_predecessor: String,
    /// Key under which the result was stored (e.g. "result/job-42")
    pub kv_key: String,
}

impl KvReference {
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("KvReference serializes")
    }
}

// ── Public API ──────────────────────────────────────────────────────────

/// Fetch escrow state from the contract.
pub fn get_escrow(rpc: &rpc_pool::Rpc, escrow_contract: &str, job_id: &str) -> Result<EscrowView> {
    let args = serde_json::json!({"job_id": job_id});
    let bytes = rpc.view(escrow_contract, "get_escrow", args.to_string().as_bytes())?;
    if bytes.is_empty() {
        bail!("escrow {} not found", job_id);
    }
    // get_escrow returns Option<EscrowView> — serde handles it
    let opt: Option<EscrowView> =
        serde_json::from_slice(&bytes).context("failed to parse EscrowView")?;
    opt.ok_or_else(|| anyhow::anyhow!("escrow {} not found", job_id))
}

/// Poll the escrow contract until the job reaches Open status.
/// Returns the EscrowView once open, or errors on timeout.
pub fn poll_until_open(
    rpc: &rpc_pool::Rpc,
    escrow_contract: &str,
    job_id: &str,
    timeout: Duration,
) -> Result<EscrowView> {
    let start = std::time::Instant::now();
    loop {
        let escrow = get_escrow(rpc, escrow_contract, job_id)?;

        match escrow.status.as_str() {
            status::OPEN => {
                tracing::info!("[escrow] {} is Open — ready to claim", job_id);
                return Ok(escrow);
            }
            status::PENDING_FUNDING => {
                if start.elapsed() > timeout {
                    bail!(
                        "[escrow] {} still PendingFunding after {}s — timed out",
                        job_id,
                        timeout.as_secs()
                    );
                }
                tracing::debug!(
                    "[escrow] {} PendingFunding, waiting... ({:.0}s elapsed)",
                    job_id,
                    start.elapsed().as_secs_f64()
                );
            }
            s if is_terminal(s) => {
                bail!(
                    "[escrow] {} reached terminal state '{}' before opening",
                    job_id,
                    s
                );
            }
            other => {
                bail!(
                    "[escrow] {} unexpected status '{}' (expected PendingFunding or Open)",
                    job_id,
                    other
                );
            }
        }

        std::thread::sleep(POLL_INTERVAL);
    }
}

/// Claim an open escrow on behalf of the worker.
/// The signer's NEAR account becomes the worker on-chain.
/// Requires 0.1 NEAR attached deposit as anti-spam stake.
pub fn claim(
    rpc_url: &str,
    signer: &InMemorySigner,
    escrow_contract: &str,
    job_id: &str,
    stake_yocto: u128,
    nonce_cache: &NonceCache,
) -> Result<(String, Option<serde_json::Value>)> {
    tracing::info!(
        "[escrow] claiming {} (stake: {} yocto)",
        job_id,
        stake_yocto
    );
    let args = serde_json::json!({"job_id": job_id});
    send_function_call(
        rpc_url,
        signer,
        escrow_contract,
        "claim",
        &args,
        GAS_CLAIM,
        stake_yocto,
        nonce_cache,
    )
}

/// Claim an open escrow via worker's multisig.
/// The worker pre-signs the claim action, daemon relays it via msig.execute().
/// The worker's msig becomes the worker on-chain — real skin in the game.
pub fn claim_via_msig(
    rpc_url: &str,
    daemon_signer: &InMemorySigner,
    worker_msig: &str,
    claim_action_json: &str,
    claim_sig_bytes: &[u8],
    nonce_cache: &NonceCache,
) -> Result<(String, Option<serde_json::Value>)> {
    tracing::info!(
        "[escrow] claiming via worker msig {} ({} byte action)",
        worker_msig,
        claim_action_json.len()
    );
    let execute_args = serde_json::json!({
        "action_json": claim_action_json,
        "signature": claim_sig_bytes,
    });
    send_function_call(
        rpc_url,
        daemon_signer,
        worker_msig,
        "execute",
        &execute_args,
        GAS_CLAIM,
        0, // deposit already in the signed action
        nonce_cache,
    )
}

/// Submit a result to the escrow contract.
/// The `result` string is stored on-chain and triggers yield/resume verification.
/// For KV-based results, pass the KvReference JSON here.
pub fn submit_result(
    rpc_url: &str,
    signer: &InMemorySigner,
    escrow_contract: &str,
    job_id: &str,
    result: &str,
    nonce_cache: &NonceCache,
) -> Result<(String, Option<serde_json::Value>)> {
    tracing::info!(
        "[escrow] submitting result for {} ({} bytes)",
        job_id,
        result.len()
    );
    let args = serde_json::json!({
        "job_id": job_id,
        "result": result,
    });
    send_function_call(
        rpc_url,
        signer,
        escrow_contract,
        "submit_result",
        &args,
        GAS_SUBMIT_RESULT,
        0, // no deposit
        nonce_cache,
    )
}

/// Submit a result via worker's multisig.
/// The worker pre-signs the submit_result action (with deterministic kv_reference),
/// daemon relays it via msig.execute(). Worker's msig is the caller on-chain.
pub fn submit_result_via_msig(
    rpc_url: &str,
    daemon_signer: &InMemorySigner,
    worker_msig: &str,
    submit_action_json: &str,
    submit_sig_bytes: &[u8],
    nonce_cache: &NonceCache,
) -> Result<(String, Option<serde_json::Value>)> {
    tracing::info!(
        "[escrow] submitting result via worker msig {} ({} byte action)",
        worker_msig,
        submit_action_json.len()
    );
    let execute_args = serde_json::json!({
        "action_json": submit_action_json,
        "signature": submit_sig_bytes,
    });
    send_function_call(
        rpc_url,
        daemon_signer,
        worker_msig,
        "execute",
        &execute_args,
        GAS_SUBMIT_RESULT,
        0,
        nonce_cache,
    )
}

/// Write a key-value pair to FastNear KV via __fastdata_kv contract call.
/// The target account doesn't need a contract deployed — FastNear indexes
/// the data from the transaction itself.
///
/// Read back via HTTP: GET https://kv.main.fastnear.com/v0/latest/{kv_account}/{predecessor}/{key}
pub fn write_kv(
    rpc_url: &str,
    signer: &InMemorySigner,
    kv_account: &str,
    key: &str,
    value: &str,
    nonce_cache: &NonceCache,
) -> Result<String> {
    tracing::info!(
        "[kv] writing key '{}' to {} ({} bytes)",
        key,
        kv_account,
        value.len()
    );

    // __fastdata_kv takes { entries: [{ key, value }] }
    let args = serde_json::json!({
        "entries": [{ "key": key, "value": value }]
    });

    let (tx_hash, _) = send_function_call(
        rpc_url,
        signer,
        kv_account,
        "__fastdata_kv",
        &args,
        50_000_000_000_000, // 50 Tgas — simple KV write
        0,                  // no deposit
        nonce_cache,
    )?;

    tracing::info!("[kv] written ✓ tx={}", tx_hash);
    Ok(tx_hash)
}

/// Poll the escrow contract until it reaches a terminal state.
/// Returns the final EscrowView.
pub fn wait_for_settlement(
    rpc: &rpc_pool::Rpc,
    escrow_contract: &str,
    job_id: &str,
    timeout: Duration,
) -> Result<EscrowView> {
    let start = std::time::Instant::now();
    loop {
        let escrow = get_escrow(rpc, escrow_contract, job_id)?;

        if is_terminal(&escrow.status) {
            tracing::info!(
                "[escrow] {} settled: {} ({:.0}s)",
                job_id,
                escrow.status,
                start.elapsed().as_secs_f64()
            );
            return Ok(escrow);
        }

        if start.elapsed() > timeout {
            bail!(
                "[escrow] {} still {} after {}s — timed out waiting for settlement",
                job_id,
                escrow.status,
                timeout.as_secs()
            );
        }

        tracing::debug!(
            "[escrow] {} status={}, waiting for settlement... ({:.0}s elapsed)",
            job_id,
            escrow.status,
            start.elapsed().as_secs_f64()
        );

        std::thread::sleep(POLL_INTERVAL);
    }
}

// ── Convenience: full escrow flow for a single job ──────────────────────

/// Result of a completed escrow job.
#[derive(Debug)]
pub struct EscrowJobResult {
    pub job_id: String,
    pub kv_reference: KvReference,
    pub final_status: String,
    pub tx_hash_claim: String,
    pub tx_hash_result: String,
    pub tx_hash_kv: String,
}

/// Pre-signed worker msig actions for claim + submit_result.
/// The worker agent creates these offline and posts them in the kind 41002 event tags.
/// The daemon relays both via msig.execute() — worker's msig is the caller on-chain.
pub struct WorkerMsigClaim {
    /// Worker's msig account ID (e.g. "worker.v1.test.near")
    pub worker_msig: String,
    /// Pre-signed claim() action JSON
    pub claim_action_json: String,
    /// Ed25519 signature of the claim action (64 bytes)
    pub claim_sig_bytes: Vec<u8>,
    /// Pre-signed submit_result() action JSON (with deterministic kv_reference)
    pub submit_action_json: String,
    /// Ed25519 signature of the submit action (64 bytes)
    pub submit_sig_bytes: Vec<u8>,
}

/// Run the full escrow job lifecycle via worker's multisig:
///   1. Poll until Open (funded)
///   2. Claim via worker_msig.execute() — worker's own funds at stake
///   3. Write result to FastNear KV (daemon's signer — not the escrow contract)
///   4. Submit KV reference via worker_msig.execute()
///   5. Wait for verification + settlement
///
/// The worker pre-signs both claim and submit_result actions with deterministic args.
/// The kv_reference is known at sign time: `{"account": kv_account, "key": "result/{job_id}"}`.
/// Settlement pays the worker's msig directly.
pub fn run_escrow_job(
    rpc: &rpc_pool::Rpc,
    rpc_url: &str,
    signer: &InMemorySigner,
    escrow_contract: &str,
    kv_account: &str,
    job_id: &str,
    stake_yocto: u128,
    nonce_cache: &NonceCache,
    result_output: &str,
    worker_claim: Option<&WorkerMsigClaim>,
) -> Result<EscrowJobResult> {
    // 1. Poll until Open
    let _escrow = poll_until_open(
        rpc,
        escrow_contract,
        job_id,
        Duration::from_secs(600), // 10 min timeout for funding
    )?;

    // 2. Claim — via worker msig (preferred) or daemon signer (fallback)
    let tx_hash_claim = if let Some(claim) = worker_claim {
        let (tx, _) = claim_via_msig(
            rpc_url,
            signer,
            &claim.worker_msig,
            &claim.claim_action_json,
            &claim.claim_sig_bytes,
            nonce_cache,
        )?;
        tracing::info!("[escrow] {} claimed via worker msig {} ✓ tx={}", job_id, claim.worker_msig, tx);
        tx
    } else {
        let (tx, _) = claim(
            rpc_url,
            signer,
            escrow_contract,
            job_id,
            stake_yocto,
            nonce_cache,
        )?;
        tracing::info!("[escrow] {} claimed (daemon signer) ✓ tx={}", job_id, tx);
        tx
    };

    // 3. Write result to KV — always daemon's signer (FastNear, not escrow contract)
    let kv_key = format!("result/{}", job_id);
    let tx_hash_kv = write_kv(rpc_url, signer, kv_account, &kv_key, result_output, nonce_cache)?;

    // 4. Submit KV reference — via worker msig (preferred) or daemon signer (fallback)
    let kv_ref = KvReference {
        kv_account: kv_account.to_string(),
        kv_predecessor: if let Some(claim) = worker_claim {
            claim.worker_msig.clone()
        } else {
            signer.account_id.to_string()
        },
        kv_key,
    };

    let tx_hash_result = if let Some(claim) = worker_claim {
        let (tx, _) = submit_result_via_msig(
            rpc_url,
            signer,
            &claim.worker_msig,
            &claim.submit_action_json,
            &claim.submit_sig_bytes,
            nonce_cache,
        )?;
        tracing::info!("[escrow] {} result submitted via worker msig ✓ tx={}", job_id, tx);
        tx
    } else {
        let (tx, _) = submit_result(
            rpc_url,
            signer,
            escrow_contract,
            job_id,
            &kv_ref.to_json(),
            nonce_cache,
        )?;
        tracing::info!("[escrow] {} result submitted (daemon signer) ✓ tx={}", job_id, tx);
        tx
    };

    // 5. Wait for settlement
    let final_escrow = wait_for_settlement(
        rpc,
        escrow_contract,
        job_id,
        Duration::from_secs(600), // 10 min timeout for verification + settlement
    )?;

    Ok(EscrowJobResult {
        job_id: job_id.to_string(),
        kv_reference: kv_ref,
        final_status: final_escrow.status,
        tx_hash_claim,
        tx_hash_result,
        tx_hash_kv,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── is_terminal ─────────────────────────────────────────────────────

    #[test]
    fn test_terminal_claimed() {
        assert!(is_terminal("Claimed"));
    }

    #[test]
    fn test_terminal_refunded() {
        assert!(is_terminal("Refunded"));
    }

    #[test]
    fn test_terminal_cancelled() {
        assert!(is_terminal("Cancelled"));
    }

    #[test]
    fn test_terminal_settlement_failed() {
        assert!(is_terminal("SettlementFailed"));
    }

    #[test]
    fn test_not_terminal_pending_funding() {
        assert!(!is_terminal("PendingFunding"));
    }

    #[test]
    fn test_not_terminal_open() {
        assert!(!is_terminal("Open"));
    }

    #[test]
    fn test_not_terminal_in_progress() {
        assert!(!is_terminal("InProgress"));
    }

    #[test]
    fn test_not_terminal_verifying() {
        assert!(!is_terminal("Verifying"));
    }

    #[test]
    fn test_not_terminal_garbage() {
        assert!(!is_terminal("garbage"));
        assert!(!is_terminal(""));
        assert!(!is_terminal("random_status"));
    }

    // ── default_threshold ───────────────────────────────────────────────

    #[test]
    fn test_default_threshold_value() {
        assert_eq!(default_threshold(), 80);
    }

    // ── KvReference roundtrip ──────────────────────────────────────────

    #[test]
    fn test_kv_reference_serialization_roundtrip() {
        let kv = KvReference {
            kv_account: "kv.test.near".to_string(),
            kv_predecessor: "worker.test.near".to_string(),
            kv_key: "result/job-42".to_string(),
        };
        let json = kv.to_json();
        let parsed: KvReference = serde_json::from_str(&json).expect("roundtrip deserialize");
        assert_eq!(parsed.kv_account, "kv.test.near");
        assert_eq!(parsed.kv_predecessor, "worker.test.near");
        assert_eq!(parsed.kv_key, "result/job-42");
    }

    #[test]
    fn test_kv_reference_json_contains_fields() {
        let kv = KvReference {
            kv_account: "kv.test.near".to_string(),
            kv_predecessor: "worker.test.near".to_string(),
            kv_key: "result/job-99".to_string(),
        };
        let json = kv.to_json();
        assert!(json.contains("kv_account"), "JSON should contain kv_account");
        assert!(json.contains("kv_predecessor"), "JSON should contain kv_predecessor");
        assert!(json.contains("kv_key"), "JSON should contain kv_key");
        assert!(json.contains("result/job-99"), "JSON should contain the key value");
    }
}
