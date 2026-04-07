//! HTTP API handlers for the dashboard and execution endpoints.

use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    body::Body,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::sse::{Event, KeepAlive, Sse},
    routing::{get, post},
    Json, Router,
};
use base64::Engine;
use near_crypto::Signer;
use near_jsonrpc_client::{methods, JsonRpcClient};
use near_primitives::action::{Action, FunctionCallAction};
use near_primitives::transaction::{Transaction, TransactionV0};
use serde::Serialize;
use tokio_stream::StreamExt;
use tower_http::cors::CorsLayer;

use super::{
    DaemonConfig, DashboardState, ParsedSource, RequestInfo,
    SHARED_CONTRACT_ID, SHARED_DEPOSIT_YOCTO, SHARED_NONCE_CACHE, SHARED_SIGNER,
    execute_single_wasm, find_wasm, resolve_wasm,
};
use crate::daemon::payment::{
    compute_challenge_hmac, get_used_receipts, mark_receipt_used, verify_payment, Challenge402, ExecuteRequest,
    EXECUTION_PRICE_NEAR,
};
use crate::daemon::rpc_pool::Rpc;

/// Status endpoint response.
#[derive(Serialize)]
pub(crate) struct StorageEntry {
    name: String,
    hex_name: String,
    size: u64,
}

/// Contract state response.
#[derive(Serialize)]
pub(crate) struct ContractState {
    pending_request_ids: Vec<u64>,
    pending_count: usize,
    contract_id: String,
}

/// GET /api/status - Daemon status.
pub(crate) async fn api_status(State(state): State<Arc<DashboardState>>) -> Json<super::DaemonStatus> {
    let inner = state.status.lock().unwrap();
    Json(super::DaemonStatus {
        running: true,
        uptime_secs: inner.start_time.elapsed().as_secs(),
        poll_count: inner.poll_count,
        last_poll_time: inner.last_poll_time.clone(),
        contract_id: inner.contract_id.clone(),
        account_id: inner.account_id.clone(),
        rpc_url: inner.rpc_url.clone(),
        poll_interval_secs: inner.poll_interval_secs,
        dashboard_addr: inner.dashboard_addr.clone(),
    })
}

/// GET /api/history - Execution history.
pub(crate) async fn api_history(State(state): State<Arc<DashboardState>>) -> Json<serde_json::Value> {
    let hist = state.history.lock().unwrap();
    let records: Vec<serde_json::Value> = hist.iter().rev().take(50).map(|r| {
        serde_json::json!({
            "request_id": r.request_id,
            "input": r.input,
            "output": r.output,
            "execution_time_ms": r.execution_time_ms,
            "instructions": r.instructions,
            "timestamp": r.timestamp,
            "success": r.success,
            "resolve_tx_hash": r.resolve_tx_hash,
        })
    }).collect();
    Json(serde_json::Value::Array(records.into_iter().rev().collect()))
}

/// GET /api/stream - SSE event stream.
pub(crate) async fn api_stream(
    State(state): State<Arc<DashboardState>>,
) -> Sse<impl tokio_stream::Stream<Item = Result<Event, std::convert::Infallible>>> {
    let rx = state.events_tx.subscribe();
    let stream = tokio_stream::wrappers::BroadcastStream::new(rx);
    let stream = stream.filter_map(|result| {
        match result {
            Ok(msg) => Some(Ok(Event::default().data(msg))),
            Err(_) => None,
        }
    });
    Sse::new(stream).keep_alive(
        KeepAlive::new().interval(Duration::from_secs(15)).text("ping"),
    )
}

/// GET /api/storage - List storage entries.
pub(crate) async fn api_storage(State(state): State<Arc<DashboardState>>) -> Json<Vec<StorageEntry>> {
    let dir = &state.storage_dir;
    let mut entries = Vec::new();
    if let Ok(rd) = fs::read_dir(dir) {
        for e in rd.flatten() {
            let hex_name = e.file_name().to_string_lossy().to_string();
            let decoded = hex::decode(&hex_name).ok().and_then(|b| String::from_utf8(b).ok()).unwrap_or_else(|| hex_name.clone());
            let size = e.metadata().map(|m| m.len()).unwrap_or(0);
            entries.push(StorageEntry { name: decoded, hex_name, size });
        }
    }
    Json(entries)
}

/// GET /api/contract - Contract pending requests.
pub(crate) async fn api_contract(State(state): State<Arc<DashboardState>>) -> Json<ContractState> {
    let rpc_url = state.rpc_url.clone();
    let contract_id = state.contract_id.clone();
    let result = std::thread::spawn(move || -> anyhow::Result<Vec<u64>> {
        let rpc = Rpc::new(&rpc_url)?;
        super::get_pending_ids(&rpc, &contract_id)
    }).join().unwrap_or(Ok(vec![]));
    let ids = result.unwrap_or_default();
    Json(ContractState { pending_count: ids.len(), pending_request_ids: ids, contract_id: state.contract_id.clone() })
}

/// GET /catalog — List available WASM programs from ~/.inlayer/programs/
async fn api_catalog() -> Json<Vec<serde_json::Value>> {
    let mut programs = vec![];
    let programs_dir = dirs::home_dir()
        .unwrap_or_default()
        .join(".inlayer")
        .join("programs");

    if let Ok(entries) = std::fs::read_dir(&programs_dir) {
        for entry in entries.flatten() {
            let dir = entry.path();
            if !dir.is_dir() { continue; }

            let wasm_path = dir.join("program.wasm");
            let manifest_path = dir.join("manifest.json");

            if !wasm_path.exists() { continue; }

            let size = std::fs::metadata(&wasm_path).map(|m| m.len()).unwrap_or(0);

            // Load manifest if present, otherwise use defaults
            let manifest: serde_json::Value = std::fs::read_to_string(&manifest_path)
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_else(|| {
                    let name = dir.file_name().unwrap_or_default().to_string_lossy().to_string();
                    serde_json::json!({"name": name})
                });

            programs.push(serde_json::json!({
                "name": manifest["name"].as_str().unwrap_or("unknown"),
                "description": manifest["description"].as_str().unwrap_or("No description available"),
                "version": manifest["version"].as_str().unwrap_or("0.0.0"),
                "size_kb": size / 1024,
                "input": manifest["input"].as_str().unwrap_or("Not specified"),
                "output": manifest["output"].as_str().unwrap_or("Not specified"),
                "max_instructions": manifest["max_instructions"].as_u64().unwrap_or(10_000_000_000),
                "max_memory_mb": manifest["max_memory_mb"].as_u64().unwrap_or(256),
            }));
        }
    }

    Json(programs)
}

/// POST /execute - Paid execution endpoint (MPP-402).
pub(crate) async fn api_execute(
    State(state): State<Arc<DashboardState>>,
    headers: HeaderMap,
    Json(body): Json<ExecuteRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let challenge_id = format!("{:016x}", std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis());

    // Check for Payment-Receipt header
    let receipt_header = headers.get("Payment-Receipt")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Read the HMAC from the original challenge (agent must echo it back)
    let client_hmac = headers.get("Challenge-Hmac")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Read signer account to verify the requester is the payer
    let signer_account = headers.get("Signer-Account")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let receipt = match receipt_header {
        None => {
            // Step 1: Return 402 challenge with HMAC binding
            let hmac = compute_challenge_hmac(&challenge_id, EXECUTION_PRICE_NEAR, &state.contract_id);
            let challenge = Challenge402 {
                version: "MPP/1.0".to_string(),
                amount: EXECUTION_PRICE_NEAR.to_string(),
                token: "NEAR".to_string(),
                recipient: state.contract_id.clone(),
                challenge_id: challenge_id.clone(),
                hmac: hmac.clone(),
                description: "OutLayer WASM execution".to_string(),
                methods: vec!["near-intents".to_string()],
            };
            return (
                StatusCode::PAYMENT_REQUIRED,
                Json(serde_json::json!({
                    "error": "payment_required",
                    "challenge": challenge,
                    "www_authenticate": format!(
                        "MPP challenge_id=\"{}\", amount=\"{}\", token=\"NEAR\", recipient=\"{}\", hmac=\"{}\"",
                        challenge_id, EXECUTION_PRICE_NEAR, state.contract_id, hmac
                    ),
                    "instructions": "Send payment via NEAR Intents to the recipient, then retry with Payment-Receipt header containing the tx hash",
                })),
            );
        }
        Some(tx_hash) => tx_hash,
    };

    // Step 2: Check replay (same tx hash can't be used twice)
    {
        let used = get_used_receipts();
        let set = used.lock().unwrap();
        if set.contains(&receipt) {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "receipt_already_used",
                    "message": "This payment receipt has already been redeemed",
                })),
            );
        }
    }

    // Step 3: Verify HMAC if provided (prevents challenge tampering)
    if let Some(ref hmac) = client_hmac {
        let expected = compute_challenge_hmac(&receipt, EXECUTION_PRICE_NEAR, &state.contract_id);
        if hmac != &expected {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "hmac_mismatch",
                    "message": "Challenge HMAC does not match expected value",
                })),
            );
        }
    }

    let expected_signer = signer_account.unwrap_or_default();

    // Step 4: Verify payment on-chain via RPC
    let rpc_url = state.rpc_url.clone();
    let contract_id = state.contract_id.clone();
    let receipt_for_spawn = receipt.clone();
    let verification = tokio::task::spawn_blocking(move || {
        verify_payment(&receipt_for_spawn, &expected_signer, &rpc_url, &contract_id)
    }).await;

    let verify_err = match verification {
        Ok(Ok(())) => None,
        Ok(Err(msg)) => Some(msg),
        Err(e) => Some(e.to_string()),
    };

    if let Some(msg) = verify_err {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "payment_verification_failed",
                "message": msg,
            })),
        );
    }

    // Step 5: Persist used receipt (replay protection, survives restarts)
    mark_receipt_used(&receipt);

    // Step 6: Execute WASM
    let input_str = body.input;
    let wasm_url_hint = body.wasm_url;
    let max_instructions = body.max_instructions.unwrap_or(10_000_000_000);
    let max_memory_mb = body.max_memory_mb.unwrap_or(256);
    let rpc_url = state.rpc_url.clone();
    let search_paths = state.search_paths.clone();
    let start = std::time::Instant::now();

    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<serde_json::Value> {
        let source = if let Some(ref url) = wasm_url_hint {
            ParsedSource::WasmUrl { url: url.clone(), hash: String::new() }
        } else {
            ParsedSource::Unknown
        };
        let config = DaemonConfig { search_paths: search_paths.clone(), ..Default::default() };
        let wasm_bytes = resolve_wasm(&source, &config)
            .or_else(|| find_wasm(&DaemonConfig { search_paths, ..Default::default() }).and_then(|p| fs::read(&p).ok()))
            .ok_or_else(|| anyhow::anyhow!("No WASM found"))?;

        let info = RequestInfo {
            input: input_str.clone(),
            max_instructions,
            max_memory_mb,
            max_execution_seconds: 60,
            source: ParsedSource::Unknown,
        };
        let mut env = HashMap::new();
        env.insert("REQUEST_TYPE".into(), "http".into());
        env.insert("PAYMENT_VERIFIED".into(), "true".into());
        env.insert("PAYMENT_RECEIPT".into(), receipt.clone());

        let wasm_result = execute_single_wasm(&wasm_bytes, 0, &input_str, &rpc_url, &env, &info);
        let elapsed = start.elapsed();

        // Submit to contract in background (settled execution record)
        let mut tx_hash_out = "no_signer".to_string();
        if let (Some(signer), Some(contract_id), Some(nonce_cache)) =
            (SHARED_SIGNER.get(), SHARED_CONTRACT_ID.get(), SHARED_NONCE_CACHE.get())
        {
            match nonce_cache.reserve_batch(1) {
                Ok((nonce, block_hash)) => {
                    let input_b64 = base64::engine::general_purpose::STANDARD.encode(input_str.as_bytes());
                    let source_json = serde_json::json!({"WasmUrl": {"url": "local", "hash": "0000000000000000000000000000000000000000000000000000000000000000", "build_target": "wasm32-wasip2"}});
                    let args = serde_json::json!({
                        "source": source_json,
                        "input_data": input_b64,
                        "resource_limits": {"max_instructions": max_instructions, "max_memory_mb": max_memory_mb, "max_execution_seconds": 60u64},
                        "secrets_ref": null, "response_format": null, "payer_account_id": null, "params": null
                    });
                    let receiver_id = match contract_id.parse::<near_primitives::types::AccountId>() {
                        Ok(id) => id,
                        Err(e) => {
                            tracing::error!("   /execute: contract_id parse error: {}", e);
                            return Ok(serde_json::json!({"status": "error", "error": format!("contract_id parse: {}", e)}));
                        }
                    };
                    let tx = TransactionV0 {
                        signer_id: signer.account_id.clone(),
                        public_key: signer.public_key.clone(),
                        nonce,
                        receiver_id,
                        block_hash,
                        actions: vec![Action::FunctionCall(Box::new(FunctionCallAction {
                            method_name: "request_execution".to_string(),
                            args: serde_json::to_vec(&args).unwrap_or_default(),
                            gas: 300_000_000_000_000,
                            deposit: SHARED_DEPOSIT_YOCTO.get().copied().unwrap_or(7_001_000_000_000_000_000_000u128),
                        }))],
                    };
                    let signed_tx = Transaction::V0(tx).sign(&Signer::InMemory(signer.clone()));
                    tx_hash_out = format!("{}", signed_tx.get_hash());
                    let rpc_url_bg = rpc_url.clone();
                    std::thread::spawn(move || {
                        let client = JsonRpcClient::connect(&rpc_url_bg);
                        let rt = match tokio::runtime::Runtime::new() { Ok(r) => r, Err(_) => return };
                        let _ = rt.block_on(async {
                            client.call(methods::send_tx::RpcSendTransactionRequest {
                                signed_transaction: signed_tx,
                                wait_until: near_primitives::views::TxExecutionStatus::None,
                            }).await
                        });
                    });
                }
                Err(e) => tracing::error!("   /execute: nonce failed: {}", e),
            }
        }

        Ok(serde_json::json!({
            "status": if wasm_result.success { "completed" } else { "failed" },
            "output": if wasm_result.success { serde_json::from_str::<serde_json::Value>(&wasm_result.output).unwrap_or_else(|_| serde_json::json!(wasm_result.output)) } else { serde_json::Value::Null },
            "error": wasm_result.error,
            "execution_time_ms": elapsed.as_millis() as u64,
            "instructions": wasm_result.instructions,
            "transaction_hash": tx_hash_out,
            "payment": {
                "amount": EXECUTION_PRICE_NEAR,
                "token": "NEAR",
                "challenge_id": challenge_id,
                "verified": true,
            },
        }))
    }).await;

    match result {
        Ok(Ok(v)) => (StatusCode::OK, Json(v)),
        Ok(Err(e)) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))),
    }
}

/// POST /call/:owner/:project - Direct execution endpoint.
pub(crate) async fn api_call(
    State(state): State<Arc<DashboardState>>,
    Path((_owner, _project)): Path<(String, String)>,
    Json(body): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    let input_str = match body.get("input") {
        Some(v) => v.as_str().unwrap_or("").to_string(),
        None => return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "status": "failed", "error": "Missing 'input' field" })),
        ),
    };
    let wasm_url_hint = body.get("wasm_url").and_then(|v| v.as_str()).map(|s| s.to_string());
    let rpc_url = state.rpc_url.clone();
    let search_paths = state.search_paths.clone();
    let start = std::time::Instant::now();

    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<serde_json::Value> {
        // 1. Resolve and execute WASM locally (fast)
        let source = if let Some(ref url) = wasm_url_hint {
            ParsedSource::WasmUrl { url: url.clone(), hash: String::new() }
        } else {
            ParsedSource::Unknown
        };
        let temp_config = DaemonConfig { search_paths: search_paths.clone(), ..Default::default() };
        let wasm_bytes = resolve_wasm(&source, &temp_config)
            .or_else(|| find_wasm(&DaemonConfig { search_paths, ..Default::default() }).and_then(|p| fs::read(&p).ok()))
            .ok_or_else(|| anyhow::anyhow!("No WASM found"))?;

        let info = RequestInfo {
            input: input_str.clone(),
            max_instructions: 10_000_000_000,
            max_memory_mb: 256,
            max_execution_seconds: 60,
            source: ParsedSource::Unknown,
        };
        let mut env = HashMap::new();
        env.insert("REQUEST_TYPE".into(), "http".into());

        let wasm_result = execute_single_wasm(&wasm_bytes, 0, &input_str, &rpc_url, &env, &info);
        let elapsed = start.elapsed();

        // 2. Pre-warm nonce upfront, pass to background thread. No contention, no retries.
        let mut tx_hash = "no_signer".to_string();
        if let (Some(signer), Some(contract_id), Some(nonce_cache)) = 
            (SHARED_SIGNER.get(), SHARED_CONTRACT_ID.get(), SHARED_NONCE_CACHE.get()) 
        {
            // Reserve nonce BEFORE spawning thread (atomic, no contention)
            match nonce_cache.reserve_batch(1) {
                Ok((nonce, block_hash)) => {
                    let input_b64 = base64::engine::general_purpose::STANDARD.encode(input_str.as_bytes());
                    let source_json = if let ParsedSource::WasmUrl { ref url, .. } = source {
                        serde_json::json!({"WasmUrl": {"url": url, "hash": "0000000000000000000000000000000000000000000000000000000000000000", "build_target": "wasm32-wasip2"}})
                    } else {
                        serde_json::json!({"WasmUrl": {"url": "local", "hash": "0000000000000000000000000000000000000000000000000000000000000000", "build_target": "wasm32-wasip2"}})
                    };
                    let args = serde_json::json!({
                        "source": source_json,
                        "input_data": input_b64,
                        "resource_limits": {"max_instructions": 10_000_000_000u64, "max_memory_mb": 256u64, "max_execution_seconds": 60u64},
                        "secrets_ref": null, "response_format": null, "payer_account_id": null, "params": null
                    });
                    let receiver_id = match contract_id.parse::<near_primitives::types::AccountId>() {
                        Ok(id) => id,
                        Err(e) => {
                            tracing::error!("   /call: contract_id parse error: {}", e);
                            return Ok(serde_json::json!({"status": "error", "error": format!("contract_id parse: {}", e)}));
                        }
                    };
                    // Build + sign tx RIGHT NOW (before spawning) with pre-warmed nonce
                    let tx = TransactionV0 {
                        signer_id: signer.account_id.clone(),
                        public_key: signer.public_key.clone(),
                        nonce,
                        receiver_id,
                        block_hash,
                        actions: vec![Action::FunctionCall(Box::new(FunctionCallAction {
                            method_name: "request_execution".to_string(),
                            args: serde_json::to_vec(&args).unwrap_or_default(),
                            gas: 300_000_000_000_000,
                            deposit: SHARED_DEPOSIT_YOCTO.get().copied().unwrap_or(7_001_000_000_000_000_000_000u128),
                        }))],
                    };
                    let signed_tx = Transaction::V0(tx).sign(&Signer::InMemory(signer.clone()));
                    tx_hash = format!("{}", signed_tx.get_hash());
                    let rpc_url_bg = rpc_url.clone();
                    // Only send in background (HTTP latency ~300ms) — tx is already signed
                    std::thread::spawn(move || {
                        let client = JsonRpcClient::connect(&rpc_url_bg);
                        let rt = match tokio::runtime::Runtime::new() {
                            Ok(r) => r,
                            Err(_) => return,
                        };
                        let _ = rt.block_on(async {
                            client.call(methods::send_tx::RpcSendTransactionRequest {
                                signed_transaction: signed_tx,
                                wait_until: near_primitives::views::TxExecutionStatus::None,
                            }).await
                        });
                        tracing::debug!("   /call bg: tx sent (nonce={})", nonce);
                    });
                }
                Err(e) => tracing::error!("   /call: nonce pre-warm failed: {}", e),
            }
        }

        Ok(serde_json::json!({
            "status": if wasm_result.success { "completed" } else { "failed" },
            "output": if wasm_result.success { serde_json::from_str::<serde_json::Value>(&wasm_result.output).unwrap_or_else(|_| serde_json::json!(wasm_result.output)) } else { serde_json::Value::Null },
            "error": wasm_result.error,
            "execution_time_ms": elapsed.as_millis() as u64,
            "instructions": wasm_result.instructions,
            "transaction_hash": tx_hash,
        }))
    }).await;

    match result {
        Ok(Ok(response)) => (StatusCode::OK, Json(response)),
        Ok(Err(e)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "status": "failed", "error": e.to_string() })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "status": "failed", "error": format!("Execution panicked: {}", e) })),
        ),
    }
}

/// GET /wasm/:owner/:project - Serve WASM files for project registration.
pub(crate) async fn api_wasm(
    State(state): State<Arc<DashboardState>>,
    Path((owner, project)): Path<(String, String)>,
) -> (StatusCode, Body) {
    let search_paths = state.search_paths.clone();

    // Find WASM file for this project
    let result = tokio::task::spawn_blocking(move || -> Option<PathBuf> {
        let temp_config = DaemonConfig {
            search_paths,
            ..Default::default()
        };

        // First find the WASM
        if let Some(wasm_path) = find_wasm(&temp_config) {
            // Check if filename contains project name
            let filename = wasm_path.file_name()?.to_string_lossy();
            if filename.contains(&project) || project.is_empty() {
                return Some(wasm_path);
            }
        }

        // Try more specific search
        for dir in &temp_config.search_paths {
            let base = PathBuf::from(dir);
            if let Ok(entries) = base.read_dir() {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() && path.file_name()?.to_string_lossy().contains(&project) {
                        let release = path.join("target").join("wasm32-wasip2").join("release");
                        if let Ok(wasm_entries) = release.read_dir() {
                            for wasm_entry in wasm_entries.flatten() {
                                let wasm_path = wasm_entry.path();
                                if wasm_path.is_file() && wasm_path.extension().map(|e| e == "wasm").unwrap_or(false) {
                                    return Some(wasm_path);
                                }
                            }
                        }
                    }
                }
            }

        }
        None
    }).await;

    match result {
        Ok(Some(wasm_path)) => match fs::read(&wasm_path) {
            Ok(bytes) => (
                StatusCode::OK,
                Body::from(bytes),
            ),
            Err(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Body::from("Failed to read WASM file"),
            ),
        },
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Body::from("WASM file not found"),
        ),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Body::from("Error searching for WASM"),
        ),
    }
}

/// Spawn the dashboard HTTP server.
pub(crate) fn spawn_dashboard(addr: &str, state: Arc<DashboardState>) {
    let addr_str = addr.to_string();
    let addr: SocketAddr = match addr.parse() {
        Ok(a) => a,
        Err(e) => {
            tracing::error!("Invalid dashboard address '{}': {}", addr, e);
            return;
        }
    };
    let state_clone = state.clone();
    std::thread::spawn(move || {
        let rt = match tokio::runtime::Runtime::new() {
            Ok(rt) => rt,
            Err(e) => {
                tracing::error!("Dashboard runtime failed: {}", e);
                return;
            }
        };
        rt.block_on(async move {
            let app = Router::new()
                .route("/call/:owner/:project", post(api_call))
                .route("/execute", post(api_execute))
                .route("/catalog", get(api_catalog))
                .route("/wasm/:owner/:project", get(api_wasm))
                .route("/api/status", get(api_status))
                .route("/api/history", get(api_history))
                .route("/api/stream", get(api_stream))
                .route("/api/storage", get(api_storage))
                .route("/api/contract", get(api_contract))
                .layer(CorsLayer::permissive())
                .with_state(state_clone);
            tracing::info!("Dashboard: http://{}", addr_str);
            let listener = match tokio::net::TcpListener::bind(addr).await {
                Ok(l) => l,
                Err(e) => {
                    tracing::error!("Dashboard bind failed: {}", e);
                    return;
                }
            };
            if let Err(e) = axum::serve(listener, app).await {
                tracing::error!("Dashboard server error: {}", e);
            }
        });
    });
}
