//! Daemon mode — polls NEAR contract for pending execution requests,
//! executes WASM locally, and resolves results on-chain.
//!
//! Exposed as `inlayer daemon [--start|--stop|--status|--log|--daemon|--foreground|--dashboard <addr>]`.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use base64::Engine;
use near_crypto::{InMemorySigner, Signer};
use near_jsonrpc_client::{methods, JsonRpcClient};
use near_primitives::action::{Action, FunctionCallAction};
use near_primitives::transaction::{Transaction, TransactionV0};
use near_primitives::views::ExecutionStatusView;
use serde::Serialize;
use sha2::Digest;
use std::sync::OnceLock;
use tokio::sync::broadcast;

use crate::api_client::{ExecutionOutput, ResourceLimits, ResponseFormat};
use crate::compiled_cache::CompiledCache;
use crate::config::RpcProxyConfig;
use crate::executor::{ExecutionContext, Executor};
use crate::outlayer_rpc::RpcProxy;

// Re-export submodules
mod api;
mod escrow_client;
pub mod escrow_commands;
mod manage;
mod nonce;
mod payment;
mod rpc_pool;
mod tunnel;
mod watcher;
mod nostr;

pub use manage::{DaemonConfig, load_signer};

// ── Global statics ──────────────────────────────────────────────────────────

static WASM_PATH_CACHE: OnceLock<PathBuf> = OnceLock::new();
static SHARED_RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
static COMPILED_CACHE: OnceLock<Arc<std::sync::Mutex<CompiledCache>>> = OnceLock::new();

/// Global shared nonce cache - set once after signer loads, used by both /call and daemon loop
static SHARED_NONCE_CACHE: OnceLock<Arc<nonce::NonceCache>> = OnceLock::new();

/// Global signer — set once after loading, used by /call for tx signing
static SHARED_SIGNER: OnceLock<InMemorySigner> = OnceLock::new();

/// Global contract id — set once after config loads
static SHARED_CONTRACT_ID: OnceLock<String> = OnceLock::new();

/// Global deposit amount in yoctoNEAR — set once after config loads
static SHARED_DEPOSIT_YOCTO: OnceLock<u128> = OnceLock::new();

// ── Shared types ────────────────────────────────────────────────────────────

/// Execution record for history tracking.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct ExecutionRecord {
    pub(crate) request_id: u64,
    pub(crate) input: String,
    pub(crate) output: String,
    pub(crate) execution_time_ms: u64,
    pub(crate) instructions: u64,
    pub(crate) timestamp: String,
    pub(crate) success: bool,
    pub(crate) resolve_tx_hash: Option<String>,
}

/// Daemon status response.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct DaemonStatus {
    pub(crate) running: bool,
    pub(crate) uptime_secs: u64,
    pub(crate) poll_count: u64,
    pub(crate) last_poll_time: Option<String>,
    pub(crate) contract_id: String,
    pub(crate) account_id: String,
    pub(crate) rpc_url: String,
    pub(crate) poll_interval_secs: u64,
    pub(crate) dashboard_addr: Option<String>,
}

/// Dashboard state shared across handlers.
pub(crate) struct DashboardState {
    pub(crate) history: std::sync::Mutex<Vec<ExecutionRecord>>,
    pub(crate) status: std::sync::Mutex<DashboardStatusInner>,
    pub(crate) events_tx: broadcast::Sender<String>,
    pub(crate) storage_dir: PathBuf,
    pub(crate) contract_id: String,
    pub(crate) rpc_url: String,
    pub(crate) search_paths: Vec<String>,
    pub(crate) signer: std::sync::Mutex<Option<InMemorySigner>>,
}

/// Internal dashboard status.
#[derive(Debug)]
pub(crate) struct DashboardStatusInner {
    pub(crate) start_time: std::time::Instant,
    pub(crate) poll_count: u64,
    pub(crate) last_poll_time: Option<String>,
    pub(crate) last_block_height: Option<u64>,
    pub(crate) contract_id: String,
    pub(crate) account_id: String,
    pub(crate) rpc_url: String,
    pub(crate) poll_interval_secs: u64,
    pub(crate) dashboard_addr: Option<String>,
}

/// Parsed execution source from contract request.
#[derive(Debug, Clone)]
pub(crate) enum ParsedSource {
    /// Use WASM from a URL (download + cache)
    WasmUrl { url: String, hash: String },
    /// Use registered project WASM (match by project_id in search paths)
    Project { project_id: String },
    /// No source info — fall back to default WASM discovery
    Unknown,
}

/// Request info fetched from contract.
pub(crate) struct RequestInfo {
    pub(crate) input: String,
    pub(crate) max_instructions: u64,
    pub(crate) max_memory_mb: u32,
    pub(crate) max_execution_seconds: u64,
    pub(crate) source: ParsedSource,
}

/// WASM execution result.
pub(crate) struct WasmResult {
    pub(crate) request_id: u64,
    pub(crate) success: bool,
    pub(crate) output: String,
    pub(crate) time_ms: u64,
    pub(crate) instructions: u64,
    pub(crate) error: Option<String>,
    pub(crate) input: String,
}

// ── Shared functions ────────────────────────────────────────────────────────

fn shared_runtime() -> &'static tokio::runtime::Runtime {
    SHARED_RUNTIME.get_or_init(|| tokio::runtime::Runtime::new().expect("failed to create shared runtime"))
}

fn init_compiled_cache(secret_key_bytes: [u8; 32]) {
    let home = dirs::home_dir().unwrap_or_default();
    let cache_dir = home.join(".inlayer").join("compiled_cache");
    match CompiledCache::new(cache_dir, 500, &secret_key_bytes) {
        Ok(cache) => {
            COMPILED_CACHE.set(Arc::new(std::sync::Mutex::new(cache))).ok();
        }
        Err(e) => tracing::error!("Compiled cache init failed: {}", e),
    }
}

fn compiled_cache() -> Option<Arc<std::sync::Mutex<CompiledCache>>> {
    COMPILED_CACHE.get().cloned()
}

/// Inject signer_id and signer_key into WASM input if not already present
fn inject_signer(input: &mut serde_json::Value, signer: &InMemorySigner) {
    if let Some(obj) = input.as_object_mut() {
        if !obj.contains_key("signer_id") {
            obj.insert("signer_id".into(), serde_json::Value::String(signer.account_id.to_string()));
        }
        if !obj.contains_key("signer_key") {
            obj.insert("signer_key".into(), serde_json::Value::String(format!("{}", signer.secret_key)));
        }
    }
}

// ── Phase 1 Security: Input Validation ──────────────────────────────────

/// Patterns that must never appear in agent input (secrets/sensitive data).
const BLOCKED_PATTERNS: &[&str] = &["private_key", "mnemonic", "seed_phrase"];

/// Rate limiter state: tracks job counts per pubkey per hour.
static RATE_LIMITER: once_cell::sync::Lazy<Mutex<HashMap<String, Vec<u64>>>> =
    once_cell::sync::Lazy::new(|| Mutex::new(HashMap::new()));

/// Validate input JSON for security before WASM execution.
/// Returns Err(reason) if validation fails.
fn validate_input(input: &serde_json::Value, config: &DaemonConfig) -> Result<(), String> {
    // 1. "action" must be present
    let action = input.get("action").and_then(|v| v.as_str()).ok_or_else(|| "missing required field: action".to_string())?;

    // 2. Action must be whitelisted
    if !config.allowed_actions.iter().any(|a| a == action) {
        return Err(format!("action '{}' not allowed (allowed: {:?})", action, config.allowed_actions));
    }

    // 3. "entries" must be an object if present
    if let Some(entries) = input.get("entries") {
        if !entries.is_object() {
            return Err("field 'entries' must be an object".to_string());
        }
        // Enforce max_entries
        if entries.as_object().map(|o| o.len()).unwrap_or(0) > config.max_entries {
            return Err(format!("entries count exceeds max_entries ({})", config.max_entries));
        }
    }

    // 4. Reject if input already contains signer_key (daemon injects it)
    if input.get("signer_key").is_some() {
        return Err("input must not contain 'signer_key' (daemon injects it)".to_string());
    }

    // 5. Reject blocked patterns anywhere in the JSON string
    let input_str = serde_json::to_string(input).unwrap_or_default().to_lowercase();
    for pattern in BLOCKED_PATTERNS {
        if input_str.contains(pattern) {
            return Err(format!("input contains blocked pattern: '{}'", pattern));
        }
    }

    Ok(())
}

/// Check rate limit for a pubkey. Returns false if over limit.
fn check_rate_limit(pubkey: &str, max_per_hour: usize) -> bool {
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let hour_ago = now_secs.saturating_sub(3600);

    let mut map = RATE_LIMITER.lock().unwrap();
    let timestamps = map.entry(pubkey.to_string()).or_default();
    timestamps.retain(|&t| t > hour_ago);
    if timestamps.len() >= max_per_hour {
        return false;
    }
    timestamps.push(now_secs);
    true
}

/// Validate WASM output. Returns (validated_output, error_if_any).
fn validate_output(output: &str, max_bytes: usize) -> Result<String, String> {
    // Enforce max size
    if output.len() > max_bytes {
        return Err(format!("output exceeds max_output_bytes ({} > {})", output.len(), max_bytes));
    }

    // Must be valid JSON with "success" boolean
    let mut parsed: serde_json::Value = serde_json::from_str(output)
        .map_err(|e| format!("output is not valid JSON: {}", e))?;

    if parsed.get("success").and_then(|v| v.as_bool()).is_none() {
        // Not a hard error — some outputs don't have this field. Just log.
    }

    // Strip any field values matching private key patterns
    strip_sensitive_values(&mut parsed);
    Ok(serde_json::to_string(&parsed).unwrap_or_else(|_| output.to_string()))
}

/// Recursively strip values containing private key patterns from JSON.
fn strip_sensitive_values(val: &mut serde_json::Value) {
    match val {
        serde_json::Value::Object(map) => {
            for v in map.values_mut() {
                strip_sensitive_values(v);
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr.iter_mut() {
                strip_sensitive_values(v);
            }
        }
        serde_json::Value::String(s) => {
            let lower = s.to_lowercase();
            if BLOCKED_PATTERNS.iter().any(|p| lower.contains(p)) {
                *s = "[REDACTED]".to_string();
            }
        }
        _ => {}
    }
}

fn signer_key_bytes(signer: &InMemorySigner) -> [u8; 32] {
    let sk_str = signer.secret_key.to_string();
    let b64 = sk_str.strip_prefix("ed25519:").unwrap_or(&sk_str);
    let sk_bytes = base64::engine::general_purpose::STANDARD.decode(b64).unwrap_or_default();
    let mut hasher = sha2::Sha256::new();
    hasher.update(&sk_bytes);
    hasher.finalize().into()
}

/// Parse the execution source from contract request JSON.
pub(crate) fn parse_source(req: &serde_json::Value) -> ParsedSource {
    // Try resolved_source first (resolved by contract), then execution_source, then code_source
    let source = match req.get("resolved_source") {
        Some(s) => s,
        None => match req.get("execution_source") {
            Some(s) => s,
            None => match req.get("code_source") {
                Some(s) => s,
                None => match req.get("source") {
                    Some(s) => s,
                    None => return ParsedSource::Unknown,
                },
            },
        },
    };

    // WasmUrl: { "WasmUrl": { "url": "...", "hash": "..." } }
    if let Some(wu) = source.get("WasmUrl") {
        let url = wu.get("url").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let hash = wu.get("hash").and_then(|v| v.as_str()).unwrap_or("").to_string();
        if !url.is_empty() {
            return ParsedSource::WasmUrl { url, hash };
        }
    }

    // Project: { "Project": { "project_id": "owner/name" } }
    if let Some(proj) = source.get("Project") {
        let project_id = proj.get("project_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
        if !project_id.is_empty() {
            return ParsedSource::Project { project_id };
        }
    }

    // GitHub: { "GitHub": { "repo": "...", "commit": "..." } }
    // For now we can't compile from GitHub locally, fall through
    if source.get("GitHub").is_some() {
        return ParsedSource::Unknown;
    }

    ParsedSource::Unknown
}

/// Resolve WASM bytes for a given request source.
pub(crate) fn resolve_wasm(source: &ParsedSource, config: &DaemonConfig) -> Option<Vec<u8>> {
    match source {
        ParsedSource::WasmUrl { url, hash } => {
            resolve_wasm_from_url(url, hash)
        }
        ParsedSource::Project { project_id } => {
            resolve_wasm_from_project(project_id, config)
        }
        ParsedSource::Unknown => {
            // Fall back to default WASM discovery
            let path = find_wasm(config)?;
            fs::read(&path).ok()
        }
    }
}

/// Find WASM locally by URL filename, then fall back to download.
fn resolve_wasm_from_url(url: &str, _hash: &str) -> Option<Vec<u8>> {
    // Extract filename from URL (e.g. "nostr-identity-zkp-tee-wasip2.wasm")
    let filename = url.rsplit('/').next().unwrap_or("");

    // Search local paths first
    if !filename.is_empty() {
        let home = dirs::home_dir().unwrap_or_default();
        let search_dirs = vec![
            home.join(".openclaw/workspace"),
            home.join(".openclaw/workspace/nostr-identity"),
            PathBuf::from("."),
        ];
        for dir in &search_dirs {
            let candidate = dir.join(filename);
            if candidate.exists() {
                tracing::info!("   📦 Local WASM: {}", candidate.display());
                return fs::read(&candidate).ok();
            }
            // Also check for wasip2 variant
            if !filename.contains("wasip2") {
                let p2_name = filename.replace(".wasm", "-wasip2.wasm");
                let candidate2 = dir.join(&p2_name);
                if candidate2.exists() {
                    tracing::info!("   📦 Local WASM: {}", candidate2.display());
                    return fs::read(&candidate2).ok();
                }
            }
        }

        // Broader search: find any file matching the filename in search paths
        let workspace = home.join(".openclaw/workspace");
        if let Ok(entries) = walk_wasm_files(&workspace) {
            for path in entries {
                let fname = path.file_name().unwrap_or_default().to_string_lossy();
                if fname == filename || (filename.contains("wasip2") && fname.contains("wasip2") && fname.contains(&filename.replace("-wasip2.wasm", "").replace(".wasm", ""))) {
                    tracing::info!("   📦 Local WASM: {}", path.display());
                    return fs::read(&path).ok();
                }
            }
        }
    }

    // Fallback: download (only if no local match)
    tracing::info!("   ⬇️ Not found locally, downloading: {}", url);
    let cache_dir = dirs::home_dir().unwrap_or_default().join(".inlayer").join("wasm_cache");
    fs::create_dir_all(&cache_dir).ok();
    let cache_key = {
        let mut hasher = sha2::Sha256::new();
        hasher.update(url.as_bytes());
        format!("{:x}", hasher.finalize())
    };
    let cached_path = cache_dir.join(format!("{}.wasm", cache_key));
    if cached_path.exists() {
        return fs::read(&cached_path).ok();
    }
    let response = reqwest::blocking::ClientBuilder::new()
        .timeout(std::time::Duration::from_secs(60))
        .build().ok()?
        .get(url)
        .send()
        .ok()?;
    if !response.status().is_success() { return None; }
    let bytes = response.bytes().ok()?.to_vec();
    fs::write(&cached_path, &bytes).ok();
    Some(bytes)
}

/// Walk a directory recursively for .wasm files (max depth 3).
fn walk_wasm_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut results = Vec::new();
    if !dir.exists() { return Ok(results); }
    fn walk(dir: &Path, depth: u32, out: &mut Vec<PathBuf>) {
        if depth > 3 { return; }
        if let Ok(entries) = dir.read_dir() {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() && path.extension().map(|e| e == "wasm").unwrap_or(false) {
                    out.push(path);
                } else if path.is_dir() {
                    walk(&path, depth + 1, out);
                }
            }
        }
    }
    walk(dir, 0, &mut results);
    Ok(results)
}

/// Find WASM by project_id in search paths.
fn resolve_wasm_from_project(project_id: &str, config: &DaemonConfig) -> Option<Vec<u8>> {
    // Extract project name from "owner/project" or use as-is
    let project_name = project_id.split('/').next_back().unwrap_or(project_id);

    for dir in &config.search_paths {
        let base = PathBuf::from(dir);
        if !base.exists() { continue; }

        if let Ok(entries) = base.read_dir() {
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_dir() { continue; }

                let dirname = path.file_name()?.to_string_lossy();
                // Match by project name (e.g. "nostr-identity" matches "nostr-identity-zkp-tee")
                if !dirname.contains(project_name) { continue; }

                // Check for built WASM
                let release = path.join("target").join("wasm32-wasip2").join("release");
                if release.is_dir() {
                    if let Ok(wasm_entries) = release.read_dir() {
                        for wasm_entry in wasm_entries.flatten() {
                            let wasm_path = wasm_entry.path();
                            if wasm_path.is_file() && wasm_path.extension().map(|e| e == "wasm").unwrap_or(false) {
                                let fname = wasm_path.file_name().unwrap_or_default().to_string_lossy();
                                if !fname.starts_with('.') && !fname.contains("-deps") {
                                    tracing::info!("   📦 Project WASM: {}", wasm_path.display());
                                    return fs::read(&wasm_path).ok();
                                }
                            }
                        }
                    }
                }

                // Check for standalone WASM files in the directory
                if let Ok(dir_entries) = path.read_dir() {
                    for entry in dir_entries.flatten() {
                        let p = entry.path();
                        if p.is_file() && p.extension().map(|e| e == "wasm").unwrap_or(false) {
                            let fname = p.file_name().unwrap_or_default().to_string_lossy();
                            if fname.contains("wasip2") || fname.contains("p2") {
                                tracing::info!("   📦 Project WASM: {}", p.display());
                                return fs::read(&p).ok();
                            }
                        }
                    }
                }
            }
        }
    }

    tracing::warn!("   ⚠️ No WASM found for project: {}", project_id);
    None
}

/// Find WASM file in configured search paths.
pub(crate) fn find_wasm(config: &DaemonConfig) -> Option<PathBuf> {
    // Check cache first
    if let Some(cached) = WASM_PATH_CACHE.get() {
        if cached.exists() { return Some(cached.clone()); }
    }

    // First check ~/.inlayer/programs/ for installed programs
    let programs_dir = dirs::home_dir().unwrap_or_default().join(".inlayer").join("programs");
    if let Ok(entries) = programs_dir.read_dir() {
        for entry in entries.flatten() {
            let wasm = entry.path().join("program.wasm");
            if wasm.is_file() {
                let size = wasm.metadata().map(|m| m.len()).unwrap_or(u64::MAX);
                tracing::info!("Found program: {} ({} bytes)", entry.path().file_name().unwrap_or_default().to_string_lossy(), size);
                WASM_PATH_CACHE.set(wasm.clone()).ok();
                return Some(wasm);
            }
        }
    }

    let mut best: Option<(PathBuf, u64)> = None;

    for dir in &config.search_paths {
        let base = PathBuf::from(dir);
        if !base.exists() {
            continue;
        }

        // Search for WASM files in this directory
        if let Ok(entries) = base.read_dir() {
            for entry in entries.flatten() {
                let path = entry.path();

                // Direct WASM file
                if path.is_file() && path.extension().map(|e| e == "wasm").unwrap_or(false) {
                    let size = path.metadata().map(|m| m.len()).unwrap_or(u64::MAX);
                    let is_better = best.as_ref().is_none_or(|(_, sz)| size < *sz);
                    if is_better {
                        best = Some((path, size));
                    }
                    continue;
                }

                // Subdirectory - check for target/wasm32-wasip2/release
                if !path.is_dir() { continue; }

                let release = path.join("target").join("wasm32-wasip2").join("release");
                if release.is_dir() {
                    if let Ok(wasm_entries) = release.read_dir() {
                        for wasm_entry in wasm_entries.flatten() {
                            let wasm_path = wasm_entry.path();
                            if wasm_path.is_file() && wasm_path.extension().map(|e| e == "wasm").unwrap_or(false) {
                                let fname = wasm_path.file_name().unwrap_or_default().to_string_lossy();
                                // Skip deps and hidden files
                                if !fname.starts_with('.') && !fname.contains("-deps") {
                                    let size = wasm_path.metadata().map(|m| m.len()).unwrap_or(u64::MAX);
                                    let is_better = best.as_ref().is_none_or(|(_, sz)| size < *sz);
                                    if is_better {
                                        best = Some((wasm_path, size));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if let Some((path, size)) = best {
        tracing::info!("Found WASM: {} ({} bytes)", path.display(), size);
        if size > 1_000_000 {
            tracing::warn!("WASM binary is >1MB. Consider running wasm-opt -Oz.");
        }
        let _ = WASM_PATH_CACHE.set(path.clone());
        Some(path)
    } else {
        tracing::warn!("No WASM found in search_paths: {:?}", config.search_paths);
        None
    }
}

/// Execute WASM locally and return results.
pub(crate) fn execute_single_wasm(
    wasm_bytes: &[u8],
    request_id: u64,
    input: &str,
    rpc_url: &str,
    env_vars: &HashMap<String, String>,
    req_limits: &RequestInfo,
) -> WasmResult {
    let storage_dir = env::var("STORAGE_DIR").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from("./storage"));
    fs::create_dir_all(&storage_dir).ok();

    let rpc_cfg = RpcProxyConfig {
        enabled: true,
        rpc_url: Some(rpc_url.to_string()),
        max_calls_per_execution: 100,
        allow_transactions: true,
    };
    let proxy = match RpcProxy::new(rpc_cfg, rpc_url) {
        Ok(p) => p,
        Err(e) => return WasmResult { request_id, success: false, output: String::new(), time_ms: 0, instructions: 0, error: Some(format!("RPC proxy error: {}", e)), input: input.to_string() },
    };

    let rt = shared_runtime();
    let handle = rt.handle().clone();

    let exec_ctx = ExecutionContext {
        outlayer_rpc: Some(Arc::new(proxy)),
        storage_config: None,
        runtime_handle: handle,
        compiled_cache: compiled_cache(),
        vrf_config: None,
        wallet_config: None,
    };

    let executor = Executor::new(req_limits.max_instructions, true).with_context(exec_ctx);
    let limits = ResourceLimits {
        max_instructions: req_limits.max_instructions,
        max_memory_mb: req_limits.max_memory_mb,
        max_execution_seconds: req_limits.max_execution_seconds,
    };
    let env = if env_vars.is_empty() { None } else { Some(env_vars.clone()) };

    let wasm_checksum = {
        use std::fmt::Write;
        let mut s = String::with_capacity(64);
        for &b in sha2::Sha256::digest(wasm_bytes).iter() { write!(&mut s, "{:02x}", b).unwrap(); }
        s
    };

    let result = rt.block_on(executor.execute(
        wasm_bytes, Some(&wasm_checksum), input.as_bytes(), &limits,
        env, Some("wasm32-wasip2"), &ResponseFormat::Text,
        None, None, None,
    ));
    drop(executor);

    match result {
        Ok(r) => {
            let output = match &r.output {
                Some(ExecutionOutput::Text(t)) => t.clone(),
                Some(ExecutionOutput::Json(j)) => serde_json::to_string(j).unwrap_or_default(),
                Some(ExecutionOutput::Bytes(b)) => format!("{} bytes", b.len()),
                None => String::new(),
            };
            WasmResult { request_id, success: r.success, output, time_ms: r.execution_time_ms, instructions: r.instructions, error: r.error, input: input.to_string() }
        }
        Err(e) => WasmResult { request_id, success: false, output: String::new(), time_ms: 0, instructions: 0, error: Some(format!("{}", e)), input: input.to_string() },
    }
}

/// Get pending request IDs from the contract.
pub(crate) fn get_pending_ids(rpc: &rpc_pool::Rpc, contract: &str) -> anyhow::Result<Vec<u64>> {
    let args = serde_json::to_vec(&serde_json::json!({"from_index": 0, "limit": 10}))?;
    let bytes = rpc.view(contract, "get_pending_request_ids", &args)?;
    if bytes.is_empty() { return Ok(vec![]); }
    Ok(serde_json::from_slice(&bytes)?)
}


// ── Nostr event handlers ────────────────────────────────────────────────

/// Dispatch incoming Nostr events to the appropriate handler.
fn handle_nostr_event(
    event: &nostr::NostrEvent,
    daemon_cfg: &DaemonConfig,
    signer: &InMemorySigner,
    nonce_cache: &nonce::NonceCache,
    rpc_url: &str,
    log: &mut dyn FnMut(&str),
) {
    // Skip our own RESULT events to prevent feedback loops (allow DISPATCH from self)
    if event.kind != nostr::KIND_TASK {
        if let Some(ref nsec) = daemon_cfg.nostr_nsec {
            if let Ok(npub) = nostr::npub_from_nsec(nsec) {
                if event.pubkey == npub {
                    return; // ignore own non-dispatch events
                }
                // Different pubkey — process normally
            }
        }
    }

    match event.kind {
        nostr::KIND_TASK => {
            log(&format!(" nostr DISPATCH from {}...", &event.pubkey[..8.min(event.pubkey.len())]));
            handle_nostr_dispatch(event, daemon_cfg, signer, nonce_cache, rpc_url, log);
        }
        nostr::KIND_RESULT => {
            log(&format!(" nostr RESULT from {}...", &event.pubkey[..8.min(event.pubkey.len())]));
            match daemon_cfg.execution_mode.as_str() {
                "escrow" => {
                    log("   [41002] escrow mode: routing to escrow plumbing");
                    handle_nostr_result_escrow(event, daemon_cfg, signer, nonce_cache, rpc_url, log);
                }
                "both" => {
                    // If result has job_id in escrow format, use escrow flow; otherwise direct
                    let has_escrow_context = event.content.contains("\"job_id\"")
                        || event.tags.iter().any(|t| t.len() >= 2 && t[0] == "job_id");
                    if has_escrow_context && daemon_cfg.escrow_contract.is_some() {
                        log("   [41002] both mode: routing to escrow plumbing");
                        handle_nostr_result_escrow(event, daemon_cfg, signer, nonce_cache, rpc_url, log);
                    } else {
                        handle_nostr_result(event, daemon_cfg, signer, nonce_cache, rpc_url, log);
                    }
                }
                _ => handle_nostr_result(event, daemon_cfg, signer, nonce_cache, rpc_url, log),
            }
        }
        nostr::KIND_CLAIM => {
            log(&format!(" nostr CLAIM from {}...", &event.pubkey[..8.min(event.pubkey.len())]));
            handle_nostr_claim(event, daemon_cfg, log);
        }
        _ => {
            log(&format!(" nostr unhandled kind {}", event.kind));
        }
    }
}

/// Kind 41000 — Agent posted a task.
///
/// In escrow mode, the relayer thread handles submitting on-chain. The daemon
/// just logs it here — no direct action needed.
/// In direct/both mode, routes to the existing inlayer request_execution flow.
fn handle_nostr_dispatch(
    event: &nostr::NostrEvent,
    daemon_cfg: &DaemonConfig,
    signer: &InMemorySigner,
    nonce_cache: &nonce::NonceCache,
    rpc_url: &str,
    log: &mut dyn FnMut(&str),
) {
    log("   [41000] handle_nostr_dispatch start");

    match daemon_cfg.execution_mode.as_str() {
        "escrow" => {
            // Relayer thread handles task submission — nothing for daemon to do
            log("   [41000] escrow mode: task picked up by relayer thread");
        }
        "both" => {
            // If event has escrow tags, relayer handles it
            let has_escrow_tags = event.tags.iter().any(|t| t.len() >= 2 && t[0] == "fund_action_sig");
            if has_escrow_tags {
                log("   [41000] both mode: escrow task — relayer thread handles");
            } else {
                log("   [41000] both mode: routing to direct (no escrow tags)");
                handle_nostr_dispatch_direct(event, daemon_cfg, signer, nonce_cache, rpc_url, log);
            }
        }
        _ => handle_nostr_dispatch_direct(event, daemon_cfg, signer, nonce_cache, rpc_url, log),
    }
}

/// Escrow mode handler for kind 41002 (RESULT from external AI agent).
///
/// The external AI agent posts its work output via Nostr kind 41002.
/// The daemon handles the on-chain plumbing: claim → write KV → submit result → wait for settlement.
///
/// Flow: parse result from event → claim escrow → write KV → submit_result → wait for settlement → publish 41005
fn handle_nostr_result_escrow(
    event: &nostr::NostrEvent,
    daemon_cfg: &DaemonConfig,
    signer: &InMemorySigner,
    nonce_cache: &nonce::NonceCache,
    rpc_url: &str,
    log: &mut dyn FnMut(&str),
) {
    let escrow_contract = match daemon_cfg.escrow_contract {
        Some(ref c) => c.as_str(),
        None => { log("   [escrow] escrow_contract not configured — skipping"); return; }
    };
    let kv_account = match daemon_cfg.kv_account {
        Some(ref c) => c.as_str(),
        None => { log("   [escrow] kv_account not configured — skipping"); return; }
    };

    // Parse result content from agent
    let content: serde_json::Value = match serde_json::from_str(&event.content) {
        Ok(v) => v,
        Err(e) => { log(&format!("   [escrow] result: invalid JSON — {}", e)); return; }
    };

    let job_id = match content.get("job_id").and_then(|v| v.as_str()) {
        Some(id) => id.to_string(),
        None => {
            // Fallback: check tags
            match event.tags.iter()
                .find(|t| t.len() >= 2 && t[0] == "job_id")
                .and_then(|t| t.get(1))
                .map(|s| s.as_str())
            {
                Some(id) => id.to_string(),
                None => { log("   [escrow] result: missing job_id — skipping"); return; }
            }
        }
    };

    // Agent's output — can be in "result" or "output" field
    let result_output = content.get("result")
        .or_else(|| content.get("output"))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if result_output.is_empty() {
        log("   [escrow] result: empty output — skipping");
        return;
    }

    log(&format!("   [escrow] agent result for job_id={} ({} bytes)", job_id, result_output.len()));

    // Build RPC pool for view calls
    let rpc = match rpc_pool::Rpc::new(rpc_url) {
        Ok(r) => r,
        Err(e) => { log(&format!("   [escrow] RPC init failed: {}", e)); return; }
    };

    // Run the full escrow plumbing: claim → KV → submit_result → wait for settlement
    let result = escrow_client::run_escrow_job(
        &rpc,
        rpc_url,
        signer,
        escrow_contract,
        kv_account,
        &job_id,
        daemon_cfg.worker_stake_yocto,
        nonce_cache,
        result_output,
    );

    match result {
        Ok(job_result) => {
            log(&format!(
                "   [escrow] {} settled: {} (claim={}, kv={}, result={})",
                job_result.job_id, job_result.final_status,
                &job_result.tx_hash_claim[..12.min(job_result.tx_hash_claim.len())],
                &job_result.tx_hash_kv[..12.min(job_result.tx_hash_kv.len())],
                &job_result.tx_hash_result[..12.min(job_result.tx_hash_result.len())],
            ));

            // Publish kind 41005 (confirmed) to Nostr
            if let (Some(ref relay), Some(ref nsec)) = (&daemon_cfg.nostr_relay, &daemon_cfg.nostr_nsec) {
                let response = serde_json::json!({
                    "job_id": job_result.job_id,
                    "status": job_result.final_status,
                    "kv_key": job_result.kv_reference.kv_key,
                });
                let content_str = serde_json::to_string(&response).unwrap_or_default();
                let tags = vec![vec!["e".into(), event.id.clone()], vec!["p".into(), event.pubkey.clone()]];
                match nostr::publish_event(relay, nsec, nostr::KIND_CONFIRMED, &content_str, tags) {
                    Ok(()) => log("   published kind 41005 (confirmed) ✓"),
                    Err(e) => log(&format!("   failed to publish 41005: {}", e)),
                }
            }
        }
        Err(e) => {
            log(&format!("   [escrow] {} FAILED: {}", job_id, e));
        }
    }
}

/// Direct mode handler for kind 41000 (original inlayer flow).
/// Flow: parse content → call request_execution() on contract → publish kind 41004 (dispatched).
fn handle_nostr_dispatch_direct(
    event: &nostr::NostrEvent,
    daemon_cfg: &DaemonConfig,
    signer: &InMemorySigner,
    nonce_cache: &nonce::NonceCache,
    rpc_url: &str,
    log: &mut dyn FnMut(&str),
) {
    log("   [41000] handle_nostr_dispatch start");

    // ── Phase 1 Security: Rate limiting ────────────────────────────────
    if !check_rate_limit(&event.pubkey, daemon_cfg.max_jobs_per_hour) {
        log(&format!("   RATE LIMITED: {} exceeded {} jobs/hour", &event.pubkey[..8.min(event.pubkey.len())], daemon_cfg.max_jobs_per_hour));
        // Publish 41002 error result
        if let (Some(ref relay), Some(ref nsec)) = (&daemon_cfg.nostr_relay, &daemon_cfg.nostr_nsec) {
            let err_content = serde_json::json!({
                "job_id": 0u64,
                "success": false,
                "error": "rate limited: too many jobs",
                "creator": event.pubkey,
            });
            let tags = vec![vec!["e".into(), event.id.clone()], vec!["p".into(), event.pubkey.clone()]];
            let _ = nostr::publish_event(relay, nsec, nostr::KIND_RESULT, &serde_json::to_string(&err_content).unwrap_or_default(), tags);
        }
        return;
    }

    // Parse event content
    let content: serde_json::Value = match serde_json::from_str(&event.content) {
        Ok(v) => v,
        Err(e) => {
            log(&format!("   dispatch: invalid JSON — {}", e));
            return;
        }
    };

    // ── Phase 1 Security: Program whitelist ────────────────────────────
    if let Some(program) = content.get("program").and_then(|v| v.as_str()) {
        if !daemon_cfg.allowed_programs.iter().any(|p| p == program) {
            log(&format!("   REJECTED: program '{}' not whitelisted", program));
            return;
        }
    }

    // ── Phase 1 Security: Input validation ─────────────────────────────
    let mut input_val: serde_json::Value = match content.get("input") {
        Some(v) if v.is_string() => {
            serde_json::from_str(v.as_str().unwrap_or("{}")).unwrap_or(serde_json::Value::Object(Default::default()))
        }
        Some(v) => v.clone(),
        None => serde_json::Value::Object(Default::default()),
    };

    if let Err(reason) = validate_input(&input_val, daemon_cfg) {
        log(&format!("   INPUT REJECTED: {}", reason));
        // Publish 41002 error result
        if let (Some(ref relay), Some(ref nsec)) = (&daemon_cfg.nostr_relay, &daemon_cfg.nostr_nsec) {
            let err_content = serde_json::json!({
                "job_id": 0u64,
                "success": false,
                "error": format!("input validation failed: {}", reason),
                "creator": event.pubkey,
            });
            let tags = vec![vec!["e".into(), event.id.clone()], vec!["p".into(), event.pubkey.clone()]];
            let _ = nostr::publish_event(relay, nsec, nostr::KIND_RESULT, &serde_json::to_string(&err_content).unwrap_or_default(), tags);
        }
        return;
    }

    // ── Phase 1 Security: agent_pays check ─────────────────────────────
    // When agent_pays=false (default), the operator covers all costs.
    // deposit=1 yocto and operator account is used for execution — already handled.
    // If agent_pays=true were enabled, we'd charge the agent's account instead.
    if daemon_cfg.agent_pays {
        log("   WARNING: agent_pays=true is not yet implemented; operator still covering costs");
    }

    let input = {
        // We already parsed input_val above; inject signer and serialize
        inject_signer(&mut input_val, signer);
        serde_json::to_string(&input_val).unwrap_or_default()
    };
    let wasm_url = content.get("wasm_url").and_then(|v| v.as_str()).unwrap_or("local");
    let max_instructions = content.get("max_instructions").and_then(|v| v.as_u64()).unwrap_or(10_000_000_000);
    let max_memory_mb = content.get("max_memory_mb").and_then(|v| v.as_u64()).unwrap_or(256) as u32;

    log(&format!("   [41000] parsed: wasm_url={}, input_len={}", wasm_url, input.len()));

    // Build request_execution args
    let input_b64 = base64::engine::general_purpose::STANDARD.encode(input.as_bytes());
    let args = serde_json::json!({
        "source": {"WasmUrl": {"url": wasm_url, "hash": "0".repeat(64)}},
        "input_data": input_b64,
        "resource_limits": {
            "max_instructions": max_instructions,
            "max_memory_mb": max_memory_mb,
            "max_execution_seconds": 120u64
        },
        "secrets_ref": null,
        "response_format": null,
        "payer_account_id": null,
        "params": null
    });

    log("   [41000] calling request_execution on-chain...");

    // Send transaction to contract
    match send_function_call(
        rpc_url, signer, &daemon_cfg.contract_id,
        "request_execution", &args,
        300_000_000_000_000, // 300 Tgas
        daemon_cfg.deposit_yocto,
        nonce_cache,
    ) {
        Ok((tx_hash, return_value)) => {
            log(&format!("   request_execution tx={}", tx_hash));

            // Extract request_id from return value
            let request_id = return_value
                .as_ref()
                .and_then(|v| v.as_u64())
                .or_else(|| return_value.as_ref().and_then(|v| v.as_str().and_then(|s| s.parse::<u64>().ok())))
                .unwrap_or(0);

            log(&format!("   job_id={} creator={}", request_id, &event.pubkey[..16.min(event.pubkey.len())]));

            // Publish kind 41004 (job available) to Nostr
            if let (Some(ref relay), Some(ref nsec)) = (&daemon_cfg.nostr_relay, &daemon_cfg.nostr_nsec) {
                let response = serde_json::json!({
                    "job_id": request_id,
                    "creator": event.pubkey,
                    "status": "pending",
                    "tx_hash": tx_hash,
                    "wasm_url": wasm_url,
                });
                let content_str = serde_json::to_string(&response).unwrap_or_default();
                let tags = vec![vec!["e".into(), event.id.clone()], vec!["p".into(), event.pubkey.clone()]];
                match nostr::publish_event(relay, nsec, nostr::KIND_DISPATCH, &content_str, tags) {
                    Ok(()) => log("   published kind 41004 (job available) ✓"),
                    Err(e) => log(&format!("   failed to publish 41004: {}", e)),
                }
            } else {
                log("   (nostr_relay or nostr_nsec not configured — skipping 41004 publish)");
            }
        }
        Err(e) => {
            log(&format!("   request_execution FAILED: {}", e));
            nonce_cache.invalidate();
        }
    }
}

/// Kind 41002 — Work result submitted.
///
/// Flow: parse content → call resolve_execution() on contract → publish kind 41005 (confirmed).
fn handle_nostr_result(
    event: &nostr::NostrEvent,
    daemon_cfg: &DaemonConfig,
    signer: &InMemorySigner,
    nonce_cache: &nonce::NonceCache,
    rpc_url: &str,
    log: &mut dyn FnMut(&str),
) {
    let content: serde_json::Value = match serde_json::from_str(&event.content) {
        Ok(v) => v,
        Err(e) => {
            log(&format!("   result: invalid JSON — {}", e));
            return;
        }
    };

    let job_id = match content.get("job_id").and_then(|v| v.as_u64()) {
        Some(id) => id,
        None => {
            log("   result: missing job_id");
            return;
        }
    };

    let result_output = content.get("result").and_then(|v| v.as_str()).unwrap_or("");
    let success = content.get("success").and_then(|v| v.as_bool()).unwrap_or(true);
    let instructions = content.get("instructions").and_then(|v| v.as_u64()).unwrap_or(0);
    let time_ms = content.get("time_ms").and_then(|v| v.as_u64()).unwrap_or(0);

    // Build resolve_execution args (same format as nonce::resolve_one)
    let args = serde_json::json!({
        "request_id": job_id,
        "response": {
            "success": success,
            "output": {"Text": result_output},
            "error": if success { serde_json::Value::Null } else { serde_json::Value::String("Agent reported failure".into()) },
            "resources_used": {"instructions": instructions, "time_ms": time_ms},
            "compilation_note": null,
            "refund_usd": null,
        }
    });

    match send_function_call(
        rpc_url, signer, &daemon_cfg.contract_id,
        "resolve_execution", &args,
        100_000_000_000_000, // 100 Tgas
        0, // no deposit for resolve
        nonce_cache,
    ) {
        Ok((tx_hash, _return_value)) => {
            log(&format!("   resolve_execution job={} tx={}", job_id, tx_hash));

            // Publish kind 41005 (confirmed on-chain)
            if let (Some(ref relay), Some(ref nsec)) = (&daemon_cfg.nostr_relay, &daemon_cfg.nostr_nsec) {
                let response = serde_json::json!({
                    "job_id": job_id,
                    "worker": event.pubkey,
                    "status": "on-chain",
                    "tx_hash": tx_hash,
                    "success": success,
                });
                let content_str = serde_json::to_string(&response).unwrap_or_default();
                let tags = vec![vec!["e".into(), event.id.clone()], vec!["p".into(), event.pubkey.clone()]];
                match nostr::publish_event(relay, nsec, nostr::KIND_CONFIRMED, &content_str, tags) {
                    Ok(()) => log("   published kind 41005 (confirmed) ✓"),
                    Err(e) => log(&format!("   failed to publish 41005: {}", e)),
                }
            }
        }
        Err(e) => {
            log(&format!("   resolve_execution FAILED for job={}: {}", job_id, e));
            nonce_cache.invalidate();
        }
    }
}

/// Kind 41001 — Worker claims a job.
///
/// Flow: parse content → log claim → publish kind 41004 update.
/// (Contract claim handling depends on contract API — logging for now.)
fn handle_nostr_claim(
    event: &nostr::NostrEvent,
    daemon_cfg: &DaemonConfig,
    log: &mut dyn FnMut(&str),
) {
    let content: serde_json::Value = match serde_json::from_str(&event.content) {
        Ok(v) => v,
        Err(e) => {
            log(&format!("   claim: invalid JSON — {}", e));
            return;
        }
    };

    let job_id = content.get("job_id").and_then(|v| v.as_u64()).unwrap_or(0);
    log(&format!("   job={} claimed by {}", job_id, &event.pubkey[..16.min(event.pubkey.len())]));

    // Publish kind 41004 update (claimed status)
    if let (Some(ref relay), Some(ref nsec)) = (&daemon_cfg.nostr_relay, &daemon_cfg.nostr_nsec) {
        let response = serde_json::json!({
            "job_id": job_id,
            "worker": event.pubkey,
            "status": "claimed",
        });
        let content_str = serde_json::to_string(&response).unwrap_or_default();
        let tags = vec![vec!["e".into(), event.id.clone()], vec!["p".into(), event.pubkey.clone()]];
        match nostr::publish_event(relay, nsec, nostr::KIND_DISPATCH, &content_str, tags) {
            Ok(()) => log("   published kind 41004 update (claimed) ✓"),
            Err(e) => log(&format!("   failed to publish 41004 update: {}", e)),
        }
    }
}

/// Generic function call to a NEAR contract.
///
/// Uses broadcast_tx_commit (waits for finalization) and extracts the return value.
/// Returns (tx_hash, Option<return_value>).
fn send_function_call(
    rpc_url: &str,
    signer: &InMemorySigner,
    contract_id: &str,
    method: &str,
    args: &serde_json::Value,
    gas: u64,
    deposit: u128,
    nonce_cache: &nonce::NonceCache,
) -> anyhow::Result<(String, Option<serde_json::Value>)> {
    tracing::info!("[send_function_call] start: {}.{} gas={} deposit={}", contract_id, method, gas, deposit);

    let (nonce_val, block_hash) = nonce_cache
        .reserve_batch(1)
        .map_err(|e| {
            tracing::error!("[send_function_call] nonce reserve failed: {:?}", e);
            nonce_cache.invalidate();
            e
        })?;

    tracing::info!("[send_function_call] nonce={} reserved", nonce_val);

    let client = JsonRpcClient::connect(rpc_url);
    let rt = tokio::runtime::Runtime::new().map_err(|e| {
        tracing::error!("[send_function_call] tokio runtime creation failed: {:?}", e);
        e
    })?;
    let contract: near_primitives::types::AccountId = contract_id.parse()?;

    tracing::info!("[send_function_call] calling rt.block_on for {}...", method);

    rt.block_on(async {
        let tx = TransactionV0 {
            signer_id: signer.account_id.clone(),
            public_key: signer.public_key.clone(),
            nonce: nonce_val,
            receiver_id: contract,
            block_hash,
            actions: vec![Action::FunctionCall(Box::new(FunctionCallAction {
                method_name: method.to_string(),
                args: serde_json::to_vec(args)?,
                gas,
                deposit,
            }))],
        };
        let signed_tx = Transaction::V0(tx).sign(&Signer::InMemory(signer.clone()));
        let tx_hash = format!("{:?}", signed_tx.get_hash());

        let outcome = client
            .call(methods::broadcast_tx_commit::RpcBroadcastTxCommitRequest {
                signed_transaction: signed_tx,
            })
            .await
            .map_err(|e| anyhow::anyhow!("{} failed: {}", method, e))?;

        let return_value = extract_return_value(&outcome);

        Ok((tx_hash, return_value))
    })
}

/// Extract return value from a FinalExecutionOutcomeView.
/// Checks all receipt outcomes for SuccessValue.
fn extract_return_value(
    outcome: &near_primitives::views::FinalExecutionOutcomeView,
) -> Option<serde_json::Value> {
    // Check receipt outcomes first (where function call results appear)
    for receipt in &outcome.receipts_outcome {
        if let ExecutionStatusView::SuccessValue(bytes) = &receipt.outcome.status {
            if let Ok(s) = String::from_utf8(bytes.clone()) {
                // Try JSON
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&s) {
                    return Some(v);
                }
                // Try as plain number (e.g., request_id)
                if let Ok(n) = s.trim().parse::<u64>() {
                    return Some(serde_json::json!(n));
                }
                return Some(serde_json::json!(s));
            }
            // Try borsh-encoded u64 (8 bytes LE)
            if bytes.len() == 8 {
                let n = u64::from_le_bytes(bytes.clone().try_into().ok()?);
                return Some(serde_json::json!(n));
            }
        }
    }
    // Fallback: check top-level status
    if let near_primitives::views::FinalExecutionStatus::SuccessValue(bytes) = &outcome.status {
        if let Ok(s) = String::from_utf8(bytes.clone()) {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&s) {
                return Some(v);
            }
        }
    }
    None
}



// ── Main entry point ────────────────────────────────────────────────────────

/// Main entry point for `inlayer daemon`.
///
/// Parses CLI flags (`--start`, `--stop`, `--status`, `--log`, `--daemon`,
/// `--foreground`, `--dashboard`, `--tunnel`), loads config, optionally
/// daemonizes, starts the dashboard HTTP server, then enters the main loop:
///
/// 1. Block watcher (neardata.xyz) signals new finalised blocks
/// 2. Poll contract for pending request IDs
/// 3. Fetch request details, resolve WASM per source
/// 4. Execute WASM in parallel (scoped threads)
/// 5. Batch-resolve results on-chain
///
/// Args after "daemon" subcommand are passed here.
pub fn run_daemon(args: &[String], config_dir: &Path) -> Result<()> {
    let mut daemon_cfg = DaemonConfig::load(config_dir);

    // Determine mode from args
    if args.iter().any(|a| a == "--stop") {
        tunnel::stop_cloudflare_tunnel(); // Stop tunnel if running
        return manage::stop_daemon(&daemon_cfg.pid_file_path());
    } else if args.iter().any(|a| a == "--start") {
        return manage::start_daemon_via_launchd();
    } else if args.iter().any(|a| a == "--status") {
        return manage::check_status(&daemon_cfg.pid_file_path(), &daemon_cfg.log_file_path());
    } else if args.iter().any(|a| a == "--log") {
        return manage::tail_log(&daemon_cfg.log_file_path());
    }

    let dashboard_addr = manage::parse_dashboard_flag(args).or(daemon_cfg.dashboard_addr.clone());
    let is_daemon = args.iter().any(|a| a == "--daemon");
    let _is_foreground = args.iter().any(|a| a == "--foreground");
    let use_tunnel = args.iter().any(|a| a == "--tunnel");

    // Validate configuration before starting daemon
    daemon_cfg.validate()?;

    // ── Cloudflare Tunnel Setup ───────────────────────────────────────────
    if use_tunnel {
        tracing::info!("🌐 Cloudflare tunnel requested...");
        let tunnel_url = tunnel::spawn_cloudflare_tunnel(8082)?;

        // Save tunnel URL to config
        let config_path = config_dir.join("inlayer.config");
        if config_path.exists() {
            let mut config_str = fs::read_to_string(&config_path)?;
            if !config_str.contains("tunnel_url") {
                config_str.push_str(&format!("\ntunnel_url = \"{}\"\n", tunnel_url));
                fs::write(&config_path, config_str)?;
                tracing::info!("💾 Saved tunnel URL to config");
            }
        }

        daemon_cfg.tunnel_url = Some(tunnel_url);
    }

    if is_daemon {
        let pid_path = daemon_cfg.pid_file_path();
        let log_path = daemon_cfg.log_file_path();
        if manage::is_running(&pid_path) {
            tracing::error!(
                "inlayer daemon already running (PID {})",
                manage::read_pid(&pid_path).unwrap_or_default()
            );
            std::process::exit(1);
        }
        tracing::info!("Starting inlayer daemon...");
        tracing::info!("   Log: {}", log_path.display());
        tracing::info!("   PID: {}", pid_path.display());
        manage::daemonize(&log_path, &pid_path)?;
    } else {
        let pid_path = daemon_cfg.pid_file_path();
        if let Some(parent) = pid_path.parent() {
            fs::create_dir_all(parent).ok();
        }
        fs::write(&pid_path, std::process::id().to_string()).ok();
        tracing::info!("⚡ inlayer daemon — OutLayer local worker (direct RPC)");
        tracing::info!("   Contract:   {}", daemon_cfg.contract_id);
        tracing::info!("   Account:    {}", daemon_cfg.account_id);
        tracing::info!("   RPC:        {}", daemon_cfg.rpc_url());
        tracing::info!("   Poll:       {}s", daemon_cfg.poll_interval_secs);
        tracing::info!("   WASM paths: {:?}", daemon_cfg.search_paths);
    }

    // ── Dashboard setup ────────────────────────────────────────────────
    let (events_tx, _) = broadcast::channel(100);
    let storage_dir = env::var("STORAGE_DIR").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from("./storage"));

    let rpc_url = daemon_cfg.rpc_url();

    let dashboard_state = Arc::new(DashboardState {
        history: std::sync::Mutex::new(Vec::new()),
        status: std::sync::Mutex::new(DashboardStatusInner {
            start_time: std::time::Instant::now(),
            poll_count: 0,
            last_poll_time: None,
            last_block_height: None,
            contract_id: daemon_cfg.contract_id.clone(),
            account_id: daemon_cfg.account_id.clone(),
            rpc_url: rpc_url.clone(),
            poll_interval_secs: daemon_cfg.poll_interval_secs,
            dashboard_addr: dashboard_addr.clone(),
        }),
        events_tx,
        storage_dir,
        contract_id: daemon_cfg.contract_id.clone(),
        rpc_url: rpc_url.clone(),
        search_paths: daemon_cfg.search_paths.clone(),
        signer: std::sync::Mutex::new(None),
    });

    if let Some(ref addr) = dashboard_addr {
        api::spawn_dashboard(addr, dashboard_state.clone());
    }

    // ── Worker loop ─────────────────────────────────────────────────────
    let signer = load_signer(&daemon_cfg.key_path)?;
    init_compiled_cache(signer_key_bytes(&signer));

    // Set signer in dashboard state for API calls
    {
        let mut state = dashboard_state.signer.lock().unwrap();
        *state = Some(signer.clone());
    }

    let mut log_file = if is_daemon {
        let log_path = daemon_cfg.log_file_path();
        if let Some(parent) = log_path.parent() { fs::create_dir_all(parent).ok(); }
        fs::OpenOptions::new().create(true).append(true).open(&log_path).ok()
    } else {
        None
    };

    let mut log = |msg: &str| {
        let line = format!("{} {}\n", manage::now(), msg);
        if is_daemon {
            if let Some(ref mut f) = log_file { let _ = f.write_all(line.as_bytes()); }
        } else {
            eprint!("{}", line);
        }
        let _ = dashboard_state.events_tx.send(msg.to_string());
    };

    log(&format!("inlayer daemon started — Contract: {} Account: {} RPC: {}",
        daemon_cfg.contract_id, daemon_cfg.account_id, rpc_url));

    let rpc_urls = daemon_cfg.rpc_urls();
    tracing::info!("   RPC pool:   {} endpoints", rpc_urls.len());
    let rpc = rpc_pool::Rpc::from_urls(rpc_urls);
    let mut processed: HashSet<u64> = HashSet::new();
    let nonce_cache = Arc::new(nonce::NonceCache::new(rpc_url.clone(), signer.clone()));
    // Set globals for /call handler access
    SHARED_NONCE_CACHE.set(nonce_cache.clone()).ok();
    SHARED_SIGNER.set(signer.clone()).ok();
    SHARED_CONTRACT_ID.set(daemon_cfg.contract_id.clone()).ok();
    SHARED_DEPOSIT_YOCTO.set(daemon_cfg.deposit_yocto).ok();
    let pid_path = daemon_cfg.pid_file_path();
    // Clean up PID file on Ctrl+C / SIGTERM
    let pid_path_cleanup = pid_path.clone();
    ctrlc::set_handler(move || {
        tracing::info!("Received Ctrl+C, shutting down...");
        let _ = std::fs::remove_file(&pid_path_cleanup);
        std::process::exit(0);
    }).ok();

    let block_rx = watcher::spawn_block_watcher(&daemon_cfg.network, &rpc_url, daemon_cfg.poll_interval_secs);
    log("Block watcher started (neardata.xyz event-driven polling)");

    // ── Nostr subscriber ───────────────────────────────────────────────
    let nostr_rx = daemon_cfg.nostr_relay.as_ref().map(|relay| {
        let rx = nostr::spawn_nostr_subscriber(relay);
        log(&format!("Nostr subscriber started ({})", relay));
        if let Some(ref nsec) = daemon_cfg.nostr_nsec {
            if let Ok(npub) = nostr::npub_from_nsec(nsec) {
                log(&format!("Nostr identity: npub1{}...", &npub[..8.min(npub.len())]));
            }
        }
        rx
    });

    // ── Escrow background threads (relayer + verifier) ─────────────────
    let execution_mode = daemon_cfg.execution_mode.clone();
    if execution_mode == "escrow" || execution_mode == "both" {
        let config_dir_clone = config_dir.to_path_buf();
        let has_verifier = daemon_cfg.escrow_contract.is_some() && std::env::var("GEMINI_API_KEY").is_ok();

        // Use health-monitored threads with supervisor
        let relayer_health = escrow_commands::ThreadHealth::new("relayer");
        let verifier_health = escrow_commands::ThreadHealth::new("verifier");

        let _relayer_handle = escrow_commands::spawn_relayer_thread_with_health(
            config_dir_clone.clone(),
            Some(relayer_health.clone()),
        );
        log(&format!("Escrow relayer thread spawned (mode={})", execution_mode));

        if has_verifier {
            let _verifier_handle = escrow_commands::spawn_verifier_thread_with_health(
                config_dir_clone.clone(),
                Some(verifier_health.clone()),
            );
            log("Escrow verifier thread spawned");
        } else {
            if daemon_cfg.escrow_contract.is_none() {
                log("Escrow verifier NOT started: escrow_contract not configured");
            }
            if std::env::var("GEMINI_API_KEY").is_err() {
                log("Escrow verifier NOT started: GEMINI_API_KEY not set");
            }
        }

        // Start supervisor — monitors heartbeats, respawns dead threads
        let _supervisor = escrow_commands::spawn_supervisor(
            config_dir_clone,
            relayer_health,
            if has_verifier { Some(verifier_health) } else { None },
        );
        log("Escrow supervisor thread spawned");
    }

    let mut consecutive_errors = 0u32;
    let last_rpc_poll = std::time::Instant::now();
    let min_rpc_interval = Duration::from_secs(daemon_cfg.poll_interval_secs.max(5));

    loop {
        // ── Process Nostr events (non-blocking) ───────────────────────
        if let Some(ref rx) = nostr_rx {
            while let Ok(event) = rx.try_recv() {
                handle_nostr_event(&event, &daemon_cfg, &signer, &nonce_cache, &rpc_url, &mut log);
            }
        }

        let watcher_height = block_rx.recv_timeout(min_rpc_interval).unwrap_or_default();

        // Rate-limit RPC polling: never hit RPC more than once per min_rpc_interval
        let elapsed = last_rpc_poll.elapsed();
        if elapsed < min_rpc_interval {
            std::thread::sleep(min_rpc_interval - elapsed);
        }

        if watcher_height > 0 {
            let mut st = dashboard_state.status.lock().unwrap();
            st.last_block_height = Some(watcher_height);
        }

        {
            let mut st = dashboard_state.status.lock().unwrap();
            st.poll_count += 1;
            st.last_poll_time = Some(manage::now());
        }

        match get_pending_ids(&rpc, &daemon_cfg.contract_id) {
            Ok(ids) => {
                consecutive_errors = 0;
                if ids.is_empty() { continue; }

                log(&format!("Pending: {:?}", ids));

                let unprocessed: Vec<u64> = ids.iter().filter(|id| !processed.contains(id)).copied().collect();
                if unprocessed.is_empty() { continue; }

                let infos = rpc.fetch_request_infos(&daemon_cfg.contract_id, &unprocessed);

                let nonce_prefetch = std::thread::spawn({
                    let rpc_url = rpc_url.clone();
                    let signer_clone = signer.clone();
                    move || nonce::fetch_nonce_block(&rpc_url, &signer_clone)
                });

                // Resolve WASM per-request based on source (WasmUrl, Project, or default)
                let default_wasm_bytes = find_wasm(&daemon_cfg)
                    .and_then(|p| fs::read(&p).ok());

                let wasm_results: Vec<WasmResult> = std::thread::scope(|s| {
                    let handles: Vec<_> = infos.into_iter()
                        .filter_map(|(req_id, info_result)| {
                            match info_result {
                                Ok(info) => {
                                    log(&format!("Request #{} — {}", req_id, &info.input[..info.input.len().min(80)]));

                                    // Resolve WASM bytes for this specific request
                                    let wasm_bytes = match resolve_wasm(&info.source, &daemon_cfg) {
                                        Some(b) => {
                                            log(&format!("   Source: {:?}", info.source));
                                            b
                                        }
                                        None => match &default_wasm_bytes {
                                            Some(b) => {
                                                log("   Using default WASM (no source match)");
                                                b.clone()
                                            }
                                            None => {
                                                log("   No WASM found for this request, skipping");
                                                return None;
                                            }
                                        }
                                    };

                                    let mut env = HashMap::new();
                                    env.insert("REQUEST_TYPE".into(), "blockchain".into());
                                    let rpc_url = rpc_url.clone();
                                    Some(s.spawn(move || {
                                        execute_single_wasm(&wasm_bytes, req_id, &info.input, &rpc_url, &env, &info)
                                    }))
                                }
                                Err(e) => { log(&format!("   Request #{} info failed: {}", req_id, e)); None }
                            }
                        })
                        .collect();
                    handles.into_iter().map(|h| h.join().unwrap()).collect()
                });

                // Capture everything we need before consuming wasm_results
                let wasm_captured: Vec<(u64, bool, String, String, u64, u64)> = wasm_results.into_iter().map(|result| {
                    // Phase 1 Security: output validation
                    let output = if result.success {
                        match validate_output(&result.output, daemon_cfg.max_output_bytes) {
                            Ok(validated) => {
                                log(&format!("   #{} | {}ms | {} instr", result.request_id, result.time_ms, result.instructions));
                                log(&format!("   {}", &validated[..validated.len().min(200)]));
                                validated
                            }
                            Err(reason) => {
                                log(&format!("   #{} OUTPUT REJECTED: {}", result.request_id, reason));
                                format!("{{\"success\":false,\"error\":\"output validation: {}\"}}", reason)
                            }
                        }
                    } else {
                        let err = result.error.clone().unwrap_or_default();
                        log(&format!("   #{}: {}", result.request_id, err));
                        err
                    };
                    (result.request_id, result.success, result.input.clone(), output, result.time_ms, result.instructions)
                }).collect();

                // Build resolve payloads from captured data
                let resolve_payloads: Vec<(u64, bool, String, u64, u64)> = wasm_captured.iter().map(|(id, success, _input, output, time_ms, instructions)| {
                    (*id, *success, output.clone(), *time_ms, *instructions)
                }).collect();

                // Save full results for history creation after resolve
                let wasm_results_clone = wasm_captured;

                if let Ok(Ok((nonce, hash))) = nonce_prefetch.join() {
                    nonce_cache.prefill(nonce, hash);
                }

                let resolve_results = nonce::resolve_batch(&nonce_cache, &signer, &daemon_cfg.contract_id, resolve_payloads);

                // Now create history records WITH resolve tx hashes, + broadcast SSE events
                for (req_id, tx_result) in resolve_results {
                    let resolve_hash = match &tx_result {
                        Ok(h) => Some(h.clone()),
                        Err(_) => None,
                    };
                    if let Some(wr) = wasm_results_clone.iter().find(|(id, _, _, _, _, _)| *id == req_id) {
                        let record = ExecutionRecord {
                            request_id: wr.0,
                            input: wr.2.clone(),
                            output: wr.3.clone(),
                            execution_time_ms: wr.4,
                            instructions: wr.5,
                            timestamp: manage::now(),
                            success: wr.1,
                            resolve_tx_hash: resolve_hash.clone(),
                        };
                        {
                            let mut hist = dashboard_state.history.lock().unwrap();
                            hist.push(record);
                            if hist.len() > 200 { let excess = hist.len().saturating_sub(200); hist.drain(0..excess); }
                        }
                        // Broadcast SSE event with resolve info
                        if let Some(ref hash) = resolve_hash {
                            let _ = dashboard_state.events_tx.send(
                                serde_json::to_string(&serde_json::json!({
                                    "type": "resolve",
                                    "request_id": req_id,
                                    "tx_hash": hash,
                                    "success": wr.1
                                })).unwrap_or_default()
                            );
                            log(&format!("   Tx: {}", hash));
                        }

                        // Publish kind 41002 (result) to Nostr after on-chain resolve
                        if wr.1 {
                            if let (Some(ref relay), Some(ref nsec)) = (&daemon_cfg.nostr_relay, &daemon_cfg.nostr_nsec) {
                                let result_content = serde_json::json!({
                                    "job_id": req_id,
                                    "result": wr.3,
                                    "success": wr.1,
                                    "instructions": wr.5,
                                    "time_ms": wr.4,
                                    "tx_hash": resolve_hash,
                                });
                                let content_str = serde_json::to_string(&result_content).unwrap_or_default();
                                let tags = vec![vec!["job".into(), req_id.to_string()]];
                                match nostr::publish_event(relay, nsec, nostr::KIND_RESULT, &content_str, tags) {
                                    Ok(()) => log(&format!("   published kind 41002 (result) for job={} ✓", req_id)),
                                    Err(e) => log(&format!("   failed to publish 41002: {}", e)),
                                }
                            }
                        }
                    }
                    if tx_result.is_ok() { processed.insert(req_id); }
                }

                if processed.len() > 500 {
                    let max_id = processed.iter().max().copied().unwrap_or(0);
                    let min_keep = max_id.saturating_sub(1000);
                    processed.retain(|&id| id > min_keep);
                }
                continue;
            }
            Err(e) => {
                consecutive_errors += 1;
                let backoff = std::cmp::min(daemon_cfg.poll_interval_secs * (1 << std::cmp::min(consecutive_errors, 5)), 300);
                log(&format!("{} (backoff {}s, attempt #{})", e, backoff, consecutive_errors));
                std::thread::sleep(Duration::from_secs(backoff));
                continue;
            }
        }
    }

    // Cleanup (unreachable in infinite loop, but here for completeness)
    #[allow(unreachable_code)]
    tunnel::stop_cloudflare_tunnel();

    Ok(())
}
