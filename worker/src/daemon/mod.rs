//! Daemon mode — polls NEAR contract for pending execution requests,
//! executes WASM locally, and resolves results on-chain.
//!
//! Exposed as `inlayer daemon [--start|--stop|--status|--log|--daemon|--foreground|--dashboard <addr>]`.

use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use base64::Engine;
use near_crypto::InMemorySigner;
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
mod manage;
mod nonce;
mod payment;
mod rpc_pool;
mod tunnel;
mod watcher;

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
    let project_name = project_id.split('/').last().unwrap_or(project_id);

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
                    let is_better = best.as_ref().map_or(true, |(_, sz)| size < *sz);
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
                                    let is_better = best.as_ref().map_or(true, |(_, sz)| size < *sz);
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
    let is_foreground = args.iter().any(|a| a == "--foreground");
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

    let mut consecutive_errors = 0u32;
    let mut last_rpc_poll = std::time::Instant::now();
    let min_rpc_interval = Duration::from_secs(daemon_cfg.poll_interval_secs.max(60));

    loop {
        let watcher_height = match block_rx.recv_timeout(min_rpc_interval) {
            Ok(h) => h,
            Err(_) => 0,
        };

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
                    if result.success {
                        log(&format!("   #{} | {}ms | {} instr", result.request_id, result.time_ms, result.instructions));
                        log(&format!("   {}", result.output));
                    } else {
                        let err = result.error.clone().unwrap_or_default();
                        log(&format!("   #{}: {}", result.request_id, err));
                    }
                    let output = if result.success { result.output.clone() } else { result.error.unwrap_or_default() };
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
                    }
                    match tx_result {
                        Ok(_) => { processed.insert(req_id); },
                        Err(_) => {},
                    }
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
    tunnel::stop_cloudflare_tunnel();

    Ok(())
}
