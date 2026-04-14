use offchainvm_worker::api_client::ExecutionOutput;
use offchainvm_worker::api_client::{ResourceLimits, ResponseFormat};
use offchainvm_worker::config::RpcProxyConfig;
use offchainvm_worker::config_client::{ClientConfig, ExecuteRequest, ExecuteResponse, PaymentChallenge, PaymentReceipt, PaymentRequiredResponse};
use offchainvm_worker::executor::{ExecutionContext, Executor};
use offchainvm_worker::outlayer_rpc::RpcProxy;
use offchainvm_worker::outlayer_storage::client::StorageConfig;

use std::collections::HashMap;
use std::env;
use std::io::{self, IsTerminal, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context as AnyhowContext, Result};
use base64::Engine;
use near_crypto::{InMemorySigner, Signer};
use near_jsonrpc_client::{JsonRpcClient, methods};
use near_jsonrpc_primitives::types::query::QueryResponseKind;
use near_primitives::action::{Action, FunctionCallAction};
use near_primitives::transaction::{Transaction, TransactionV0};
use near_primitives::types::BlockReference;
use near_primitives::views::QueryRequest;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
struct Config {
    rpc: RpcConfig,
    storage: StorageConfigSection,
    runner: RunnerConfig,
    env: HashMap<String, String>,
    search_paths: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
struct RpcConfig { url: String }

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
struct StorageConfigSection { mode: String, dir: String }

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
struct RunnerConfig {
    max_instructions: u64,
    max_memory_mb: u32,
    max_execution_seconds: u64,
    log_level: String,
    default_input: Option<String>,
}

impl Default for RpcConfig {
    fn default() -> Self { Self { url: "https://rpc.testnet.near.org".into() } }
}
impl Default for StorageConfigSection {
    fn default() -> Self { Self { mode: "local".into(), dir: "./storage".into() } }
}
impl Default for RunnerConfig {
    fn default() -> Self {
        Self {
            max_instructions: 10_000_000_000,
            max_memory_mb: 256,
            max_execution_seconds: 60,
            log_level: "info".into(),
            default_input: None,
        }
    }
}

impl Config {
    fn load(dir: &Path) -> Self {
        for name in &["inlayer.config", "inlayer.config.toml"] {
            let path = dir.join(name);
            if let Ok(s) = std::fs::read_to_string(&path) {
                if let Ok(cfg) = toml::from_str(&s) { return cfg; }
            }
        }
        if let Some(home) = dirs::home_dir() {
            for name in &["inlayer.config", "inlayer.config.toml"] {
                let path = home.join(".inlayer").join(name);
                if let Ok(s) = std::fs::read_to_string(&path) {
                    if let Ok(cfg) = toml::from_str(&s) { return cfg; }
                }
            }
        }
        Config::default()
    }

    fn resolved_search_paths(&self, config_dir: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        if let Some(p) = config_dir.parent() { out.push(p.to_path_buf()); }
        for p in &self.search_paths {
            let exp = if p.starts_with("~/") {
                dirs::home_dir().map(|h| h.join(&p[2..])).unwrap_or_else(|| PathBuf::from(p))
            } else { PathBuf::from(p) };
            if exp.exists() && !out.contains(&exp) { out.push(exp); }
        }
        out
    }
}

fn find_wasm(name: &str, config_dir: &Path, cfg: &Config) -> Result<PathBuf> {
    let p = PathBuf::from(name);
    if p.is_file() { return Ok(p); }
    let with_ext = if name.ends_with(".wasm") { name.to_string() } else { format!("{}.wasm", name) };

    for base in &cfg.resolved_search_paths(config_dir) {
        if let Ok(entries) = base.read_dir() {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    let fname = path.file_name().unwrap_or_default().to_string_lossy();
                    if fname == with_ext || fname == name { return Ok(path); }
                    continue;
                }
                if !path.is_dir() { continue; }
                let candidate = path.join(&with_ext);
                if candidate.is_file() { return Ok(candidate); }
                let release = path.join("target").join("wasm32-wasip2").join("release");
                if release.is_dir() {
                    if entry.file_name() == name {
                        if let Ok(rd) = release.read_dir() {
                            for f in rd.flatten() {
                                let fname = f.file_name();
                                let s = fname.to_string_lossy();
                                if s.ends_with(".wasm") && !s.starts_with('.') && !s.contains("-deps") {
                                    return Ok(f.path());
                                }
                            }
                        }
                    }
                    let candidate = release.join(&with_ext);
                    if candidate.is_file() { return Ok(candidate); }
                }
            }
        }
    }
    anyhow::bail!("WASM not found: {}\n  Run `inlayer list` to see available WASMs", name)
}

fn cmd_run(config_dir: &Path, wasm_name: &str, input: &str, rpc_override: Option<&str>) -> Result<()> {
    let cfg = Config::load(config_dir);
    let wasm_path = find_wasm(wasm_name, config_dir, &cfg)?;

    let filter = EnvFilter::try_new(format!(
        "inlayer={},offchainvm_worker={}", cfg.runner.log_level, cfg.runner.log_level
    )).unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let rpc_url = rpc_override.map(|s| s.to_string()).unwrap_or(cfg.rpc.url.clone());
    let storage_dir = PathBuf::from(&cfg.storage.dir);
    std::fs::create_dir_all(&storage_dir).ok();

    // Set env vars from config
    for (k, v) in &cfg.env { env::set_var(k, v); }
    env::set_var("STORAGE_DIR", &storage_dir);

    let wasm_bytes = std::fs::read(&wasm_path)
        .with_context(|| format!("reading {}", wasm_path.display()))?;

    eprintln!("🚀 {}", wasm_path.file_name().unwrap_or_default().to_string_lossy());
    eprintln!("   Input: {}", input);
    eprintln!("   RPC: {}", rpc_url);
    eprintln!("   Storage: {} ({})", cfg.storage.mode, cfg.storage.dir);
    eprintln!();

    // Create RPC proxy and storage config in blocking thread
    let rpc_owned = rpc_url.clone();
    let (proxy, storage_config) = std::thread::scope(|s| {
        s.spawn(|| -> Result<(RpcProxy, StorageConfig)> {
            let rpc_cfg = RpcProxyConfig {
                enabled: true,
                rpc_url: Some(rpc_owned.clone()),
                max_calls_per_execution: 100,
                allow_transactions: true,
            };
            let proxy = RpcProxy::new(rpc_cfg, &rpc_owned)?;
            let storage_config = StorageConfig {
                coordinator_url: "http://127.0.0.1:9999".into(),
                coordinator_token: "local".into(),
                keystore_url: "http://127.0.0.1:9998".into(),
                keystore_token: "local".into(),
                project_uuid: "local-test".into(),
                wasm_hash: "00000000".into(),
                account_id: cfg_env("TEE_SIGNER_ID", "test.testnet"),
                tee_mode: "local".into(),
                keystore_tee_session_id: None,
            };
            Ok((proxy, storage_config))
        }).join().unwrap()
    })?;

    // Pass env vars from config to WASM
    let env_vars: HashMap<String, String> = cfg.env.clone();

    let rt = tokio::runtime::Runtime::new()?;
    let handle = rt.handle().clone();

    let exec_ctx = ExecutionContext {
        outlayer_rpc: Some(Arc::new(proxy)),
        storage_config: Some(storage_config),
        runtime_handle: handle,
        compiled_cache: None,
        vrf_config: None,
        wallet_config: None,
    };

    let executor = Executor::new(cfg.runner.max_instructions, true).with_context(exec_ctx);

    let limits = ResourceLimits {
        max_instructions: cfg.runner.max_instructions,
        max_memory_mb: cfg.runner.max_memory_mb,
        max_execution_seconds: cfg.runner.max_execution_seconds,
    };

    let result = rt.block_on(executor.execute(
        &wasm_bytes,
        None,
        input.as_bytes(),
        &limits,
        if env_vars.is_empty() { None } else { Some(env_vars) },
        Some("wasm32-wasip2"),
        &ResponseFormat::Text,
        None,
        None,
        None,
    ))?;

    println!("{}", "=".repeat(60));
    println!("✅ Success: {}", result.success);
    println!("⏱️  Time: {}ms | Instructions: {}", result.execution_time_ms, result.instructions);
    if let Some(output) = &result.output {
        let s = match output {
            ExecutionOutput::Text(t) => t.clone(),
            ExecutionOutput::Json(j) => serde_json::to_string_pretty(j).unwrap_or_default(),
            ExecutionOutput::Bytes(b) => format!("{} bytes", b.len()),
        };
        println!("📤 Output: {}", s);
    }
    if let Some(error) = &result.error { println!("❌ Error: {}", error); }

    // Drop executor first (releases runtime handle), then runtime drops cleanly
    drop(executor);
    drop(rt);
    Ok(())
}

/// Get env var with fallback, checking config env first
fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn cfg_env(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
}

fn cmd_submit(extra_args: &[String]) -> Result<()> {
    use base64::Engine;

    if extra_args.is_empty() || extra_args[0] == "--help" {
        eprintln!("Usage: inlayer submit <input_json> [--contract <id>] [--account <id>] [--network <net>] [--wasm-url <url>]");
        eprintln!("       Env: INLAYER_CONTRACT, INLAYER_ACCOUNT, INLAYER_NETWORK, INLAYER_WASM_URL, INLAYER_DEPOSIT");
        eprintln!();
        eprintln!("Submits an execution request to the OutLayer contract.");
        eprintln!("layerd will pick it up and execute it.");
        std::process::exit(0);
    }

    // Parse args
    let mut input = extra_args[0].clone();
    let mut contract_id: Option<String> = std::env::var("INLAYER_CONTRACT").ok();
    let mut account_id: Option<String> = std::env::var("INLAYER_ACCOUNT").ok();
    let mut network: Option<String> = std::env::var("INLAYER_NETWORK").ok();
    let mut wasm_url: Option<String> = std::env::var("INLAYER_WASM_URL").ok();
    let mut deposit_str = env_or("INLAYER_DEPOSIT", "0.01");

    let mut i = 1;
    while i < extra_args.len() {
        match extra_args[i].as_str() {
            "--contract" if i + 1 < extra_args.len() => { contract_id = Some(extra_args[i + 1].clone()); i += 2; }
            "--account" if i + 1 < extra_args.len() => { account_id = Some(extra_args[i + 1].clone()); i += 2; }
            "--network" if i + 1 < extra_args.len() => { network = Some(extra_args[i + 1].clone()); i += 2; }
            "--wasm-url" if i + 1 < extra_args.len() => { wasm_url = Some(extra_args[i + 1].clone()); i += 2; }
            "--deposit" if i + 1 < extra_args.len() => { deposit_str = extra_args[i + 1].clone(); i += 2; }
            other => { input = other.to_string(); i += 1; }
        }
    }

    let contract_id = contract_id.unwrap_or_else(|| {
        eprintln!("Error: --contract or INLAYER_CONTRACT required");
        std::process::exit(1);
    });
    let account_id = account_id.unwrap_or_else(|| {
        eprintln!("Error: --account or INLAYER_ACCOUNT required");
        std::process::exit(1);
    });
    let network = network.unwrap_or_else(|| "testnet".to_string());
    let wasm_url = wasm_url.unwrap_or_else(|| {
        eprintln!("Error: --wasm-url or INLAYER_WASM_URL required");
        std::process::exit(1);
    });

    let rpc_url = match network.as_str() {
        "mainnet" => "https://rpc.mainnet.near.org".to_string(),
        "testnet" => "https://test.rpc.fastnear.com".to_string(),
        other => other.to_string(),
    };

    let deposit: f64 = deposit_str.parse().context("invalid deposit amount")?;
    let deposit_yocto = (deposit * 1e24) as u128;

    let input_b64 = base64::engine::general_purpose::STANDARD.encode(input.as_bytes());

    let args_json = serde_json::json!({
        "source": {
            "WasmUrl": {
                "url": wasm_url,
                "hash": "0000000000000000000000000000000000000000000000000000000000000000",
                "build_target": "wasm32-wasip2"
            }
        },
        "resource_limits": {
            "max_instructions": 500_000_000_000u64,
            "max_memory_mb": 256u32,
            "max_execution_seconds": 60u64
        },
        "input_data": input_b64
    });
    let args_bytes = serde_json::to_vec(&args_json)?;

    eprintln!("📤 Submitting to {}...", contract_id);
    eprintln!("   Input: {}", input);
    eprintln!("   Account: {}", account_id);

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let client = JsonRpcClient::connect(&rpc_url);
        let signer = find_signer(&account_id, &network)?;

        let query_response = client
            .call(near_jsonrpc_client::methods::query::RpcQueryRequest {
                block_reference: BlockReference::latest(),
                request: QueryRequest::ViewAccessKey { account_id: account_id.parse()?, public_key: signer.public_key() },
            })
            .await
            .context("query access key failed")?;

        let nonce = match query_response.kind {
            QueryResponseKind::AccessKey(ak) => ak.nonce,
            _ => anyhow::bail!("unexpected query response"),
        };

        let transaction = TransactionV0 {
            signer_id: account_id.parse()?,
            public_key: signer.public_key.clone(),
            nonce: nonce + 1,
            receiver_id: contract_id.parse()?,
            block_hash: query_response.block_hash,
            actions: vec![Action::FunctionCall(Box::new(FunctionCallAction {
                method_name: "request_execution".into(),
                args: args_bytes,
                gas: 100_000_000_000_000,
                deposit: deposit_yocto,
            }))],
        };

        let signed_tx = Transaction::V0(transaction).sign(&near_crypto::Signer::InMemory(signer));
        let tx_hash = signed_tx.get_hash();

        let result = client
            .call(near_jsonrpc_client::methods::broadcast_tx_commit::RpcBroadcastTxCommitRequest {
                signed_transaction: signed_tx,
            })
            .await
            .context("broadcast tx failed")?;

        match &result.status {
            near_primitives::views::FinalExecutionStatus::Failure(e) => {
                anyhow::bail!("Transaction failed: {:?}", e);
            }
            near_primitives::views::FinalExecutionStatus::SuccessValue(_) => {}
            _ => {}
        }

        eprintln!("✅ Submitted! tx: {}", tx_hash);
        eprintln!("   layerd will pick it up automatically.");
        Ok(())
    })
}

/// Find signer key from ~/.near-credentials
fn find_signer(account_id: &str, network: &str) -> Result<InMemorySigner> {
    use near_crypto::SecretKey;
    use near_primitives::types::AccountId;

    let home = dirs::home_dir().context("no home dir")?;
    let key_path = home.join(format!(".near-credentials/{}/{}.json", network, account_id));
    if !key_path.exists() {
        anyhow::bail!("Key not found at {}. Run: near login", key_path.display());
    }
    let data = std::fs::read_to_string(&key_path)
        .with_context(|| format!("reading {}", key_path.display()))?;
    let kf: serde_json::Value = serde_json::from_str(&data)?;
    let private_key = kf["private_key"].as_str().unwrap_or("");
    let account_id: AccountId = account_id.parse()?;
    let secret_key: SecretKey = private_key.parse()?;
    Ok(InMemorySigner::from_secret_key(account_id, secret_key))
}

fn cmd_status(extra_args: &[String]) -> Result<()> {
    use base64::Engine;

    let mut contract_id: Option<String> = std::env::var("INLAYER_CONTRACT").ok();
    let mut network: Option<String> = std::env::var("INLAYER_NETWORK").ok();

    let mut i = 0;
    while i < extra_args.len() {
        match extra_args[i].as_str() {
            "--contract" if i + 1 < extra_args.len() => { contract_id = Some(extra_args[i + 1].clone()); i += 2; }
            "--network" if i + 1 < extra_args.len() => { network = Some(extra_args[i + 1].clone()); i += 2; }
            _ => { i += 1; }
        }
    }

    let contract_id = contract_id.unwrap_or_else(|| {
        eprintln!("Error: --contract or INLAYER_CONTRACT required");
        std::process::exit(1);
    });
    let network = network.unwrap_or_else(|| "testnet".to_string());

    let rpc_url = match network.as_str() {
        "mainnet" => "https://rpc.mainnet.near.org".to_string(),
        "testnet" => "https://test.rpc.fastnear.com".to_string(),
        other => format!("https://rpc.{}.near.org", other),
    };

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let client = JsonRpcClient::connect(&rpc_url);

        let resp = client
            .call(near_jsonrpc_client::methods::query::RpcQueryRequest {
                block_reference: BlockReference::latest(),
                request: QueryRequest::CallFunction {
                    account_id: contract_id.parse()?,
                    method_name: "get_pending_request_ids".into(),
                    args: near_primitives::types::FunctionArgs::from(
                        serde_json::to_vec(&serde_json::json!({"from_index":0,"limit":10}))?
                    ),
                },
            })
            .await
            .context("query pending requests failed")?;

        let ids: Vec<u64> = match resp.kind {
            QueryResponseKind::CallResult(result) => {
                serde_json::from_slice(&result.result).unwrap_or_default()
            }
            _ => anyhow::bail!("unexpected response"),
        };

        if ids.is_empty() {
            eprintln!("✅ No pending requests");
            return Ok(());
        }

        eprintln!("📋 Pending requests: {:?}", ids);

        for id in &ids {
            let args = serde_json::json!({"request_id": id});
            let args_bytes = serde_json::to_vec(&args)?;

            let resp = client
                .call(near_jsonrpc_client::methods::query::RpcQueryRequest {
                    block_reference: BlockReference::latest(),
                    request: QueryRequest::CallFunction {
                        account_id: contract_id.parse()?,
                        method_name: "get_request".into(),
                        args: near_primitives::types::FunctionArgs::from(args_bytes),
                    },
                })
                .await;

            if let Ok(resp) = resp {
                if let QueryResponseKind::CallResult(result) = resp.kind {
                    if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&result.result) {
                        let input_b64 = val.get("input_data").and_then(|v| v.as_str()).unwrap_or("");
                        let input_bytes = base64::engine::general_purpose::STANDARD.decode(input_b64).unwrap_or_default();
                        let input_str = String::from_utf8_lossy(&input_bytes);
                        let status = if val.get("response").is_some() { "✅ resolved" } else { "⏳ pending" };
                        eprintln!("   #{} {} input={}", id, status, input_str);
                    }
                }
            }
        }
        Ok(())
    })
}

fn cmd_list(config_dir: &Path) {
    let cfg = Config::load(config_dir);
    let mut all: Vec<PathBuf> = Vec::new();

    for base in &cfg.resolved_search_paths(config_dir) {
        if let Ok(entries) = base.read_dir() {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() && path.extension().map(|e| e == "wasm").unwrap_or(false) {
                    all.push(path); continue;
                }
                if !path.is_dir() { continue; }
                if let Ok(sub) = path.read_dir() {
                    for f in sub.flatten() {
                        if f.path().is_file() && f.path().extension().map(|e| e == "wasm").unwrap_or(false) {
                            all.push(f.path());
                        }
                    }
                }
                let release = path.join("target").join("wasm32-wasip2").join("release");
                if let Ok(rd) = release.read_dir() {
                    for f in rd.flatten() {
                        let fname = f.file_name();
                        let s = fname.to_string_lossy();
                        if s.ends_with(".wasm") && !s.starts_with('.') && !s.contains("/deps/") {
                            all.push(f.path());
                        }
                    }
                }
            }
        }
    }

    if !all.is_empty() {
        all.sort(); all.dedup();
        println!("Available WASMs:");
        for w in &all {
            let size = w.metadata().map(|m| m.len()).unwrap_or(0);
            let rel = cfg.resolved_search_paths(config_dir).iter()
                .filter_map(|b| w.strip_prefix(b).ok()).next().unwrap_or(w);
            println!("  {:60} {:.0} KB", rel.display(), size as f64 / 1024.0);
        }
    } else {
        println!("No WASM files found.\n  Build: cargo build --target wasm32-wasip2 --release\n  Or add search_paths in inlayer.config");
    }
}

fn cmd_init(extra_args: &[String]) -> Result<()> {
    let cwd = env::current_dir()?;
    let config_path = cwd.join("inlayer.config");

    // Check if config already exists
    if config_path.exists() {
        eprintln!("⚠️  Config file already exists: {}", config_path.display());
        eprintln!("   Delete it first or edit it directly.");
        std::process::exit(1);
    }

    // Parse optional flags
    let mut contract_id: Option<String> = None;
    let mut account_id: Option<String> = None;
    let mut network: Option<String> = None;
    let mut force = false;

    let mut i = 0;
    while i < extra_args.len() {
        match extra_args[i].as_str() {
            "--contract" if i + 1 < extra_args.len() => {
                contract_id = Some(extra_args[i + 1].clone());
                i += 2;
            }
            "--account" if i + 1 < extra_args.len() => {
                account_id = Some(extra_args[i + 1].clone());
                i += 2;
            }
            "--network" if i + 1 < extra_args.len() => {
                network = Some(extra_args[i + 1].clone());
                i += 2;
            }
            "--force" => {
                force = true;
                i += 1;
            }
            _ => {
                eprintln!("Unknown flag: {}", extra_args[i]);
                eprintln!("Usage: inlayer init [--contract <id>] [--account <id>] [--network <net>] [--force]");
                std::process::exit(1);
            }
        }
    }

    if force && config_path.exists() {
        std::fs::remove_file(&config_path)?;
        eprintln!("🗑️  Removed existing config file");
    }

    // 🔍 Auto-discover WASM projects recursively
    eprintln!("🔍 Scanning for WASM projects...");
    let mut wasm_projects = Vec::new();

    fn scan_directory(dir: &Path, max_depth: usize, current_depth: usize, found: &mut Vec<String>) {
        if current_depth > max_depth {
            return;
        }

        let Ok(entries) = dir.read_dir() else { return };

        for entry in entries.flatten() {
            let path = entry.path();

            // Skip hidden directories and common non-project dirs
            if let Some(name) = path.file_name() {
                let name_str = name.to_string_lossy();
                if name_str.starts_with('.') || name_str == "node_modules" || name_str == "target" {
                    continue;
                }
            }

            // Check if this directory contains WASM files
            let release_path = path.join("target").join("wasm32-wasip2").join("release");
            if release_path.exists() {
                if let Ok(wasm_entries) = release_path.read_dir() {
                    let has_wasm = wasm_entries.flatten().any(|w| {
                        w.path().extension().map(|e| e == "wasm").unwrap_or(false)
                    });
                    if has_wasm {
                        let rel_path = path.strip_prefix(env::current_dir().unwrap_or_else(|_| PathBuf::from("."))).unwrap_or(&path);
                        found.push(format!("./{}", rel_path.display()));
                        eprintln!("   ✅ Found project: {}", rel_path.display());
                    }
                }
            }

            // Recursively scan subdirectories
            if path.is_dir() {
                scan_directory(&path, max_depth, current_depth + 1, found);
            }
        }
    }

    scan_directory(&cwd, 3, 0, &mut wasm_projects);

    // Try to auto-detect account from NEAR credentials
    let detected_account = if account_id.is_none() {
        // Try to find NEAR credential files
        if let Some(home) = dirs::home_dir() {
            for net in &["testnet", "mainnet"] {
                let cred_dir = home.join(".near-credentials").join(net);
                if cred_dir.exists() {
                    if let Ok(entries) = cred_dir.read_dir() {
                        for entry in entries.flatten() {
                            let path = entry.path();
                            if path.extension().map(|e| e == "json").unwrap_or(false) {
                                let account_name = path.file_stem()
                                    .unwrap_or_default()
                                    .to_string_lossy()
                                    .to_string();
                                if !account_name.is_empty() {
                                    eprintln!("✅ Detected account: {} ({})", account_name, net);
                                    if account_id.is_none() {
                                        account_id = Some(account_name.clone());
                                    }
                                    if network.is_none() {
                                        network = Some(net.to_string());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        account_id
    } else {
        account_id
    };

    // Build search_paths - add discovered projects plus some defaults
    let mut search_paths = Vec::new();

    // Add discovered projects first
    for project in &wasm_projects {
        search_paths.push(project.clone());
    }

    // Add common paths if not already discovered
    if !wasm_projects.iter().any(|p| p.contains("wasi-examples")) {
        search_paths.push("./wasi-examples".to_string());
    }

    // Format search_paths for TOML
    let search_paths_toml = if search_paths.is_empty() {
        r#"search_paths = [
    "./wasi-examples",
    # Add your WASM project directories here
]"#.to_string()
    } else {
        let paths: Vec<String> = search_paths.iter().map(|p| format!("    \"{}\",", p)).collect();
        format!("search_paths = [\n{}]", paths.join("\n"))
    };

    // Build config with defaults
    let contract_id = contract_id.unwrap_or_else(|| "outlayer.testnet".to_string());
    let account_id = detected_account.unwrap_or_else(|| "your-account.testnet".to_string());
    let network = network.unwrap_or_else(|| "testnet".to_string());
    let _home = dirs::home_dir().unwrap_or_default();

    let config_content = format!(
        r#"# inlayer.config - OutLayer local worker configuration
# Generated by: inlayer init
#

# NEAR contract to poll for execution requests
contract_id = "{}"

# Your NEAR account (will submit resolve transactions)
account_id = "{}"

# NEAR network
network = "{}"

# Path to your NEAR account key file
# Run: near login --network {}
key_path = "~/.near-credentials/{}/{}"

# Directories to search for WASM files (auto-discovered)
{}
# You can add more paths manually:
# search_paths = [
#     "./my-wasm-project",
#     "~/other-projects",
# ]

# How often to poll for new requests (seconds)
poll_interval_secs = 5

# Optional: Dashboard HTTP server (e.g. "127.0.0.1:8082")
# dashboard_addr = "127.0.0.1:8082"
"#,
        contract_id,
        account_id,
        network,
        network,
        network,
        account_id,
        search_paths_toml
    );

    // Write config file
    std::fs::write(&config_path, config_content)?;

    eprintln!("✅ Created config file: {}", config_path.display());
    eprintln!();
    eprintln!("Next steps:");
    eprintln!("1. Review and edit the config if needed:");
    eprintln!("   nano {}", config_path.display());
    eprintln!();
    eprintln!("2. Make sure you have NEAR credentials:");
    eprintln!("   near login --network {}", network);
    eprintln!();
    eprintln!("3. Start the daemon:");
    eprintln!("   inlayer daemon --foreground");
    eprintln!();

    Ok(())
}

fn cmd_config(config_dir: &Path) {
    let cfg = Config::load(config_dir);
    println!("{}", toml::to_string_pretty(&cfg).unwrap_or_else(|e| format!("Error: {}", e)));
}

fn cmd_register(extra_args: &[String], config_dir: &Path) -> Result<()> {
    let mut project_name = None;
    let mut network = "testnet".to_string();
    let mut contract_id = "outlayer.kampouse.testnet".to_string();
    let mut tunnel_url = None;

    // Parse args
    let mut i = 0;
    while i < extra_args.len() {
        match extra_args[i].as_str() {
            "--network" if i + 1 < extra_args.len() => {
                network = extra_args[i + 1].clone();
                i += 2;
            }
            "--contract" if i + 1 < extra_args.len() => {
                contract_id = extra_args[i + 1].clone();
                i += 2;
            }
            "--tunnel" if i + 1 < extra_args.len() => {
                tunnel_url = Some(extra_args[i + 1].clone());
                i += 2;
            }
            name if !name.starts_with("--") => {
                project_name = Some(name.to_string());
                i += 1;
            }
            _ => { i += 1; }
        }
    }

    let project_name = project_name.ok_or_else(|| anyhow::anyhow!("Usage: inlayer register <project-name> [--network testnet] [--contract outlayer.kampouse.testnet] [--tunnel https://...]"))?;

    eprintln!("📦 Registering project '{}' to blockchain...", project_name);

    // Load signer credentials
    let cfg = offchainvm_worker::daemon::DaemonConfig::load(config_dir);
    let signer = offchainvm_worker::daemon::load_signer(&cfg.key_path)?;
    let account_id = signer.account_id.clone();

    // Find WASM file for project
    eprintln!("   🔍 Finding WASM file...");
    let wasm_path = find_project_wasm(&cfg.search_paths, &project_name)
        .ok_or_else(|| anyhow::anyhow!("WASM file not found for project '{}'. Searched in: {:?}", project_name, cfg.search_paths))?;

    eprintln!("   ✅ Found: {}", wasm_path.display());

    // Calculate SHA256
    eprintln!("   🔐 Calculating SHA256...");
    let wasm_bytes = std::fs::read(&wasm_path)?;
    let hash = format!("{:x}", sha2::Sha256::digest(&wasm_bytes));
    eprintln!("   ✅ SHA256: {}", hash);

    // Get tunnel URL (from args, config, or prompt user)
    let wasm_url = if let Some(url) = tunnel_url.or(cfg.tunnel_url) {
        url
    } else {
        eprintln!();
        eprintln!("⚠️  No tunnel URL provided. Your daemon needs to be accessible for workers to download the WASM.");
        eprintln!();
        eprintln!("Options:");
        eprintln!("1. Start daemon with tunnel: inlayer daemon --tunnel");
        eprintln!("2. Then run: inlayer register {} --tunnel <URL>", project_name);
        eprintln!();
        anyhow::bail!("Tunnel URL required. Start daemon with: inlayer daemon --tunnel");
    };

    let wasm_url = format!("{}/wasm/{}/{}", wasm_url.trim_end_matches('/'), signer.account_id, project_name);
    eprintln!("   📍 WASM URL: {}", wasm_url);

    // Build create_project transaction
    eprintln!("   📝 Calling create_project on contract...");
    let rpc_url = match network.as_str() {
        "mainnet" => "https://rpc.mainnet.near.org",
        "testnet" => "https://test.rpc.fastnear.com",
        _ => return Err(anyhow::anyhow!("Unknown network: {}", network)),
    };

    let client = JsonRpcClient::connect(rpc_url);
    let rt = tokio::runtime::Runtime::new()?;

    let tx_result = rt.block_on(async {
        // Fetch nonce
        let query = methods::query::RpcQueryRequest {
            block_reference: BlockReference::latest(),
            request: QueryRequest::ViewAccessKey {
                account_id: signer.account_id.clone(),
                public_key: signer.public_key.clone(),
            },
        };
        let response = client.call(query).await?;
        let nonce = match response.kind {
            QueryResponseKind::AccessKey(ak) => ak.nonce + 1,
            _ => anyhow::bail!("unexpected query response"),
        };

        // Build args
        let args = serde_json::json!({
            "name": project_name,
            "source": {
                "WasmUrl": {
                    "url": wasm_url,
                    "hash": hash,
                    "build_target": "wasm32-wasip2"
                }
            }
        });
        let args_bytes = serde_json::to_vec(&args)?;

        // Calculate storage cost (rough estimate: 100KB to be safe)
        let deposit = 100_000_000_000_000_000_000_000; // 0.1 NEAR (100 billion yocto)

        let transaction = TransactionV0 {
            signer_id: signer.account_id.clone(),
            public_key: signer.public_key.clone(),
            nonce,
            receiver_id: contract_id.parse()?,
            block_hash: response.block_hash,
            actions: vec![Action::FunctionCall(Box::new(FunctionCallAction {
                method_name: "create_project".to_string(),
                args: args_bytes,
                gas: 100_000_000_000_000,
                deposit,
            }))],
        };

        let signed_tx = Transaction::V0(transaction).sign(&Signer::InMemory(signer));

        // Send transaction and capture result
        eprintln!("   ⏳ Submitting transaction...");
        client.call(methods::send_tx::RpcSendTransactionRequest {
            signed_transaction: signed_tx,
            wait_until: near_primitives::views::TxExecutionStatus::ExecutedOptimistic,
        }).await.map_err(|e| anyhow::anyhow!("Transaction failed: {}", e))
    });

    tx_result?;

    // Verify the project was actually created
    eprintln!("   🔍 Verifying project creation...");
    let client2 = JsonRpcClient::connect(rpc_url);
    let verify_result = rt.block_on(async {
        let project_id = format!("{}/{}", account_id, project_name);
        let args_bytes = format!("\"{}\"", project_id).into_bytes();
        let query = methods::query::RpcQueryRequest {
            block_reference: BlockReference::latest(),
            request: QueryRequest::CallFunction {
                account_id: contract_id.parse().unwrap(),
                method_name: "get_project".to_string(),
                args: near_primitives::types::FunctionArgs::from(args_bytes),
            },
        };

        client2.call(query).await
    });

    match verify_result {
        Ok(response) => {
            if let QueryResponseKind::CallResult(result) = response.kind {
                if !result.result.is_empty() {
                    eprintln!("   ✅ Project verified on contract!");
                } else {
                    eprintln!("   ⚠️  Warning: Project not found on contract after creation");
                    eprintln!("   This might mean the transaction failed silently.");
                    eprintln!("   Check transaction status on NEAR Explorer");
                }
            }
        }
        Err(e) => {
            eprintln!("   ⚠️  Could not verify project: {}", e);
            eprintln!("   Check transaction status on NEAR Explorer");
        }
    }

    drop(rt); // Drop runtime before continuing

    eprintln!();
    eprintln!("✅ Project '{}' registered successfully!", project_name);
    eprintln!("   Project ID: {}/{}", account_id, project_name);
    eprintln!();
    eprintln!("💡 Frontend can now call:");
    eprintln!("   POST /call/{}/{}", account_id, project_name);
    eprintln!();

    Ok(())
}

fn find_project_wasm(search_paths: &[String], project_name: &str) -> Option<PathBuf> {
    for dir in search_paths {
        let base = PathBuf::from(dir);
        if !base.exists() { continue; }

        // Check for project directory
        if let Ok(entries) = base.read_dir() {
            for entry in entries.flatten() {
                let path = entry.path();

                // Check if directory name matches project
                if path.is_dir() {
                    let dirname = path.file_name()?.to_string_lossy();
                    if dirname.contains(project_name) {
                        let release = path.join("target").join("wasm32-wasip2").join("release");
                        if let Ok(wasm_entries) = release.read_dir() {
                            for wasm_entry in wasm_entries.flat_map(|e| e.ok()) {
                                let wasm_path = wasm_entry.path();
                                if wasm_path.is_file() && wasm_path.extension().map(|e| e == "wasm").unwrap_or(false) {
                                    let fname = wasm_path.file_name()?.to_string_lossy();
                                    if !fname.starts_with('.') && !fname.contains("-deps") {
                                        return Some(wasm_path);
                                    }
                                }
                            }
                        }
                    }
                }

                // Check for direct WASM file
                if path.is_file() && path.extension().map(|e| e == "wasm").unwrap_or(false) {
                    let fname = path.file_name()?.to_string_lossy();
                    if fname.contains(project_name) {
                        return Some(path);
                    }
                }
            }
        }
    }
    None
}

// ============================================================================
// Client Commands - Execute on remote workers
// ============================================================================

/// Execute a command on a remote worker
fn cmd_exec(extra_args: &[String]) -> Result<()> {
    let cfg = ClientConfig::load();
    
    let mut worker_url: Option<String> = None;
    let mut input: Option<String> = None;
    let mut program: Option<String> = None;
    let mut wasm_url: Option<String> = None;
    let mut account_id: Option<String> = None;
    let mut no_pay = false;
    let mut max_instructions: Option<u64> = None;
    let mut max_memory_mb: Option<u32> = None;

    let mut i = 0;
    while i < extra_args.len() {
        match extra_args[i].as_str() {
            "--worker" if i + 1 < extra_args.len() => {
                worker_url = Some(extra_args[i + 1].clone());
                i += 2;
            }
            "--input" if i + 1 < extra_args.len() => {
                input = Some(extra_args[i + 1].clone());
                i += 2;
            }
            "--program" if i + 1 < extra_args.len() => {
                program = Some(extra_args[i + 1].clone());
                i += 2;
            }
            "--wasm-url" if i + 1 < extra_args.len() => {
                wasm_url = Some(extra_args[i + 1].clone());
                i += 2;
            }
            "--account" if i + 1 < extra_args.len() => {
                account_id = Some(extra_args[i + 1].clone());
                i += 2;
            }
            "--max-instructions" if i + 1 < extra_args.len() => {
                max_instructions = Some(extra_args[i + 1].parse()?);
                i += 2;
            }
            "--max-memory" if i + 1 < extra_args.len() => {
                max_memory_mb = Some(extra_args[i + 1].parse()?);
                i += 2;
            }
            "--no-pay" => {
                no_pay = true;
                i += 1;
            }
            other if !other.starts_with("--") => {
                // Positional argument - treat as input if not set
                if input.is_none() {
                    input = Some(other.to_string());
                }
                i += 1;
            }
            _ => {
                eprintln!("Unknown flag: {}", extra_args[i]);
                eprintln!("Usage: inlayer exec --worker <url> --input <data> [--program <name>] [--no-pay]");
                std::process::exit(1);
            }
        }
    }

    // Get worker URL
    let worker_url = cfg.get_worker_url(worker_url.as_deref())?;

    // Get input from stdin if not provided
    let input = match input {
        Some(i) => i,
        None => {
            if !io::stdin().is_terminal() {
                let mut buf = String::new();
                io::stdin().read_to_string(&mut buf)?;
                buf.trim().to_string()
            } else {
                anyhow::bail!("No input provided. Use --input <data> or pipe data via stdin.");
            }
        }
    };

    // Build request
    let req = ExecuteRequest {
        input,
        wasm_url,
        program,
        max_instructions,
        max_memory_mb,
    };

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()?;

    let url = format!("{}/execute", worker_url.trim_end_matches('/'));
    
    eprintln!("🚀 Executing on {}", worker_url);
    eprintln!("   Input: {} bytes", req.input.len());

    // First request - may get 402 payment challenge
    let resp = client
        .post(&url)
        .json(&req)
        .send()
        .context("Failed to connect to worker")?;

    match resp.status() {
        reqwest::StatusCode::OK => {
            // Success - print result
            let result: ExecuteResponse = resp.json().context("Failed to parse response")?;
            print_execute_result(&result);
            if !result.success {
                std::process::exit(1);
            }
        }
        reqwest::StatusCode::PAYMENT_REQUIRED => {
            // Payment required
            let resp_wrapper: PaymentRequiredResponse = resp.json().context("Failed to parse payment challenge")?;
            let challenge = resp_wrapper.challenge;
            handle_payment_challenge(&client, &worker_url, &req, challenge, &cfg, account_id.as_deref(), no_pay)?;
        }
        reqwest::StatusCode::FORBIDDEN => {
            let error_text = resp.text().unwrap_or_else(|_| "Unknown error".to_string());
            eprintln!("❌ Access denied: {}", error_text);
            std::process::exit(1);
        }
        status => {
            let error_text = resp.text().unwrap_or_else(|_| "Unknown error".to_string());
            eprintln!("❌ Error {}: {}", status, error_text);
            std::process::exit(1);
        }
    }

    Ok(())
}

/// Handle 402 payment challenge
fn handle_payment_challenge(
    client: &reqwest::blocking::Client,
    worker_url: &str,
    req: &ExecuteRequest,
    challenge: PaymentChallenge,
    cfg: &ClientConfig,
    account_id: Option<&str>,
    no_pay: bool,
) -> Result<()> {
    let token = challenge.token.as_deref().unwrap_or("NEAR");
    eprintln!();
    eprintln!("💳 Payment required:");
    eprintln!("   Amount: {} {}", challenge.amount, token);
    eprintln!("   To: {}", challenge.recipient);
    eprintln!("   Challenge ID: {}", challenge.challenge_id);
    
    if let Some(ref methods) = challenge.methods {
        eprintln!("   Methods: {}", methods.join(", "));
    }
    eprintln!();

    if no_pay {
        eprintln!("ℹ️  --no-pay flag set. Exiting without payment.");
        eprintln!("   To pay manually, send the amount and retry with payment receipt.");
        std::process::exit(0);
    }

    // Try to get account ID
    let account = match cfg.get_account_id(account_id) {
        Ok(a) => a,
        Err(_) => {
            eprintln!("⚠️  No account ID configured. Cannot auto-pay.");
            eprintln!("   Set account_id in ~/.inlayer/config.toml or use --account");
            eprintln!("   Or use --no-pay to handle payment separately.");
            std::process::exit(1);
        }
    };

    // Check payment limits
    let amount_near: f64 = challenge.amount.parse().unwrap_or(0.0);
    let max_per_request: f64 = cfg.payment.max_per_request.parse().unwrap_or(0.01);
    
    if amount_near > max_per_request {
        eprintln!("⚠️  Payment amount ({}) exceeds max_per_request ({})", 
            challenge.amount, cfg.payment.max_per_request);
        eprintln!("   Increase max_per_request in ~/.inlayer/config.toml to allow this payment.");
        std::process::exit(1);
    }

    // Determine RPC URL from network
    let rpc_url = if account.ends_with(".testnet") || account.contains(".testnet.") {
        "https://rpc.testnet.near.org"
    } else {
        "https://rpc.mainnet.near.org"
    };

    let token = challenge.token.as_deref().unwrap_or("NEAR");
    eprintln!("🔄 Auto-paying {} {} to {} (via RPC, no CLI)...", challenge.amount, token, challenge.recipient);

    let tx_hash = if token == "NEAR" || token.is_empty() {
        pay_near(&account, &challenge.recipient, &challenge.amount, rpc_url)?
    } else {
        pay_intents(&account, &challenge.recipient, &challenge.amount, token, rpc_url)?
    };

    eprintln!("✅ Payment sent! tx: {}", tx_hash);
    eprintln!("🔄 Retrying execution with payment receipt...");

    // Wait a moment for transaction to be processed
    std::thread::sleep(std::time::Duration::from_secs(2));

    // Retry with payment receipt
    let receipt = PaymentReceipt {
        tx_hash: tx_hash.clone(),
        signer_account: account.clone(),
        challenge_id: challenge.challenge_id.clone(),
    };

    let url = format!("{}/execute", worker_url.trim_end_matches('/'));
    let resp = client
        .post(&url)
        .json(&req)
        .header("Payment-Receipt", base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&receipt)?))
        .header("Signer-Account", &account)
        .send()
        .context("Failed to connect to worker")?;

    match resp.status() {
        reqwest::StatusCode::OK => {
            let result: ExecuteResponse = resp.json().context("Failed to parse response")?;
            print_execute_result(&result);
            if !result.success {
                std::process::exit(1);
            }
        }
        status => {
            let error_text = resp.text().unwrap_or_else(|_| "Unknown error".to_string());
            eprintln!("❌ Error after payment {}: {}", status, error_text);
            eprintln!("   Payment was already sent (tx: {}). Contact worker operator.", tx_hash);
            std::process::exit(1);
        }
    }

    Ok(())
}

/// Pay native NEAR via direct RPC (no CLI dependency)
fn pay_near(from: &str, to: &str, amount: &str, rpc_url: &str) -> Result<String> {
    use near_primitives::transaction::{Transaction, TransactionV0, Action, TransferAction};
    use near_primitives::types::AccountId;

    let signer_account_id: AccountId = from.parse().context("Invalid signer")?;
    let receiver_id: AccountId = to.parse().context("Invalid receiver")?;
    let amount_near: f64 = amount.parse().context("Invalid amount")?;
    let amount_yocto = (amount_near * 1e24) as u128;

    let secret_key = load_signer_key(from)?;
    let signer = InMemorySigner::from_secret_key(signer_account_id.clone(), secret_key);
    let public_key = signer.public_key.clone();

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let client = JsonRpcClient::connect(rpc_url);

        // Fetch nonce + block hash
        let query = methods::query::RpcQueryRequest {
            block_reference: near_primitives::types::BlockReference::latest(),
            request: near_primitives::views::QueryRequest::ViewAccessKey {
                account_id: signer_account_id.clone(),
                public_key: public_key.clone(),
            },
        };
        let resp = client.call(query).await.context("Failed to get access key")?;
        let nonce = match resp.kind {
            near_jsonrpc_primitives::types::query::QueryResponseKind::AccessKey(ak) => ak.nonce + 1,
            _ => anyhow::bail!("Unexpected access key response"),
        };
        let block_hash = resp.block_hash;

        let tx = TransactionV0 {
            signer_id: signer_account_id,
            public_key,
            nonce,
            receiver_id,
            block_hash,
            actions: vec![Action::Transfer(TransferAction { deposit: amount_yocto })],
        };
        let signed_tx = Transaction::V0(tx).sign(&Signer::InMemory(signer));
        let tx_hash = format!("{:?}", signed_tx.get_hash());
        eprintln!("   TX: {}", tx_hash);

        client.call(methods::send_tx::RpcSendTransactionRequest {
            signed_transaction: signed_tx,
            wait_until: near_primitives::views::TxExecutionStatus::ExecutedOptimistic,
        }).await.map_err(|e| anyhow::anyhow!("send_tx failed: {}", e))?;

        Ok(tx_hash)
    })
}

/// Pay via NEAR Intents (ft_transfer_call) or fall back to plain NEAR
fn pay_intents(from: &str, to: &str, amount: &str, token_contract: &str, rpc_url: &str) -> Result<String> {
    use near_primitives::transaction::{Transaction, TransactionV0, Action, FunctionCallAction};
    use near_primitives::types::AccountId;

    if token_contract == "NEAR" || token_contract.is_empty() {
        return pay_near(from, to, amount, rpc_url);
    }

    let signer_account_id: AccountId = from.parse().context("Invalid signer")?;
    let token_id: AccountId = token_contract.parse().context("Invalid token contract")?;
    let amount_near: f64 = amount.parse().context("Invalid amount")?;
    let amount_raw = (amount_near * 1e24) as u128;

    let secret_key = load_signer_key(from)?;
    let signer = InMemorySigner::from_secret_key(signer_account_id.clone(), secret_key);
    let public_key = signer.public_key.clone();

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let client = JsonRpcClient::connect(rpc_url);

        let query = methods::query::RpcQueryRequest {
            block_reference: near_primitives::types::BlockReference::latest(),
            request: near_primitives::views::QueryRequest::ViewAccessKey {
                account_id: signer_account_id.clone(),
                public_key: public_key.clone(),
            },
        };
        let resp = client.call(query).await.context("Failed to get access key")?;
        let nonce = match resp.kind {
            near_jsonrpc_primitives::types::query::QueryResponseKind::AccessKey(ak) => ak.nonce + 1,
            _ => anyhow::bail!("Unexpected access key response"),
        };
        let block_hash = resp.block_hash;

        let msg = serde_json::json!({
            "receiver_id": to,
            "amount": amount_raw.to_string(),
            "msg": ""
        });
        let args = serde_json::to_vec(&msg).unwrap_or_default();

        let tx = TransactionV0 {
            signer_id: signer_account_id,
            public_key,
            nonce,
            receiver_id: token_id,
            block_hash,
            actions: vec![Action::FunctionCall(Box::new(FunctionCallAction {
                method_name: "ft_transfer_call".to_string(),
                args,
                gas: 50_000_000_000_000,
                deposit: 1,
            }))],
        };
        let signed_tx = Transaction::V0(tx).sign(&Signer::InMemory(signer));
        let tx_hash = format!("{:?}", signed_tx.get_hash());
        eprintln!("   TX: {}", tx_hash);

        client.call(methods::send_tx::RpcSendTransactionRequest {
            signed_transaction: signed_tx,
            wait_until: near_primitives::views::TxExecutionStatus::ExecutedOptimistic,
        }).await.map_err(|e| anyhow::anyhow!("send_tx failed: {}", e))?;

        Ok(tx_hash)
    })
}

/// Load signer secret key from near-cli keychain
fn load_signer_key(account_id: &str) -> Result<near_crypto::SecretKey> {
    let home = dirs::home_dir().context("No home directory")?;
    let network = if account_id.contains("testnet") { "testnet" } else { "mainnet" };

    for dir in &[".near-credentials", ".near/credentials", ".near"] {
        let key_path = home.join(dir).join(network).join(format!("{}.json", account_id));
        if key_path.exists() {
            let data = std::fs::read_to_string(&key_path)?;
            let key_json: serde_json::Value = serde_json::from_str(&data)?;
            if let Some(pk) = key_json["private_key"].as_str() {
                let sk: near_crypto::SecretKey = pk.parse()
                    .map_err(|e| anyhow::anyhow!("Invalid key: {}", e))?;
                return Ok(sk);
            }
        }
    }
    anyhow::bail!("No key found for {} in ~/.near-credentials/", account_id)
}

fn print_execute_result(result: &ExecuteResponse) {
    println!("{}", "=".repeat(60));
    println!("✅ Success: {}", result.success);
    if let Some(time) = result.execution_time_ms {
        println!("⏱️  Time: {}ms", time);
    }
    if let Some(instr) = result.instructions {
        println!("📊 Instructions: {}", instr);
    }
    if let Some(ref output) = result.output {
        println!("📤 Output:");
        match output {
            serde_json::Value::String(s) => println!("{}", s),
            _ => println!("{}", serde_json::to_string_pretty(output).unwrap_or_default()),
        }
    }
    if let Some(ref error) = result.error {
        println!("❌ Error: {}", error);
    }
}

/// Check worker status
fn cmd_ping(extra_args: &[String]) -> Result<()> {
    let cfg = ClientConfig::load();
    
    let mut worker_url: Option<String> = None;

    let mut i = 0;
    while i < extra_args.len() {
        match extra_args[i].as_str() {
            "--worker" if i + 1 < extra_args.len() => {
                worker_url = Some(extra_args[i + 1].clone());
                i += 2;
            }
            _ => { i += 1; }
        }
    }

    let worker_url = cfg.get_worker_url(worker_url.as_deref())?;
    let url = format!("{}/api/status", worker_url.trim_end_matches('/'));

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    eprintln!("🏓 Pinging {}...", worker_url);

    let resp = client
        .get(&url)
        .send()
        .context("Failed to connect to worker")?;

    if resp.status().is_success() {
        let status: serde_json::Value = resp.json().context("Failed to parse status response")?;
        println!("{}", "=".repeat(60));
        println!("✅ Worker Status:");
        println!("{}", serde_json::to_string_pretty(&status).unwrap_or_default());
    } else {
        eprintln!("❌ Worker returned status: {}", resp.status());
        std::process::exit(1);
    }

    Ok(())
}

/// List available programs on worker
fn cmd_catalog(extra_args: &[String]) -> Result<()> {
    let cfg = ClientConfig::load();
    
    let mut worker_url: Option<String> = None;

    let mut i = 0;
    while i < extra_args.len() {
        match extra_args[i].as_str() {
            "--worker" if i + 1 < extra_args.len() => {
                worker_url = Some(extra_args[i + 1].clone());
                i += 2;
            }
            _ => { i += 1; }
        }
    }

    let worker_url = cfg.get_worker_url(worker_url.as_deref())?;
    let url = format!("{}/catalog", worker_url.trim_end_matches('/'));

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    eprintln!("📚 Fetching catalog from {}...", worker_url);

    let resp = client
        .get(&url)
        .send()
        .context("Failed to connect to worker")?;

    match resp.status() {
        reqwest::StatusCode::OK => {
            let catalog: serde_json::Value = resp.json().context("Failed to parse catalog")?;
            println!("{}", "=".repeat(60));
            println!("📚 Available Programs:");
            println!("{}", serde_json::to_string_pretty(&catalog).unwrap_or_default());
        }
        reqwest::StatusCode::NOT_FOUND => {
            println!("📚 Catalog endpoint not implemented on this worker.");
            println!("   The worker may not support program listings.");
        }
        status => {
            eprintln!("❌ Error {}: {}", status, resp.text().unwrap_or_default());
            std::process::exit(1);
        }
    }

    Ok(())
}

fn cmd_projects(extra_args: &[String], config_dir: &Path) -> Result<()> {
    let mut network = "testnet".to_string();
    let mut contract_id = "outlayer.kampouse.testnet".to_string();
    let mut account_id = None;

    let mut i = 0;
    while i < extra_args.len() {
        match extra_args[i].as_str() {
            "--network" if i + 1 < extra_args.len() => {
                network = extra_args[i + 1].clone();
                i += 2;
            }
            "--contract" if i + 1 < extra_args.len() => {
                contract_id = extra_args[i + 1].clone();
                i += 2;
            }
            "--account" if i + 1 < extra_args.len() => {
                account_id = Some(extra_args[i + 1].clone());
                i += 2;
            }
            _ => { i += 1; }
        }
    }

    // Load signer to get account_id if not provided
    let cfg = offchainvm_worker::daemon::DaemonConfig::load(config_dir);
    let account_id = account_id.unwrap_or_else(|| {
        // Try to load from config
        match offchainvm_worker::daemon::load_signer(&cfg.key_path) {
            Ok(signer) => signer.account_id.to_string(),
            Err(_) => "your-account.testnet".to_string(),
        }
    });

    eprintln!("📋 Listing projects for: {}", account_id);

    let rpc_url = match network.as_str() {
        "mainnet" => "https://rpc.mainnet.near.org",
        "testnet" => "https://test.rpc.fastnear.com",
        _ => return Err(anyhow::anyhow!("Unknown network: {}", network)),
    };

    let client = JsonRpcClient::connect(rpc_url);
    let rt = tokio::runtime::Runtime::new()?;

    let result = rt.block_on(async {
        let args_bytes = format!("\"{}\"", account_id).into_bytes();
        let query = methods::query::RpcQueryRequest {
            block_reference: BlockReference::latest(),
            request: QueryRequest::CallFunction {
                account_id: contract_id.parse().unwrap(),
                method_name: "list_user_projects".to_string(),
                args: near_primitives::types::FunctionArgs::from(args_bytes),
            },
        };

        client.call(query).await
    });

    match result {
        Ok(response) => {
            if let QueryResponseKind::CallResult(result) = response.kind {
                if result.result.is_empty() {
                    eprintln!("   No projects found");
                } else {
                    let projects: Vec<serde_json::Value> = serde_json::from_slice(&result.result)?;
                    eprintln!("   Found {} projects:", projects.len());
                    for project in projects {
                        let name = project.get("name").and_then(|v| v.as_str()).unwrap_or("unknown");
                        let uuid = project.get("uuid").and_then(|v| v.as_str()).unwrap_or("unknown");
                        eprintln!("   • {} (uuid: {})", name, uuid);
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("   Error: {}", e);
        }
    }

    Ok(())
}

fn main() -> Result<()> {
    // Initialize tracing early so daemon/other commands get logs
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let args: Vec<String> = env::args().collect();

    let config_dir = if let Ok(dir) = env::var("INLAYER_DIR") {
        PathBuf::from(dir)
    } else {
        let cwd = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        if cwd.join("inlayer.config").exists() || cwd.join("inlayer.config.toml").exists() { cwd }
        else if let Some(home) = dirs::home_dir() {
            let hc = home.join(".inlayer");
            if hc.join("inlayer.config").exists() || hc.join("inlayer.config.toml").exists() { hc } else { cwd }
        } else { cwd }
    };

    if args.len() < 2 || args[1] == "-h" || args[1] == "--help" || args[1] == "help" {
        eprintln!("inlayer v{} — OutLayer local WASM runner + remote execution\n\n\
Usage:\n\
  inlayer exec --worker <url> --input <data> [--program <name>] [--no-pay]\n\
                                           Execute on remote worker (auto-payment)\n\
  inlayer ping --worker <url>              Check worker status\n\
  inlayer catalog --worker <url>           List available programs\n\
  inlayer init                                Create inlayer.config in current directory\n\
  inlayer register <project-name> <source>    Register project on contract\n\
                                             Sources: --github <repo> <commit> | --wasm-url <url> <sha256>\n\
  inlayer projects [--account <id>]           List registered projects\n\
  inlayer run <wasm> <input> [--rpc <url>]    Run WASM locally\n\
  inlayer submit <input> [--wasm-url <url>]   Submit request to contract\n\
  inlayer status [--contract <id>]            Check pending requests\n\
  inlayer list                                List available WASMs\n\
  inlayer config                              Show current config\n\
  inlayer daemon [--start|--stop|--status|--log|--daemon|--foreground|--dashboard <addr>|--tunnel]\n\
                                           Start/manage daemon (polls contract & executes WASM)\n\
                                           --tunnel: Create Cloudflare tunnel for public internet access\n\
  inlayer version                             Show version\n\n\
Config: ./inlayer.config or ~/.inlayer/inlayer.config\n\
Client config: ~/.inlayer/config.toml (worker_url, account_id, payment limits)\n\n\
Environment Variables:\n\
  OUTLAYER_WORKER_URL — override worker URL\n\
  OUTLAYER_ACCOUNT_ID — override account ID\n\
  OUTLAYER_CONFIG — config file path", env!("CARGO_PKG_VERSION"));
        std::process::exit(0);
    }

    if args[1] == "version" || args[1] == "-v" || args[1] == "--version" {
        eprintln!("inlayer {}", env!("CARGO_PKG_VERSION"));
        std::process::exit(0);
    }

    match args[1].as_str() {
        "exec" => {
            cmd_exec(&args[2..])?;
        }
        "ping" => {
            cmd_ping(&args[2..])?;
        }
        "catalog" => {
            cmd_catalog(&args[2..])?;
        }
        "init" => {
            cmd_init(&args[2..])?;
        }
        "register" => {
            cmd_register(&args[2..], &config_dir)?;
        }
        "projects" => {
            cmd_projects(&args[2..], &config_dir)?;
        }
        "run" => {
            if args.len() < 3 {
                eprintln!("Usage: inlayer run <wasm> <input> [--rpc <url>]");
                std::process::exit(1);
            }
            let cfg = Config::load(&config_dir);
            let wasm = &args[2];
            let mut input = cfg.runner.default_input.clone()
                .unwrap_or_else(|| r#"{}"#.to_string());
            let mut rpc_override: Option<String> = None;
            let mut i = 3;
            while i < args.len() {
                if args[i] == "--rpc" && i + 1 < args.len() {
                    rpc_override = Some(args[i + 1].clone()); i += 2;
                } else {
                    input = args[i].clone(); i += 1;
                }
            }
            cmd_run(&config_dir, wasm, &input, rpc_override.as_deref())?;
        }
        "submit" => {
            cmd_submit(&args[2..])?;
        }
        "status" => {
            cmd_status(&args[2..])?;
        }
        "list" | "ls" => cmd_list(&config_dir),
        "config" => cmd_config(&config_dir),
        "daemon" => {
            // Delegate to daemon module
            offchainvm_worker::daemon::run_daemon(&args[2..], &config_dir)?;
        }
        "post-task" => {
            offchainvm_worker::daemon::escrow_commands::cmd_post_task(&args[2..], &config_dir)?;
        }
        "relayer" => {
            offchainvm_worker::daemon::escrow_commands::cmd_relayer(&args[2..], &config_dir)?;
        }
        "verifier" => {
            offchainvm_worker::daemon::escrow_commands::cmd_verifier(&args[2..], &config_dir)?;
        }

        cmd => { eprintln!("Unknown: {}. Run: inlayer help", cmd); std::process::exit(1); }
    }
    Ok(())
}
