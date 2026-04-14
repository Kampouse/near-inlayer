//! Escrow subcommands for the inlayer binary.
//!
//! `inlayer post-task`  — Sign & post a task (kind 41000) to Nostr
//! `inlayer relayer`    — Watch Nostr, submit signed actions to msig on-chain
//! `inlayer verifier`   — Poll verifying escrows, score with Gemini, resume yield
//!
//! Workers post results (kind 41002) independently — see WORKER-SPEC.md for the protocol.

use std::collections::VecDeque;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use near_crypto::InMemorySigner;
use serde::{Deserialize, Serialize};

use super::manage::DaemonConfig;
use super::nonce::NonceCache;
use super::rpc_pool;

// ── Thread health monitoring ──────────────────────────────────────────

/// Heartbeat for a background thread. The thread sets `alive` to true each
/// cycle. A supervisor reads and resets it — if still false after N checks,
/// the thread is considered dead.
#[derive(Debug)]
pub struct ThreadHealth {
    pub name: String,
    pub alive: AtomicBool,
    pub restart_count: AtomicBool, // u8 via AtomicBool — just tracking if restarted
}

impl ThreadHealth {
    pub fn new(name: &str) -> Arc<Self> {
        Arc::new(Self {
            name: name.to_string(),
            alive: AtomicBool::new(true),
            restart_count: AtomicBool::new(false),
        })
    }

    /// Called by the relayer or verifier thread each successful cycle.
    pub fn ping(&self) {
        self.alive.store(true, Ordering::Relaxed);
    }

    /// Called by the supervisor. Returns true if the thread pinged since last check.
    /// Resets the flag.
    pub fn check_and_reset(&self) -> bool {
        self.alive.swap(false, Ordering::Relaxed)
    }
}

/// Spawn a supervisor thread that monitors health heartbeats and re-spawns
/// threads if they go silent for too long.
pub fn spawn_supervisor(
    config_dir: std::path::PathBuf,
    relayer_health: Arc<ThreadHealth>,
    verifier_health: Option<Arc<ThreadHealth>>,
) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name("escrow-supervisor".into())
        .spawn(move || {
            let check_interval = Duration::from_secs(30);
            let max_missed = 6; // 6 * 30s = 3 minutes silent = dead
            let mut relayer_missed: u32 = 0;
            let mut verifier_missed: u32 = 0;

            eprintln!("[supervisor] started — checking every {}s", check_interval.as_secs());

            loop {
                std::thread::sleep(check_interval);

                // Check relayer
                if relayer_health.check_and_reset() {
                    relayer_missed = 0;
                } else {
                    relayer_missed += 1;
                    if relayer_missed >= max_missed {
                        eprintln!("[supervisor] relayer silent for {} checks — restarting", relayer_missed);
                        relayer_missed = 0;
                        let cfg = config_dir.clone();
                        let health = relayer_health.clone();
                        std::thread::spawn(move || {
                            eprintln!("[supervisor] spawning new relayer thread...");
                            let handle = spawn_relayer_thread(cfg);
                            health.ping(); // Mark alive on spawn
                            let _ = handle.join();
                            eprintln!("[supervisor] relayer thread exited");
                        });
                        relayer_health.restart_count.store(true, Ordering::Relaxed);
                    } else if relayer_missed > 1 {
                        eprintln!("[supervisor] relayer missed {} heartbeat(s)", relayer_missed);
                    }
                }

                // Check verifier
                if let Some(ref vh) = verifier_health {
                    if vh.check_and_reset() {
                        verifier_missed = 0;
                    } else {
                        verifier_missed += 1;
                        if verifier_missed >= max_missed {
                            eprintln!("[supervisor] verifier silent for {} checks — restarting", verifier_missed);
                            verifier_missed = 0;
                            let cfg = config_dir.clone();
                            let health = vh.clone();
                            std::thread::spawn(move || {
                                eprintln!("[supervisor] spawning new verifier thread...");
                                let handle = spawn_verifier_thread(cfg);
                                health.ping();
                                let _ = handle.join();
                                eprintln!("[supervisor] verifier thread exited");
                            });
                            vh.restart_count.store(true, Ordering::Relaxed);
                        } else if verifier_missed > 1 {
                            eprintln!("[supervisor] verifier missed {} heartbeat(s)", verifier_missed);
                        }
                    }
                }
            }
        })
        .expect("failed to spawn supervisor thread")
}

// ── Shared helpers ──────────────────────────────────────────────────────

/// Ed25519 sign a JSON string for msig.execute().
/// Key format: "ed25519:<base58>" or raw hex bytes.
fn sign_action_ed25519(action_json: &str, private_key_str: &str) -> Result<Vec<u8>> {
    let seed = if private_key_str.starts_with("ed25519:") {
        let b58 = private_key_str.trim_start_matches("ed25519:");
        bs58::decode(b58).into_vec()?
    } else {
        hex::decode(private_key_str)?
    };

    let seed: &[u8] = if seed.len() == 64 {
        // seed + pubkey — take first 32 bytes
        &seed[..32]
    } else if seed.len() == 32 {
        &seed
    } else {
        bail!("invalid key length: {} bytes", seed.len());
    };

    use ed25519_dalek::{Signer, SigningKey};
    let signing_key = SigningKey::try_from(seed)?;
    let signature = signing_key.sign(action_json.as_bytes());
    Ok(signature.to_bytes().to_vec())
}

/// Read msig nonce from on-chain.
fn get_msig_nonce(rpc: &rpc_pool::Rpc, msig_address: &str) -> Result<u64> {
    let bytes = rpc.view(msig_address, "get_nonce", b"{}")?;
    let nonce: u64 = serde_json::from_slice(&bytes).context("parse nonce")?;
    Ok(nonce)
}

/// Build RPC from a URL string.
fn make_rpc(rpc_url: &str) -> Result<rpc_pool::Rpc> {
    rpc_pool::Rpc::new(rpc_url)
}

// ════════════════════════════════════════════════════════════════════════
// POST-TASK
// ════════════════════════════════════════════════════════════════════════

pub fn cmd_post_task(args: &[String], _config_dir: &Path) -> Result<()> {
    let mut rpc_url = "https://rpc.testnet.near.org".to_string();
    let mut relay = "wss://nostr-relay-production.up.railway.app/".to_string();
    let mut nostr_key = String::new();
    let mut agent_key = String::new();
    let mut msig = String::new();
    let mut escrow = String::new();
    let mut job_id = String::new();
    let mut description = String::new();
    let mut criteria = String::new();
    let mut reward = "1".to_string();
    let mut token = String::new();
    let mut timeout = "86400".to_string();
    let mut verifier_fee = String::new();
    let mut threshold = String::new();
    let mut category = String::new();
    let mut skills = String::new();
    let mut npub = String::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--rpc" => { rpc_url = args[i + 1].clone(); i += 2; }
            "--relay" | "--relays" => { relay = args[i + 1].clone(); i += 2; }
            "--nostr-key" => { nostr_key = args[i + 1].clone(); i += 2; }
            "--agent-key" => { agent_key = args[i + 1].clone(); i += 2; }
            "--msig" => { msig = args[i + 1].clone(); i += 2; }
            "--escrow" => { escrow = args[i + 1].clone(); i += 2; }
            "--job-id" => { job_id = args[i + 1].clone(); i += 2; }
            "--description" => { description = args[i + 1].clone(); i += 2; }
            "--criteria" => { criteria = args[i + 1].clone(); i += 2; }
            "--reward" => { reward = args[i + 1].clone(); i += 2; }
            "--token" => { token = args[i + 1].clone(); i += 2; }
            "--timeout" => { timeout = args[i + 1].clone(); i += 2; }
            "--verifier-fee" => { verifier_fee = args[i + 1].clone(); i += 2; }
            "--threshold" => { threshold = args[i + 1].clone(); i += 2; }
            "--category" => { category = args[i + 1].clone(); i += 2; }
            "--skills" => { skills = args[i + 1].clone(); i += 2; }
            "--npub" => { npub = args[i + 1].clone(); i += 2; }
            _ => { eprintln!("Unknown arg: {}", args[i]); i += 1; }
        }
    }

    if nostr_key.is_empty() || agent_key.is_empty() || msig.is_empty() || job_id.is_empty() || description.is_empty() {
        bail!("Required: --nostr-key, --agent-key, --msig, --job-id, --description");
    }

    // 1. Get msig nonce
    let rpc = make_rpc(&rpc_url)?;
    let current_nonce = get_msig_nonce(&rpc, &msig).unwrap_or(0);
    let next_nonce = current_nonce + 1;

    // 2. Build CreateEscrow action
    let mut action = serde_json::json!({
        "nonce": next_nonce,
        "action": {
            "type": "create_escrow",
            "job_id": job_id,
            "escrow_contract": escrow,
            "reward": reward,
            "timeout_seconds": timeout.parse::<u64>().unwrap_or(86400),
        }
    });
    if !token.is_empty() {
        action["action"]["token"] = serde_json::Value::String(token.clone());
    }
    if !verifier_fee.is_empty() {
        action["action"]["verifier_fee"] = serde_json::Value::String(verifier_fee.clone());
    }
    if !threshold.is_empty() {
        action["action"]["score_threshold"] = serde_json::Value::Number(
            threshold.parse::<u64>().unwrap_or(80).into()
        );
    }

    let action_json = serde_json::to_string(&action).context("serialize action")?;
    let sig = sign_action_ed25519(&action_json, &agent_key)?;
    let sig_hex = hex::encode(&sig);

    // 3. Build FundEscrow action (combined create+fund in one event)
    let fund_nonce = next_nonce + 1;
    let mut fund_action = serde_json::json!({
        "nonce": fund_nonce,
        "action": {
            "type": "fund_escrow",
            "job_id": job_id,
            "amount": reward,
        }
    });
    if !token.is_empty() {
        fund_action["action"]["token"] = serde_json::Value::String(token.clone());
    }

    let fund_action_json = serde_json::to_string(&fund_action).context("serialize fund action")?;
    let fund_sig = sign_action_ed25519(&fund_action_json, &agent_key)?;
    let fund_sig_hex = hex::encode(&fund_sig);

    // 4. Build Nostr event (kind 41000)
    let content = serde_json::json!({
        "task_description": description,
        "criteria": if criteria.is_empty() { "Complete the task as described" } else { &criteria },
    });
    let content_str = serde_json::to_string(&content)?;

    let mut tags: Vec<Vec<String>> = vec![
        vec!["job_id".into(), job_id.clone()],
        vec!["reward".into(), reward.clone()],
        vec!["timeout".into(), timeout.clone()],
        vec!["agent".into(), msig.clone()],
        vec!["escrow".into(), escrow.clone()],
        vec!["action".into(), action_json.clone()],
        vec!["action_sig".into(), sig_hex],
        vec!["fund_action".into(), fund_action_json],
        vec!["fund_action_sig".into(), fund_sig_hex],
    ];
    if !npub.is_empty() { tags.push(vec!["npub".into(), npub]); }
    if !verifier_fee.is_empty() { tags.push(vec!["verifier_fee".into(), verifier_fee]); }
    if !threshold.is_empty() { tags.push(vec!["score_threshold".into(), threshold]); }
    if !category.is_empty() { tags.push(vec!["category".into(), category]); }
    if !skills.is_empty() { tags.push(vec!["skills".into(), skills]); }

    // 5. Publish
    let relay = relay.trim_end_matches('/');
    super::nostr::publish_event(relay, &nostr_key, super::nostr::KIND_TASK, &content_str, tags)
        .map_err(|e| anyhow::anyhow!("publish: {}", e))?;

    println!("Task posted: job_id={}", job_id);
    println!("  kind=41000, nonce={}, fund_nonce={}", next_nonce, fund_nonce);
    Ok(())
}

// ════════════════════════════════════════════════════════════════════════
// RELAYER
// ════════════════════════════════════════════════════════════════════════

/// Relayer CLI subcommand — loads config and runs the relayer loop.
pub fn cmd_relayer(args: &[String], config_dir: &Path) -> Result<()> {
    let mut config_path = String::new();
    let mut dry_run = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--config" => { config_path = args[i + 1].clone(); i += 2; }
            "--dry-run" => { dry_run = true; i += 1; }
            _ => { i += 1; }
        }
    }

    let daemon_cfg: DaemonConfig = if !config_path.is_empty() {
        let txt = std::fs::read_to_string(&config_path)?;
        toml::from_str(&txt)?
    } else {
        DaemonConfig::load(config_dir)
    };

    let rpc_url = daemon_cfg.rpc_url();
    let signer = super::manage::load_signer(&daemon_cfg.key_path)?;
    let nonce_cache = NonceCache::new(rpc_url.clone(), signer.clone());

    if dry_run {
        let relay = daemon_cfg.nostr_relay.as_deref()
            .ok_or_else(|| anyhow::anyhow!("nostr_relay not configured"))?;
        println!("Relayer dry-run: relay={}", relay);
        println!("  account={}, watching kinds 41000,41003", signer.account_id);
        println!("  (use without --dry-run to actually submit)");
        return Ok(());
    }

    run_relayer_inner(&daemon_cfg, &rpc_url, &signer, &nonce_cache, None)
}

// ════════════════════════════════════════════════════════════════════════
// VERIFIER
// ════════════════════════════════════════════════════════════════════════

#[derive(Debug, Deserialize)]
struct VerifyingEscrow {
    job_id: String,
    #[allow(dead_code)]
    data_id: String,
}

#[derive(Debug, Serialize)]
struct Verdict {
    score: u8,
    passed: bool,
    detail: String,
}

/// Verifier subcommand — polls escrow for Verifying status, scores via Gemini, resumes yield.
pub fn cmd_verifier(args: &[String], config_dir: &Path) -> Result<()> {
    let mut config_path = String::new();
    let mut once = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--config" => { config_path = args[i + 1].clone(); i += 2; }
            "--once" => { once = true; i += 1; }
            _ => { i += 1; }
        }
    }

    let daemon_cfg: DaemonConfig = if !config_path.is_empty() {
        let txt = std::fs::read_to_string(&config_path)?;
        toml::from_str(&txt)?
    } else {
        DaemonConfig::load(config_dir)
    };

    let rpc_url = daemon_cfg.rpc_url();
    let escrow_contract = daemon_cfg.escrow_contract.as_deref()
        .ok_or_else(|| anyhow::anyhow!("escrow_contract not configured"))?;

    let signer = super::manage::load_signer(&daemon_cfg.key_path)?;
    let rpc = make_rpc(&rpc_url)?;
    let nonce_cache = NonceCache::new(rpc_url.clone(), signer.clone());
    let processed: Mutex<VecDeque<String>> = Mutex::new(VecDeque::new());

    let gemini_key = std::env::var("GEMINI_API_KEY")
        .context("GEMINI_API_KEY env var required")?;

    println!("Verifier starting: escrow={}", escrow_contract);
    println!("  account={}", signer.account_id);

    loop {
        match run_verifier_cycle(&rpc, &rpc_url, &signer, &nonce_cache, escrow_contract, &gemini_key, &processed) {
            Ok(count) => {
                if count > 0 {
                    println!("  processed {} escrows", count);
                }
            }
            Err(e) => {
                eprintln!("  verifier cycle error: {}", e);
            }
        }

        if once { break; }
        std::thread::sleep(Duration::from_secs(3));
    }

    Ok(())
}

fn run_verifier_cycle(
    rpc: &rpc_pool::Rpc,
    rpc_url: &str,
    signer: &InMemorySigner,
    nonce_cache: &NonceCache,
    escrow_contract: &str,
    gemini_key: &str,
    processed: &Mutex<VecDeque<String>>,
) -> Result<usize> {
    // Fetch verifying escrows
    let bytes = rpc.view(escrow_contract, "list_verifying", b"{}")?;
    if bytes.is_empty() { return Ok(0); }
    let verifying: Vec<VerifyingEscrow> = serde_json::from_slice(&bytes)
        .context("parse verifying list")?;

    let mut count = 0;
    for ve in verifying {
        // Dedup
        {
            let mut p = processed.lock().unwrap();
            if p.iter().any(|id| id == &ve.job_id) { continue; }
            p.push_back(ve.job_id.clone());
            while p.len() > 10_000 { p.pop_front(); }
        }

        println!("[verifier] processing job_id={}", ve.job_id);

        // 1. Get escrow details
        let escrow = super::escrow_client::get_escrow(rpc, escrow_contract, &ve.job_id)?;
        if escrow.status != "Verifying" {
            eprintln!("  job {} status={} (not Verifying), skipping", ve.job_id, escrow.status);
            continue;
        }

        let result_str = escrow.result.as_deref().unwrap_or("");

        // 2. Try to fetch result from KV
        let result_content = match fetch_kv_result(result_str) {
            Ok(content) => content,
            Err(e) => {
                eprintln!("  KV fetch failed for {}: {}, using raw result", ve.job_id, e);
                result_str.to_string()
            }
        };

        // 3. Score with Gemini
        let score = score_with_gemini(
            gemini_key,
            &escrow.task_description,
            &escrow.criteria,
            &result_content,
            80, // threshold
        )?;

        let passed = score.score >= 80;
        let verdict = Verdict {
            score: score.score,
            passed,
            detail: score.detail,
        };
        let verdict_json = serde_json::to_string(&verdict)?;

        println!("  scored: {} ({}passed)", verdict.score, if passed { "" } else { "NOT " });

        // 4. Resume verification on-chain
        let resume_args = serde_json::json!({
            "data_id_hex": ve.data_id,
            "verdict": verdict_json,
        });

        match super::send_function_call(
            rpc_url, signer, escrow_contract, "resume_verification", &resume_args,
            300_000_000_000_000, // 300 Tgas
            0,
            nonce_cache,
        ) {
            Ok((tx_hash, _)) => {
                println!("  resumed ✓ tx={}", &tx_hash[..16.min(tx_hash.len())]);
            }
            Err(e) => {
                eprintln!("  resume FAILED for {}: {}", ve.job_id, e);
            }
        }

        count += 1;
    }

    Ok(count)
}

/// Fetch result content from FastNear KV HTTP endpoint.
fn fetch_kv_result(kv_ref_str: &str) -> Result<String> {
    let kv_ref: serde_json::Value = serde_json::from_str(kv_ref_str)
        .context("parse KV reference")?;

    let account = kv_ref["kv_account"].as_str().ok_or_else(|| anyhow::anyhow!("missing kv_account"))?;
    let predecessor = kv_ref["kv_predecessor"].as_str().ok_or_else(|| anyhow::anyhow!("missing kv_predecessor"))?;
    let key = kv_ref["kv_key"].as_str().ok_or_else(|| anyhow::anyhow!("missing kv_key"))?;

    let url = format!(
        "https://kv.main.fastnear.com/v0/latest/{}/{}/{}",
        account, predecessor, key
    );

    let client = reqwest::blocking::Client::new();
    let resp = client.get(&url)
        .timeout(Duration::from_secs(10))
        .send()
        .context("KV HTTP request")?;

    if !resp.status().is_success() {
        bail!("KV HTTP {} for {}", resp.status(), url);
    }

    let body: serde_json::Value = resp.json().context("parse KV response")?;
    // FastNear returns { "values": [{ "key": "...", "value": "..." }] }
    let value = body["value"].as_str()
        .or_else(|| body["values"].as_array().and_then(|a| a.first()).and_then(|v| v["value"].as_str()))
        .unwrap_or("");

    Ok(value.to_string())
}

struct GeminiScore {
    score: u8,
    detail: String,
}

/// Score a task result using Google Gemini API.
fn score_with_gemini(
    api_key: &str,
    task_description: &str,
    criteria: &str,
    result: &str,
    threshold: u8,
) -> Result<GeminiScore> {
    let prompt = format!(
        "You are an expert task verifier. Score the following work result against the criteria.\n\n\
         Task: {}\n\n\
         Criteria: {}\n\n\
         Result: {}\n\n\
         Score threshold: {}/100\n\n\
         Respond with ONLY valid JSON: {{\"score\": <number 0-100>, \"reasoning\": \"<brief explanation>\"}}",
        task_description, criteria, result, threshold
    );

    let url = format!(
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={}",
        api_key
    );

    let body = serde_json::json!({
        "contents": [{
            "parts": [{ "text": prompt }]
        }],
        "generationConfig": {
            "temperature": 0.3,
            "responseMimeType": "application/json"
        }
    });

    let client = reqwest::blocking::Client::new();
    let resp = client.post(&url)
        .json(&body)
        .timeout(Duration::from_secs(30))
        .send()
        .context("Gemini API request")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().unwrap_or_default();
        bail!("Gemini API {} : {}", status, text);
    }

    let resp_json: serde_json::Value = resp.json().context("parse Gemini response")?;

    // Extract text from candidates[0].content.parts[0].text
    let text = resp_json["candidates"][0]["content"]["parts"][0]["text"]
        .as_str()
        .unwrap_or("{}");

    let parsed: serde_json::Value = serde_json::from_str(text).unwrap_or_default();
    let score = parsed["score"].as_u64().unwrap_or(0) as u8;
    let detail = parsed["reasoning"].as_str().unwrap_or("no reasoning").to_string();

    Ok(GeminiScore { score, detail })
}

// ════════════════════════════════════════════════════════════════════════
// DAEMON THREAD SPAWNERS
// ════════════════════════════════════════════════════════════════════════

/// Spawn the relayer as a background thread (called from daemon when execution_mode is escrow/both).
/// Takes config_dir so it can load its own DaemonConfig, signer, NonceCache.
pub fn spawn_relayer_thread(config_dir: std::path::PathBuf) -> std::thread::JoinHandle<()> {
    spawn_relayer_thread_with_health(config_dir, None)
}

pub fn spawn_relayer_thread_with_health(
    config_dir: std::path::PathBuf,
    health: Option<Arc<ThreadHealth>>,
) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name("escrow-relayer".into())
        .spawn(move || {
            let daemon_cfg: DaemonConfig = DaemonConfig::load(&config_dir);
            let rpc_url = match daemon_cfg.nostr_relay.as_deref() {
                Some(_) => daemon_cfg.rpc_url(),
                None => {
                    eprintln!("[relayer] nostr_relay not configured, thread exiting");
                    return;
                }
            };

            let signer = match super::manage::load_signer(&daemon_cfg.key_path) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("[relayer] failed to load signer: {}", e);
                    return;
                }
            };
            let nonce_cache = NonceCache::new(rpc_url.clone(), signer.clone());

            if let Err(e) = run_relayer_inner(&daemon_cfg, &rpc_url, &signer, &nonce_cache, health.as_ref()) {
                eprintln!("[relayer] thread exited with error: {}", e);
            }
        })
        .expect("failed to spawn relayer thread")
}

/// Spawn the verifier as a background thread (called from daemon when execution_mode is escrow/both).
pub fn spawn_verifier_thread(config_dir: std::path::PathBuf) -> std::thread::JoinHandle<()> {
    spawn_verifier_thread_with_health(config_dir, None)
}

pub fn spawn_verifier_thread_with_health(
    config_dir: std::path::PathBuf,
    health: Option<Arc<ThreadHealth>>,
) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name("escrow-verifier".into())
        .spawn(move || {
            let daemon_cfg: DaemonConfig = DaemonConfig::load(&config_dir);
            let rpc_url = daemon_cfg.rpc_url();
            let escrow_contract = match daemon_cfg.escrow_contract.as_deref() {
                Some(c) => c.to_string(),
                None => {
                    eprintln!("[verifier] escrow_contract not configured, thread exiting");
                    return;
                }
            };

            let signer = match super::manage::load_signer(&daemon_cfg.key_path) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("[verifier] failed to load signer: {}", e);
                    return;
                }
            };
            let rpc = match make_rpc(&rpc_url) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("[verifier] RPC init failed: {}", e);
                    return;
                }
            };
            let nonce_cache = NonceCache::new(rpc_url.clone(), signer.clone());
            let processed: Mutex<VecDeque<String>> = Mutex::new(VecDeque::new());

            let gemini_key = match std::env::var("GEMINI_API_KEY") {
                Ok(k) => k,
                Err(_) => {
                    eprintln!("[verifier] GEMINI_API_KEY not set, thread exiting");
                    return;
                }
            };

            eprintln!("[verifier] starting: escrow={}", escrow_contract);
            eprintln!("[verifier]   account={}", signer.account_id);

            loop {
                match run_verifier_cycle(&rpc, &rpc_url, &signer, &nonce_cache, &escrow_contract, &gemini_key, &processed) {
                    Ok(count) => {
                        if count > 0 {
                            eprintln!("[verifier]   processed {} escrows", count);
                        }
                    }
                    Err(e) => {
                        eprintln!("[verifier]   cycle error: {}", e);
                    }
                }

                // Heartbeat
                if let Some(h) = health.as_ref() {
                    h.ping();
                }

                std::thread::sleep(Duration::from_secs(3));
            }
        })
        .expect("failed to spawn verifier thread")
}

/// Internal relayer loop — shared by CLI cmd_relayer and daemon thread.
fn run_relayer_inner(
    daemon_cfg: &DaemonConfig,
    rpc_url: &str,
    signer: &near_crypto::InMemorySigner,
    nonce_cache: &NonceCache,
    health: Option<&Arc<ThreadHealth>>,
) -> Result<()> {
    let relay = daemon_cfg.nostr_relay.as_deref()
        .ok_or_else(|| anyhow::anyhow!("nostr_relay not configured"))?;
    let rpc = make_rpc(rpc_url)?;
    let processed: Mutex<VecDeque<String>> = Mutex::new(VecDeque::new());

    eprintln!("[relayer] starting: relay={}", relay);
    eprintln!("[relayer]   account={}, watching kinds 41000,41003", signer.account_id);

    let rx = super::nostr::spawn_nostr_subscriber(relay);
    eprintln!("[relayer]   subscribed, waiting for events...");

    loop {
        let event = match rx.recv_timeout(Duration::from_secs(5)) {
            Ok(ev) => ev,
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => continue,
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {
                eprintln!("[relayer] Nostr subscriber disconnected, exiting");
                break;
            }
        };

        if event.kind != super::nostr::KIND_TASK && event.kind != super::nostr::KIND_ACTION {
            continue;
        }

        // Dedup
        {
            let mut p = processed.lock().unwrap();
            if p.iter().any(|id| id == &event.id) { continue; }
            p.push_back(event.id.clone());
            while p.len() > 10_000 { p.pop_front(); }
        }

        let kind_label = if event.kind == super::nostr::KIND_TASK { "TASK" } else { "ACTION" };
        eprintln!("[relayer] [{}] event from {}...", kind_label, &event.pubkey[..8.min(event.pubkey.len())]);

        let action_json = event.tags.iter()
            .find(|t| t.len() >= 2 && t[0] == "action")
            .and_then(|t| t.get(1))
            .map(|s| s.as_str())
            .unwrap_or("");
        let action_sig_hex = event.tags.iter()
            .find(|t| t.len() >= 2 && t[0] == "action_sig")
            .and_then(|t| t.get(1))
            .map(|s| s.as_str())
            .unwrap_or("");

        if action_json.is_empty() || action_sig_hex.is_empty() {
            eprintln!("[relayer]   missing action/action_sig tags, skipping");
            continue;
        }

        let sig_bytes = match hex::decode(action_sig_hex) {
            Ok(b) => b,
            Err(e) => { eprintln!("[relayer]   invalid sig hex: {}", e); continue; }
        };
        if sig_bytes.len() != 64 {
            eprintln!("[relayer]   invalid sig length: {} bytes", sig_bytes.len());
            continue;
        }

        let msig = event.tags.iter()
            .find(|t| t.len() >= 2 && t[0] == "agent")
            .and_then(|t| t.get(1))
            .map(|s| s.clone())
            .unwrap_or_else(|| {
                let parsed: serde_json::Value = serde_json::from_str(action_json)
                    .ok().unwrap_or_default();
                parsed.get("action")
                    .and_then(|a| a.get("msig"))
                    .and_then(|v| v.as_str().map(String::from))
                    .unwrap_or_default()
            });

        if msig.is_empty() {
            eprintln!("[relayer]   no msig address found, skipping");
            continue;
        }

        let execute_args = serde_json::json!({
            "action_json": action_json,
            "signature": sig_bytes,
        });

        let create_tx = match super::send_function_call(
            rpc_url, signer, &msig, "execute", &execute_args,
            300_000_000_000_000,
            0,
            nonce_cache,
        ) {
            Ok((tx_hash, _)) => {
                eprintln!("[relayer]   submitted ✓ tx={}", &tx_hash[..16.min(tx_hash.len())]);
                tx_hash
            }
            Err(e) => {
                eprintln!("[relayer]   submit FAILED: {}", e);
                continue;
            }
        };

        // Heartbeat
        if let Some(h) = health {
            h.ping();
        }

        // For kind 41000 (Task), also submit fund_action if present
        if event.kind == super::nostr::KIND_TASK {
            let fund_action_json = event.tags.iter()
                .find(|t| t.len() >= 2 && t[0] == "fund_action")
                .and_then(|t| t.get(1))
                .map(|s| s.as_str())
                .unwrap_or("");
            let fund_sig_hex = event.tags.iter()
                .find(|t| t.len() >= 2 && t[0] == "fund_action_sig")
                .and_then(|t| t.get(1))
                .map(|s| s.as_str())
                .unwrap_or("");

            if !fund_action_json.is_empty() && !fund_sig_hex.is_empty() {
                let fund_sig_bytes = match hex::decode(fund_sig_hex) {
                    Ok(b) => b,
                    Err(e) => { eprintln!("[relayer]   invalid fund_sig hex: {}", e); continue; }
                };

                let fund_args = serde_json::json!({
                    "action_json": fund_action_json,
                    "signature": fund_sig_bytes,
                });

                match super::send_function_call(
                    rpc_url, signer, &msig, "execute", &fund_args,
                    300_000_000_000_000,
                    0,
                    nonce_cache,
                ) {
                    Ok((tx_hash, _)) => {
                        eprintln!("[relayer]   fund submitted ✓ tx={}", &tx_hash[..16.min(tx_hash.len())]);

                        // Publish kind 41004 (FUNDED) — signals workers that escrow is ready to claim
                        if let (Some(ref relay), Some(ref nsec)) = (&daemon_cfg.nostr_relay, &daemon_cfg.nostr_nsec) {
                            let job_id_tag = event.tags.iter()
                                .find(|t| t.len() >= 2 && t[0] == "job_id")
                                .and_then(|t| t.get(1))
                                .map(|s| s.clone())
                                .unwrap_or_else(|| "unknown".into());
                            let funded_content = serde_json::json!({
                                "job_id": job_id_tag,
                                "escrow_status": "Open",
                                "create_tx": &create_tx,
                                "fund_tx": &tx_hash[..16.min(tx_hash.len())],
                            });
                            let funded_str = serde_json::to_string(&funded_content).unwrap_or_default();
                            let funded_tags = vec![
                                vec!["e".into(), event.id.clone()],
                                vec!["p".into(), event.pubkey.clone()],
                                vec!["job_id".into(), job_id_tag],
                            ];
                            match super::nostr::publish_event(relay, nsec, super::nostr::KIND_DISPATCH, &funded_str, funded_tags) {
                                Ok(()) => eprintln!("[relayer]   published 41004 (FUNDED) ✓"),
                                Err(e) => eprintln!("[relayer]   failed to publish 41004: {}", e),
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("[relayer]   fund submit FAILED: {}", e);
                    }
                }
            }
        }
    }

    Ok(())
}


