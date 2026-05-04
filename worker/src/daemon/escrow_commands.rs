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
use tracing::{info, warn, error, debug};

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
    pub is_recovering: AtomicBool, // true while a recovery thread is already running
}

impl ThreadHealth {
    pub fn new(name: &str) -> Arc<Self> {
        Arc::new(Self {
            name: name.to_string(),
            alive: AtomicBool::new(true),
            restart_count: AtomicBool::new(false),
            is_recovering: AtomicBool::new(false),
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

            info!("supervisor started — checking every {}s", check_interval.as_secs());

            loop {
                std::thread::sleep(check_interval);

                // Check relayer
                if relayer_health.check_and_reset() {
                    relayer_missed = 0;
                    relayer_health.is_recovering.store(false, Ordering::Relaxed);
                } else {
                    relayer_missed += 1;
                    if relayer_missed >= max_missed {
                        if relayer_health.is_recovering.load(Ordering::Relaxed) {
                            warn!("relayer still recovering — skipping duplicate spawn");
                        } else {
                            warn!("relayer silent for {} checks — restarting", relayer_missed);
                            relayer_health.is_recovering.store(true, Ordering::Relaxed);
                            relayer_missed = 0;
                            let cfg = config_dir.clone();
                            let health = relayer_health.clone();
                            std::thread::spawn(move || {
                                info!("spawning new relayer thread");
                                let handle = spawn_relayer_thread(cfg);
                                health.ping(); // Mark alive on spawn
                                let _ = handle.join();
                                info!("relayer thread exited");
                            });
                            relayer_health.restart_count.store(true, Ordering::Relaxed);
                        }
                    } else if relayer_missed > 1 {
                        warn!("relayer missed {} heartbeat(s)", relayer_missed);
                    }
                }

                // Check verifier
                if let Some(ref vh) = verifier_health {
                    if vh.check_and_reset() {
                        verifier_missed = 0;
                        vh.is_recovering.store(false, Ordering::Relaxed);
                    } else {
                        verifier_missed += 1;
                        if verifier_missed >= max_missed {
                            if vh.is_recovering.load(Ordering::Relaxed) {
                                warn!("verifier still recovering — skipping duplicate spawn");
                            } else {
                                warn!(
                                    "verifier silent for {} checks — restarting",
                                    verifier_missed
                                );
                                vh.is_recovering.store(true, Ordering::Relaxed);
                                verifier_missed = 0;
                                let cfg = config_dir.clone();
                                let health = vh.clone();
                                std::thread::spawn(move || {
                                    info!("spawning new verifier thread");
                                    let handle = spawn_verifier_thread(cfg);
                                    health.ping();
                                    let _ = handle.join();
                                    info!("verifier thread exited");
                                });
                                vh.restart_count.store(true, Ordering::Relaxed);
                            }
                        } else if verifier_missed > 1 {
                            warn!("verifier missed {} heartbeat(s)", verifier_missed);
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
pub(crate) fn sign_action_ed25519(action_json: &str, private_key_str: &str) -> Result<Vec<u8>> {
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
            _ => { warn!("unknown arg: {}", args[i]); i += 1; }
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

    info!(job_id = %job_id, nonce = next_nonce, fund_nonce, "task posted (kind=41000)");
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
        info!(relay = %relay, account = %signer.account_id, "relayer dry-run (use without --dry-run to submit)");
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

    info!(escrow = %escrow_contract, account = %signer.account_id, "verifier starting");

    loop {
        match run_verifier_cycle(&rpc, &rpc_url, &signer, &nonce_cache, escrow_contract, &gemini_key, &processed) {
            Ok(count) => {
                if count > 0 {
                    info!("processed {} escrows", count);
                }
            }
            Err(e) => {
                error!("verifier cycle error: {}", e);
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
            let mut p = processed.lock().unwrap_or_else(|e| e.into_inner());
            if p.iter().any(|id| id == &ve.job_id) { continue; }
            p.push_back(ve.job_id.clone());
            while p.len() > 10_000 { p.pop_front(); }
        }

        info!(job_id = %ve.job_id, "verifier processing escrow");

        // 1. Get escrow details
        let escrow = super::escrow_client::get_escrow(rpc, escrow_contract, &ve.job_id)?;
        if escrow.status != "Verifying" {
            warn!(job_id = %ve.job_id, status = %escrow.status, "skipping — not Verifying");
            continue;
        }

        let result_str = escrow.result.as_deref().unwrap_or("");

        // 2. Try to fetch result from KV
        let result_content = match fetch_kv_result(result_str) {
            Ok(content) => content,
            Err(e) => {
                warn!(job_id = %ve.job_id, error = %e, "KV fetch failed, using raw result");
                result_str.to_string()
            }
        };

        // 3. Score with Gemini (multi-pass, uses escrow's own threshold)
        let threshold = escrow.score_threshold;
        let score = score_with_gemini(
            gemini_key,
            &escrow.task_description,
            &escrow.criteria,
            &result_content,
            threshold,
        )?;

        let passed = score.score >= threshold;
        let verdict = Verdict {
            score: score.score,
            passed,
            detail: score.detail,
        };
        let verdict_json = serde_json::to_string(&verdict)?;

        info!(score = verdict.score, passed, "escrow scored");

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
                info!(tx = &&tx_hash[..16.min(tx_hash.len())], "verification resumed");
            }
            Err(e) => {
                error!(job_id = %ve.job_id, error = %e, "resume FAILED");
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

/// Single-pass scoring result.
#[derive(Debug)]
struct PassResult {
    score: u8,
    reasoning: String,
}

/// Build the scoring prompt. Same prompt for all passes — temperature variation provides diversity.
pub(crate) fn build_scoring_prompt(
    task_description: &str,
    criteria: &str,
    result: &str,
    threshold: u8,
) -> String {
    format!(
        r#"You are an impartial work verifier. Score the following work result against the given criteria.

## Task Description
{task_description}

## Acceptance Criteria
{criteria}

## Work Result
{result}

## Instructions
1. Carefully evaluate the work result against each criterion.
2. Score from 0 to 100, where:
   - 0-20: Completely fails to address the task
   - 21-40: Addresses some aspects but major gaps
   - 41-60: Partially meets criteria, significant issues remain
   - 61-80: Mostly meets criteria, minor issues
   - 81-100: Fully meets or exceeds all criteria
3. The passing threshold is {threshold}/100.
4. Be strict. Do not give partial credit for incomplete work.

Respond in JSON format:
{{"score": <number 0-100>, "reasoning": "<detailed explanation of the score, addressing each criterion>"}}"#,
        task_description = task_description,
        criteria = criteria,
        result = result,
        threshold = threshold,
    )
}

/// Run a single Gemini scoring pass. Returns (score, reasoning).
fn gemini_single_pass(
    api_key: &str,
    prompt: &str,
    pass_num: usize,
) -> Result<PassResult> {
    // Temperature ramps slightly per pass for diversity: 0.2, 0.3, 0.4, 0.5
    let temperature = 0.2 + (pass_num as f32 * 0.1);
    let temperature = temperature.min(0.5);

    let url = format!(
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={}",
        api_key
    );

    let body = serde_json::json!({
        "contents": [{
            "parts": [{ "text": prompt }]
        }],
        "generationConfig": {
            "temperature": temperature,
            "responseMimeType": "application/json"
        }
    });

    let client = reqwest::blocking::Client::new();
    let resp = client
        .post(&url)
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
    let score = (parsed["score"].as_u64().unwrap_or(0) as u8).min(100);
    let reasoning = parsed["reasoning"]
        .as_str()
        .unwrap_or("no reasoning")
        .to_string();

    Ok(PassResult { score, reasoning })
}

/// Multi-pass scoring: run N independent Gemini calls, take median score.
/// Uses temperature variation across passes for robustness.
fn score_with_gemini(
    api_key: &str,
    task_description: &str,
    criteria: &str,
    result: &str,
    threshold: u8,
) -> Result<GeminiScore> {
    let num_passes = 4;
    let prompt = build_scoring_prompt(task_description, criteria, result, threshold);

    let mut pass_results: Vec<PassResult> = Vec::with_capacity(num_passes);

    for i in 0..num_passes {
        match gemini_single_pass(api_key, &prompt, i) {
            Ok(pr) => {
                debug!(pass = i + 1, total = num_passes, score = pr.score, "scoring pass complete");
                pass_results.push(pr);
            }
            Err(e) => {
                warn!(pass = i + 1, total = num_passes, error = %e, "scoring pass FAILED");
                pass_results.push(PassResult {
                    score: 0,
                    reasoning: format!("Error: {}", e),
                });
            }
        }
    }

    // Median of scores
    let mut scores: Vec<u8> = pass_results.iter().map(|p| p.score).collect();
    scores.sort();
    let median_score = scores[scores.len() / 2];

    // Pick the pass closest to median for reasoning
    let fallback = PassResult {
        score: 0,
        reasoning: "no passes completed".into(),
    };
    let best_pass = pass_results
        .iter()
        .min_by_key(|p| (p.score as i16 - median_score as i16).abs() as u8)
        .unwrap_or(&fallback);

    let detail = format!(
        "Median of {} passes: {}/100. Threshold: {}. Best reasoning: {}",
        num_passes, median_score, threshold, best_pass.reasoning
    );

    Ok(GeminiScore {
        score: median_score,
        detail,
    })
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
                    error!("nostr_relay not configured, relayer thread exiting");
                    return;
                }
            };

            let signer = match super::manage::load_signer(&daemon_cfg.key_path) {
                Ok(s) => s,
                Err(e) => {
                    error!(error = %e, "failed to load signer, relayer thread exiting");
                    return;
                }
            };
            let nonce_cache = NonceCache::new(rpc_url.clone(), signer.clone());

            if let Err(e) = run_relayer_inner(&daemon_cfg, &rpc_url, &signer, &nonce_cache, health.as_ref()) {
                error!(error = %e, "relayer thread exited with error");
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
                    error!("escrow_contract not configured, verifier thread exiting");
                    return;
                }
            };

            let signer = match super::manage::load_signer(&daemon_cfg.key_path) {
                Ok(s) => s,
                Err(e) => {
                    error!(error = %e, "failed to load signer, verifier thread exiting");
                    return;
                }
            };
            let rpc = match make_rpc(&rpc_url) {
                Ok(r) => r,
                Err(e) => {
                    error!(error = %e, "RPC init failed, verifier thread exiting");
                    return;
                }
            };
            let nonce_cache = NonceCache::new(rpc_url.clone(), signer.clone());
            let processed: Mutex<VecDeque<String>> = Mutex::new(VecDeque::new());

            let gemini_key = match std::env::var("GEMINI_API_KEY") {
                Ok(k) => k,
                Err(_) => {
                    error!("GEMINI_API_KEY not set, verifier thread exiting");
                    return;
                }
            };

            info!(escrow = %escrow_contract, account = %signer.account_id, "verifier thread starting");

            loop {
                match run_verifier_cycle(&rpc, &rpc_url, &signer, &nonce_cache, &escrow_contract, &gemini_key, &processed) {
                    Ok(count) => {
                        if count > 0 {
                            info!("verifier processed {} escrows", count);
                        }
                    }
                    Err(e) => {
                        error!(error = %e, "verifier cycle error");
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

// ════════════════════════════════════════════════════════════════════════
// WORKER RESULT HANDLER (kind 41002)
// ════════════════════════════════════════════════════════════════════════

/// Handle kind 41002 (WORKER_RESULT) — extract worker-signed claim_for and
/// submit_result_for actions from the Nostr event, relay them on-chain.
///
/// The event carries:
///   - claim_sig:  ed25519 signature for the claim_for message
///   - submit_sig: ed25519 signature for the submit_result_for message
///   - job_id, worker_msig, patch_id, etc.
///
/// The relayer calls escrow.claim_for() then escrow.submit_result_for()
/// directly on the escrow contract using the daemon's NEAR key.
fn handle_worker_result_event(
    event: &super::nostr::NostrEvent,
    rpc_url: &str,
    signer: &InMemorySigner,
    nonce_cache: &NonceCache,
    daemon_cfg: &DaemonConfig,
    health: Option<&Arc<ThreadHealth>>,
) {
    let escrow_contract = match daemon_cfg.escrow_contract.as_deref() {
        Some(c) => c,
        None => {
            error!("escrow_contract not configured, cannot process 41002");
            return;
        }
    };

    // Extract required tags
    let job_id = event
        .tags
        .iter()
        .find(|t| t.len() >= 2 && t[0] == "job_id")
        .and_then(|t| t.get(1))
        .cloned()
        .unwrap_or_default();

    if job_id.is_empty() {
        warn!("41002 missing job_id tag, skipping");
        return;
    }

    let worker_pubkey = event.pubkey.clone();

    let claim_sig_hex = event
        .tags
        .iter()
        .find(|t| t.len() >= 2 && t[0] == "claim_sig")
        .and_then(|t| t.get(1))
        .map(|s| s.as_str())
        .unwrap_or("");

    let submit_sig_hex = event
        .tags
        .iter()
        .find(|t| t.len() >= 2 && t[0] == "submit_sig")
        .and_then(|t| t.get(1))
        .map(|s| s.as_str())
        .unwrap_or("");

    let result_content = event.content.clone();
    let patch_id = event
        .tags
        .iter()
        .find(|t| t.len() >= 2 && t[0] == "patch_id")
        .and_then(|t| t.get(1))
        .cloned()
        .unwrap_or_default();

    info!(
        job_id = %job_id,
        worker = &worker_pubkey[..8.min(worker_pubkey.len())],
        "👷 relayer processing WORKER_RESULT (41002)"
    );

    // ── Step 1: claim_for ──────────────────────────────────────────────
    if !claim_sig_hex.is_empty() {
        let claim_sig = match hex::decode(claim_sig_hex) {
            Ok(b) => b,
            Err(e) => {
                warn!(job_id = %job_id, error = %e, "invalid claim_sig hex");
                return;
            }
        };

        if claim_sig.len() != 64 {
            warn!(
                job_id = %job_id,
                len = claim_sig.len(),
                "claim_sig must be 64 bytes"
            );
            return;
        }

        let claim_args = serde_json::json!({
            "job_id": job_id,
            "worker_pubkey": worker_pubkey,
            "worker_signature": claim_sig,
        });

        match super::send_function_call(
            rpc_url,
            signer,
            escrow_contract,
            "claim_for",
            &claim_args,
            100_000_000_000_000, // 100 Tgas
            0,
            nonce_cache,
        ) {
            Ok((tx_hash, _)) => {
                info!(
                    tx = &&tx_hash[..16.min(tx_hash.len())],
                    "claim_for submitted on-chain"
                );
            }
            Err(e) => {
                // Don't return — claim_for might fail because the escrow
                // was already claimed (idempotent re-submission). Try submit anyway.
                warn!(
                    job_id = %job_id,
                    error = %e,
                    "claim_for failed (may be already claimed, continuing)"
                );
            }
        }
    } else {
        info!(
            job_id = %job_id,
            "no claim_sig in 41002, skipping claim_for (escrow may be pre-claimed)"
        );
    }

    // ── Step 2: submit_result_for ──────────────────────────────────────
    if submit_sig_hex.is_empty() {
        warn!(
            job_id = %job_id,
            "41002 missing submit_sig, cannot submit result"
        );
        return;
    }

    let submit_sig = match hex::decode(submit_sig_hex) {
        Ok(b) => b,
        Err(e) => {
            warn!(job_id = %job_id, error = %e, "invalid submit_sig hex");
            return;
        }
    };

    if submit_sig.len() != 64 {
        warn!(
            job_id = %job_id,
            len = submit_sig.len(),
            "submit_sig must be 64 bytes"
        );
        return;
    }

    // Use patch_id as result reference if content is short, else content itself
    let result_ref = if !patch_id.is_empty() {
        format!("{{\"patch_id\":\"{}\",\"summary\":{}}}", patch_id, serde_json::to_string(&result_content).unwrap_or_default())
    } else {
        result_content.clone()
    };

    let submit_args = serde_json::json!({
        "job_id": job_id,
        "result": result_ref,
        "worker_pubkey": worker_pubkey,
        "worker_signature": submit_sig,
    });

    match super::send_function_call(
        rpc_url,
        signer,
        escrow_contract,
        "submit_result_for",
        &submit_args,
        200_000_000_000_000, // 200 Tgas (triggers yield, needs headroom)
        0,
        nonce_cache,
    ) {
        Ok((tx_hash, _)) => {
            info!(
                tx = &&tx_hash[..16.min(tx_hash.len())],
                "submit_result_for submitted on-chain"
            );
        }
        Err(e) => {
            error!(
                job_id = %job_id,
                error = %e,
                "submit_result_for FAILED"
            );
            return;
        }
    }

    // Heartbeat
    if let Some(h) = health {
        h.ping();
    }

    info!(job_id = %job_id, "worker result relayed on-chain successfully");
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

    info!(relay = %relay, account = %signer.account_id, "relayer starting, watching kinds 41000,41003");

    let rx = super::nostr::spawn_nostr_subscriber(vec![relay.to_string()]);
    info!("relayer subscribed, waiting for events");

    loop {
        let event = match rx.recv_timeout(Duration::from_secs(5)) {
            Ok(ev) => ev,
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => continue,
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {
                error!("Nostr subscriber channel disconnected, relayer exiting to avoid tight-loop");
                break;
            }
        };

        // ── Route by kind ──────────────────────────────────────────────
        if event.kind == super::nostr::KIND_RESULT {
            // Kind 41002 — WORKER_RESULT
            handle_worker_result_event(
                &event, &rpc_url, signer, nonce_cache, daemon_cfg, health,
            );
            continue;
        }

        if event.kind != super::nostr::KIND_TASK && event.kind != super::nostr::KIND_ACTION {
            continue;
        }

        // Dedup
        {
            let mut p = processed.lock().unwrap_or_else(|e| e.into_inner());
            if p.iter().any(|id| id == &event.id) { continue; }
            p.push_back(event.id.clone());
            while p.len() > 10_000 { p.pop_front(); }
        }

        let kind_label = if event.kind == super::nostr::KIND_TASK { "TASK" } else { "ACTION" };
        info!(kind = kind_label, pubkey = &event.pubkey[..8.min(event.pubkey.len())], "relayer received event");

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
            warn!("missing action/action_sig tags, skipping event");
            continue;
        }

        let sig_bytes = match hex::decode(action_sig_hex) {
            Ok(b) => b,
            Err(e) => { warn!(error = %e, "invalid sig hex, skipping"); continue; }
        };
        if sig_bytes.len() != 64 {
            warn!(len = sig_bytes.len(), "invalid sig length");
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
            warn!("no msig address found, skipping event");
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
                info!(tx = &&tx_hash[..16.min(tx_hash.len())], "relayer submitted on-chain");
                tx_hash
            }
            Err(e) => {
                error!(error = %e, "relayer submit FAILED");
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
                    Err(e) => { warn!(error = %e, "invalid fund_sig hex, skipping"); continue; }
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
                        info!(tx = &&tx_hash[..16.min(tx_hash.len())], "fund submitted on-chain");

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
                                Ok(()) => info!("published 41004 (FUNDED)"),
                                Err(e) => warn!(error = %e, "failed to publish 41004"),
                            }
                        }
                    }
                    Err(e) => {
                        error!(error = %e, "fund submit FAILED");
                    }
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── sign_action_ed25519 ─────────────────────────────────────────────

    /// Generate a valid 32-byte seed for testing.
    fn test_seed_hex() -> String {
        hex::encode([42u8; 32])
    }

    /// Generate a valid 64-byte (seed+pubkey) for testing.
    fn test_seed64_hex() -> String {
        hex::encode([42u8; 64])
    }

    #[test]
    fn test_sign_with_raw_hex_32_bytes() {
        let key = test_seed_hex();
        let sig = sign_action_ed25519(r#"{"test":true}"#, &key);
        assert!(sig.is_ok(), "32-byte hex key should be accepted");
        let sig = sig.unwrap();
        assert_eq!(sig.len(), 64, "Ed25519 signature must be 64 bytes");
    }

    #[test]
    fn test_sign_with_raw_hex_64_bytes() {
        let key = test_seed64_hex();
        let sig = sign_action_ed25519(r#"{"test":true}"#, &key);
        assert!(sig.is_ok(), "64-byte hex key should be accepted (uses first 32 bytes)");
        let sig = sig.unwrap();
        assert_eq!(sig.len(), 64, "Ed25519 signature must be 64 bytes");
    }

    #[test]
    fn test_sign_deterministic() {
        let key = test_seed_hex();
        let msg = r#"{"action":"test","nonce":1}"#;
        let sig1 = sign_action_ed25519(msg, &key).unwrap();
        let sig2 = sign_action_ed25519(msg, &key).unwrap();
        assert_eq!(sig1, sig2, "same key + message must produce identical signatures");
    }

    #[test]
    fn test_sign_different_messages_differ() {
        let key = test_seed_hex();
        let sig1 = sign_action_ed25519(r#"{"msg":1}"#, &key).unwrap();
        let sig2 = sign_action_ed25519(r#"{"msg":2}"#, &key).unwrap();
        assert_ne!(sig1, sig2, "different messages must produce different signatures");
    }

    #[test]
    fn test_sign_with_ed25519_prefix() {
        // Encode the 32-byte seed as base58 with "ed25519:" prefix
        let seed_bytes = [42u8; 32];
        let b58 = bs58::encode(seed_bytes).into_string();
        let key = format!("ed25519:{}", b58);
        let sig = sign_action_ed25519(r#"{"test":true}"#, &key);
        assert!(sig.is_ok(), "ed25519:<base58> key should be accepted");
    }

    #[test]
    fn test_sign_ed25519_prefix_matches_raw_hex() {
        let seed_bytes = [42u8; 32];
        let b58 = bs58::encode(seed_bytes).into_string();
        let prefixed_key = format!("ed25519:{}", b58);
        let raw_hex_key = hex::encode(seed_bytes);

        let msg = r#"{"test":true}"#;
        let sig_prefixed = sign_action_ed25519(msg, &prefixed_key).unwrap();
        let sig_raw = sign_action_ed25519(msg, &raw_hex_key).unwrap();
        assert_eq!(sig_prefixed, sig_raw, "ed25519: prefix and raw hex should produce same signature");
    }

    #[test]
    fn test_sign_invalid_key_length() {
        // 16 bytes — too short
        let key = hex::encode([0u8; 16]);
        let result = sign_action_ed25519("test", &key);
        assert!(result.is_err(), "wrong key length should fail");
    }

    #[test]
    fn test_sign_empty_key() {
        let result = sign_action_ed25519("test", "");
        assert!(result.is_err(), "empty key should fail");
    }

    #[test]
    fn test_sign_invalid_hex() {
        let result = sign_action_ed25519("test", "not_hex_at_all!!!");
        assert!(result.is_err(), "invalid hex should fail");
    }

    // ── build_scoring_prompt ────────────────────────────────────────────

    #[test]
    fn test_scoring_prompt_contains_task_description() {
        let prompt = build_scoring_prompt("Build a web scraper", "Must be fast", "Result here", 80);
        assert!(prompt.contains("Build a web scraper"), "prompt should contain task description");
    }

    #[test]
    fn test_scoring_prompt_contains_criteria() {
        let prompt = build_scoring_prompt("Task", "Must pass all tests", "Result", 80);
        assert!(prompt.contains("Must pass all tests"), "prompt should contain criteria");
    }

    #[test]
    fn test_scoring_prompt_contains_result() {
        let prompt = build_scoring_prompt("Task", "Criteria", "The actual work output", 80);
        assert!(prompt.contains("The actual work output"), "prompt should contain result");
    }

    #[test]
    fn test_scoring_prompt_contains_threshold() {
        let prompt = build_scoring_prompt("Task", "Criteria", "Result", 75);
        assert!(prompt.contains("75"), "prompt should contain threshold value");
    }

    #[test]
    fn test_scoring_prompt_contains_scoring_instructions() {
        let prompt = build_scoring_prompt("Task", "Criteria", "Result", 80);
        assert!(prompt.contains("score"), "prompt should mention score");
        assert!(prompt.contains("impartial"), "prompt should mention impartial verifier");
        assert!(prompt.contains("reasoning"), "prompt should request reasoning");
    }

    #[test]
    fn test_scoring_prompt_contains_json_format() {
        let prompt = build_scoring_prompt("Task", "Criteria", "Result", 80);
        assert!(prompt.contains("JSON"), "prompt should specify JSON response format");
    }

    // ── ThreadHealth ────────────────────────────────────────────────────

    #[test]
    fn test_thread_health_new_is_alive() {
        // ThreadHealth::new sets alive = true initially
        let health = ThreadHealth::new("test-thread");
        // check_and_reset returns the current value and sets to false
        assert!(health.check_and_reset(), "new ThreadHealth should be alive (true)");
    }

    #[test]
    fn test_thread_health_ping_then_check() {
        let health = ThreadHealth::new("test-thread");
        // Reset first (new starts true)
        let _ = health.check_and_reset();
        // Now alive should be false
        assert!(!health.check_and_reset(), "after reset, should be false");

        // Ping
        health.ping();
        assert!(health.check_and_reset(), "after ping, should be true");
    }

    #[test]
    fn test_thread_health_check_resets_to_false() {
        let health = ThreadHealth::new("test-thread");
        // First check returns true (initial value) and resets to false
        assert!(health.check_and_reset());
        // Second check should return false
        assert!(!health.check_and_reset(), "check_and_reset should have cleared the flag");
    }

    #[test]
    fn test_thread_health_no_ping_means_timeout() {
        let health = ThreadHealth::new("test-thread");
        // Consume the initial true
        let _ = health.check_and_reset();
        // Without calling ping(), repeated checks return false (simulating a dead thread)
        assert!(!health.check_and_reset());
        assert!(!health.check_and_reset());
    }

    #[test]
    fn test_thread_health_ping_multiple_times() {
        let health = ThreadHealth::new("test-thread");
        health.ping();
        health.ping();
        // Only one check should return true, then false
        assert!(health.check_and_reset());
        assert!(!health.check_and_reset());
    }

    #[test]
    fn test_thread_health_name() {
        let health = ThreadHealth::new("my-worker-thread");
        assert_eq!(health.name, "my-worker-thread");
    }
}