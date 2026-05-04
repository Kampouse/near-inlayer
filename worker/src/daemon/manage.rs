//! Daemon configuration and process management.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use near_crypto::InMemorySigner;
use serde::{Deserialize, Serialize};

/// Deserialize a u128 from TOML. TOML 0.8 only supports i64 integers,
/// so we accept both integer (for small values) and string (for large yoctoNEAR amounts).
fn deserialize_yocto<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<u128, D::Error> {
    use serde::de::{self, Visitor};
    use std::fmt;

    struct YoctoVisitor;
    impl<'de> Visitor<'de> for YoctoVisitor {
        type Value = u128;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("an integer or string representing a u128 yoctoNEAR amount")
        }
        fn visit_u64<E: de::Error>(self, v: u64) -> Result<u128, E> {
            Ok(v as u128)
        }
        fn visit_i64<E: de::Error>(self, v: i64) -> Result<u128, E> {
            Ok(v as u128)
        }
        fn visit_str<E: de::Error>(self, v: &str) -> Result<u128, E> {
            v.parse::<u128>().map_err(de::Error::custom)
        }
    }
    deserializer.deserialize_any(YoctoVisitor)
}

/// Default worker stake: 0.1 NEAR in yoctoNEAR.
fn default_worker_stake() -> u128 {
    100_000_000_000_000_000_000_000 // 0.1 NEAR
}

/// Daemon configuration fields (merged into inlayer Config).
/// These are daemon-specific settings that complement the base inlayer Config.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct DaemonConfig {
    pub contract_id: String,
    pub account_id: String,
    pub network: String,
    pub key_path: String,
    pub poll_interval_secs: u64,
    pub dashboard_addr: Option<String>,
    /// WASM search directories (shared with inlayer Config)
    pub search_paths: Vec<String>,
    /// Cloudflare tunnel URL (auto-populated when using --tunnel)
    pub tunnel_url: Option<String>,
    /// Deposit for request_execution in yoctoNEAR (default: 1 yocto — operator covers all costs)
    /// Config accepts string to handle large u128 values beyond TOML i64 limits.
    #[serde(deserialize_with = "deserialize_yocto")]
    pub deposit_yocto: u128,
    /// Nostr relay URL for agent coordination (e.g. "wss://nostr-relay.example.com")
    pub nostr_relay: Option<String>,
    /// Nostr nsec (hex, 64 chars) for signing coordination events
    pub nostr_nsec: Option<String>,
    // ── Phase 1 Security ──────────────────────────────────────────────
    /// Allowed program names for Nostr dispatch (default: ["kv-writer"])
    pub allowed_programs: Vec<String>,
    /// Allowed actions in input JSON (default: ["write"])
    pub allowed_actions: Vec<String>,
    /// Max entries per request (default: 100)
    pub max_entries: usize,
    /// Max output size in bytes (default: 1_000_000)
    pub max_output_bytes: usize,
    /// Max jobs per pubkey per hour (default: 60)
    pub max_jobs_per_hour: usize,
    /// Whether agents pay for their own runtime (default: false — operator covers all costs)
    pub agent_pays: bool,
    // ── Escrow mode ──────────────────────────────────────────────────
    /// Execution mode: "direct" (inlayer contract), "escrow" (escrow contract), or "both"
    pub execution_mode: String,
    /// Escrow contract account ID (e.g. "escrow.kampouse.testnet")
    pub escrow_contract: Option<String>,
    /// FastNear KV account for writing results (e.g. "kv.kampouse.near")
    pub kv_account: Option<String>,
    /// Worker stake in yoctoNEAR for escrow claims (default: 0.1 NEAR)
    #[serde(default = "default_worker_stake")]
    #[serde(deserialize_with = "deserialize_yocto")]
    pub worker_stake_yocto: u128,
    /// Timeout in seconds to wait for escrow to be funded (default: 600)
    pub escrow_fund_timeout_secs: u64,
    /// Timeout in seconds to wait for escrow settlement after result submission (default: 600)
    pub escrow_settle_timeout_secs: u64,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        let home = dirs::home_dir().unwrap_or_default();
        Self {
            contract_id: "outlayer.kampouse.testnet".to_string(),
            account_id: "your-account.testnet".to_string(),
            network: "testnet".to_string(),
            key_path: format!(
                "{}/.near-credentials/testnet/your-account.testnet.json",
                home.display()
            ),
            poll_interval_secs: 5,
            dashboard_addr: None,
            search_paths: vec!["./wasi-examples".to_string()],
            tunnel_url: None,
            deposit_yocto: 1u128, // 1 yocto — operator gets free execution
            nostr_relay: None,
            nostr_nsec: None,
            // Phase 1 Security defaults
            allowed_programs: vec!["kv-writer".to_string()],
            allowed_actions: vec!["write".to_string()],
            max_entries: 100,
            max_output_bytes: 1_000_000,
            max_jobs_per_hour: 60,
            agent_pays: false, // Operator covers all execution costs
            // Escrow mode defaults
            execution_mode: "direct".to_string(),
            escrow_contract: None,
            kv_account: None,
            worker_stake_yocto: default_worker_stake(),
            escrow_fund_timeout_secs: 600,
            escrow_settle_timeout_secs: 600,
        }
    }
}

impl DaemonConfig {
    pub fn deposit_yocto(&self) -> u128 {
        self.deposit_yocto
    }

    pub fn validate(&self) -> Result<()> {
        // Check if using default placeholder values
        if self.account_id.contains("your-account") {
            bail!(
                "⚠️  Configuration not set up.\n\n\
                Please create ./inlayer.config in your project directory:\n\
                ---\n\
                contract_id = \"outlayer.kampouse.testnet\"\n\
                account_id = \"your-actual-account.testnet\"\n\
                key_path = \"~/.near-credentials/testnet/your-actual-account.testnet.json\"\n\
                network = \"testnet\"\n\
                search_paths = [\"./wasi-examples\"]\n\
                poll_interval_secs = 5\n\
                ---\n\n\
                💡 Get your account key with: near login --network testnet\n\
                📁 Or create global config at: ~/.inlayer/inlayer.config"
            );
        }

        // Validate key file exists (try both with and without .json extension)
        let key_path = std::path::Path::new(&self.key_path);
        if !key_path.exists() {
            // Try adding .json if not present
            let with_json = format!("{}.json", self.key_path);
            let json_path = std::path::Path::new(&with_json);
            if json_path.exists() {
                // File exists with .json extension - provide helpful message
                bail!(
                    "⚠️  Key file not found: {}\n\
                    But found: {}\n\n\
                    Please update your inlayer.config:\n\
                    key_path = \"{}\"",
                    self.key_path, with_json, with_json
                );
            }

            // Try removing .json if present
            let without_json = self.key_path.trim_end_matches(".json");
            let no_json_path = std::path::Path::new(without_json);
            if no_json_path.exists() {
                // File exists without .json extension - provide helpful message
                bail!(
                    "⚠️  Key file not found: {}\n\
                    But found: {}\n\n\
                    Please update your inlayer.config:\n\
                    key_path = \"{}\"",
                    self.key_path, without_json, without_json
                );
            }

            // File not found at all
            bail!(
                "⚠️  Key file not found: {}\n\n\
                Run: near login --network {}\n\
                Then update key_path in your ./inlayer.config",
                self.key_path, self.network
            );
        }

        Ok(())
    }

    pub fn load(config_dir: &Path) -> Self {
        // Priority 1: Current working directory (project-specific config)
        let cwd = env::current_dir().unwrap_or_else(|_| config_dir.to_path_buf());
        for name in &["inlayer.config", "inlayer.config.toml"] {
            let path = cwd.join(name);
            if path.exists() {
                if let Ok(s) = std::fs::read_to_string(&path) {
                    if let Ok(mut cfg) = toml::from_str::<DaemonConfig>(&s) {
                        cfg.expand_tildes();
                        cfg.apply_env_overrides();
                        tracing::info!("📁 Using config from: {}", path.display());
                        return cfg;
                    } else {
                        tracing::warn!("TOML parse failed for {}", path.display());
                    }
                }
            }
        }

        // Priority 2: Config directory parameter (where inlayer was invoked)
        for name in &["inlayer.config", "inlayer.config.toml"] {
            let path = config_dir.join(name);
            if path.exists() {
                if let Ok(s) = std::fs::read_to_string(&path) {
                    if let Ok(mut cfg) = toml::from_str::<DaemonConfig>(&s) {
                        cfg.expand_tildes();
                        cfg.apply_env_overrides();
                        tracing::info!("📁 Using config from: {}", path.display());
                        return cfg;
                    }
                }
            }
        }

        // Priority 3: Global config in home directory
        if let Some(home) = dirs::home_dir() {
            let home_config_dir = home.join(".inlayer");
            for name in &["inlayer.config", "inlayer.config.toml"] {
                let path = home_config_dir.join(name);
                if path.exists() {
                    if let Ok(s) = std::fs::read_to_string(&path) {
                    if let Ok(mut cfg) = toml::from_str::<DaemonConfig>(&s) {
                        cfg.expand_tildes();
                        cfg.apply_env_overrides();
                        tracing::info!("📁 Using global config from: {}", path.display());
                        return cfg;
                        }
                    }
                }
            }
        }

        // No config found - return default
        tracing::warn!("⚠️  No config file found. Using defaults.");
        tracing::warn!("   Create ./inlayer.config in your project directory:");
        tracing::warn!("   ---");
        tracing::warn!("   contract_id = \"outlayer.kampouse.testnet\"");
        tracing::warn!("   account_id = \"your-account.testnet\"");
        tracing::warn!("   key_path = \"~/.near-credentials/testnet/your-account.testnet.json\"");
        tracing::warn!("   network = \"testnet\"");
        tracing::warn!("   search_paths = [\"./wasi-examples\"]");
        tracing::warn!("   poll_interval_secs = 5");
        tracing::warn!("   ---");

        let mut cfg = DaemonConfig::default();
        cfg.expand_tildes();
        cfg.apply_env_overrides();
        cfg
    }

    fn expand_tildes(&mut self) {
        if let Some(home) = dirs::home_dir() {
            let home_str = home.display().to_string();
            if self.key_path.starts_with("~/") {
                self.key_path = format!("{}/{}", home_str, &self.key_path[2..]);
            }
            for dir in &mut self.search_paths {
                if dir.starts_with("~/") {
                    *dir = format!("{}/{}", home_str, &dir[2..]);
                }
            }
        }
    }

    /// Apply environment variable overrides (H1 fix).
    /// Env vars take precedence over config file values.
    fn apply_env_overrides(&mut self) {
        if let Ok(val) = std::env::var("INLAYER_NOSTR_NSEC") {
            self.nostr_nsec = Some(val);
        }
        if let Ok(val) = std::env::var("INLAYER_NOSTR_RELAY") {
            self.nostr_relay = Some(val);
        }
    }

    pub fn rpc_urls(&self) -> Vec<String> {
        match self.network.as_str() {
            "mainnet" => vec![
                "https://rpc.fastnear.com".into(),
                "https://near.drpc.org".into(),
                "https://near.lava.build".into(),
                "https://near-rpc.publicnode.com".into(),
                "https://near-mainnet.api.pagoda.co/rpc/v1".into(),
            ],
            "testnet" => vec![
                "https://rpc.testnet.fastnear.com".into(),
                "https://neart.lava.build".into(),
                "https://near-testnet.gateway.tatum.io".into(),
            ],
            other => vec![format!("https://rpc.{}.near.org", other)],
        }
    }

    pub fn rpc_url(&self) -> String {
        self.rpc_urls().into_iter().next().unwrap()
    }

    pub fn pid_file_path(&self) -> PathBuf {
        let home = dirs::home_dir().unwrap_or_default();
        home.join(".inlayer").join("layerd.pid")
    }

    pub fn log_file_path(&self) -> PathBuf {
        let home = dirs::home_dir().unwrap_or_default();
        home.join(".inlayer").join("layerd.log")
    }

    pub fn tunnel_pid_file_path(&self) -> PathBuf {
        let home = dirs::home_dir().unwrap_or_default();
        home.join(".inlayer").join("cloudflared.pid")
    }
}

/// Key file structure for NEAR credentials.
#[derive(Deserialize)]
pub(crate) struct KeyFile {
    pub(crate) private_key: String,
    pub(crate) account_id: String,
}

/// Load a NEAR signer from a key file.
pub fn load_signer(path: &str) -> Result<InMemorySigner> {
    // Check if key file exists first
    if !std::path::Path::new(path).exists() {
        bail!(
            "Key file not found: {}\n\n\
            To fix this:\n\
            1. Create a config file at ~/.inlayer/inlayer.config with:\n\
               contract_id = \"your-contract.testnet\"\n\
               account_id = \"your-account.testnet\"\n\
               key_path = \"~/.near-credentials/testnet/your-account.testnet.json\"\n\
               network = \"testnet\"\n\n\
            2. Or login with NEAR CLI:\n\
               near login --network testnet\n\n\
            3. Then run: inlayer daemon --status",
            path
        );
    }

    let data = std::fs::read_to_string(path).context("reading key file")?;
    let kf: KeyFile = serde_json::from_str(&data).context("parsing key file")?;
    let signer_account_id: near_primitives::types::AccountId = kf.account_id.parse()?;
    let signer_secret_key: near_crypto::SecretKey = kf.private_key.parse()?;
    Ok(InMemorySigner::from_secret_key(signer_account_id, signer_secret_key))
}

/// Check if the daemon is currently running.
pub(crate) fn is_running(pid_path: &Path) -> bool {
    if let Ok(pid_str) = fs::read_to_string(pid_path) {
        if let Ok(pid) = pid_str.trim().parse::<u32>() {
            // Safe check: use kill command to check if process exists
            Command::new("kill")
                .args(["-0", &pid.to_string()])
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        } else {
            false
        }
    } else {
        false
    }
}

/// Read the PID from the PID file.
pub(crate) fn read_pid(pid_path: &Path) -> Result<u32> {
    let s = fs::read_to_string(pid_path)?;
    Ok(s.trim().parse()?)
}

/// Daemonize the current process.
pub(crate) fn daemonize(_log_path: &Path, pid_path: &Path) -> Result<()> {
    if let Some(parent) = pid_path.parent() {
        fs::create_dir_all(parent)?;
    }

    // Simple daemonization: just write PID and continue
    // The actual forking/detaching is handled by launchd or the caller
    let pid = std::process::id();
    fs::write(pid_path, pid.to_string())?;

    tracing::info!("Daemonized with PID: {}", pid);
    Ok(())
}

/// Start the daemon via launchd (macOS).
pub(crate) fn start_daemon_via_launchd() -> Result<()> {
    let plist = dirs::home_dir()
        .map(|h| h.join("Library/LaunchAgents/com.outlayer.layerd.plist"))
        .filter(|p| p.exists());
    if let Some(plist_path) = &plist {
        let status = std::process::Command::new("launchctl")
            .args(["load", &plist_path.display().to_string()])
            .status()?;
        if status.success() {
            tracing::info!("inlayer daemon started via launchd");
        } else {
            bail!("launchctl load failed");
        }
    } else {
        bail!("launchd plist not found at ~/Library/LaunchAgents/com.outlayer.layerd.plist");
    }
    Ok(())
}

/// Stop the daemon.
pub(crate) fn stop_daemon(pid_path: &Path) -> Result<()> {
    let plist = dirs::home_dir()
        .map(|h| h.join("Library/LaunchAgents/com.outlayer.layerd.plist"))
        .filter(|p| p.exists());
    if let Some(plist_path) = &plist {
        let _ = std::process::Command::new("launchctl")
            .args(["unload", &plist_path.display().to_string()])
            .status();
        std::thread::sleep(Duration::from_millis(500));
    }
    if is_running(pid_path) {
        let pid = read_pid(pid_path)?;
        let my_pid = std::process::id();
        if pid == my_pid {
            tracing::info!("Stopped via launchd");
            return Ok(());
        }
        tracing::info!("Stopping inlayer daemon (PID {})...", pid);

        // Send SIGTERM via kill command (safe wrapper)
        let _ = Command::new("kill")
            .args([&pid.to_string()])
            .status();

        for _ in 0..10 {
            if !is_running(pid_path) {
                let _ = fs::remove_file(pid_path);
                tracing::info!("Stopped");
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(500));
        }

        // Force kill if still running
        let _ = Command::new("kill")
            .args(["-9", &pid.to_string()])
            .status();
        let _ = fs::remove_file(pid_path);
        tracing::warn!("Force killed");
    } else {
        let _ = fs::remove_file(pid_path);
        tracing::info!("Stopped (was not running)");
    }
    Ok(())
}

/// Check and print the daemon status.
pub(crate) fn check_status(pid_path: &Path, log_path: &Path) -> Result<()> {
    if is_running(pid_path) {
        let pid = read_pid(pid_path)?;
        tracing::info!("inlayer daemon running (PID {})", pid);
        tracing::info!("   Log: {}", log_path.display());
        tracing::info!("   PID: {}", pid_path.display());
    } else {
        tracing::info!("inlayer daemon not running");
        if pid_path.exists() {
            tracing::warn!("   (stale PID file, cleaning up)");
            let _ = fs::remove_file(pid_path);
        }
    }
    Ok(())
}

/// Tail the daemon log file.
pub(crate) fn tail_log(log_path: &Path) -> Result<()> {
    if !log_path.exists() {
        tracing::warn!("No log file at {}", log_path.display());
        return Ok(());
    }
    let _ = std::process::Command::new("tail")
        .args(["-20", &log_path.display().to_string()])
        .status()?;
    Ok(())
}

/// Parse the --dashboard flag from args.
pub(crate) fn parse_dashboard_flag(args: &[String]) -> Option<String> {
    for i in 0..args.len() {
        if args[i] == "--dashboard" && i + 1 < args.len() {
            return Some(args[i + 1].clone());
        }
    }
    None
}

/// Get the current time as HH:MM:SS.
pub(crate) fn now() -> String {
    let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
    format!("{:02}:{:02}:{:02}", (secs / 3600) % 24, (secs / 60) % 60, secs % 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── DaemonConfig::validate() ──────────────────────────────────────────

    #[test]
    fn test_validate_rejects_placeholder_account() {
        let cfg = DaemonConfig::default();
        // default has "your-account" in account_id
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("not set up"), "expected placeholder message, got: {}", err);
    }

    #[test]
    fn test_validate_rejects_missing_key_file() {
        let mut cfg = DaemonConfig::default();
        cfg.account_id = "real-account.testnet".to_string();
        cfg.key_path = "/nonexistent/path/key.json".to_string();
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("Key file not found"), "expected key file error, got: {}", err);
    }

    // ── DaemonConfig::rpc_urls() ──────────────────────────────────────────

    #[test]
    fn test_rpc_urls_mainnet() {
        let cfg = DaemonConfig { network: "mainnet".to_string(), ..DaemonConfig::default() };
        let urls = cfg.rpc_urls();
        assert!(urls.contains(&"https://rpc.fastnear.com".to_string()));
        assert!(urls.contains(&"https://near.drpc.org".to_string()));
        assert_eq!(urls.len(), 5);
    }

    #[test]
    fn test_rpc_urls_testnet() {
        let cfg = DaemonConfig { network: "testnet".to_string(), ..DaemonConfig::default() };
        let urls = cfg.rpc_urls();
        assert!(urls.contains(&"https://rpc.testnet.fastnear.com".to_string()));
        assert_eq!(urls.len(), 3);
    }

    #[test]
    fn test_rpc_urls_unknown_network() {
        let cfg = DaemonConfig { network: "mycustomnet".to_string(), ..DaemonConfig::default() };
        let urls = cfg.rpc_urls();
        assert_eq!(urls.len(), 1);
        assert_eq!(urls[0], "https://rpc.mycustomnet.near.org");
    }

    // ── deserialize_yocto ─────────────────────────────────────────────────

    #[test]
    fn test_deserialize_yocto_from_integer() {
        #[derive(Deserialize)]
        struct Wrap { #[serde(deserialize_with = "deserialize_yocto")] val: u128 }
        let toml_str = "val = 42\n";
        let w: Wrap = toml::from_str(toml_str).unwrap();
        assert_eq!(w.val, 42u128);
    }

    #[test]
    fn test_deserialize_yocto_from_string() {
        #[derive(Deserialize)]
        struct Wrap { #[serde(deserialize_with = "deserialize_yocto")] val: u128 }
        let toml_str = "val = \"1000000000000000000000000\"\n";
        let w: Wrap = toml::from_str(toml_str).unwrap();
        assert_eq!(w.val, 1_000_000_000_000_000_000_000_000u128);
    }

    #[test]
    fn test_deserialize_yocto_from_zero() {
        #[derive(Deserialize)]
        struct Wrap { #[serde(deserialize_with = "deserialize_yocto")] val: u128 }
        let toml_str = "val = 0\n";
        let w: Wrap = toml::from_str(toml_str).unwrap();
        assert_eq!(w.val, 0u128);
    }

    #[test]
    fn test_deserialize_yocto_invalid_string() {
        #[derive(Deserialize)]
        struct Wrap { #[serde(deserialize_with = "deserialize_yocto")] val: u128 }
        let toml_str = "val = \"not_a_number\"\n";
        let result = toml::from_str::<Wrap>(toml_str);
        assert!(result.is_err());
    }

    // ── default_worker_stake ──────────────────────────────────────────────

    #[test]
    fn test_default_worker_stake_value() {
        assert_eq!(default_worker_stake(), 100_000_000_000_000_000_000_000u128);
    }

    #[test]
    fn test_config_default_worker_stake() {
        let cfg = DaemonConfig::default();
        assert_eq!(cfg.worker_stake_yocto, default_worker_stake());
    }

    // ── expand_tildes ─────────────────────────────────────────────────────

    #[test]
    fn test_expand_tildes_key_path() {
        let home = dirs::home_dir();
        if home.is_none() { return; } // skip in envs without home
        let home = home.unwrap();
        let mut cfg = DaemonConfig {
            key_path: "~/my-keys/test.json".to_string(),
            search_paths: vec![],
            ..DaemonConfig::default()
        };
        cfg.expand_tildes();
        assert_eq!(cfg.key_path, format!("{}/my-keys/test.json", home.display()));
        assert!(!cfg.key_path.starts_with("~"));
    }

    #[test]
    fn test_expand_tildes_absolute_path_unchanged() {
        let mut cfg = DaemonConfig {
            key_path: "/absolute/path/key.json".to_string(),
            search_paths: vec![],
            ..DaemonConfig::default()
        };
        cfg.expand_tildes();
        assert_eq!(cfg.key_path, "/absolute/path/key.json");
    }

    #[test]
    fn test_expand_tildes_search_paths() {
        let home = dirs::home_dir();
        if home.is_none() { return; }
        let home = home.unwrap();
        let mut cfg = DaemonConfig {
            key_path: "/tmp/key.json".to_string(),
            search_paths: vec!["~/projects/wasm".to_string(), "/opt/wasm".to_string()],
            ..DaemonConfig::default()
        };
        cfg.expand_tildes();
        assert_eq!(cfg.search_paths[0], format!("{}/projects/wasm", home.display()));
        assert_eq!(cfg.search_paths[1], "/opt/wasm"); // no tilde → unchanged
    }

    #[test]
    fn test_expand_tildes_no_tilde_unchanged() {
        let mut cfg = DaemonConfig {
            key_path: "relative/path/key.json".to_string(),
            search_paths: vec!["./local".to_string()],
            ..DaemonConfig::default()
        };
        cfg.expand_tildes();
        assert_eq!(cfg.key_path, "relative/path/key.json");
        assert_eq!(cfg.search_paths[0], "./local");
    }

    // ── parse_dashboard_flag ──────────────────────────────────────────────

    #[test]
    fn test_parse_dashboard_flag_present() {
        let args: Vec<String> = ["inlayer", "--dashboard", "0.0.0.0:8080"]
            .iter().map(|s| s.to_string()).collect();
        assert_eq!(parse_dashboard_flag(&args), Some("0.0.0.0:8080".to_string()));
    }

    #[test]
    fn test_parse_dashboard_flag_absent() {
        let args: Vec<String> = ["inlayer", "--foreground"]
            .iter().map(|s| s.to_string()).collect();
        assert_eq!(parse_dashboard_flag(&args), None);
    }

    #[test]
    fn test_parse_dashboard_flag_no_value() {
        let args: Vec<String> = ["inlayer", "--dashboard"]
            .iter().map(|s| s.to_string()).collect();
        assert_eq!(parse_dashboard_flag(&args), None);
    }

    #[test]
    fn test_parse_dashboard_flag_empty_args() {
        let args: Vec<String> = vec![];
        assert_eq!(parse_dashboard_flag(&args), None);
    }

    // ── now() ─────────────────────────────────────────────────────────────

    #[test]
    fn test_now_returns_nonempty() {
        let t = now();
        assert!(!t.is_empty());
        // Format: HH:MM:SS (8 chars)
        assert_eq!(t.len(), 8);
        assert!(t.contains(':'));
    }

    #[test]
    fn test_now_format_valid() {
        let t = now();
        let parts: Vec<&str> = t.split(':').collect();
        assert_eq!(parts.len(), 3);
        let h: u32 = parts[0].parse().unwrap();
        let m: u32 = parts[1].parse().unwrap();
        let s: u32 = parts[2].parse().unwrap();
        assert!(h < 24);
        assert!(m < 60);
        assert!(s < 60);
    }

    // ── DaemonConfig defaults ─────────────────────────────────────────────

    #[test]
    fn test_default_config_values() {
        let cfg = DaemonConfig::default();
        assert_eq!(cfg.network, "testnet");
        assert_eq!(cfg.poll_interval_secs, 5);
        assert_eq!(cfg.deposit_yocto, 1u128);
        assert_eq!(cfg.execution_mode, "direct");
        assert!(cfg.escrow_contract.is_none());
        assert!(cfg.kv_account.is_none());
        assert_eq!(cfg.max_entries, 100);
        assert_eq!(cfg.max_output_bytes, 1_000_000);
        assert!(!cfg.agent_pays);
    }
}
