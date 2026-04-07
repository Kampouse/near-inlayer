//! Client configuration for remote worker execution
//!
//! Loads from ~/.inlayer/config.toml or uses CLI flags

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::env;

/// Client configuration loaded from config file or CLI
#[derive(Debug, Clone, Deserialize)]
pub struct ClientConfig {
    /// Worker URL (e.g., https://worker.example.com)
    pub worker_url: Option<String>,
    /// NEAR account ID for payments
    pub account_id: Option<String>,
    /// Payment limits
    #[serde(default)]
    pub payment: PaymentConfig,
}

/// Payment configuration
#[derive(Debug, Clone, Deserialize, Default)]
pub struct PaymentConfig {
    /// Maximum payment per request (NEAR amount as string, e.g., "0.01")
    #[serde(default = "default_max_per_request")]
    pub max_per_request: String,
    /// Maximum payment per day (NEAR amount as string, e.g., "1.0")
    #[serde(default = "default_max_per_day")]
    pub max_per_day: String,
}

fn default_max_per_request() -> String { "0.01".to_string() }
fn default_max_per_day() -> String { "1.0".to_string() }

impl ClientConfig {
    /// Load configuration from file, falling back to defaults
    pub fn load() -> Self {
        // Check for custom config path from env
        let config_path = env::var("OUTLAYER_CONFIG")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                dirs::home_dir()
                    .map(|h| h.join(".inlayer").join("config.toml"))
                    .unwrap_or_else(|| PathBuf::from(".inlayer/config.toml"))
            });

        if config_path.exists() {
            match std::fs::read_to_string(&config_path) {
                Ok(contents) => {
                    match toml::from_str(&contents) {
                        Ok(cfg) => {
                            eprintln!("📋 Loaded config from {}", config_path.display());
                            return cfg;
                        }
                        Err(e) => {
                            eprintln!("⚠️  Failed to parse {}: {}", config_path.display(), e);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("⚠️  Failed to read {}: {}", config_path.display(), e);
                }
            }
        }

        Self::default()
    }

    /// Get worker URL from config, env, or argument
    pub fn get_worker_url(&self, arg: Option<&str>) -> Result<String> {
        if let Some(url) = arg {
            return Ok(url.to_string());
        }
        if let Some(url) = env::var("OUTLAYER_WORKER_URL").ok() {
            return Ok(url);
        }
        if let Some(ref url) = self.worker_url {
            return Ok(url.clone());
        }
        anyhow::bail!("Worker URL required. Use --worker, set OUTLAYER_WORKER_URL, or add worker_url to ~/.inlayer/config.toml");
    }

    /// Get account ID from config, env, or argument
    pub fn get_account_id(&self, arg: Option<&str>) -> Result<String> {
        if let Some(id) = arg {
            return Ok(id.to_string());
        }
        if let Some(id) = env::var("OUTLAYER_ACCOUNT_ID").ok() {
            return Ok(id);
        }
        if let Some(ref id) = self.account_id {
            return Ok(id.clone());
        }
        anyhow::bail!("Account ID required for payment. Use --account, set OUTLAYER_ACCOUNT_ID, or add account_id to ~/.inlayer/config.toml");
    }

    /// Parse max_per_request as yoctoNEAR
    pub fn max_per_request_yocto(&self) -> Result<u128> {
        let near: f64 = self.payment.max_per_request.parse()
            .context("Invalid max_per_request value")?;
        Ok((near * 1e24) as u128)
    }

    /// Parse max_per_day as yoctoNEAR
    pub fn max_per_day_yocto(&self) -> Result<u128> {
        let near: f64 = self.payment.max_per_day.parse()
            .context("Invalid max_per_day value")?;
        Ok((near * 1e24) as u128)
    }
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            worker_url: None,
            account_id: None,
            payment: PaymentConfig::default(),
        }
    }
}

/// Payment challenge returned by worker on 402
#[derive(Debug, Clone, Deserialize)]
pub struct PaymentChallenge {
    /// Amount to pay (as string, could be NEAR or token amount)
    pub amount: String,
    /// Recipient account ID
    pub recipient: String,
    /// Challenge ID for tracking
    pub challenge_id: String,
    /// HMAC for verification
    pub hmac: Option<String>,
    /// Token contract (if FT, otherwise NEAR)
    pub token: Option<String>,
    /// Payment methods accepted
    pub methods: Option<Vec<String>>,
    /// Description
    #[serde(default)]
    pub description: Option<String>,
    /// Version
    #[serde(default)]
    pub version: Option<String>,
}

/// 402 response wrapper
#[derive(Debug, Clone, Deserialize)]
pub struct PaymentRequiredResponse {
    /// Nested challenge object
    pub challenge: PaymentChallenge,
    /// Error type
    pub error: Option<String>,
    /// Instructions
    #[serde(default)]
    pub instructions: Option<String>,
    /// WWW-Authenticate header value
    #[serde(rename = "www_authenticate", default)]
    pub www_authenticate: Option<String>,
}

/// Payment receipt to send back to worker
#[derive(Debug, Clone, Serialize)]
pub struct PaymentReceipt {
    /// Transaction hash of the payment
    pub tx_hash: String,
    /// Account that made the payment
    pub signer_account: String,
    /// Challenge ID being paid
    pub challenge_id: String,
}

/// Execute request body
#[derive(Debug, Clone, Serialize)]
pub struct ExecuteRequest {
    /// Input data (plain text or JSON string)
    pub input: String,
    /// Optional WASM URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wasm_url: Option<String>,
    /// Optional program name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub program: Option<String>,
    /// Max instructions
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_instructions: Option<u64>,
    /// Max memory in MB
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_memory_mb: Option<u32>,
}

/// Execute response (success)
#[derive(Debug, Clone, Deserialize)]
pub struct ExecuteResponse {
    /// Success flag
    pub success: bool,
    /// Output data
    pub output: Option<serde_json::Value>,
    /// Error message
    pub error: Option<String>,
    /// Execution time in ms
    pub execution_time_ms: Option<u64>,
    /// Instructions executed
    pub instructions: Option<u64>,
}
