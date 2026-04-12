use anyhow::{Context, Result};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Response format for execution output
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub enum ResponseFormat {
    Bytes,
    #[default]
    Text,
    Json,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum CodeSource {
    GitHub {
        repo: String,
        commit: String,
        build_target: String,
    },
    /// Pre-compiled WASM file accessible via URL
    /// Worker downloads from URL, verifies SHA256 hash, then executes without compilation
    WasmUrl {
        url: String,           // URL for downloading (https://, ipfs://, ar://)
        hash: String,          // SHA256 hash for verification (hex encoded)
        build_target: String,
    },
}

impl CodeSource {
    pub fn repo(&self) -> Option<&str> {
        match self {
            CodeSource::GitHub { repo, .. } => Some(repo),
            CodeSource::WasmUrl { .. } => None,
        }
    }

    pub fn commit(&self) -> Option<&str> {
        match self {
            CodeSource::GitHub { commit, .. } => Some(commit),
            CodeSource::WasmUrl { .. } => None,
        }
    }

    pub fn build_target(&self) -> Option<&str> {
        match self {
            CodeSource::GitHub { build_target, .. } => Some(build_target),
            CodeSource::WasmUrl { build_target, .. } => Some(build_target),
        }
    }

    /// Get the hash for WasmUrl sources (used for verification)
    #[allow(dead_code)]
    pub fn hash(&self) -> Option<&str> {
        match self {
            CodeSource::GitHub { .. } => None,
            CodeSource::WasmUrl { hash, .. } => Some(hash),
        }
    }

    /// Get the URL for WasmUrl sources
    #[allow(dead_code)]
    pub fn url(&self) -> Option<&str> {
        match self {
            CodeSource::GitHub { .. } => None,
            CodeSource::WasmUrl { url, .. } => Some(url),
        }
    }

    /// Check if this is a WasmUrl source (pre-compiled, no compilation needed)
    #[allow(dead_code)]
    pub fn is_wasm_url(&self) -> bool {
        matches!(self, CodeSource::WasmUrl { .. })
    }

    /// Normalize repo URL to full https:// format for git clone
    /// Examples:
    /// - "github.com/user/repo" -> "https://github.com/user/repo"
    /// - "https://github.com/user/repo" -> "https://github.com/user/repo" (unchanged)
    /// - "user/repo" -> "https://github.com/user/repo"
    /// - "git@github.com:user/repo.git" -> "https://github.com/user/repo"
    /// - "ssh://git@github.com/user/repo" -> "https://github.com/user/repo"
    pub fn normalize(mut self) -> Self {
        match &mut self {
            CodeSource::GitHub { repo, .. } => {
                // Skip if already has https/http protocol
                if repo.starts_with("https://") || repo.starts_with("http://") {
                    return self;
                }

                // Handle SSH format: git@github.com:user/repo.git
                if repo.starts_with("git@github.com:") {
                    let path = repo.strip_prefix("git@github.com:").unwrap();
                    let path = path.strip_suffix(".git").unwrap_or(path);
                    *repo = format!("https://github.com/{}", path);
                    return self;
                }

                // Handle SSH URL format: ssh://git@github.com/user/repo
                if repo.starts_with("ssh://git@github.com/") {
                    let path = repo.strip_prefix("ssh://git@github.com/").unwrap();
                    let path = path.strip_suffix(".git").unwrap_or(path);
                    *repo = format!("https://github.com/{}", path);
                    return self;
                }

                // Handle ssh:// without git@ prefix
                if repo.starts_with("ssh://") {
                    // Leave as is, will fail later with better error
                    return self;
                }

                // Add https:// prefix
                if repo.starts_with("github.com/") {
                    *repo = format!("https://{}", repo);
                } else if !repo.contains('/') {
                    // Invalid format - leave as is, will fail later with better error
                    return self;
                } else {
                    // Assume it's "user/repo" format
                    *repo = format!("https://github.com/{}", repo);
                }

                self
            }
            CodeSource::WasmUrl { .. } => {
                // WasmUrl already has full URL, no normalization needed
                self
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    pub max_instructions: u64,
    pub max_memory_mb: u32,
    pub max_execution_seconds: u64,
}

/// Execution output - can be bytes, text, or parsed JSON
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExecutionOutput {
    Bytes(Vec<u8>),
    Text(String),
    Json(serde_json::Value),
}

/// Execution result to send back to coordinator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    pub success: bool,
    pub output: Option<ExecutionOutput>,
    pub error: Option<String>,
    pub execution_time_ms: u64,
    pub instructions: u64,
    pub compile_time_ms: Option<u64>, // Compilation time if WASM was compiled in this execution
    pub compilation_note: Option<String>, // e.g., "Cached WASM from 2025-01-10 14:30 UTC"
    /// Refund amount to return to user from attached_usd (stablecoin, minimal token units)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refund_usd: Option<u64>,
}

/// API client for communicating with Coordinator API
#[derive(Clone)]
pub struct ApiClient {
    client: Client,
    base_url: String,
    auth_token: String,
}

impl ApiClient {
    /// Create a new API client
    pub fn new(base_url: String, auth_token: String) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(120)) // 2 minutes default timeout
            .connect_timeout(Duration::from_secs(10)) // Fast fail on connection issues
            .tcp_keepalive(Duration::from_secs(30)) // Detect dead connections
            .pool_idle_timeout(Duration::from_secs(60)) // Don't reuse stale connections
            .build()
            .context("Failed to build HTTP client")?;

        Ok(Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            auth_token,
        })
    }

    /// Add standard auth headers (bearer token)
    fn add_auth_headers(&self, builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        builder.bearer_auth(&self.auth_token)
    }

    /// Download WASM binary from cache
    pub async fn download_wasm(&self, checksum: &str) -> Result<Vec<u8>> {
        let url = format!("{}/wasm/{}", self.base_url, checksum);

        let response = self.add_auth_headers(self.client.get(&url))
            .send()
            .await
            .context("Failed to download WASM")?;

        if response.status() == StatusCode::NOT_FOUND {
            anyhow::bail!("WASM file not found: {}", checksum)
        }

        if !response.status().is_success() {
            anyhow::bail!("Download failed with status: {}", response.status())
        }

        let bytes = response
            .bytes()
            .await
            .context("Failed to read WASM bytes")?
            .to_vec();

        Ok(bytes)
    }

    /// Upload compiled WASM binary to cache
    pub async fn upload_wasm(
        &self,
        checksum: String,
        repo: String,
        commit: String,
        build_target: String,
        bytes: Vec<u8>,
    ) -> Result<()> {
        let url = format!("{}/wasm/upload", self.base_url);

        // Create multipart form with correct field names (matching coordinator's handler)
        let file_part = reqwest::multipart::Part::bytes(bytes.clone())
            .file_name(format!("{}.wasm", checksum))
            .mime_str("application/wasm")
            .context("Failed to create file part")?;

        let form = reqwest::multipart::Form::new()
            .text("checksum", checksum.clone())
            .text("repo_url", repo.clone())         // coordinator expects "repo_url"
            .text("commit_hash", commit.clone())    // coordinator expects "commit_hash"
            .text("build_target", build_target.clone()) // coordinator expects "build_target"
            .part("wasm_file", file_part);          // coordinator expects "wasm_file"

        tracing::info!(
            "Uploading WASM: checksum={} size={} bytes repo={} commit={} target={}",
            checksum, bytes.len(), repo, commit, build_target
        );

        let response = self.add_auth_headers(self.client.post(&url))
            .multipart(form)
            .send()
            .await
            .context("Failed to upload WASM")?;

        if !response.status().is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            anyhow::bail!("Upload failed: {}", error_text)
        }

        Ok(())
    }

    /// Check if WASM file exists in cache
    pub async fn wasm_exists(&self, checksum: &str) -> Result<(bool, Option<String>)> {
        let url = format!("{}/wasm/exists/{}", self.base_url, checksum);

        let response = self.add_auth_headers(self.client.get(&url))
            .send()
            .await
            .context("Failed to check WASM existence")?;

        if !response.status().is_success() {
            anyhow::bail!("Check failed with status: {}", response.status())
        }

        #[derive(Deserialize)]
        struct ExistsResponse {
            exists: bool,
            created_at: Option<String>,
        }

        let result = response
            .json::<ExistsResponse>()
            .await
            .context("Failed to parse exists response")?;

        Ok((result.exists, result.created_at))
    }

    /// Acquire a distributed lock
    pub async fn acquire_lock(&self, lock_key: String, worker_id: String, ttl: u64) -> Result<bool> {
        let url = format!("{}/locks/acquire", self.base_url);

        #[derive(Serialize)]
        struct AcquireRequest {
            lock_key: String,
            worker_id: String,
            ttl_seconds: u64,
        }

        let request = AcquireRequest {
            lock_key,
            worker_id,
            ttl_seconds: ttl,
        };

        let response = self.add_auth_headers(self.client.post(&url))
            .json(&request)
            .send()
            .await
            .context("Failed to acquire lock")?;

        if !response.status().is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            anyhow::bail!("Lock acquire failed: {}", error_text)
        }

        #[derive(Deserialize)]
        struct AcquireResponse {
            acquired: bool,
        }

        let result = response
            .json::<AcquireResponse>()
            .await
            .context("Failed to parse lock response")?;

        Ok(result.acquired)
    }

    /// Release a distributed lock
    pub async fn release_lock(&self, lock_key: &str) -> Result<()> {
        let encoded_key = urlencoding::encode(lock_key);
        let url = format!("{}/locks/release/{}", self.base_url, encoded_key);

        let response = self.add_auth_headers(self.client.delete(&url))
            .send()
            .await
            .context("Failed to release lock")?;

        if !response.status().is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            anyhow::bail!("Lock release failed: {}", error_text)
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_client_creation() {
        let client = ApiClient::new(
            "http://localhost:8080".to_string(),
            "test-token".to_string(),
        );
        assert!(client.is_ok());
    }

    #[test]
    fn test_base_url_trimming() {
        let client = ApiClient::new(
            "http://localhost:8080/".to_string(),
            "test-token".to_string(),
        )
        .unwrap();
        assert_eq!(client.base_url, "http://localhost:8080");
    }
}
