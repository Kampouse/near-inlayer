//! Circuit-breaker RPC pool that tries endpoints in order of fewest failures.

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use anyhow::{bail, Result};
use base64::Engine;

use super::{RequestInfo, parse_source};

/// Single RPC endpoint with failure tracking.
pub(crate) struct RpcEndpoint {
    pub(crate) url: String,
    pub(crate) fails: AtomicU32,
}

/// Multi-endpoint RPC client with circuit-breaker behavior.
/// Endpoints are tried in ascending order of failure count, so healthy RPCs
/// are preferred. On success the failure counter is decremented; on error or
/// rate-limit it is incremented.
pub(crate) struct Rpc {
    endpoints: Vec<RpcEndpoint>,
    client: reqwest::blocking::Client,
}

impl Rpc {
    pub(crate) fn new(url: &str) -> Result<Self> {
        Ok(Self::from_urls(vec![url.to_string()]))
    }

    pub(crate) fn from_urls(urls: Vec<String>) -> Self {
        Self {
            endpoints: urls.into_iter().map(|u| RpcEndpoint { url: u, fails: AtomicU32::new(0) }).collect(),
            client: reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("failed to build HTTP client"),
        }
    }

    pub(crate) fn call(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
        let mut indices: Vec<usize> = (0..self.endpoints.len()).collect();
        indices.sort_by_key(|i| self.endpoints[*i].fails.load(Ordering::Relaxed));

        let mut last_err = String::new();
        for i in indices {
            let ep = &self.endpoints[i];
            let resp = self.client.post(&ep.url)
                .json(&serde_json::json!({"jsonrpc":"2.0","id":"1","method":method,"params":params}))
                .send();
            match resp {
                Ok(r) => {
                    if let Ok(v) = r.json::<serde_json::Value>() {
                        if let Some(err) = v.get("error") {
                            let msg = err.to_string();
                            ep.fails.fetch_add(1, Ordering::Relaxed);
                            if msg.contains("rate limit") || msg.contains("exceeded") || msg.contains("Too many") {
                                tracing::warn!("   ⚠️ {} rate limited, trying next", ep.url);
                            }
                            last_err = msg;
                            continue;
                        }
                        ep.fails.fetch_sub(ep.fails.load(Ordering::Relaxed).min(1), Ordering::Relaxed);
                        return Ok(v["result"].clone());
                    }
                }
                Err(e) => {
                    ep.fails.fetch_add(1, Ordering::Relaxed);
                    last_err = e.to_string();
                }
            }
        }
        bail!("all RPCs failed: {}", last_err)
    }

    pub(crate) fn view(&self, contract: &str, method: &str, args: &[u8]) -> Result<Vec<u8>> {
        let args_b64 = base64::engine::general_purpose::STANDARD.encode(args);
        let result = self.call("query", serde_json::json!({
            "request_type": "call_function",
            "finality": "final",
            "account_id": contract,
            "method_name": method,
            "args_base64": args_b64
        }))?;
        let bytes: Vec<u8> = serde_json::from_value(result["result"].clone()).unwrap_or_default();
        Ok(bytes)
    }

    pub(crate) fn fetch_request_infos(&self, contract: &str, ids: &[u64]) -> Vec<(u64, Result<RequestInfo>)> {
        ids.iter().map(|&req_id| {
            let result = self.view(contract, "get_request", serde_json::json!({"request_id": req_id}).to_string().as_bytes())
                .and_then(|bytes| {
                    if bytes.is_empty() { bail!("request {} not found", req_id); }
                    let req: serde_json::Value = serde_json::from_slice(&bytes)?;
                    let input_raw = req.get("input_data").and_then(|v| v.as_str()).unwrap_or("");
                    let input_str = if input_raw.is_empty() {
                        String::new()
                    } else {
                        match base64::engine::general_purpose::STANDARD.decode(input_raw) {
                            Ok(decoded) if !decoded.is_empty() => String::from_utf8_lossy(&decoded).to_string(),
                            _ => input_raw.to_string(),
                        }
                    };
                    let limits = req.get("resource_limits");
                    let source = parse_source(&req);
                    Ok(RequestInfo {
                        input: input_str,
                        max_instructions: limits.and_then(|l| l.get("max_instructions")).and_then(|v| v.as_u64()).unwrap_or(10_000_000_000),
                        max_memory_mb: limits.and_then(|l| l.get("max_memory_mb")).and_then(|v| v.as_u64()).unwrap_or(256) as u32,
                        max_execution_seconds: limits.and_then(|l| l.get("max_execution_seconds")).and_then(|v| v.as_u64()).unwrap_or(60),
                        source,
                    })
                });
            (req_id, result)
        }).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rpc_new_single_url() {
        let rpc = Rpc::new("https://rpc.testnet.near.org").unwrap();
        assert_eq!(rpc.endpoints.len(), 1);
        assert_eq!(rpc.endpoints[0].url, "https://rpc.testnet.near.org");
        assert_eq!(rpc.endpoints[0].fails.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_rpc_from_urls_multiple() {
        let urls = vec![
            "https://rpc.fastnear.com".to_string(),
            "https://near.drpc.org".to_string(),
            "https://near.lava.build".to_string(),
        ];
        let rpc = Rpc::from_urls(urls.clone());
        assert_eq!(rpc.endpoints.len(), 3);
        for (i, url) in urls.iter().enumerate() {
            assert_eq!(rpc.endpoints[i].url, *url);
            assert_eq!(rpc.endpoints[i].fails.load(Ordering::Relaxed), 0);
        }
    }

    #[test]
    fn test_rpc_from_urls_empty() {
        let rpc = Rpc::from_urls(vec![]);
        assert_eq!(rpc.endpoints.len(), 0);
    }

    #[test]
    fn test_rpc_from_urls_single() {
        let rpc = Rpc::from_urls(vec!["https://example.com/rpc".to_string()]);
        assert_eq!(rpc.endpoints.len(), 1);
        assert_eq!(rpc.endpoints[0].url, "https://example.com/rpc");
    }

    #[test]
    fn test_rpc_new_delegates_to_from_urls() {
        let rpc = Rpc::new("https://rpc.example.com").unwrap();
        // new() should produce the same result as from_urls with a single URL
        let rpc2 = Rpc::from_urls(vec!["https://rpc.example.com".to_string()]);
        assert_eq!(rpc.endpoints.len(), rpc2.endpoints.len());
        assert_eq!(rpc.endpoints[0].url, rpc2.endpoints[0].url);
    }

    #[test]
    fn test_endpoint_failure_tracking_independent() {
        let rpc = Rpc::from_urls(vec![
            "https://a.com".to_string(),
            "https://b.com".to_string(),
        ]);
        rpc.endpoints[0].fails.fetch_add(3, Ordering::Relaxed);
        assert_eq!(rpc.endpoints[0].fails.load(Ordering::Relaxed), 3);
        assert_eq!(rpc.endpoints[1].fails.load(Ordering::Relaxed), 0);
    }
}
