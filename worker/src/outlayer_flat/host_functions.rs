//! Outlayer host function implementations for P2 WASI components.
//!
//! Uses `wasmtime::component::bindgen!` to generate typed bindings from the
//! outlayer:api/host WIT interface. All memory lifting/lowering is handled
//! automatically by wasmtime's canonical ABI.

use anyhow::Result;
use base64::Engine;
use std::path::PathBuf;
use tracing::debug;
use wasmtime::component::Linker;

// Generate typed bindings from WIT
wasmtime::component::bindgen!({
    path: "wit-outlayer",
    world: "outlayer-world",
});

/// Host state for outlayer functions
pub struct OutlayerHostState {
    storage_dir: PathBuf,
    /// RPC URL for view calls (from env var RPC_URL)
    rpc_url: Option<String>,
}

impl OutlayerHostState {
    pub fn new() -> Self {
        let storage_dir = std::env::var("STORAGE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("./storage"));
        std::fs::create_dir_all(&storage_dir).ok();
        let rpc_url = std::env::var("RPC_URL").ok();
        Self { storage_dir, rpc_url }
    }

    fn safe_path(&self, key: &str) -> PathBuf {
        let hex: String = key.bytes().map(|b| format!("{:02x}", b)).collect();
        self.storage_dir.join(hex)
    }
}

// Implement the generated Host trait — all params are typed Rust values
impl outlayer::api::host::Host for OutlayerHostState {
    fn view(&mut self, contract_id: String, method_name: String, args_json: String) -> Result<String, String> {
        debug!("outlayer::view contract={} method={}", contract_id, method_name);
        // Wire to RPC URL if available
        let rpc_url = self.rpc_url.clone();
        if let Some(rpc_url) = rpc_url {
            // Use thread scope to avoid blocking in async context
            std::thread::scope(|s| {
                s.spawn(move || {
                    // Use blocking HTTP client inside thread scope
                    let client = reqwest::blocking::Client::builder()
                        .timeout(std::time::Duration::from_secs(30))
                        .build()
                        .map_err(|e| e.to_string())?;
                    let args_base64 = base64::engine::general_purpose::STANDARD.encode(args_json.as_bytes());
                    let request = serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": "outlayer",
                        "method": "query",
                        "params": {
                            "request_type": "call_function",
                            "account_id": contract_id,
                            "method_name": method_name,
                            "args_base64": args_base64,
                            "finality": "final"
                        }
                    });
                    let response = client
                        .post(&rpc_url)
                        .header("Content-Type", "application/json")
                        .json(&request)
                        .send()
                        .map_err(|e| e.to_string())?;
                    let result: serde_json::Value = response.json().map_err(|e| e.to_string())?;
                    // Extract result array and decode to string
                    if let Some(result_obj) = result.get("result") {
                        if let Some(result_array) = result_obj.get("result") {
                            if let Some(arr) = result_array.as_array() {
                                let bytes: Vec<u8> = arr
                                    .iter()
                                    .filter_map(|v| v.as_u64().map(|n| n as u8))
                                    .collect();
                                return Ok(String::from_utf8_lossy(&bytes).to_string());
                            }
                        }
                    }
                    // Return raw result if can't decode
                    Ok(serde_json::to_string(&result).unwrap_or_default())
                })
                .join()
                .map_err(|_| "thread panicked".to_string())?
            })
        } else {
            Err("RPC not available".into())
        }
    }

    fn call(&mut self, _signer_key: String, receiver_id: String, method_name: String, _args_json: String, _deposit_yocto: String, _gas: String) -> Result<String, String> {
        debug!("outlayer::call receiver={} method={}", receiver_id, method_name);
        Err("RPC not available".into())
    }

    fn transfer(&mut self, _signer_key: String, receiver_id: String, _amount_yocto: String) -> Result<String, String> {
        debug!("outlayer::transfer receiver={}", receiver_id);
        Err("RPC not available".into())
    }

    fn http_get(&mut self, url: String) -> Result<Vec<u8>, String> {
        debug!("outlayer::http-get url={}", url);
        std::thread::scope(|s| {
            s.spawn(|| {
                let resp = reqwest::blocking::Client::builder()
                    .timeout(std::time::Duration::from_secs(10))
                    .build()
                    .map_err(|e| e.to_string())?
                    .get(&url)
                    .send()
                    .map_err(|e| e.to_string())?
                    .bytes()
                    .map_err(|e| e.to_string())?;
                let data = resp.to_vec();
                // Print response as UTF-8 if valid, for debugging
                if let Ok(s) = std::str::from_utf8(&data) {
                    eprintln!("[http-get response] {}", s);
                } else {
                    eprintln!("[http-get response] {} bytes", data.len());
                }
                Ok(data)
            })
            .join()
            .map_err(|_| "thread panicked".to_string())?
        })
    }

    fn http_post(&mut self, url: String, body: Vec<u8>, content_type: String) -> Result<Vec<u8>, String> {
        debug!("outlayer::http-post url={} content_type={}", url, content_type);
        std::thread::scope(|s| {
            s.spawn(move || {
                let mut req = reqwest::blocking::Client::builder()
                    .timeout(std::time::Duration::from_secs(30))
                    .build()
                    .map_err(|e| e.to_string())?
                    .post(&url)
                    .header("Content-Type", &content_type);
                // Auto-inject auth headers from environment
                if url.contains("api.z.ai") || url.contains("openai.com") || url.contains("anthropic.com") {
                    if let Ok(key) = std::env::var("GLM_API_KEY") {
                        req = req.header("Authorization", format!("Bearer {}", key));
                    }
                }
                let resp = req.body(body).send().map_err(|e| e.to_string())?;
                let status = resp.status();
                let bytes = resp.bytes().map_err(|e| e.to_string())?;
                debug!("outlayer::http-post response status={} len={}", status, bytes.len());
                Ok(bytes.to_vec())
            })
            .join()
            .map_err(|_| "thread panicked".to_string())?
        })
    }

    fn storage_set(&mut self, key: String, value: Vec<u8>) -> Result<(), String> {
        debug!("outlayer::storage-set key={} len={}", key, value.len());
        let path = self.safe_path(&key);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        std::fs::write(&path, &value).map_err(|e| e.to_string())
    }

    fn storage_get(&mut self, key: String) -> Result<Option<Vec<u8>>, String> {
        debug!("outlayer::storage-get key={}", key);
        let path = self.safe_path(&key);
        if path.exists() {
            Ok(Some(std::fs::read(&path).map_err(|e| e.to_string())?))
        } else {
            Ok(None)
        }
    }

    fn storage_has(&mut self, key: String) -> Result<bool, String> {
        Ok(self.safe_path(&key).exists())
    }

    fn storage_delete(&mut self, key: String) -> Result<(), String> {
        let path = self.safe_path(&key);
        if path.exists() {
            std::fs::remove_file(&path).map_err(|e| e.to_string())
        } else {
            Ok(())
        }
    }

    fn storage_increment(&mut self, key: String, delta: i64) -> Result<i64, String> {
        let path = self.safe_path(&key);
        let current = if path.exists() {
            let data = std::fs::read(&path).map_err(|e| e.to_string())?;
            i64::from_le_bytes(data[..8].try_into().unwrap_or([0; 8]))
        } else {
            0
        };
        let new_val = current + delta;
        std::fs::write(&path, new_val.to_le_bytes()).map_err(|e| e.to_string())?;
        Ok(new_val)
    }

    fn storage_decrement(&mut self, key: String, delta: i64) -> Result<i64, String> {
        self.storage_increment(key, -delta)
    }

    fn storage_set_if_absent(&mut self, key: String, value: Vec<u8>) -> Result<bool, String> {
        let path = self.safe_path(&key);
        if path.exists() {
            return Ok(false);
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        std::fs::write(&path, &value).map_err(|e| e.to_string())?;
        Ok(true)
    }

    fn storage_set_if_equals(&mut self, key: String, expected: Vec<u8>, new_value: Vec<u8>) -> Result<bool, String> {
        let path = self.safe_path(&key);
        if path.exists() {
            let current = std::fs::read(&path).map_err(|e| e.to_string())?;
            if current == expected {
                std::fs::write(&path, &new_value).map_err(|e| e.to_string())?;
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn storage_list_keys(&mut self, prefix: String) -> Result<Vec<String>, String> {
        let dir = &self.storage_dir;
        if !dir.exists() {
            return Ok(vec![]);
        }
        let keys: Vec<String> = std::fs::read_dir(dir)
            .map_err(|e| e.to_string())?
            .filter_map(|e| e.ok())
            .filter_map(|e| {
                let hex_str = e.file_name().to_string_lossy().to_string();
                let key: String = (0..hex_str.len())
                    .step_by(2)
                    .filter_map(|i| {
                        u8::from_str_radix(&hex_str[i..i + 2.min(hex_str.len() - i)], 16).ok()
                    })
                    .map(|b| b as char)
                    .collect();
                if key.starts_with(&prefix) {
                    Some(key)
                } else {
                    None
                }
            })
            .collect();
        Ok(keys)
    }

    fn storage_clear_all(&mut self) -> Result<(), String> {
        let dir = &self.storage_dir;
        let _ = std::fs::remove_dir_all(dir);
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())
    }

    fn storage_set_worker(&mut self, key: String, value: Vec<u8>) -> Result<(), String> {
        // For now, same as storage_set
        self.storage_set(key, value)
    }

    fn storage_get_worker(&mut self, key: String) -> Result<Option<Vec<u8>>, String> {
        self.storage_get(key)
    }

    fn storage_set_worker_public(&mut self, key: String, value: Vec<u8>) -> Result<(), String> {
        self.storage_set(key, value)
    }

    fn storage_get_worker_from_project(&mut self, key: String, _project: String) -> Result<Option<Vec<u8>>, String> {
        self.storage_get(key)
    }

    fn env_signer(&mut self) -> String {
        std::env::var("OUTLAYER_SIGNER").unwrap_or_default()
    }

    fn env_predecessor(&mut self) -> String {
        std::env::var("OUTLAYER_PREDECESSOR").unwrap_or_default()
    }

    fn env_get(&mut self, key: String) -> Option<String> {
        let result = std::env::var(&key).ok();
        debug!("[env-get] {} = {:?}", key, result);
        result
    }

    fn sleep_ms(&mut self, ms: u32) -> Result<(), String> {
        debug!("[sleep-ms] {}", ms);
        std::thread::sleep(std::time::Duration::from_millis(ms as u64));
        Ok(())
    }

    fn send_telegram(&mut self, chat_id: String, text: String) -> Result<String, String> {
        eprintln!("[send-telegram] CALLED! chat={} text={}", chat_id, text);
        let token = std::env::var("TELEGRAM_BOT_TOKEN")
            .map_err(|e| { eprintln!("[send-telegram] TOKEN ERROR: {}", e); "TELEGRAM_BOT_TOKEN not set".to_string() })?;
        let url = format!("https://api.telegram.org/bot{}/sendMessage", token);
        let body = serde_json::json!({"chat_id": chat_id, "text": &text});
        eprintln!("[send-telegram] POST {}", url);
        std::thread::scope(|s| {
            s.spawn(move || {
                let resp = reqwest::blocking::Client::builder()
                    .timeout(std::time::Duration::from_secs(10))
                    .build()
                    .map_err(|e| { eprintln!("[send-telegram] CLIENT BUILD ERROR: {}", e); e.to_string() })?
                    .post(&url)
                    .header("Content-Type", "application/json")
                    .json(&body)
                    .send()
                    .map_err(|e| { eprintln!("[send-telegram] HTTP ERROR: {}", e); e.to_string() })?;
                let status = resp.status();
                eprintln!("[send-telegram] HTTP STATUS: {}", status);
                let result: serde_json::Value = resp.json().map_err(|e| { eprintln!("[send-telegram] JSON PARSE ERROR: {}", e); e.to_string() })?;
                eprintln!("[send-telegram] RESPONSE: {}", result);
                if status.is_success() {
                    Ok(result.to_string())
                } else {
                    Err(format!("Telegram API error {}: {}", status, result))
                }
            })
            .join()
            .map_err(|e| { eprintln!("[send-telegram] THREAD PANIC: {:?}", e); "thread panicked".to_string() })?
        })
    }
}

/// Add outlayer host functions to a wasmtime component linker
pub fn add_outlayer_to_linker<T: Send + 'static>(
    linker: &mut Linker<T>,
    get_state: impl Fn(&mut T) -> &mut OutlayerHostState + Send + Sync + Copy + 'static,
) -> Result<()> {
    outlayer::api::host::add_to_linker(linker, get_state)
}