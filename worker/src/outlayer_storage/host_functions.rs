//! Storage host functions for WASM components
//!
//! Implements the `near:storage/api` WIT interface.
//! When keystore is unavailable, falls back to local filesystem.
//! When running locally (no coordinator URL), skips remote calls entirely.

use anyhow::Result;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;
use tracing::debug;
use wasmtime::component::Linker;

use super::client::StorageClient;

// Generate bindings from WIT (storage is now separate package near:storage)
wasmtime::component::bindgen!({
    path: "wit",
    world: "near:storage/storage-host",
});

/// Host state for storage functions
pub struct StorageHostState {
    client: StorageClient,
    /// Local filesystem fallback
    local_dir: PathBuf,
    local_cache: Mutex<HashMap<String, Vec<u8>>>,
}

impl StorageHostState {
    /// Create new storage host state from existing client
    pub fn from_client(client: StorageClient) -> Self {
        let local_dir = std::env::var("STORAGE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/tmp/outlayer-storage"));
        fs::create_dir_all(&local_dir).ok();
        Self { client, local_dir, local_cache: Mutex::new(HashMap::new()) }
    }

    /// Create local-only storage (no remote coordinator — for inlayer/testing)
    pub fn local_only() -> Result<Self> {
        let local_dir = std::env::var("STORAGE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("./storage"));
        fs::create_dir_all(&local_dir).ok();
        // Create with empty URL — is_local() returns true, all remote calls skipped
        let client = StorageClient::new_local()?;
        Ok(Self { client, local_dir, local_cache: Mutex::new(HashMap::new()) })
    }

    fn safe_key(&self, key: &str) -> PathBuf {
        let hex: String = key.bytes().map(|b| format!("{:02x}", b)).collect();
        self.local_dir.join(hex)
    }

    fn local_set(&mut self, key: &str, value: &[u8]) -> String {
        let path = self.safe_key(key);
        match fs::write(&path, value) {
            Ok(()) => { self.local_cache.lock().unwrap().insert(key.to_string(), value.to_vec()); String::new() }
            Err(e) => { e.to_string() }
        }
    }

    fn local_get(&mut self, key: &str) -> (Vec<u8>, String) {
        if let Some(cached) = self.local_cache.lock().unwrap().get(key).cloned() {
            return (cached, String::new());
        }
        let path = self.safe_key(key);
        match fs::read(&path) {
            Ok(data) => { self.local_cache.lock().unwrap().insert(key.to_string(), data.clone()); (data, String::new()) }
            Err(_) => (Vec::new(), String::new()),
        }
    }

    fn local_has(&mut self, key: &str) -> bool {
        if self.local_cache.lock().unwrap().contains_key(key) { return true; }
        self.safe_key(key).exists()
    }

    fn local_delete(&mut self, key: &str) -> bool {
        self.local_cache.lock().unwrap().remove(key);
        let path = self.safe_key(key);
        path.exists() && fs::remove_file(path).is_ok()
    }
}

impl near::storage::api::Host for StorageHostState {
    fn set(&mut self, key: String, value: Vec<u8>) -> String {
        debug!("storage::set key={}, value_len={}", key, value.len());
        let local_err = self.local_set(&key, &value);
        if local_err.is_empty() && !self.client.is_local() {
            let client = self.client.clone();
            let _ = std::thread::spawn(move || { let _ = client.set(&key, &value); });
        }
        local_err
    }

    fn get(&mut self, key: String) -> (Vec<u8>, String) {
        debug!("storage::get key={}", key);
        let (data, err) = self.local_get(&key);
        if !data.is_empty() || self.client.is_local() { return (data, err); }
        let client = self.client.clone();
        let key_c = key.clone();
        match std::thread::spawn(move || client.get(&key_c)).join() {
            Ok(Ok(Some(value))) => { self.local_set(&key, &value); (value, String::new()) }
            _ => (Vec::new(), String::new()),
        }
    }

    fn has(&mut self, key: String) -> bool {
        debug!("storage::has key={}", key);
        if self.local_has(&key) { return true; }
        if self.client.is_local() { return false; }
        let client = self.client.clone();
        let key_c = key.clone();
        std::thread::spawn(move || client.has(&key_c).unwrap_or(false))
            .join().unwrap_or(false)
    }

    fn delete(&mut self, key: String) -> bool {
        debug!("storage::delete key={}", key);
        let deleted = self.local_delete(&key);
        if self.client.is_local() { return deleted; }
        let client = self.client.clone();
        let key_c = key.clone();
        std::thread::spawn(move || client.delete(&key_c).unwrap_or(false))
            .join().unwrap_or(deleted)
    }

    fn list_keys(&mut self, prefix: String) -> (String, String) {
        debug!("storage::list_keys prefix={}", prefix);
        if self.client.is_local() {
            let keys: Vec<String> = fs::read_dir(&self.local_dir)
                .ok()
                .map(|entries| {
                    entries.filter_map(|e| e.ok())
                        .filter_map(|e| {
                            let hex_str = e.file_name().to_string_lossy().to_string();
                            // Decode hex filename back to original key string
                            let key = (0..hex_str.len())
                                .step_by(2)
                                .filter_map(|i| {
                                    u8::from_str_radix(&hex_str[i..i+2.min(hex_str.len()-i)], 16).ok()
                                })
                                .map(|b| b as char)
                                .collect::<String>();
                            if key.starts_with(&prefix) { Some(format!("\"{}\"", key)) } else { None }
                        })
                        .collect()
                })
                .unwrap_or_default();
            return (format!("[{}]", keys.join(",")), String::new());
        }
        let client = self.client.clone();
        let prefix_c = prefix.clone();
        std::thread::spawn(move || client.list_keys(&prefix_c).unwrap_or_else(|_| "[]".into()))
            .join().map(|v| (v, String::new())).unwrap_or(("[]".into(), String::new()))
    }

    fn set_worker(&mut self, key: String, value: Vec<u8>, is_encrypted: Option<bool>) -> String {
        debug!("storage::set_worker key={}, value_len={}", key, value.len());
        let err = self.local_set(&key, &value);
        if err.is_empty() && !self.client.is_local() {
            let client = self.client.clone();
            let _ = std::thread::spawn(move || { let _ = client.set_worker(&key, &value, is_encrypted.unwrap_or(true)); });
        }
        err
    }

    fn get_worker(&mut self, key: String, project: Option<String>) -> (Vec<u8>, String) {
        debug!("storage::get_worker key={}", key);
        let (data, err) = self.local_get(&key);
        if !data.is_empty() || self.client.is_local() { return (data, err); }
        let client = self.client.clone();
        let key_c = key.clone();
        match std::thread::spawn(move || client.get_worker(&key_c, project.as_deref())).join() {
            Ok(Ok(Some(value))) => { self.local_set(&key, &value); (value, String::new()) }
            _ => (Vec::new(), String::new()),
        }
    }

    fn get_by_version(&mut self, key: String, wasm_hash: String) -> (Vec<u8>, String) {
        debug!("storage::get_by_version key={}", key);
        let (data, err) = self.local_get(&key);
        if !data.is_empty() || self.client.is_local() { return (data, err); }
        let client = self.client.clone();
        let key_c = key.clone();
        match std::thread::spawn(move || client.get_by_version(&key_c, &wasm_hash)).join() {
            Ok(Ok(Some(value))) => (value, String::new()),
            _ => (Vec::new(), String::new()),
        }
    }

    fn clear_all(&mut self) -> String {
        debug!("storage::clear_all");
        let _ = fs::remove_dir_all(&self.local_dir);
        fs::create_dir_all(&self.local_dir).ok();
        self.local_cache.lock().unwrap().clear();
        if !self.client.is_local() {
            let client = self.client.clone();
            let _ = std::thread::spawn(move || { let _ = client.clear_all(); });
        }
        String::new()
    }

    fn clear_version(&mut self, wasm_hash: String) -> String {
        debug!("storage::clear_version wasm_hash={}", wasm_hash);
        if self.client.is_local() { return String::new(); }
        let client = self.client.clone();
        std::thread::spawn(move || client.clear_version(&wasm_hash).err().map(|e| e.to_string()).unwrap_or_default())
            .join().unwrap_or_default()
    }

    fn set_if_absent(&mut self, key: String, value: Vec<u8>) -> (bool, String) {
        debug!("storage::set_if_absent key={}", key);
        if self.local_has(&key) { return (false, String::new()); }
        let err = self.local_set(&key, &value);
        (err.is_empty(), err)
    }

    fn set_if_equals(&mut self, key: String, expected: Vec<u8>, new_value: Vec<u8>) -> (bool, Vec<u8>, String) {
        debug!("storage::set_if_equals key={}", key);
        let (current, _) = self.local_get(&key);
        if current == expected {
            let err = self.local_set(&key, &new_value);
            (err.is_empty(), Vec::new(), err)
        } else {
            (false, current, String::new())
        }
    }

    fn increment(&mut self, key: String, delta: i64) -> (i64, String) {
        debug!("storage::increment key={}, delta={}", key, delta);
        let (current, _) = self.local_get(&key);
        let val = if current.is_empty() { delta } else { i64::from_le_bytes(current[..8].try_into().unwrap_or([0;8])) + delta };
        let err = self.local_set(&key, &val.to_le_bytes());
        (val, err)
    }

    fn decrement(&mut self, key: String, delta: i64) -> (i64, String) {
        debug!("storage::decrement key={}, delta={}", key, delta);
        self.increment(key, -delta)
    }
}

/// Add storage host functions to a wasmtime component linker
pub fn add_storage_to_linker<T: Send + 'static>(
    linker: &mut Linker<T>,
    get_state: impl Fn(&mut T) -> &mut StorageHostState + Send + Sync + Copy + 'static,
) -> Result<()> {
    near::storage::api::add_to_linker(linker, get_state)
}
