use near_sdk::borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::collections::LookupMap;
use near_sdk::json_types::U128;
use near_sdk::serde_json;
use near_sdk::{
    env, log, near, near_bindgen, AccountId, BorshStorageKey, Gas, NearToken,
    PanicOnDefault,
};

mod events;
mod execution;
mod views;

pub type Balance = u128;
pub type CryptoHash = [u8; 32];

// Gas constants
pub const MIN_RESPONSE_GAS: Gas = Gas::from_tgas(50);
pub const DATA_ID_REGISTER: u64 = 37;

// Timeout for stale execution cancellation (10 minutes)
pub const EXECUTION_TIMEOUT: u64 = 600 * 1_000_000_000;

// Maximum resource limits (hard caps)
pub const MAX_INSTRUCTIONS: u64 = 500_000_000_000; // 500 billion instructions
pub const MAX_EXECUTION_SECONDS: u64 = 180; // 180 seconds
pub const MAX_COMPILATION_SECONDS: u64 = 300; // 5 minutes max compilation time

// Large payload handling: threshold for including input_data in event log
// Payloads >= this size are stored in state only, worker fetches via get_request()
// NEAR has 16KB limit per log message, so we use 10KB to leave room for other fields
pub const INPUT_DATA_EVENT_THRESHOLD: usize = 10_000; // 10KB

#[derive(BorshSerialize, BorshStorageKey)]
#[borsh(crate = "near_sdk::borsh")]
enum StorageKey {
    PendingRequests,
}

/// Execution source - GitHub repo, pre-compiled WASM URL, or project reference
#[derive(Clone, Debug)]
#[near(serializers = [borsh, json])]
pub enum ExecutionSource {
    /// GitHub repository with source code to compile
    GitHub {
        repo: String,
        commit: String,
        build_target: Option<String>, // e.g., "wasm32-wasip1"
    },
    /// Pre-compiled WASM file accessible via URL
    /// Worker downloads from URL, verifies SHA256 hash, then executes without compilation
    WasmUrl {
        url: String,           // URL for downloading (https://, ipfs://, ar://)
        hash: String,          // SHA256 hash for verification (hex encoded)
        build_target: Option<String>, // e.g., "wasm32-wasip1", "wasm32-wasip2"
    },
    /// Project reference - uses registered project's code
    /// If version_key is None, uses active version
    Project {
        project_id: String,              // "alice.near/my-app"
        version_key: Option<String>,     // None = active version, Some = specific version
    },
}

/// Resolved code source for worker (GitHub or WasmUrl only, no Project)
/// This is what gets sent to worker after resolving Project references
#[derive(Clone, Debug)]
#[near(serializers = [borsh, json])]
pub enum CodeSource {
    GitHub {
        repo: String,
        commit: String,
        build_target: Option<String>,
    },
    WasmUrl {
        url: String,
        hash: String,
        build_target: Option<String>,
    },
}

/// Optional request parameters for additional options
#[derive(Clone, Debug, Default)]
#[near(serializers = [borsh, json])]
pub struct RequestParams {
    /// Force recompilation even if WASM exists in cache
    #[serde(default)]
    pub force_rebuild: bool,

    /// Compile only flag. Also set = true if resource_limits is none
    #[serde(default)]
    pub compile_only: bool,

    /// Project UUID for project-based execution
    /// Set automatically by request_execution_project
    /// Used by worker to enable persistent storage for the project
    #[serde(default)]
    pub project_uuid: Option<String>,

}

/// Response format for execution output
#[derive(Clone, Debug, PartialEq, Eq)]
#[near(serializers = [borsh, json])]
pub enum ResponseFormat {
    /// Raw bytes - no parsing
    Bytes,
    /// UTF-8 text string (default)
    Text,
    /// Parse stdout as JSON
    Json,
}

impl Default for ResponseFormat {
    fn default() -> Self {
        Self::Text
    }
}

/// Resource limits for execution
#[derive(Clone, Debug)]
#[near(serializers = [borsh, json])]
pub struct ResourceLimits {
    pub max_instructions: Option<u64>,
    pub max_memory_mb: Option<u32>,
    pub max_execution_seconds: Option<u64>,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_instructions: Some(1_000_000_000), // 1B instructions
            max_memory_mb: Some(128),              // 128 MB
            max_execution_seconds: Some(60),       // 60 seconds
        }
    }
}

/// Execution request stored in contract
#[derive(Clone, Debug)]
#[near(serializers = [borsh, json])]
pub struct ExecutionRequest {
    pub request_id: u64,
    pub data_id: CryptoHash,
    pub sender_id: AccountId,
    pub execution_source: ExecutionSource,  // Original source (may be Project)
    pub resolved_source: CodeSource,         // Resolved source for worker (GitHub/WasmUrl only)
    pub resource_limits: ResourceLimits,
    pub payment: Balance,
    pub timestamp: u64,
    pub response_format: ResponseFormat,
    pub input_data: Option<String>, // Optional input data for execution
}

/// Execution output - can be bytes, text, or parsed JSON
#[derive(Clone, Debug)]
#[near(serializers = [json])]
pub enum ExecutionOutput {
    Bytes(Vec<u8>),
    Text(String),
    Json(serde_json::Value),
}

/// Internal storage format for ExecutionOutput (Borsh-compatible)
/// Stores all data as Vec<u8> for efficient serialization
#[derive(Clone, Debug)]
#[near(serializers = [borsh, json])]
pub enum StoredOutput {
    Bytes(Vec<u8>),
    Text(Vec<u8>),      // UTF-8 bytes
    Json(Vec<u8>),      // JSON string as UTF-8 bytes
}

impl From<ExecutionOutput> for StoredOutput {
    fn from(output: ExecutionOutput) -> Self {
        match output {
            ExecutionOutput::Bytes(bytes) => StoredOutput::Bytes(bytes),
            ExecutionOutput::Text(text) => StoredOutput::Text(text.into_bytes()),
            ExecutionOutput::Json(value) => {
                let json_str = serde_json::to_string(&value).unwrap_or_default();
                StoredOutput::Json(json_str.into_bytes())
            }
        }
    }
}

impl From<StoredOutput> for ExecutionOutput {
    fn from(stored: StoredOutput) -> Self {
        match stored {
            StoredOutput::Bytes(bytes) => ExecutionOutput::Bytes(bytes),
            StoredOutput::Text(bytes) => ExecutionOutput::Text(
                String::from_utf8(bytes).unwrap_or_else(|_| String::from("[invalid UTF-8]"))
            ),
            StoredOutput::Json(bytes) => {
                let json_str = String::from_utf8(bytes).unwrap_or_default();
                ExecutionOutput::Json(
                    serde_json::from_str(&json_str).unwrap_or(serde_json::Value::Null)
                )
            }
        }
    }
}

/// Execution response from worker
#[derive(Clone, Debug)]
#[near(serializers = [json])]
pub struct ExecutionResponse {
    pub success: bool,
    pub output: Option<ExecutionOutput>,
    pub error: Option<String>,
    pub resources_used: ResourceMetrics,
    pub compilation_note: Option<String>, // e.g., "Cached WASM from 2025-01-10 14:30 UTC"
}

/// Resource usage metrics
#[derive(Clone, Debug)]
#[near(serializers = [json])]
pub struct ResourceMetrics {
    pub instructions: u64,        // Instructions used during WASM execution
    pub time_ms: u64,              // Execution time in milliseconds
    pub compile_time_ms: Option<u64>, // Compilation time in milliseconds (if compiled)
}


#[derive(BorshDeserialize, BorshSerialize, PanicOnDefault)]
#[borsh(crate = "near_sdk::borsh")]
#[near_bindgen]
pub struct Contract {
    owner_id: AccountId,
    operator_id: AccountId,
    open_resolution: bool,
    paused: bool,
    event_standard: String,
    event_version: String,
    // Pricing (NEAR only)
    base_fee: Balance,
    per_million_instructions_fee: Balance,
    per_ms_fee: Balance,
    per_compile_ms_fee: Balance,
    // Job queue
    next_request_id: u64,
    pending_requests: LookupMap<u64, ExecutionRequest>,
    // Stats
    total_executions: u64,
    total_fees_collected: Balance,
}

#[near_bindgen]
impl Contract {
    #[init]
    pub fn new(
        owner_id: AccountId,
        operator_id: Option<AccountId>,
        event_standard: Option<String>,
        event_version: Option<String>,
    ) -> Self {
        Self {
            owner_id: owner_id.clone(),
            operator_id: operator_id.unwrap_or(owner_id),
            open_resolution: false,
            paused: false,
            event_standard: event_standard.unwrap_or("outlayer".to_string()),
            event_version: event_version.unwrap_or("1.0.0".to_string()),
            base_fee: 1_000_000_000_000_000_000_000,
            per_million_instructions_fee: 100_000_000_000_000,
            per_ms_fee: 100_000_000_000_000_000,
            per_compile_ms_fee: 100_000_000_000_000_000,
            next_request_id: 0,
            pending_requests: LookupMap::new(StorageKey::PendingRequests),
            total_executions: 0,
            total_fees_collected: 0,
        }
    }

    /// Owner-only: set pricing
    pub fn set_pricing(
        &mut self,
        base_fee: Option<U128>,
        per_million_instructions_fee: Option<U128>,
        per_ms_fee: Option<U128>,
        per_compile_ms_fee: Option<U128>,
    ) {
        assert_eq!(env::predecessor_account_id(), self.owner_id, "Only owner");
        if let Some(v) = base_fee { self.base_fee = v.0; }
        if let Some(v) = per_million_instructions_fee { self.per_million_instructions_fee = v.0; }
        if let Some(v) = per_ms_fee { self.per_ms_fee = v.0; }
        if let Some(v) = per_compile_ms_fee { self.per_compile_ms_fee = v.0; }
    }

    /// Owner-only: pause/unpause
    pub fn set_paused(&mut self, paused: bool) {
        assert_eq!(env::predecessor_account_id(), self.owner_id, "Only owner");
        self.paused = paused;
    }

    /// Owner-only: toggle open resolution
    pub fn set_open_resolution(&mut self, open: bool) {
        assert_eq!(env::predecessor_account_id(), self.owner_id, "Only owner");
        self.open_resolution = open;
    }
}

impl Contract {
    fn assert_not_paused(&self) {
        assert!(!self.paused, "Contract is paused");
    }

    fn assert_resolver(&self) {
        if !self.open_resolution {
            assert_eq!(
                env::predecessor_account_id(),
                self.operator_id,
                "Only operator can resolve"
            );
        }
    }

    fn calculate_cost(&self, metrics: &ResourceMetrics) -> Balance {
        let instruction_cost =
            (metrics.instructions / 1_000_000) as u128 * self.per_million_instructions_fee;
        let time_cost = metrics.time_ms as u128 * self.per_ms_fee;
        let compile_cost = metrics.compile_time_ms
            .map(|ms| ms as u128 * self.per_compile_ms_fee)
            .unwrap_or(0);
        self.base_fee + instruction_cost + time_cost + compile_cost
    }

    fn estimate_cost(&self, limits: &ResourceLimits) -> Balance {
        let max_instructions = limits.max_instructions.unwrap_or(1_000_000_000);
        let max_execution_seconds = limits.max_execution_seconds.unwrap_or(60);
        let max_time_ms = max_execution_seconds * 1000;
        let instruction_cost = (max_instructions / 1_000_000) as u128 * self.per_million_instructions_fee;
        let time_cost = max_time_ms as u128 * self.per_ms_fee;
        self.base_fee + instruction_cost + time_cost
    }

    fn resolve_execution_source(&self, source: &ExecutionSource) -> (CodeSource, Option<String>) {
        match source {
            ExecutionSource::GitHub { repo, commit, build_target } => (CodeSource::GitHub {
                repo: repo.clone(),
                commit: commit.clone(),
                build_target: build_target.clone(),
            }, None),
            ExecutionSource::WasmUrl { url, hash, build_target } => (CodeSource::WasmUrl {
                url: url.clone(),
                hash: hash.clone(),
                build_target: build_target.clone(),
            }, None),
            ExecutionSource::Project { .. } => {
                env::panic_str("Projects not supported in standalone mode");
            }
        }
    }
}
