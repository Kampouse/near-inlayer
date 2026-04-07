# near-inlayer Worker

Offchain WASM execution engine for NEAR. Polls a job-queue contract, executes WASI P2/P1 WASM locally, resolves results on-chain.

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                    inlayer daemon                         │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  ┌────────────┐   ┌──────────────┐   ┌───────────────┐ │
│  │  Watcher   │──▶│  Main Loop   │──▶│   Executor    │ │
│  │ (blocks)   │   │ (poll queue) │   │ (wasmtime)    │ │
│  └────────────┘   └──────────────┘   └───────────────┘ │
│        │                  │                    │         │
│        │                  │            ┌───────┴──────┐  │
│        │                  │            │ Host Functions│  │
│        │                  │            │ ┌ RPC Proxy   │  │
│        │                  │            │ ┌ Storage     │  │
│        │                  │            └──────────────┘  │
│        │                  │                              │
│        │            ┌─────┴─────┐                        │
│        │            │ Compiler  │   ┌────────────────┐   │
│        │            │ (native)  │   │  HTTP API      │   │
│        │            └───────────┘   │  (MPP-402)     │   │
│        │                            │  /execute       │   │
│        │                            │  /status        │   │
│        │                            │  /catalog       │   │
│        │                            └────────────────┘   │
│        │                                                  │
│        │           ┌──────────────┐                       │
│        └──────────▶│ NEAR Client  │◀── nonce mgmt         │
│                    │ (RPC pool)   │                       │
│                    └──────┬───────┘                       │
│                           │                               │
└───────────────────────────┼───────────────────────────────┘
                            │
                    ┌───────▼────────┐
                    │ NEAR Blockchain │
                    │  (job queue     │
                    │   contract)     │
                    └────────────────┘
```

## Components

### Daemon (`src/daemon/`)

| File | Purpose |
|------|---------|
| `mod.rs` | Main loop: poll → fetch → compile → execute → resolve |
| `watcher.rs` | Block watcher via neardata.xyz (event-driven) |
| `nonce.rs` | Nonce management with prefetch and caching |
| `rpc_pool.rs` | Round-robin RPC pool (avoids rate limits) |
| `api.rs` | HTTP API server with MPP-402 payment |
| `payment.rs` | Payment verification via NEAR Intents |
| `manage.rs` | Daemon lifecycle (start/stop/status/log) |
| `tunnel.rs` | Cloudflare tunnel for public access |

### Executor (`src/executor/`)

| File | Purpose |
|------|---------|
| `mod.rs` | Execution dispatcher (P1 vs P2) + resource limits |
| `wasi_p2.rs` | WASI Preview 2 execution (wasmtime component model) |
| `wasi_p1.rs` | WASI Preview 1 execution (wasmi) |

### Host Functions

| Module | What WASM gets |
|--------|---------------|
| `outlayer_rpc/` | NEAR RPC proxy (query, tx, view_account, etc.) |
| `outlayer_storage/` | Persistent key-value storage (put/get/delete/increment) |

### Other

| File | Purpose |
|------|---------|
| `compiler/` | Compile GitHub repos to WASM (native mode) |
| `near_client.rs` | NEAR RPC client for contract calls |
| `compiled_cache.rs` | Compiled component cache (10x speedup) |
| `wasm_cache.rs` | WASM download cache |
| `config.rs` | Configuration from env + file |
| `api_client.rs` | HTTP client for coordinator API |
| `config_client.rs` | Client config for remote exec |

## Daemon Flow

```
1. Watcher detects new block
2. Poll get_pending_request_ids() on contract
3. For each pending request:
   a. Fetch request details via get_request()
   b. Resolve code source (GitHub → compile, WasmUrl → download)
   c. Execute WASM with limits (instructions, memory, time)
   d. Collect result + resource metrics
4. Batch resolve via batch_resolve_execution() on contract
5. Contract refunds excess NEAR, keeps fees
6. Repeat
```

## Build

```bash
cargo build --release --bin inlayer
```

## CLI Usage

```bash
# Local execution
inlayer run <wasm> '{"action":"test"}' [--rpc <url>]

# Daemon
inlayer daemon --foreground --dashboard 127.0.0.1:8082
inlayer daemon --start     # launchd
inlayer daemon --status
inlayer daemon --log
inlayer daemon --stop

# Remote exec (MPP-402 payment)
inlayer exec --worker <url> --input <data>

# Contract interaction
inlayer submit <input> [--wasm-url <url> <sha256>]
inlayer status [--contract <id>]

# Utility
inlayer list     # available WASMs
inlayer config   # show config
inlayer version
```

## Configuration

`inlayer init` creates `inlayer.config`:
```toml
search_paths = ["./wasm"]

[rpc]
url = "https://rpc.testnet.near.org"

[storage]
mode = "local"
dir = "./storage"

[runner]
max_instructions = 10000000000
max_memory_mb = 256
max_execution_seconds = 60
log_level = "info"
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `INLAYER_NETWORK` | testnet / mainnet |
| `INLAYER_ACCOUNT` | NEAR account for daemon |
| `INLAYER_CONTRACT` | Job queue contract ID |
| `NEAR_PRIVATE_KEY` | Signer key |

## Build Targets

| Target | Engine | Status |
|--------|--------|--------|
| `wasm32-wasip2` | wasmtime (component model) | ✅ Primary |
| `wasm32-wasip1` | wasmi | ✅ Supported |
| `wasm32-wasi` | wasmi (alias for wasip1) | ✅ Supported |

## License

MIT
