# OutLayer Standalone — Offchain WASM Compute on NEAR

## Overview
OutLayer lets you run WASM offchain workers that poll a NEAR contract for jobs, execute them locally, and resolve results on-chain.

## Components

| Component | Description |
|-----------|-------------|
| `contract/` | Minimal NEAR job-queue contract (~650 lines) |
| `worker/` | WASM execution engine + daemon (polls contract, executes, resolves) |
| `examples/` | Example WASI P2 programs (rpc-test, test-storage) |

## Quick Start

### 1. Run WASM locally
```bash
# Build worker
cd worker && cargo build --release --bin inlayer

# List available WASMs
./target/release/inlayer list

# Run locally
./target/release/inlayer run <wasm-path> '{"action":"test"}'
```

### 2. Deploy contract & run daemon
```bash
# Deploy contract to testnet
cd contract && cargo near deploy build non-reproducible-wasm <account-id> testnet

# Configure daemon
inlayer init  # creates inlayer.config

# Start daemon (polls contract, executes jobs, resolves on-chain)
inlayer daemon --foreground --dashboard 127.0.0.1:8082
```

### 3. Submit a job
```bash
inlayer submit '{"action":"test"}' --wasm-url <url> <sha256>
```

## Contract API

```rust
// Submit a job (payable)
request_execution(source, resource_limits, input_data, response_format, params)

// Worker resolves result
resolve_execution(request_id, response)
batch_resolve_execution(entries: Vec<(u64, ExecutionResponse)>)

// Views
get_pending_request_ids(from_index, limit)
get_request(request_id)
get_stats()
get_pricing()
estimate_execution_cost(resource_limits)
```

## Daemon Commands
```bash
inlayer daemon --start          # Start via launchd
inlayer daemon --stop           # Stop
inlayer daemon --status         # Check if running
inlayer daemon --log            # Tail logs
inlayer daemon --foreground     # Run in foreground (for testing)
inlayer daemon --dashboard 127.0.0.1:8082  # Enable web dashboard
inlayer daemon --tunnel         # Cloudflare tunnel for public access
```

## Full CLI
```
inlayer run <wasm> <input> [--rpc <url>]    Run WASM locally
inlayer exec --worker <url> --input <data>  Execute on remote worker
inlayer submit <input> [--wasm-url <url>]   Submit request to contract
inlayer daemon [...]                         Start/manage daemon
inlayer ping --worker <url>                 Check worker status
inlayer list                                List available WASMs
inlayer config                              Show current config
inlayer version                             Show version
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
```

## Environment Variables
- `INLAYER_NETWORK` — testnet/mainnet
- `INLAYER_ACCOUNT` — NEAR account for daemon
- `INLAYER_CONTRACT` — contract account ID
- `NEAR_PRIVATE_KEY` — signer key

## Payment Flow (Remote Exec)
1. `exec` sends request to worker API
2. Worker returns 402 with payment challenge
3. Client pays via NEAR Intents
4. Client retries with payment receipt
5. Worker verifies on-chain, executes WASM, returns result

## Examples

### test-storage
Persistent storage operations (set/get/increment):
```bash
cd examples/test-storage && cargo build --target wasm32-wasip2 --release
inlayer run target/wasm32-wasip2/release/test-storage-ark.wasm '{"command":"set","key":"hello","value":"world"}'
inlayer run target/wasm32-wasip2/release/test-storage-ark.wasm '{"command":"get","key":"hello"}'
```

### rpc-test
Tests all NEAR RPC methods through the proxy:
```bash
cd examples/rpc-test && cargo build --target wasm32-wasip2 --release
inlayer run target/wasm32-wasip2/release/rpc-test-ark.wasm '{"action":"view_account","account_id":"test.near"}'
```

## Host Functions (available to WASM)
- **RPC Proxy** — make NEAR RPC calls (query, tx, view_account, etc.)
- **Storage** — persistent key-value storage (put/get/delete/increment)
- ~~Wallet~~ — removed in standalone
- ~~VRF~~ — removed in standalone
- ~~Payment~~ — removed in standalone

## Build from Source
```bash
# Contract
cd contract && cargo near build non-reproducible-wasm

# Worker
cd worker && cargo build --release --bin inlayer
```
