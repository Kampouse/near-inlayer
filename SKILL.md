---
name: near-inlayer
description: Run WASI WASM programs offchain on NEAR. Use when deploying or running offchain workers, executing WASM locally, submitting jobs to a NEAR job-queue contract, or managing an inlayer daemon that polls and resolves executions on-chain.
license: MIT
compatibility: Requires Rust, cargo-near, wasmtime, NEAR CLI, and access to NEAR RPC (testnet/mainnet)
metadata:
  author: Kampouse
  version: "0.1.0"
  repo: "https://github.com/Kampouse/near-inlayer"
---

# near-inlayer — Offchain WASM Compute on NEAR

Standalone offchain compute: a NEAR contract (job queue) + WASM worker daemon. Deploy the contract, run the worker, execute WASI P2 WASM programs.

## Architecture

```
User → request_execution() → NEAR Contract (job queue)
Worker polls → get_pending_request_ids() → fetches job
Worker → executes WASM locally → resolve_execution() → on-chain
```

## Quick Start

### Build
```bash
# Worker
cd worker && cargo build --release --bin inlayer

# Contract
cd contract && cargo near build non-reproducible-wasm
```

### Run WASM Locally
```bash
inlayer run <wasm-path> '{"action":"test"}'
inlayer run <wasm-path> '{"command":"set","key":"k","value":"v"}'
```

### Deploy & Run Daemon
```bash
cd contract && cargo near deploy build non-reproducible-wasm <account-id> testnet
inlayer init
inlayer daemon --foreground --dashboard 127.0.0.1:8082
```

### Submit a Job
```bash
inlayer submit '{"action":"test"}' --wasm-url <url> <sha256>
```

## CLI Reference

| Command | Description |
|---------|-------------|
| `inlayer run <wasm> <input> [--rpc <url>]` | Run WASM locally |
| `inlayer exec --worker <url> --input <data>` | Execute on remote worker (auto-payment) |
| `inlayer submit <input> [--wasm-url <url>]` | Submit job to contract |
| `inlayer daemon --foreground` | Run daemon in foreground |
| `inlayer daemon --start/--stop/--status` | Manage daemon (launchd) |
| `inlayer daemon --dashboard <addr>` | Enable web dashboard |
| `inlayer daemon --tunnel` | Cloudflare tunnel for public access |
| `inlayer ping --worker <url>` | Check worker status |
| `inlayer list` | List available WASMs |
| `inlayer config` | Show current config |
| `inlayer version` | Show version |

## Contract API

```rust
request_execution(source, resource_limits, input_data, response_format, params)
resolve_execution(request_id, response)
batch_resolve_execution(entries: Vec<(u64, ExecutionResponse)>)
get_pending_request_ids(from_index, limit)
get_request(request_id)
get_stats()
get_pricing()
estimate_execution_cost(resource_limits)
```

## Host Functions (available to WASM)

- **RPC Proxy** — NEAR RPC calls (query, tx, view_account, etc.)
- **Storage** — persistent key-value (put/get/delete/increment)

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

Client config at `~/.inlayer/config.toml`:
```toml
worker_url = "https://your-worker.trycloudflare.com"
account_id = "your-account.testnet"

[payment]
max_per_request = "0.01"
max_per_day = "1.0"
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

### test-storage (persistent storage)
```bash
cd examples/test-storage && cargo build --target wasm32-wasip2 --release
inlayer run target/wasm32-wasip2/release/test-storage-ark.wasm '{"command":"set","key":"hello","value":"world"}'
inlayer run target/wasm32-wasip2/release/test-storage-ark.wasm '{"command":"get","key":"hello"}'
```

### rpc-test (NEAR RPC proxy)
```bash
cd examples/rpc-test && cargo build --target wasm32-wasip2 --release
inlayer run target/wasm32-wasip2/release/rpc-test-ark.wasm '{"action":"view_account","account_id":"test.near"}'
```

## What This Does NOT Include (vs full OutLayer)

No TEE/keystore/attestation, no project registry/versioning, no wallet host functions, no VRF host functions, no MPP-402 payment. Simple NEAR-only pricing. Contract is ~650 lines vs ~6100. Worker is ~15k lines vs ~23k.
