# OutLayer Standalone — Offchain WASM Compute on NEAR

## What It Is
A standalone offchain compute layer: NEAR contract (job queue) + WASM worker daemon. Anyone can deploy the contract, run the worker, and execute WASI P2 WASM programs trustlessly on-chain.

## Location
`/Users/asil/.openclaw/workspace/outlayer-standalone`

## Quick Commands

### Build
```bash
# Worker
cd worker && cargo build --release --bin inlayer

# Contract
cd contract && cargo near build non-reproducible-wasm
```

### Local WASM Execution
```bash
inlayer run <wasm-path> '{"action":"test"}'
inlayer run <wasm-path> '{"command":"set","key":"k","value":"v"}' --rpc https://rpc.testnet.near.org
```

### Daemon
```bash
inlayer daemon --foreground --dashboard 127.0.0.1:8082  # run in foreground
inlayer daemon --start    # launchd (macOS)
inlayer daemon --status
inlayer daemon --log
inlayer daemon --stop
```

### Remote Exec (with payment)
```bash
inlayer exec --worker http://127.0.0.1:8082 --input '{"action":"test"}'
inlayer exec --worker <url> --input <data> --no-pay  # dry run
inlayer ping --worker <url>
inlayer catalog --worker <url>
```

## Architecture
```
User → request_execution() → NEAR Contract (job queue)
Worker polls → get_pending_request_ids() → fetches job
Worker → executes WASM locally → resolve_execution() → on-chain
```

## Files
- `contract/` — NEAR job-queue contract (648 lines, near-sdk 5.9)
- `worker/` — Rust worker (15k lines): executor (wasmtime), daemon, RPC proxy, storage host functions, CLI
- `examples/` — WASI P2 example programs (rpc-test, test-storage)
- `README.md` — full docs

## Contract Account
- Testnet: configurable via `INLAYER_CONTRACT` env var
- Default: `outlayer.kampouse.testnet`

## Config
`inlayer init` creates `inlayer.config`. Client config at `~/.inlayer/config.toml`.

## Key Differences from Full OutLayer
- No TEE/keystore/attestation
- No project registry/versioning
- No wallet host functions
- No VRF host functions
- No MPP-402 payment (kept simple NEAR-only pricing)
- Contract is ~650 lines vs ~6100
- Worker is ~15k lines vs ~23k
