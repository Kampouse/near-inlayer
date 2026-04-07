# layerd — OutLayer Local Worker

Autonomous worker that polls the OutLayer NEAR contract for pending execution requests, runs WASM via `inlayer`, and submits results on-chain.

## Quick Start

```bash
# 1. Build
cd worker && cargo build --release --bin layerd --bin inlayer

# 2. Install
mkdir -p ~/.inlayer/bin
cp target/release/layerd ~/.inlayer/bin/
cp target/release/inlayer ~/.inlayer/bin/   # or ~/.local/bin/

# 3. Configure (optional — defaults work for testnet)
cat > ~/.inlayer/layerd.config << 'EOF'
rpc_url = "https://test.rpc.fastnear.com"
poll_interval_secs = 10
EOF

# 4. Run
layerd                          # foreground
layerd --daemon                 # background daemon
```

## Daemon Management (macOS)

```bash
# Install launchd service (auto-start on boot)
cp scripts/com.outlayer.layerd.plist ~/Library/LaunchAgents/
# Edit the plist to match your paths (binary location, home dir)

# Start / Stop
layerd --start                  # start via launchd (survives crashes)
layerd --stop                   # stop (stays stopped)
layerd --status                 # check if running
layerd --log                    # tail log file

# Manual launchctl
launchctl load ~/Library/LaunchAgents/com.outlayer.layerd.plist
launchctl unload ~/Library/LaunchAgents/com.outlayer.layerd.plist
```

## Configuration

Config file: `layerd.config` or `layerd.config.toml`

Search order:
1. `./layerd.config`
2. `~/.inlayer/layerd.config`

| Field | Default | Description |
|-------|---------|-------------|
| `contract_id` | `outlayer.kampouse.testnet` | NEAR contract |
| `account_id` | `kampouse.testnet` | Signer account |
| `network` | `testnet` | NEAR network |
| `rpc_url` | `https://test.rpc.fastnear.com` | NEAR RPC endpoint |
| `poll_interval_secs` | `5` | Seconds between polls |
| `wasm_search_dirs` | `~/.openclaw/workspace` | Directories to search for WASM |
| `key_path` | `~/.near-credentials/testnet/<account>.json` | NEAR signer key |
| `log_file` | `~/.inlayer/layerd.log` | Log file path |
| `pid_file` | `~/.inlayer/layerd.pid` | PID file path |

### Recommended RPC Endpoints

The default `rpc.testnet.near.org` is deprecated and rate-limited. Use:

- **Testnet:** `https://test.rpc.fastnear.com`
- **Mainnet:** `https://rpc.fastnear.com`

More providers: https://docs.near.org/api/rpc/providers

## Key File

Expects NEAR CLI key format at `~/.near-credentials/<network>/<account>.json`:

```json
{
  "account_id": "your-account.testnet",
  "private_key": "ed25519:..."
}
```

## WASM Discovery

Worker searches `wasm_search_dirs` for WASM files in:
```
<dir>/<project-name>/target/wasm32-wasip2/release/*.wasm
```

Currently looks for projects named `nostr-identity` or `near-signer-tee`.

## Architecture

```
User/App ──(tx)──▶ NEAR Contract ──(poll)──▶ layerd ──(exec)──▶ inlayer
                       │                         │
                       │◀──(resolve tx)──────────┘
```

- **No databases, no queues, no webhooks** — the NEAR contract IS the queue
- **No `near` CLI dependency** — direct RPC via `near-jsonrpc-client`
- **Exponential backoff** on RPC errors (max 5 min)

## Files

| File | Description |
|------|-------------|
| `worker/src/bin/layerd.rs` | Worker binary |
| `worker/src/bin/inlayer.rs` | WASM execution engine |
| `scripts/com.outlayer.layerd.plist` | macOS launchd service |
| `contract/` | NEAR smart contract |

## Requirements

- NEAR account with access key on testnet/mainnet
- Compiled WASM files in search directories
- `inlayer` binary in PATH
- macOS or Linux (for daemon mode)
