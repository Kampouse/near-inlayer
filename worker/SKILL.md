# OutLayer — Distributed Compute via NEAR

## Overview
OutLayer lets you run WASM code on remote workers and pay per execution via NEAR blockchain.

## Commands

### Execute on a remote worker
```bash
# Basic execution
inlayer exec --worker https://worker.example.com --input "your data here"

# With specific program
inlayer exec --worker https://worker.example.com --input "data" --program sign-tx

# Pipe data via stdin
echo '{"key":"val"}' | inlayer exec --worker https://worker.example.com

# Use config file (no --worker needed)
inlayer exec --input "data"

# Show payment info without paying
inlayer exec --worker https://worker.example.com --input "data" --no-pay
```

### Check worker status
```bash
inlayer ping --worker https://worker.example.com
```

### List available programs
```bash
inlayer catalog --worker https://worker.example.com
```

### Configuration
Create `~/.inlayer/config.toml`:
```toml
worker_url = "https://your-worker.trycloudflare.com"
account_id = "your-account.testnet"

[payment]
max_per_request = "0.01"
max_per_day = "1.0"
```

## Payment Flow
1. `exec` sends request to worker
2. Worker returns 402 with payment challenge (amount, recipient, challenge_id)
3. Client pays via NEAR (auto or manual)
4. Client retries with payment receipt
5. Worker verifies on-chain, executes WASM, returns result

## As a Worker (Daemon)
```bash
# Start daemon
inlayer daemon --start

# Check status
inlayer daemon --status

# View logs
inlayer daemon --log

# Stop
inlayer daemon --stop
```

## Environment Variables
- `OUTLAYER_WORKER_URL` — override worker URL
- `OUTLAYER_ACCOUNT_ID` — override account ID
- `OUTLAYER_CONFIG` — config file path (default: ~/.inlayer/config.toml)

## Full CLI Reference

```
inlayer exec --worker <url> --input <data> [--program <name>] [--no-pay]
                                           Execute on remote worker (auto-payment)
inlayer ping --worker <url>              Check worker status
inlayer catalog --worker <url>           List available programs
inlayer init                                Create inlayer.config in current directory
inlayer register <project-name> <source>    Register project on contract
inlayer projects [--account <id>]           List registered projects
inlayer run <wasm> <input> [--rpc <url>]    Run WASM locally
inlayer submit <input> [--wasm-url <url>]   Submit request to contract
inlayer status [--contract <id>]            Check pending requests
inlayer list                                List available WASMs
inlayer config                              Show current config
inlayer daemon [--start|--stop|--status|--log|--daemon|--foreground|--dashboard <addr>|--tunnel]
                                           Start/manage daemon
inlayer version                             Show version
```

## Examples

### Quick test with local daemon
```bash
# Start local daemon
inlayer daemon --foreground --dashboard 127.0.0.1:8082

# In another terminal, test exec
inlayer exec --worker http://127.0.0.1:8082 --input "test" --no-pay

# Check status
inlayer ping --worker http://127.0.0.1:8082
```

### Remote execution with payment
```bash
# Configure your account
cat > ~/.inlayer/config.toml << EOF
worker_url = "https://worker.example.com"
account_id = "your-account.testnet"

[payment]
max_per_request = "0.01"
max_per_day = "1.0"
EOF

# Execute (will auto-pay if needed)
inlayer exec --input '{"action": "sign", "data": "hello"}'
```
