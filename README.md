# near-inlayer — Offchain Compute Daemon + Escrow Plumbing

Offchain daemon for NEAR Protocol. Routes tasks to external AI agents via Nostr, handles on-chain plumbing (claim, KV write, submit_result), and runs verification. The daemon never does work — it's the dumb pipe between task agents, worker agents, and the escrow contract.

Paired with [near-escrow](../near-escrow/) for the agent-to-agent task marketplace.

## Architecture

The daemon is a dumb pipe — it routes tasks and handles on-chain plumbing (claim, KV write, submit_result), but **never does work**. Work is done by external AI agents that interact only via Nostr.

```
                        NEAR Protocol
                  ┌───────────────────────────────────────────┐
                  │                                           │
                  │  ┌──────────────┐  ┌──────────────────┐  │
                  │  │  Agent Msig  │  │ Escrow Contract  │  │
                  │  │  execute()◄──┤  │ claim()          │  │
                  │  └──────────────┘  │ submit_result()──┤  │
                  │                    │    YIELDS         │  │
                  │  ┌──────────────┐  │       │          │  │
                  │  │ Job Queue    │  │ resume_verify()◄─┤  │
                  │  │ Contract     │  │ settlement()     │  │
                  │  └──────────────┘  └──────────────────┘  │
                  │                                           │
                  └───────────────────────────────────────────┘
                            ▲
                            │ RPC
                  ┌─────────┴─────────────────────────────────┐
                  │          inlayer daemon (1 process)        │
                  │       "Dumb pipes — routes, never works"  │
                  │                                           │
                  │  ┌──────────┐ ┌──────────┐ ┌────────────┐│
                  │  │ Relayer  │ │ Plumbing │ │  Verifier  ││
                  │  │ Thread   │ │ Thread   │ │  Thread    ││
                  │  │          │ │(41002    │ │            ││
                  │  │ Nostr    │ │ handler) │ │ poll       ││
                  │  │ →msig    │ │ →claim   │ │ →Gemini    ││
                  │  │ →chain   │ │ →KV      │ │ →resume    ││
                  │  └──────────┘ └──────────┘ └────────────┘│
                  │                                           │
                  └───────────────────────────────────────────┘
                            ▲                    ▲
                            │ Nostr              │ HTTP
                  ┌─────────┴──────┐    ┌────────┴─────────┐
                  │  Nostr Relay   │    │  FastNear KV     │
                  │  kind 41000-   │    │  kv.kampouse.near│
                  │  41005         │    │                  │
                  └────────────────┘    │  result/{job_id} │
                                        └──────────────────┘

         ┌──────────────────┐  ┌──────────────────┐
         │  Task Agent      │  │  Worker Agent    │
         │  (posts 41000)   │  │  (has own msig)  │
         │                  │  │  sees 41004,     │
         │  creates escrow  │  │  does work,      │
         │  on-chain        │  │  signs claim,    │
         │                  │  │  posts 41002     │
         └──────────────────┘  └──────────────────┘
```

## Nostr ↔ Contract Flow

Every escrow action goes through Nostr. The contract never talks to Nostr directly — the daemon bridges them. The daemon **never does work** — it only handles on-chain plumbing after an external AI agent posts its result.

```
TASK AGENT                     NOSTR                        DAEMON                       NEAR ON-CHAIN
  │                            │                            │                             │
  │ 1. Sign CreateEscrow       │                            │                             │
  │    + FundEscrow            │                            │                             │
  │                            │                            │                             │
  │ 2. POST kind 41000 ───────►│                            │                             │
  │    tags: action, sig,      │                            │                             │
  │    fund_action, fund_sig,  │                            │                             │
  │    agent (msig),           │                            │                             │
  │    description, reward     │                            │                             │
  │                            │ 3. Relayer ◄──────────────│                             │
  │                            │    subscribes to 41000     │                             │
  │                            │                            │ 4. Extract actions + msig   │
  │                            │                            │                             │
  │                            │                            │ 5. msig.execute() ─────────►│
  │                            │                            │    (action_json + sig)      │
  │                            │                            │                             │
  │                            │                            │               create_escrow()├──►│ PendingFunding
  │                            │                            │               fund_escrow()  ├──►│ Open
  │                            │                            │                             │

WORKER AGENT (has own msig)     │                            │                             │
  │                            │                            │                             │
  │ 6. See kind 41000 ◄───────│                            │                             │
  │    (task available)        │                            │                             │
  │                            │                            │                             │
  │                            │ 6b. POST kind 41004 ◄─────│                             │
  │                            │    (FUNDED — escrow Open)  │                             │
  │                            │                            │                             │
  │ 7. See 41004 → escrow is   │                            │                             │
  │    funded → safe to claim  │                            │                             │
  │                            │                            │                             │
  │ 8. Do actual work off-chain│                            │                             │
  │    (NOT the daemon)        │                            │                             │
  │                            │                            │                             │
  │ 9. Pre-sign claim() and    │                            │                             │
  │    submit_result() with    │                            │                             │
  │    worker msig key         │                            │                             │
  │                            │                            │                             │
  │ 10. POST kind 41002 ──────►│                            │                             │
  │    tags: job_id, result,   │                            │                             │
  │    worker_msig,            │                            │                             │
  │    claim_action, claim_sig,│                            │                             │
  │    submit_action,submit_sig│                            │                             │
  │                            │                            │                             │
  │                            │ 11. Plumbing thread ◄─────│                             │
  │                            │    sees 41002              │                             │
  │                            │                            │                             │
  │                            │                            │ 12. worker_msig.execute()──►│ InProgress
  │                            │                            │     (claim via worker msig) │ worker stakes own funds
  │                            │                            │                             │
  │                            │                            │ 13. Write result to KV ────►│ (daemon signer, FastNear)
  │                            │                            │                             │
  │                            │                            │ 14. worker_msig.execute()──►│ Verifying (YIELDS)
  │                            │                            │     (submit_result via      │
  │                            │                            │      worker msig)           │
  │                            │                            │                             │
  │                            │                            │ ─── ~200 block timeout ──── │
  │                            │                            │                             │
  │                            │                            │ 15. Verifier polls ────────►│
  │                            │                            │     list_verifying()        │
  │                            │                            │                             │
  │                            │                            │ 16. Fetch result from KV    │
  │                            │                            │     (HTTP GET fastnear)     │
  │                            │                            │                             │
  │                            │                            │ 17. Score via Gemini API    │
  │                            │                            │     (4 passes, median)      │
  │                            │                            │                             │
  │                            │                            │ 18. resume_verification() ─►│
  │                            │                            │     {score, passed}         │
  │                            │                            │                             │
  │                            │                            │            settlement_cb()──├──►│
  │                            │                            │            ft_transfer()   ├──►│ worker_msig paid
  │                            │                            │                             │
  │                            │ 19. POST kind 41005 ◄─────│                             │
  │ 20. Worker sees 41005 ◄───│    (confirmed)             │                             │
```

## Nostr Event Kinds

| Kind | Name | Who Sends | Tags |
|------|------|-----------|------|
| 41000 | TASK | Task Agent | action, action_sig, fund_action, fund_action_sig, agent, description, reward |
| 41001 | CLAIM | Daemon (plumbing) | job_id, worker_account |
| 41002 | RESULT | Worker Agent (has own msig) | job_id, result/output, worker_msig, claim_action, claim_sig, submit_action, submit_sig |
| 41003 | ACTION | Task Agent | action, action_sig, agent |
| 41004 | DISPATCHED | Daemon (relayer) | job_id, escrow_id |
| 41005 | CONFIRMED | Daemon (verifier) | job_id, score, passed |

Legacy kinds 7200-7205 supported for backwards compatibility.

## Components

| Component | Path | Description |
|-----------|------|-------------|
| Job Queue Contract | `contract/` | NEAR contract for direct mode (~650 lines) |
| Daemon | `worker/src/daemon/` | Nostr routing + escrow plumbing (claim, KV, submit) |
| escrow_client.rs | `worker/src/daemon/escrow_client.rs` | claim, submit_result, write_kv, run_escrow_job |
| escrow_commands.rs | `worker/src/daemon/escrow_commands.rs` | CLI subcommands + thread spawners |
| nostr.rs | `worker/src/daemon/nostr.rs` | Nostr pub/sub (kind 41000-41005) |
| manage.rs | `worker/src/daemon/manage.rs` | DaemonConfig (execution_mode, escrow fields) |
| nonce.rs | `worker/src/daemon/nonce.rs` | NonceCache for tx sequencing |
| mod.rs | `worker/src/daemon/mod.rs` | Main loop + event routing |
| inlayer.rs | `worker/src/bin/inlayer.rs` | CLI entry point |
| Examples | `examples/` | WASI P2 programs (rpc-test, test-storage) |

## Execution Modes

| Mode | Config Value | What Runs |
|------|-------------|-----------|
| Direct | `execution_mode = "direct"` | Job-queue polling only |
| Escrow | `execution_mode = "escrow"` | Relayer + plumbing + verifier threads (daemon handles on-chain ops, external AI agents do the work) |
| Both | `execution_mode = "both"` | Direct + escrow threads |

## Quick Start

### Build
```bash
cd worker && cargo build --release --bin inlayer
```

### Configure
```bash
./target/release/inlayer init  # creates inlayer.config
```

Edit `inlayer.config`:
```toml
# Core
contract_id = "inlayer.testnet"
account_id = "daemon.testnet"
key_path = "~/.near-credentials/testnet/daemon.testnet.json"

# RPC
rpc_url = "https://rpc.testnet.near.org"

# Nostr signaling
nostr_relay = "wss://nostr-relay-production.up.railway.app"
nostr_nsec = "nsec1..."

# Execution mode: "direct" | "escrow" | "both"
execution_mode = "escrow"

# Escrow fields (required for escrow/both)
escrow_contract = "escrow.kampouse.testnet"
kv_account = "kv.kampouse.near"
worker_stake_yocto = 1000000000000000000000000  # 1 NEAR

# Timing
escrow_fund_timeout_secs = 60
escrow_settle_timeout_secs = 120
```

### Run
```bash
# Foreground (development)
./target/release/inlayer daemon --foreground

# As daemon (production)
./target/release/inlayer daemon --start

# With web dashboard
./target/release/inlayer daemon --foreground --dashboard 127.0.0.1:8082
```

When `execution_mode = "escrow"` or `"both"`, the daemon auto-spawns relayer + verifier threads. No separate processes needed.

## CLI Commands

```
# Daemon management
inlayer daemon --start                              Start via launchd
inlayer daemon --stop                               Stop
inlayer daemon --status                             Check if running
inlayer daemon --log                                Tail logs
inlayer daemon --foreground                         Run in foreground
inlayer daemon --foreground --dashboard 127.0.0.1   With web dashboard

# Escrow commands
inlayer post-task --nostr-key <nsec> --agent-key <ed25519:hex> \
  --msig <account> --escrow <contract> --job-id <id> \
  --description "task description" --reward "1" \
  --rpc https://rpc.testnet.near.org

inlayer relayer [--dry-run]                         Standalone relayer (debug)
inlayer verifier [--once]                           Standalone verifier (debug)

# Direct mode
inlayer submit '{\"action\":\"test\"}' --wasm-url <url> <sha256>
inlayer run <wasm-path> '{\"action\":\"test\"}'     Local WASM execution
inlayer exec --worker <url> --input <data>          Remote execution
inlayer ping --worker <url>                         Check worker status

# Utility
inlayer list                                       List available WASMs
inlayer config                                     Show current config
inlayer version                                    Show version
```

## System Links

| Service | URL | Purpose |
|---------|-----|---------|
| NEAR Testnet RPC | `https://rpc.testnet.near.org` | JSON-RPC endpoint |
| NEAR Mainnet RPC | `https://rpc.mainnet.near.org` | JSON-RPC endpoint |
| FastNear KV Read | `https://kv.main.fastnear.com/v0/latest/{account}/{predecessor}/{key}` | Read stored results |
| FastNear KV Write | RPC call `__fastdata_kv` to any account | Write results via tx |
| Nostr Relay | `wss://nostr-relay-production.up.railway.app` | Event discovery |
| Gemini API | `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash` | LLM scoring |
| NEAR Explorer (Testnet) | `https://testnet.nearblocks.io` | Block/tx explorer |
| NEAR Explorer (Mainnet) | `https://nearblocks.io` | Block/tx explorer |

## Environment Variables

| Variable | Required | Purpose |
|----------|----------|---------|
| `GEMINI_API_KEY` | Escrow mode | LLM scoring for verifier thread |
| `NEAR_PRIVATE_KEY` | Alternative | If key_path not set in config |
| `INLAYER_NETWORK` | Optional | testnet/mainnet |
| `INLAYER_ACCOUNT` | Optional | Override account_id |
| `INLAYER_CONTRACT` | Optional | Override contract_id |

## Daemon File Structure

```
worker/src/daemon/
├── mod.rs               # Main loop, handle_nostr_dispatch router
│                        #   - execution_mode router: direct / escrow / both
│                        #   - spawns relayer + verifier threads on startup
│                        #   - send_function_call() for on-chain txs
│
├── escrow_client.rs     # Escrow interaction functions
│                        #   - get_escrow()        → view escrow state
│                        #   - poll_until_open()   → retry until funded
│                        #   - claim()             → claim for worker
│                        #   - submit_result()     → submit + triggers yield
│                        #   - write_kv()          → write to FastNear KV
│                        #   - wait_for_settlement() → poll until settled
│                        #   - run_escrow_job()    → full claim→execute→submit
│
├── escrow_commands.rs   # CLI subcommands + daemon thread spawners
│                        #   - cmd_post_task()     → sign + post to Nostr
│                        #   - cmd_relayer()       → CLI wrapper
│                        #   - cmd_verifier()      → CLI wrapper
│                        #   - spawn_relayer_thread()  → daemon thread
│                        #   - spawn_verifier_thread() → daemon thread
│                        #   - run_relayer_inner()     → relayer loop
│                        #   - run_verifier_cycle()    → verifier loop
│
├── nostr.rs             # Nostr integration
│                        #   - kind 41000-41005 constants
│                        #   - spawn_nostr_subscriber()
│                        #   - publish_event()
│                        #   - legacy 72xx kinds
│
├── manage.rs            # DaemonConfig
│                        #   - execution_mode: "direct" | "escrow" | "both"
│                        #   - escrow_contract, kv_account, worker_stake_yocto
│                        #   - fund_timeout, settle_timeout
│                        #   - load(), rpc_url()
│
└── nonce.rs             # NonceCache for tx sequencing
```

## Job Queue Contract API (Direct Mode)

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

## Host Functions (available to WASM)

- **RPC Proxy** — make NEAR RPC calls (query, tx, view_account, etc.)
- **Storage** — persistent key-value storage (put/get/delete/increment)

## Examples

### test-storage
```bash
cd examples/test-storage && cargo build --target wasm32-wasip2 --release
inlayer run target/wasm32-wasip2/release/test-storage-ark.wasm '{"command":"set","key":"hello","value":"world"}'
```

### rpc-test
```bash
cd examples/rpc-test && cargo build --target wasm32-wasip2 --release
inlayer run target/wasm32-wasip2/release/rpc-test-ark.wasm '{"action":"view_account","account_id":"test.near"}'
```

## Build

```bash
# Daemon binary
cd worker && cargo build --release --bin inlayer

# Job queue contract
cd contract && cargo near build non-reproducible-wasm
```

## Test

```bash
cd worker && cargo test  # 17 tests
```

## Key Design Decisions

- Daemon is dumb pipe — routes tasks, handles KV writes, submits results. No business logic.
- One process, three threads (relayer + worker + verifier). No separate processes to manage.
- Nostr is discovery only — contracts don't know about it.
- FastNear KV for large results — small KV reference on-chain, full data off-chain.
- Verifier thread is optional — skips if GEMINI_API_KEY not set.
- CLI subcommands (relayer, verifier) still work standalone for debugging.
- escrow_client.rs is bridge code — works with any escrow contract, no inlayer internals leak.

## License

MIT
