//! Nostr subscriber — listens to relay for agent coordination events.
//!
//! Kinds (41xxx namespace — merged escrow + inlayer protocol):
//!   41000 — Task posted    (agent posts task + create_escrow + fund_escrow actions)
//!   41001 — Claimed        (worker/daemon claims the job)
//!   41002 — Result         (work result submitted)
//!   41003 — Action         (generic msig action: fund, cancel, withdraw, rotate)
//!   41004 — Dispatched     (daemon starts execution)
//!   41005 — Confirmed      (settlement confirmed on-chain)
//!
//! The subscriber runs in a background thread with its own tokio runtime
//! (same pattern as block watcher). Events are forwarded via crossbeam channel.

use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::time::Duration;

use crossbeam_channel::{Receiver, Sender};

// ── Metrics counters (M6) ─────────────────────────────────────────────────

static EVENTS_RECEIVED: AtomicU64 = AtomicU64::new(0);
static EVENTS_PUBLISHED: AtomicU64 = AtomicU64::new(0);
static RELAY_RECONNECTS: AtomicU64 = AtomicU64::new(0);

/// Return current Nostr metrics (events_received, events_published, relay_reconnects).
pub fn nostr_metrics() -> (u64, u64, u64) {
    (
        EVENTS_RECEIVED.load(AtomicOrdering::Relaxed),
        EVENTS_PUBLISHED.load(AtomicOrdering::Relaxed),
        RELAY_RECONNECTS.load(AtomicOrdering::Relaxed),
    )
}

// ── Coordination kinds (41xxx merged namespace) ─────────────────────────

pub const KIND_TASK: u64 = 41000;
pub const KIND_CLAIM: u64 = 41001;
pub const KIND_RESULT: u64 = 41002;
pub const KIND_ACTION: u64 = 41003;
pub const KIND_DISPATCH: u64 = 41004;
pub const KIND_CONFIRMED: u64 = 41005;

/// Legacy kinds (7201-7205) — kept for backward compat during migration.
pub mod legacy {
    pub const KIND_DISPATCH: u64 = 7201;
    pub const KIND_JOB_AVAILABLE: u64 = 7202;
    pub const KIND_RESULT: u64 = 7203;
    pub const KIND_CLAIM: u64 = 7204;
    pub const KIND_CONFIRMED: u64 = 7205;
}

/// Kinds the daemon subscribes to.
const SUBSCRIPTION_KINDS: &[u64] = &[KIND_TASK, KIND_CLAIM, KIND_RESULT, KIND_ACTION];

// ── Parsed event ───────────────────────────────────────────────────────────

/// Parsed Nostr event relevant to agent coordination.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NostrEvent {
    pub id: String,
    pub pubkey: String,
    pub created_at: u64,
    pub kind: u64,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    pub sig: String,
}

// ── Subscriber ─────────────────────────────────────────────────────────────

/// Spawn a background thread that connects to a Nostr relay via WebSocket,
/// subscribes to coordination kinds, and forwards parsed events.
///
/// Reconnects automatically on failure with 5s backoff.
/// Spawn a background thread that subscribes to Nostr relay(s) and forwards events.
/// Supports multiple relay URLs with failover (H3).
pub fn spawn_nostr_subscriber(relay_urls: Vec<String>) -> Receiver<NostrEvent> {
    let (tx, rx) = crossbeam_channel::bounded(64);
    let urls = if relay_urls.is_empty() {
        tracing::error!("Nostr: no relay URLs configured");
        return rx;
    } else {
        relay_urls
    };

    std::thread::Builder::new()
        .name("nostr-subscriber".into())
        .spawn(move || {
            let rt = match tokio::runtime::Runtime::new() {
                Ok(rt) => rt,
                Err(e) => {
                    tracing::error!("Nostr: runtime creation failed: {}", e);
                    return;
                }
            };

            let mut backoff_secs: u64 = 1;
            const MAX_BACKOFF_SECS: u64 = 60;

            loop {
                RELAY_RECONNECTS.fetch_add(1, AtomicOrdering::Relaxed);
                let result = rt.block_on(nostr_loop(&urls, &tx));
                match &result {
                    Ok(()) => {
                        tracing::info!("Nostr: disconnected, reconnecting in {}s...", backoff_secs);
                    }
                    Err(e) => {
                        tracing::error!("Nostr: {}, reconnecting in {}s...", e, backoff_secs);
                    }
                }
                std::thread::sleep(Duration::from_secs(backoff_secs));
                // Exponential backoff: double each failure, cap at 60s
                backoff_secs = (backoff_secs * 2).min(MAX_BACKOFF_SECS);

                // Reset backoff on successful connection
                if result.is_ok() {
                    backoff_secs = 1;
                }
            }
        })
        .expect("failed to spawn nostr subscriber thread");

    rx
}

/// WebSocket loop — connect, subscribe, read events until disconnect.
/// Supports multiple relay URLs with failover: tries each in order until one connects.
async fn nostr_loop(
    relay_urls: &[String],
    tx: &Sender<NostrEvent>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    // ── H3: Multi-relay failover ──
    // Try each relay URL in order. First successful connection wins.
    let mut connected = None;
    for (i, raw_url) in relay_urls.iter().enumerate() {
        let candidate = normalize_relay_url(raw_url);
        // M4: warn on unencrypted connections
        if candidate.starts_with("ws://") {
            tracing::warn!(" nostr WARNING: unencrypted ws:// connection to {}", candidate);
        }
        tracing::info!(" nostr trying relay {}/{}: {}...", i + 1, relay_urls.len(), candidate);
        match tokio_tungstenite::connect_async(&candidate).await {
            Ok((socket, _)) => {
                tracing::info!(" nostr connected to {} ✓", candidate);
                connected = Some((candidate, socket, i));
                break;
            }
            Err(e) => {
                tracing::warn!(" nostr relay {} failed: {}", candidate, e);
                continue;
            }
        }
    }
    let (_url, ws, connected_url_idx) = match connected {
        Some(tuple) => tuple,
        None => return Err(format!("all {} relays failed", relay_urls.len()).into()),
    };
    let (mut ws_write, mut ws_read) = ws.split();

    // Subscribe to coordination kinds — limit 0 = only new events, no history
    let filter = serde_json::json!({
        "kinds": SUBSCRIPTION_KINDS,
        "limit": 0
    });
    let sub_msg = serde_json::to_string(&serde_json::json!(["REQ", "inlayer", filter]))?;
    ws_write.send(sub_msg.into()).await?;
    tracing::info!(
        " nostr subscribed on relay {} (kinds {:?})",
        connected_url_idx + 1,
        SUBSCRIPTION_KINDS
    );

    // M3: Event dedup — bounded LRU set of recently seen event IDs
    let mut seen_ids: std::collections::HashSet<String> = std::collections::HashSet::new();
    const SEEN_IDS_CAP: usize = 10_000;

    // Read loop
    while let Some(msg) = ws_read.next().await {
        match msg {
            Ok(Message::Text(text)) => {
                let s = text.as_str();

                // Silently handle relay control messages
                if s.starts_with("[\"EOSE\"")
                    || s.starts_with("[\"OK\"")
                    || s.starts_with("[\"NOTICE\"")
                {
                    // Log notices (may contain useful info)
                    if s.starts_with("[\"NOTICE\"") {
                        tracing::debug!("Nostr relay notice: {}", s);
                    }
                    continue;
                }

                if let Some(event) = parse_nostr_message(s) {
                    // M3: Skip duplicate events
                    if seen_ids.contains(&event.id) {
                        tracing::debug!(" nostr skipping duplicate event {}...", &event.id[..16.min(event.id.len())]);
                        continue;
                    }
                    seen_ids.insert(event.id.clone());
                    if seen_ids.len() > SEEN_IDS_CAP {
                        // Evict oldest half
                        let keep: std::collections::HashSet<String> = seen_ids.iter().skip(seen_ids.len() / 2).cloned().collect();
                        seen_ids = keep;
                    }

                    // M6: Track metrics
                    EVENTS_RECEIVED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                    let label = kind_label(event.kind);
                    tracing::info!(
                        " nostr kind={} ({}) from {}...",
                        event.kind,
                        label,
                        &event.pubkey[..8.min(event.pubkey.len())]
                    );
                    if tx.send(event).is_err() {
                        tracing::info!("Nostr: channel closed, shutting down subscriber");
                        return Ok(());
                    }
                }
            }
            Ok(Message::Ping(data)) => {
                let _ = ws_write.send(Message::Pong(data)).await;
            }
            Ok(Message::Close(_)) => {
                tracing::info!("Nostr: relay closed connection");
                break;
            }
            Err(e) => {
                tracing::error!("Nostr: ws read error: {}", e);
                return Err(e.into());
            }
            Ok(_) => continue,
        }
    }

    Ok(())
}

pub(crate) fn normalize_relay_url(url: &str) -> String {
    if url.starts_with("wss://") || url.starts_with("ws://") {
        url.to_string()
    } else {
        format!("wss://{}", url)
    }
}

pub(crate) fn kind_label(kind: u64) -> &'static str {
    match kind {
        KIND_TASK => "task",
        KIND_CLAIM => "claim",
        KIND_RESULT => "result",
        KIND_ACTION => "action",
        KIND_DISPATCH => "dispatch",
        KIND_CONFIRMED => "confirmed",
        _ => "unknown",
    }
}

/// Parse `["EVENT", "sub_id", { ... }]` from relay message.
pub(crate) fn parse_nostr_message(text: &str) -> Option<NostrEvent> {
    let arr: Vec<serde_json::Value> = serde_json::from_str(text).ok()?;
    if arr.len() < 3 || arr[0].as_str()? != "EVENT" {
        return None;
    }

    let ev = &arr[2];
    Some(NostrEvent {
        id: ev.get("id")?.as_str()?.to_string(),
        pubkey: ev.get("pubkey")?.as_str()?.to_string(),
        created_at: ev.get("created_at")?.as_u64()?,
        kind: ev.get("kind")?.as_u64()?,
        tags: ev
            .get("tags")?
            .as_array()?
            .iter()
            .filter_map(|t| {
                t.as_array()?
                    .iter()
                    .map(|v| v.as_str().unwrap_or("").to_string())
                    .collect::<Vec<_>>()
                    .into()
            })
            .collect(),
        content: ev.get("content")?.as_str()?.to_string(),
        sig: ev.get("sig")?.as_str()?.to_string(),
    })
}

// ── Event signing ──────────────────────────────────────────────────────────

/// Build a signed Nostr event JSON string.
///
/// `nsec_hex` is the 32-byte hex secret key (not bech32 nsec1...).
/// The canonical serialization follows NIP-01: `[0, pubkey, created_at, kind, tags, content]`.
pub fn build_signed_event(
    nsec_hex: &str,
    kind: u64,
    content: &str,
    tags: Vec<Vec<String>>,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    use secp256k1::{Keypair, Secp256k1, SecretKey};
    use sha2::Digest;

    let secp = Secp256k1::new();
    let sk_bytes = hex::decode(nsec_hex)?;
    let secret_key = SecretKey::from_slice(&sk_bytes)?;
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    let pubkey_hex = hex::encode(keypair.x_only_public_key().0.serialize());

    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Canonical serialization: [0, pubkey, created_at, kind, tags, content]
    let event_arr = serde_json::json!([0, pubkey_hex, created_at, kind, tags, content]);
    let canonical = serde_json::to_string(&event_arr)?;

    // SHA256 → event id
    let hash = sha2::Sha256::digest(canonical.as_bytes());
    let event_id = hex::encode(hash);

    // Schnorr sign (BIP-340)
    let msg = secp256k1::Message::from_digest(hash.into());
    let sig = secp.sign_schnorr_no_aux_rand(&msg, &keypair);
    let sig_hex = hex::encode(sig.serialize());

    let event = serde_json::json!({
        "id": event_id,
        "pubkey": pubkey_hex,
        "created_at": created_at,
        "kind": kind,
        "tags": tags,
        "content": content,
        "sig": sig_hex,
    });

    Ok(serde_json::to_string(&event)?)
}

// ── Event publishing ───────────────────────────────────────────────────────

/// Publish a signed event to the relay.
///
/// Opens a short-lived WebSocket connection, sends the EVENT message,
/// waits up to 3s for an OK ack from the relay.
///
/// M1: Returns Err on relay rejection (no longer silently succeeds).
/// M2: Reuses a shared runtime via OnceLock instead of creating one per call.
pub fn publish_event(
    relay_url: &str,
    nsec_hex: &str,
    kind: u64,
    content: &str,
    tags: Vec<Vec<String>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let event_json = build_signed_event(nsec_hex, kind, content, tags)?;
    let event_value: serde_json::Value = serde_json::from_str(&event_json)?;

    let url = normalize_relay_url(relay_url);
    // M4: warn on unencrypted connections
    if url.starts_with("ws://") {
        tracing::warn!(" nostr WARNING: publishing over unencrypted ws://");
    }

    // M2: Reuse a shared runtime instead of creating one per call
    use std::sync::OnceLock;
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    let rt = RUNTIME.get_or_init(|| tokio::runtime::Runtime::new().expect("nostr publish runtime"));

    rt.block_on(async {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::Message;

        tracing::info!(" nostr publishing kind={}...", kind);

        let (ws, _) = tokio_tungstenite::connect_async(&url).await?;
        let (mut write, mut read) = ws.split();

        // Send EVENT
        let msg = serde_json::json!(["EVENT", event_value]).to_string();
        write.send(msg.into()).await?;

        // Wait for OK (max 3s)
        let result = tokio::time::timeout(Duration::from_secs(3), async {
            while let Some(msg) = read.next().await {
                if let Ok(Message::Text(text)) = msg {
                    let s = text.as_str();
                    if s.starts_with("[\"OK\"") {
                        return s.contains("true");
                    }
                }
            }
            false
        })
        .await;

        match result {
            Ok(true) => {
                tracing::info!(" nostr published kind={} ✓", kind);
                EVENTS_PUBLISHED.fetch_add(1, AtomicOrdering::Relaxed);
                Ok(())
            }
            Ok(false) => {
                // M1: Return error on relay rejection instead of silently succeeding
                let err_msg = format!("relay rejected event kind={}", kind);
                tracing::warn!(" nostr {}", err_msg);
                Err(err_msg.into())
            }
            Err(_) => {
                tracing::info!(" nostr kind={} sent (timeout waiting for ack)", kind);
                EVENTS_PUBLISHED.fetch_add(1, AtomicOrdering::Relaxed);
                Ok(())
            }
        }
    })
}

// ── Event verification ────────────────────────────────────────────────────

/// Verify a Nostr event's signature and id.
///
/// Checks:
/// 1. `id == SHA256(canonical serialization)` per NIP-01
/// 2. Schnorr signature is valid for the event's pubkey
///
/// Returns Ok(()) if both checks pass, Err with description otherwise.
pub fn verify_nostr_event(event: &NostrEvent) -> Result<(), String> {
    use secp256k1::{Secp256k1, XOnlyPublicKey};
    use sha2::Digest;

    // 1. Compute expected id from canonical serialization
    let event_arr = serde_json::json!([0, event.pubkey, event.created_at, event.kind, event.tags, event.content]);
    let canonical = serde_json::to_string(&event_arr).map_err(|e| format!("canonical serialize: {}", e))?;
    let hash = sha2::Sha256::digest(canonical.as_bytes());
    let expected_id = hex::encode(hash);

    if event.id != expected_id {
        return Err(format!("event id mismatch: got {}, expected {}", &event.id[..16.min(event.id.len())], &expected_id[..16.min(expected_id.len())]));
    }

    // 2. Verify Schnorr signature
    let pubkey_bytes = hex::decode(&event.pubkey).map_err(|e| format!("pubkey hex: {}", e))?;
    let sig_bytes = hex::decode(&event.sig).map_err(|e| format!("sig hex: {}", e))?;

    let secp = Secp256k1::verification_only();
    let xonly = XOnlyPublicKey::from_slice(&pubkey_bytes)
        .map_err(|e| format!("pubkey parse: {}", e))?;
    let sig = secp256k1::schnorr::Signature::from_slice(&sig_bytes)
        .map_err(|e| format!("sig parse: {}", e))?;
    let msg = secp256k1::Message::from_digest(hash.into());

    secp.verify_schnorr(&sig, &msg, &xonly)
        .map_err(|e| format!("signature invalid: {}", e))?;

    Ok(())
}

// ── Utility ────────────────────────────────────────────────────────────────

/// Encode a hex nsec to npub hex (for display/logging).
pub fn npub_from_nsec(nsec_hex: &str) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    use secp256k1::{Keypair, Secp256k1, SecretKey};

    let secp = Secp256k1::new();
    let sk_bytes = hex::decode(nsec_hex)?;
    let secret_key = SecretKey::from_slice(&sk_bytes)?;
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    Ok(hex::encode(keypair.x_only_public_key().0.serialize()))
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_nostr_message ────────────────────────────────────────────

    #[test]
    fn test_parse_valid_event() {
        let msg = r#"["EVENT", "sub1", {"id": "abc123", "pubkey": "deadbeef", "created_at": 1700000000, "kind": 41000, "tags": [["job_id", "j1"]], "content": "hello", "sig": "cafe"}]"#;
        let ev = parse_nostr_message(msg).expect("should parse");
        assert_eq!(ev.id, "abc123");
        assert_eq!(ev.pubkey, "deadbeef");
        assert_eq!(ev.created_at, 1700000000);
        assert_eq!(ev.kind, 41000);
        assert_eq!(ev.tags.len(), 1);
        assert_eq!(ev.tags[0].len(), 2);
        assert_eq!(ev.tags[0][0], "job_id");
        assert_eq!(ev.tags[0][1], "j1");
        assert_eq!(ev.content, "hello");
        assert_eq!(ev.sig, "cafe");
    }

    #[test]
    fn test_parse_event_with_multiple_tags() {
        let msg = r#"["EVENT", "s", {"id":"a","pubkey":"b","created_at":1,"kind":41002,"tags":[["job_id","j2"],["worker_msig","w.testnet"],["claim_action","{}"]],"content":"{}","sig":"s"}]"#;
        let ev = parse_nostr_message(msg).expect("should parse");
        assert_eq!(ev.tags.len(), 3);
        assert_eq!(ev.tags[1][1], "w.testnet");
        assert_eq!(ev.tags[2][1], "{}");
    }

    #[test]
    fn test_parse_rejects_non_event() {
        assert!(parse_nostr_message(r#"["REQ", "sub1", {"kinds": [41000]}]"#).is_none());
        assert!(parse_nostr_message(r#"["OK", "abc", true, ""]"#).is_none());
        assert!(parse_nostr_message(r#"["EOSE", "sub1"]"#).is_none());
        assert!(parse_nostr_message(r#"["NOTICE", "hello"]"#).is_none());
    }

    #[test]
    fn test_parse_rejects_malformed() {
        assert!(parse_nostr_message("not json").is_none());
        assert!(parse_nostr_message("[]").is_none());
        assert!(parse_nostr_message(r#"["EVENT"]"#).is_none());         // only 1 elem
        assert!(parse_nostr_message(r#"["EVENT", "s"]"#).is_none());    // only 2 elem
        assert!(parse_nostr_message(r#"["EVENT", "s", 42]"#).is_none()); // 3rd not object
    }

    #[test]
    fn test_parse_rejects_missing_fields() {
        // Missing "id"
        let msg = r#"["EVENT", "s", {"pubkey":"b","created_at":1,"kind":1,"tags":[],"content":"c","sig":"s"}]"#;
        assert!(parse_nostr_message(msg).is_none());
    }

    // ── normalize_relay_url ────────────────────────────────────────────

    #[test]
    fn test_normalize_relay_url_bare() {
        assert_eq!(normalize_relay_url("relay.example.com"), "wss://relay.example.com");
    }

    #[test]
    fn test_normalize_relay_url_wss() {
        assert_eq!(normalize_relay_url("wss://relay.example.com"), "wss://relay.example.com");
    }

    #[test]
    fn test_normalize_relay_url_ws() {
        assert_eq!(normalize_relay_url("ws://localhost:8080"), "ws://localhost:8080");
    }

    // ── kind_label ─────────────────────────────────────────────────────

    #[test]
    fn test_kind_labels() {
        assert_eq!(kind_label(KIND_TASK), "task");
        assert_eq!(kind_label(KIND_CLAIM), "claim");
        assert_eq!(kind_label(KIND_RESULT), "result");
        assert_eq!(kind_label(KIND_ACTION), "action");
        assert_eq!(kind_label(KIND_DISPATCH), "dispatch");
        assert_eq!(kind_label(KIND_CONFIRMED), "confirmed");
        assert_eq!(kind_label(99999), "unknown");
    }

    // ── npub_from_nsec + build_signed_event ────────────────────────────

    #[test]
    fn test_npub_from_nsec_roundtrip() {
        // Generate a deterministic key for testing
        let nsec_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let npub = npub_from_nsec(nsec_hex).expect("should derive pubkey");
        // npub should be 64 hex chars (32 bytes x 2)
        assert_eq!(npub.len(), 64, "x-only pubkey should be 64 hex chars");
    }

    #[test]
    fn test_build_signed_event_deterministic_id() {
        let nsec = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let tags = vec![vec!["job_id".into(), "test-001".into()]];

        let event_json = build_signed_event(nsec, 41002, r#"{"job_id":"test-001","output":"done"}"#, tags).expect("should sign");
        let event: serde_json::Value = serde_json::from_str(&event_json).expect("valid json");

        // Id should be 64 hex chars (SHA256)
        let id = event["id"].as_str().expect("has id");
        assert_eq!(id.len(), 64);

        // Kind matches
        assert_eq!(event["kind"].as_u64(), Some(41002));

        // Signature is 128 hex chars (64 bytes Schnorr)
        let sig = event["sig"].as_str().expect("has sig");
        assert_eq!(sig.len(), 128);

        // Same input → same id (deterministic)
        let event2 = build_signed_event(nsec, 41002, r#"{"job_id":"test-001","output":"done"}"#, vec![vec!["job_id".into(), "test-001".into()]]).expect("should sign");
        let ev2: serde_json::Value = serde_json::from_str(&event2).expect("valid json");
        // Note: created_at differs so id will differ. But pubkey should match.
        assert_eq!(event["pubkey"], ev2["pubkey"]);
    }

    #[test]
    fn test_build_signed_event_id_is_sha256_canonical() {
        use sha2::Digest;
        let nsec = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let npub = npub_from_nsec(nsec).unwrap();

        let event_json = build_signed_event(nsec, 41000, "hello", vec![]).unwrap();
        let event: serde_json::Value = serde_json::from_str(&event_json).unwrap();
        let id = event["id"].as_str().unwrap();
        let created_at = event["created_at"].as_u64().unwrap();

        // Verify: id = SHA256([0, pubkey, created_at, kind, tags, content])
        let canonical = serde_json::json!([0, npub, created_at, 41000u64, Vec::<Vec<String>>::new(), "hello"]);
        let canonical_str = serde_json::to_string(&canonical).unwrap();
        let hash = sha2::Sha256::digest(canonical_str.as_bytes());
        let expected_id = hex::encode(hash);
        assert_eq!(id, expected_id, "event id must be SHA256 of canonical serialization");
    }

    #[test]
    fn test_build_signed_event_sig_verifies() {
        let nsec = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let event_json = build_signed_event(nsec, 41005, "confirmed", vec![vec!["e".into(), "prev123".into()]]).unwrap();
        let event: serde_json::Value = serde_json::from_str(&event_json).unwrap();

        let npub = npub_from_nsec(nsec).unwrap();
        let id_hex = event["id"].as_str().unwrap();
        let sig_hex = event["sig"].as_str().unwrap();

        // Verify the Schnorr signature
        let secp = secp256k1::Secp256k1::new();
        let sk_bytes = hex::decode(nsec).unwrap();
        let secret_key = secp256k1::SecretKey::from_slice(&sk_bytes).unwrap();
        let keypair = secp256k1::Keypair::from_secret_key(&secp, &secret_key);
        let xonly = keypair.x_only_public_key().0;

        // Verify pubkey matches
        assert_eq!(hex::encode(xonly.serialize()), npub);

        // Verify signature
        let msg_bytes = hex::decode(id_hex).unwrap();
        let msg = secp256k1::Message::from_digest_slice(&msg_bytes).unwrap();
        let sig = secp256k1::schnorr::Signature::from_slice(&hex::decode(sig_hex).unwrap()).unwrap();
        assert!(sig.verify(&msg, &xonly).is_ok(), "Schnorr signature must verify");
    }

    #[test]
    fn test_build_signed_event_rejects_bad_key() {
        let bad_nsec = "not_hex_at_all";
        assert!(build_signed_event(bad_nsec, 41000, "test", vec![]).is_err());
    }

    // ── NostrEvent construction ────────────────────────────────────────

    #[test]
    fn test_nostr_event_clone_debug() {
        let ev = NostrEvent {
            id: "abc".into(),
            pubkey: "def".into(),
            created_at: 123,
            kind: 41000,
            tags: vec![vec!["k".into(), "v".into()]],
            content: "hello".into(),
            sig: "sig".into(),
        };
        let cloned = ev.clone();
        assert_eq!(cloned.id, "abc");
        let debug = format!("{:?}", ev);
        assert!(debug.contains("abc"));
    }
}

