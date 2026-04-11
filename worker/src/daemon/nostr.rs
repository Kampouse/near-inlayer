//! Nostr subscriber — listens to relay for agent coordination events.
//!
//! Kinds:
//!   7201 — dispatch    (Hermes A submits a task)
//!   7202 — available   (daemon acknowledges, includes contract request_id)
//!   7203 — result      (Hermes B submits work result)
//!   7204 — claim       (Hermes B claims a job)
//!   7205 — confirmed   (daemon confirms on-chain resolution)
//!
//! The subscriber runs in a background thread with its own tokio runtime
//! (same pattern as block watcher). Events are forwarded via crossbeam channel.

use std::time::Duration;

use crossbeam_channel::{Receiver, Sender};

// ── Coordination kinds ─────────────────────────────────────────────────────

pub const KIND_DISPATCH: u64 = 7201;
pub const KIND_JOB_AVAILABLE: u64 = 7202;
pub const KIND_RESULT: u64 = 7203;
pub const KIND_CLAIM: u64 = 7204;
pub const KIND_CONFIRMED: u64 = 7205;

/// Kinds the daemon subscribes to.
const SUBSCRIPTION_KINDS: &[u64] = &[KIND_DISPATCH, KIND_RESULT, KIND_CLAIM];

// ── Parsed event ───────────────────────────────────────────────────────────

/// Parsed Nostr event relevant to agent coordination.
#[derive(Debug, Clone)]
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
pub fn spawn_nostr_subscriber(relay_url: &str) -> Receiver<NostrEvent> {
    let (tx, rx) = crossbeam_channel::bounded(64);
    let relay = relay_url.to_string();

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

            loop {
                match rt.block_on(nostr_loop(&relay, &tx)) {
                    Ok(()) => tracing::info!("Nostr: disconnected, reconnecting in 5s..."),
                    Err(e) => tracing::error!("Nostr: {}, reconnecting in 5s...", e),
                }
                std::thread::sleep(Duration::from_secs(5));
            }
        })
        .expect("failed to spawn nostr subscriber thread");

    rx
}

/// WebSocket loop — connect, subscribe, read events until disconnect.
async fn nostr_loop(
    relay_url: &str,
    tx: &Sender<NostrEvent>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    let url = normalize_relay_url(relay_url);

    tracing::info!(" nostr connecting to {}...", url);
    let (ws, _) = tokio_tungstenite::connect_async(&url).await?;
    tracing::info!(" nostr connected ✓");

    let (mut write, mut read) = ws.split();

    // Subscribe to coordination kinds — limit 0 = only new events, no history
    let filter = serde_json::json!({
        "kinds": SUBSCRIPTION_KINDS,
        "limit": 0
    });
    let sub_msg = serde_json::to_string(&serde_json::json!(["REQ", "inlayer", filter]))?;
    write.send(sub_msg.into()).await?;
    tracing::info!(
        " nostr subscribed (kinds {:?})",
        SUBSCRIPTION_KINDS
    );

    // Read loop
    while let Some(msg) = read.next().await {
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
                let _ = write.send(Message::Pong(data)).await;
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

fn normalize_relay_url(url: &str) -> String {
    if url.starts_with("wss://") || url.starts_with("ws://") {
        url.to_string()
    } else {
        format!("wss://{}", url)
    }
}

fn kind_label(kind: u64) -> &'static str {
    match kind {
        KIND_DISPATCH => "dispatch",
        KIND_JOB_AVAILABLE => "job-available",
        KIND_RESULT => "result",
        KIND_CLAIM => "claim",
        KIND_CONFIRMED => "confirmed",
        _ => "unknown",
    }
}

/// Parse `["EVENT", "sub_id", { ... }]` from relay message.
fn parse_nostr_message(text: &str) -> Option<NostrEvent> {
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
    let event_id = hex::encode(&hash);

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

    let rt = tokio::runtime::Runtime::new()?;
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
            }
            Ok(false) => {
                tracing::warn!(" nostr kind={} rejected by relay", kind);
                // Still return Ok — the event might have been published despite rejection
            }
            Err(_) => {
                tracing::info!(" nostr kind={} sent (timeout waiting for ack)", kind);
            }
        }

        Ok(())
    })
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
