//! Integration tests for the Nostr publish/subscribe pipeline.
//!
//! Spawns a mock WebSocket relay, publishes events via `publish_event`,
//! receives them via `spawn_nostr_subscriber`, and verifies full round-trip
//! integrity: signing → WebSocket → relay → WebSocket → parsing.
//!
//! Uses `#[test]` (not `#[tokio::test]`) because the production code
//! (`publish_event`, `spawn_nostr_subscriber`) creates its own tokio runtimes,
//! which panics if nested inside another runtime.

use std::time::Duration;

use crossbeam_channel::Receiver;
use futures_util::{SinkExt, StreamExt};
use offchainvm_worker::daemon::nostr::{
    build_signed_event, npub_from_nsec, publish_event, spawn_nostr_subscriber, NostrEvent,
    KIND_CLAIM, KIND_CONFIRMED, KIND_DISPATCH, KIND_RESULT, KIND_TASK,
};

// ── Mock relay ──────────────────────────────────────────────────────────

/// Start a mock Nostr relay on a random port. Returns (url, shutdown_sender).
///
/// The relay runs in a dedicated tokio runtime on a background thread.
/// Call `shutdown_sender.send(())` to stop it.
fn start_mock_relay() -> (String, tokio::sync::oneshot::Sender<()>) {
    let (addr_tx, addr_rx) = std::sync::mpsc::channel();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    std::thread::Builder::new()
        .name("mock-relay".into())
        .spawn(move || {
            let rt = tokio::runtime::Runtime::new().expect("relay runtime");
            rt.block_on(async move {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                    .await
                    .expect("bind");
                let addr = listener.local_addr().expect("no addr");
                addr_tx.send(addr).expect("send addr");

                run_relay(listener, shutdown_rx).await;
            });
        })
        .expect("spawn relay thread");

    let addr = addr_rx.recv().expect("relay addr");
    (format!("ws://{}", addr), shutdown_tx)
}

/// Relay event loop: accept connections, forward events between clients.
async fn run_relay(
    listener: tokio::net::TcpListener,
    mut shutdown: tokio::sync::oneshot::Receiver<()>,
) {
    let (event_tx, _) = tokio::sync::broadcast::channel::<String>(256);

    loop {
        tokio::select! {
            result = listener.accept() => {
                let (stream, _) = match result {
                    Ok(s) => s,
                    Err(_) => continue,
                };

                let event_tx = event_tx.clone();
                let mut event_rx = event_tx.subscribe();

                tokio::spawn(async move {
                    let ws = match tokio_tungstenite::accept_async(stream).await {
                        Ok(ws) => ws,
                        Err(_) => return,
                    };

                    let (sink, mut read_stream) = ws.split();
                    let sink = std::sync::Arc::new(tokio::sync::Mutex::new(sink));

                    // Forward broadcast events to this client
                    let sink_fwd = sink.clone();
                    let fwd_task = tokio::spawn(async move {
                        loop {
                            match event_rx.recv().await {
                                Ok(msg_text) => {
                                    let mut s = sink_fwd.lock().await;
                                    if s.send(tokio_tungstenite::tungstenite::Message::Text(msg_text.into())).await.is_err() {
                                        break;
                                    }
                                }
                                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                                Err(_) => break,
                            }
                        }
                    });

                    // Read loop: handle REQ and EVENT messages
                    while let Some(Ok(msg)) = read_stream.next().await {
                        match msg {
                            tokio_tungstenite::tungstenite::Message::Text(text) => {
                                let s = text.as_str();

                                if s.starts_with("[\"REQ\"") {
                                    let arr: Vec<serde_json::Value> =
                                        serde_json::from_str(s).unwrap_or_default();
                                    let sub_id = arr.get(1).and_then(|v| v.as_str()).unwrap_or("sub");
                                    let eose = format!("[\"EOSE\", \"{}\"]", sub_id);
                                    let mut s = sink.lock().await;
                                    let _ = s.send(tokio_tungstenite::tungstenite::Message::Text(eose.into())).await;
                                } else if s.starts_with("[\"EVENT\"") {
                                    let arr: Vec<serde_json::Value> =
                                        serde_json::from_str(s).unwrap_or_default();

                                    // Extract event id for OK ack
                                    let event_id = arr
                                        .get(1)
                                        .and_then(|v| v["id"].as_str())
                                        .or_else(|| arr.get(2).and_then(|v| v["id"].as_str()))
                                        .unwrap_or("unknown");

                                    // Extract the event object (relay format may be
                                    // ["EVENT", event] from client or ["EVENT", sub, event] from relay)
                                    let event_obj = if arr.len() >= 3 && arr.get(2).map_or(false, |v| v.is_object()) {
                                        &arr[2]
                                    } else if arr.len() >= 2 && arr.get(1).map_or(false, |v| v.is_object()) {
                                        &arr[1]
                                    } else {
                                        continue;
                                    };

                                    // Relay to subscribers in NIP-01 format:
                                    // ["EVENT", "sub_id", {event_object}]
                                    let relay_msg = serde_json::json!(["EVENT", "inlayer", event_obj]).to_string();
                                    let _ = event_tx.send(relay_msg);

                                    // Send OK ack back to publisher
                                    let ok_msg = format!("[\"OK\", \"{}\", true, \"\"]", event_id);
                                    let mut s = sink.lock().await;
                                    let _ = s.send(tokio_tungstenite::tungstenite::Message::Text(ok_msg.into())).await;
                                }
                            }
                            tokio_tungstenite::tungstenite::Message::Ping(data) => {
                                let mut s = sink.lock().await;
                                let _ = s.send(tokio_tungstenite::tungstenite::Message::Pong(data)).await;
                            }
                            tokio_tungstenite::tungstenite::Message::Close(_) => break,
                            _ => {}
                        }
                    }

                    fwd_task.abort();
                });
            }
            _ = &mut shutdown => break,
        }
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────

/// Test signing key (deterministic, 32 bytes hex).
const TEST_NSEC: &str = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";

/// Wait for the subscriber to connect and subscribe.
fn wait_for_subscriber() {
    std::thread::sleep(Duration::from_millis(500));
}

// ── Tests ───────────────────────────────────────────────────────────────

#[test]
fn test_nostr_publish_subscribe_roundtrip() {
    let (url, _shutdown) = start_mock_relay();

    // Start subscriber
    let rx = spawn_nostr_subscriber(vec![url.clone()]);
    wait_for_subscriber();

    // Publish a kind 41000 (TASK) event
    let tags = vec![vec!["job_id".into(), "roundtrip-001".into()]];
    let content = r#"{"program":"kv-writer","input":"{}"}"#;

    publish_event(&url, TEST_NSEC, KIND_TASK, content, tags).expect("publish should succeed");

    // Subscriber should receive it
    let event = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("subscriber should receive the event");

    assert_eq!(event.kind, KIND_TASK);
    assert_eq!(event.content, content);
    assert!(event
        .tags
        .iter()
        .any(|t| t.len() >= 2 && t[0] == "job_id" && t[1] == "roundtrip-001"));
    assert!(!event.id.is_empty());
    assert!(!event.sig.is_empty());
    assert!(!event.pubkey.is_empty());
    assert!(event.created_at > 0);
}

#[test]
fn test_nostr_multiple_event_kinds() {
    let (url, _shutdown) = start_mock_relay();

    let rx = spawn_nostr_subscriber(vec![url.clone()]);
    wait_for_subscriber();

    // Publish three different event kinds
    let cases = vec![
        (KIND_TASK, r#"{"program":"kv-writer"}"#, vec![vec!["job_id".into(), "k1".into()]]),
        (KIND_RESULT, r#"{"job_id":"k1","output":"done"}"#, vec![vec!["job_id".into(), "k1".into()]]),
        (KIND_CONFIRMED, r#"{"job_id":"k1","status":"Claimed"}"#, vec![]),
    ];

    for (kind, content, tags) in &cases {
        publish_event(&url, TEST_NSEC, *kind, content, tags.clone())
            .expect("publish should succeed");
        // Small delay between publishes
        std::thread::sleep(Duration::from_millis(50));
    }

    // Receive and verify each event
    for (expected_kind, expected_content, _) in &cases {
        let event = rx
            .recv_timeout(Duration::from_secs(5))
            .unwrap_or_else(|_| panic!("should receive kind {}", expected_kind));
        assert_eq!(event.kind, *expected_kind, "received wrong kind");
        assert_eq!(event.content, *expected_content, "content mismatch for kind {}", expected_kind);
    }
}

#[test]
fn test_nostr_signed_event_integrity() {
    let (url, _shutdown) = start_mock_relay();

    let rx = spawn_nostr_subscriber(vec![url.clone()]);
    wait_for_subscriber();

    // Build a signed event manually
    let tags = vec![
        vec!["job_id".into(), "integrity-001".into()],
        vec!["worker_msig".into(), "worker.testnet".into()],
    ];
    let content = r#"{"job_id":"integrity-001","result":"hash_abc123"}"#;

    let event_json =
        build_signed_event(TEST_NSEC, KIND_RESULT, content, tags.clone()).expect("sign should work");
    let original: serde_json::Value =
        serde_json::from_str(&event_json).expect("event json valid");

    let _original_id = original["id"].as_str().unwrap();
    let original_pubkey = original["pubkey"].as_str().unwrap();
    let _original_sig = original["sig"].as_str().unwrap();

    // Publish the signed event via publish_event (re-signs, but we verify
    // the subscriber receives a valid signed event with matching pubkey)
    publish_event(&url, TEST_NSEC, KIND_RESULT, content, tags).expect("publish");

    let received = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("should receive signed event");

    // Pubkey must match (same nsec → same pubkey)
    assert_eq!(received.pubkey, original_pubkey, "pubkey must match");
    // Kind and content must match
    assert_eq!(received.kind, KIND_RESULT);
    assert_eq!(received.content, content);
    // Id and sig must be valid (non-empty, correct length)
    assert_eq!(received.id.len(), 64, "id should be 64 hex chars");
    assert_eq!(received.sig.len(), 128, "sig should be 128 hex chars");
    // Tags preserved
    assert_eq!(received.tags.len(), 2);
    assert_eq!(received.tags[0][0], "job_id");
    assert_eq!(received.tags[1][0], "worker_msig");
}

#[test]
fn test_nostr_tag_preservation_with_worker_msig() {
    let (url, _shutdown) = start_mock_relay();

    let rx = spawn_nostr_subscriber(vec![url.clone()]);
    wait_for_subscriber();

    // Simulate a worker posting kind 41002 with pre-signed msig actions
    let tags = vec![
        vec!["job_id".into(), "msig-test-001".into()],
        vec!["worker_msig".into(), "worker.v1.testnet".into()],
        vec!["claim_action".into(), r#"{"nonce":5,"action":{"type":"claim","job_id":"msig-test-001"}}"#.into()],
        vec!["claim_sig".into(), "ff".repeat(64)], // 128 hex = 64 bytes
        vec!["submit_action".into(), r#"{"nonce":6,"action":{"type":"submit_result","job_id":"msig-test-001"}}"#.into()],
        vec!["submit_sig".into(), "ee".repeat(64)],
    ];

    let content = r#"{"job_id":"msig-test-001","output":"QmXyz..."}"#;

    publish_event(&url, TEST_NSEC, KIND_RESULT, content, tags).expect("publish");

    let event = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("should receive event");

    // All 6 tags preserved
    assert_eq!(event.tags.len(), 6, "all tags must survive roundtrip");

    let find_tag = |name: &str| -> Option<String> {
        event
            .tags
            .iter()
            .find(|t| t.len() >= 2 && t[0] == name)
            .and_then(|t| t.get(1).cloned())
    };

    assert_eq!(find_tag("job_id").unwrap(), "msig-test-001");
    assert_eq!(find_tag("worker_msig").unwrap(), "worker.v1.testnet");
    assert!(find_tag("claim_action").unwrap().contains("claim"));
    assert_eq!(find_tag("claim_sig").unwrap().len(), 128);
    assert!(find_tag("submit_action").unwrap().contains("submit_result"));
    assert_eq!(find_tag("submit_sig").unwrap().len(), 128);
}

#[test]
fn test_nostr_pubkey_matches_nsec() {
    let (url, _shutdown) = start_mock_relay();

    let rx = spawn_nostr_subscriber(vec![url.clone()]);
    wait_for_subscriber();

    publish_event(&url, TEST_NSEC, KIND_TASK, "test", vec![]).expect("publish");

    let event = rx.recv_timeout(Duration::from_secs(5)).expect("receive");

    let expected_npub = npub_from_nsec(TEST_NSEC).expect("derive npub");
    assert_eq!(event.pubkey, expected_npub, "event pubkey must match signing key");
}

#[test]
fn test_nostr_relay_broadcasts_to_multiple_subscribers() {
    let (url, _shutdown) = start_mock_relay();

    // Two independent subscribers
    let rx1 = spawn_nostr_subscriber(vec![url.clone()]);
    let rx2 = spawn_nostr_subscriber(vec![url.clone()]);
    wait_for_subscriber();

    // Publish one event
    publish_event(&url, TEST_NSEC, KIND_DISPATCH, r#"{"job_id":"multi"}"#, vec![])
        .expect("publish");

    // Both subscribers should receive it
    let ev1 = rx1.recv_timeout(Duration::from_secs(5)).expect("sub1 should receive");
    let ev2 = rx2.recv_timeout(Duration::from_secs(5)).expect("sub2 should receive");

    assert_eq!(ev1.kind, KIND_DISPATCH);
    assert_eq!(ev2.kind, KIND_DISPATCH);
    assert_eq!(ev1.id, ev2.id, "both should get same event id");
}

#[test]
fn test_nostr_subscriber_receives_own_events() {
    // The subscriber receives ALL events — filtering happens in the handler,
    // not the subscriber. Verify the subscriber passes through events from
    // its own pubkey (the handler is responsible for skipping them).
    let (url, _shutdown) = start_mock_relay();

    let rx = spawn_nostr_subscriber(vec![url.clone()]);
    wait_for_subscriber();

    publish_event(&url, TEST_NSEC, KIND_CLAIM, r#"{"job_id":"loop-test"}"#, vec![])
        .expect("publish");

    let event = rx.recv_timeout(Duration::from_secs(5)).expect("subscriber receives all events");
    assert_eq!(event.kind, KIND_CLAIM);

    // Verify pubkey matches the signing key
    let npub = npub_from_nsec(TEST_NSEC).unwrap();
    assert_eq!(event.pubkey, npub);
}
