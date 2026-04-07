//! Block watcher using neardata.xyz event-driven polling.

use std::time::Duration;

use crossbeam_channel::Receiver;

/// Get the neardata.xyz base URL for a given network.
pub(crate) fn neardata_base_url(network: &str) -> String {
    match network {
        "mainnet" => "https://neardata.xyz".to_string(),
        _ => format!("https://{}.neardata.xyz", network),
    }
}

/// Discover the latest block height from neardata.xyz.
fn discover_neardata_height(base_url: &str) -> Option<u64> {
    let url = format!("{}/v0/last_block/final", base_url);
    let resp = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .ok()?
        .get(&url)
        .send()
        .ok()?;
    let final_url = resp.url();
    final_url.path_segments()
        .and_then(|mut s| s.next_back())
        .and_then(|s: &str| s.parse().ok())
}

/// Fallback: get block height directly from RPC.
fn get_rpc_block_height(rpc_url: &str) -> Option<u64> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .ok()?;
    let resp = client.post(rpc_url)
        .json(&serde_json::json!({"jsonrpc":"2.0","id":1,"method":"status","params":[]}))
        .send().ok()?;
    let body: serde_json::Value = resp.json().ok()?;
    body.get("result")?.get("sync_info")?.get("latest_block_height")?.as_u64()
}

/// Spawn a background thread that watches for new blocks.
/// Returns a channel that receives new block heights.
pub(crate) fn spawn_block_watcher(network: &str, rpc_url: &str, poll_interval_secs: u64) -> Receiver<u64> {
    let (tx, rx) = crossbeam_channel::bounded(16);
    let base_url = neardata_base_url(network);
    let rpc = rpc_url.to_string();
    std::thread::Builder::new()
        .name("block-watcher".into())
        .spawn(move || {
            let mut last_height: Option<u64> = None;
            let mut neardata_failures: u32 = 0;
            loop {
                let discovered = discover_neardata_height(&base_url);
                // Only fall back to RPC block height if neardata fails multiple times
                let discovered = discovered.or_else(|| {
                    if neardata_failures > 2 { get_rpc_block_height(&rpc) } else { None }
                });
                match discovered {
                    Some(height) => {
                        neardata_failures = 0;
                        if last_height != Some(height) {
                            last_height = Some(height);
                            if tx.send(height).is_err() { break; }
                        }
                        // Use longer interval when polling RPC (avoid rate limits)
                        std::thread::sleep(Duration::from_secs(poll_interval_secs));
                    }
                    None => {
                        neardata_failures += 1;
                        let backoff = if neardata_failures > 10 {
                            std::cmp::min(poll_interval_secs * 4, 300)
                        } else if neardata_failures > 3 {
                            poll_interval_secs * 2
                        } else {
                            poll_interval_secs
                        };
                        std::thread::sleep(Duration::from_secs(backoff));
                    }
                }
            }
        })
        .expect("failed to spawn block watcher thread");
    rx
}
