//! KV Writer — WASI P2 component for NEAR FastData KV writes
//!
//! Input (stdin): {"action":"write","signer_id":"account.near","signer_key":"ed25519:...","receiver_id":"account.near","entries":{"key":"value"}}
//! Output (stdout): {"success":true,"tx_hash":"...","entries_written":2}

use outlayer::raw::rpc;
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};

#[derive(Deserialize)]
struct Input {
    action: Option<String>,
    signer_id: String,
    signer_key: String,
    receiver_id: Option<String>,
    entries: serde_json::Map<String, serde_json::Value>,
}

#[derive(Serialize)]
struct Output {
    success: bool,
    tx_hash: Option<String>,
    entries_written: usize,
    error: Option<String>,
}

fn main() {
    let mut input = String::new();
    let _ = io::stdin().read_to_string(&mut input);

    let inp: Input = match serde_json::from_str(&input) {
        Ok(i) => i,
        Err(e) => {
            let out = Output { success: false, tx_hash: None, entries_written: 0, error: Some(format!("Parse error: {}", e)) };
            let _ = io::stdout().write_all(serde_json::to_string(&out).unwrap().as_bytes());
            return;
        }
    };

    let action = inp.action.as_deref().unwrap_or("write");

    match action {
        "write" => {
            let receiver_id = inp.receiver_id.unwrap_or_else(|| inp.signer_id.clone());
            let count = inp.entries.len();
            let args = serde_json::to_string(&inp.entries).unwrap();

            let (tx_hash, error) = rpc::call(
                &inp.signer_id,
                &inp.signer_key,
                &receiver_id,
                "__fastdata_kv",
                &args,
                "0",
                "300000000000000",
                "NONE",
            );

            let ok = error.is_empty();
            let out = Output {
                success: ok,
                tx_hash: if ok { Some(tx_hash) } else { None },
                entries_written: if ok { count } else { 0 },
                error: if ok { None } else { Some(error) },
            };
            let _ = io::stdout().write_all(serde_json::to_string(&out).unwrap().as_bytes());
        }
        _ => {
            let out = Output { success: false, tx_hash: None, entries_written: 0, error: Some(format!("Unknown action: {}", action)) };
            let _ = io::stdout().write_all(serde_json::to_string(&out).unwrap().as_bytes());
        }
    }
}
