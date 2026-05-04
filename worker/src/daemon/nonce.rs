//! Nonce cache with pipelining for high-throughput transaction submission.

use std::sync::Mutex;

use anyhow::{bail, Result};
use near_crypto::InMemorySigner;
use near_jsonrpc_client::{methods, JsonRpcClient};
use near_jsonrpc_primitives::types::query::QueryResponseKind;
use near_primitives::action::{Action, FunctionCallAction};
use near_primitives::hash::CryptoHash;
use near_primitives::transaction::{Transaction, TransactionV0};
use near_primitives::types::BlockReference;
use near_primitives::views::QueryRequest;
use near_crypto::Signer;

/// Fetch the current nonce and block hash for the signer.
pub(crate) fn fetch_nonce_block(rpc_url: &str, signer: &InMemorySigner) -> Result<(u64, CryptoHash)> {
    let client = JsonRpcClient::connect(rpc_url);
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let query = methods::query::RpcQueryRequest {
            block_reference: BlockReference::latest(),
            request: QueryRequest::ViewAccessKey {
                account_id: signer.account_id.clone(),
                public_key: signer.public_key.clone(),
            },
        };
        let response = client.call(query).await?;
        let nonce = match response.kind {
            QueryResponseKind::AccessKey(ak) => ak.nonce + 1,
            _ => bail!("unexpected query response for access key"),
        };
        Ok((nonce, response.block_hash))
    })
}

/// Nonce cache inner state.
pub(crate) struct NonceCacheInner {
    pub(crate) nonce: Option<u64>,
    pub(crate) block_hash: Option<CryptoHash>,
}

/// Nonce cache with pipelining for high-throughput tx submission.
/// 
/// Instead of fetching a fresh nonce for every transaction, the cache reserves
/// a contiguous batch (e.g. 5 nonces at once) so multiple resolve transactions
/// can be signed and sent in parallel without contention. If any tx fails with
/// `InvalidNonce`, the cache is invalidated and re-fetched on the next batch.
pub(crate) struct NonceCache {
    pub(crate) inner: Mutex<NonceCacheInner>,
    pub(crate) rpc_url: String,
    pub(crate) signer: InMemorySigner,
}

impl NonceCache {
    pub(crate) fn new(rpc_url: String, signer: InMemorySigner) -> Self {
        Self { inner: Mutex::new(NonceCacheInner { nonce: None, block_hash: None }), rpc_url, signer }
    }

    /// Create a NonceCache for unit tests (won't hit RPC unless reserve_batch is called).
    #[cfg(test)]
    pub(crate) fn new_for_test() -> Self {
        use near_crypto::SecretKey;
        Self {
            inner: Mutex::new(NonceCacheInner { nonce: None, block_hash: None }),
            rpc_url: "http://localhost:0".to_string(),
            signer: InMemorySigner::from_secret_key(
                "test.near".parse().unwrap(),
                SecretKey::from_random(near_crypto::KeyType::ED25519),
            ),
        }
    }

    pub(crate) fn reserve_batch(&self, count: usize) -> Result<(u64, CryptoHash)> {
        let mut inner = self.inner.lock().unwrap();
        if inner.nonce.is_none() {
            drop(inner);
            let (nonce, hash) = fetch_nonce_block(&self.rpc_url, &self.signer)?;
            inner = self.inner.lock().unwrap();
            inner.nonce = Some(nonce);
            inner.block_hash = Some(hash);
        }
        let base = inner.nonce.unwrap();
        let hash = inner.block_hash.unwrap();
        inner.nonce = Some(base + count as u64);
        Ok((base, hash))
    }

    pub(crate) fn invalidate(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.nonce = None;
        inner.block_hash = None;
    }

    pub(crate) fn prefill(&self, nonce: u64, block_hash: CryptoHash) {
        let mut inner = self.inner.lock().unwrap();
        if inner.nonce.is_none() {
            inner.nonce = Some(nonce);
            inner.block_hash = Some(block_hash);
        }
    }
}

/// Resolve a single execution request on-chain.
pub(crate) fn resolve_one(
    rpc_url: &str, signer: &InMemorySigner, contract: &str,
    req_id: u64, success: bool, output: &str, time_ms: u64, instructions: u64,
    nonce: u64, block_hash: CryptoHash,
) -> Result<String> {
    let args = serde_json::json!({
        "request_id": req_id,
        "response": {
            "success": success,
            "output": {"Text": output},
            "error": if success { serde_json::Value::Null } else { serde_json::Value::String("Execution failed".into()) },
            "resources_used": {"instructions": instructions, "time_ms": time_ms},
            "compilation_note": null,
            "refund_usd": null,
        }
    });
    let client = JsonRpcClient::connect(rpc_url);
    let rt = tokio::runtime::Runtime::new()?;
    let signer_account_id = signer.account_id.clone();
    let signer_public_key = signer.public_key.clone();
    let signer_clone = signer.clone();
    let contract_id: near_primitives::types::AccountId = contract.parse()?;
    let method_name = "resolve_execution".to_string();
    let args_bytes = serde_json::to_vec(&args)?;
    rt.block_on(async {
        let transaction = TransactionV0 {
            signer_id: signer_account_id,
            public_key: signer_public_key,
            nonce,
            receiver_id: contract_id,
            block_hash,
            actions: vec![Action::FunctionCall(Box::new(FunctionCallAction {
                method_name, args: args_bytes, gas: 100_000_000_000_000, deposit: 0,
            }))],
        };
        let signed_tx = Transaction::V0(transaction).sign(&Signer::InMemory(signer_clone));
        let tx_hash = format!("{:?}", signed_tx.get_hash());
        client.call(methods::send_tx::RpcSendTransactionRequest {
            signed_transaction: signed_tx,
            wait_until: near_primitives::views::TxExecutionStatus::ExecutedOptimistic,
        }).await.map_err(|e| anyhow::anyhow!("send_tx failed: {}", e))?;
        Ok(tx_hash)
    })
}

/// Resolve a batch of execution requests on-chain.
pub(crate) fn resolve_batch(
    nonce_cache: &NonceCache, signer: &InMemorySigner, contract: &str,
    payloads: Vec<(u64, bool, String, u64, u64)>,
) -> Vec<(u64, Result<String>)> {
    if payloads.is_empty() { return Vec::new(); }

    if payloads.len() == 1 {
        let (req_id, success, output, time_ms, instructions) = &payloads[0];
        for attempt in 0..5 {
            let (base_nonce, block_hash) = match nonce_cache.reserve_batch(1) {
                Ok(r) => r,
                Err(e) => return vec![(*req_id, Err(anyhow::anyhow!("nonce fetch failed: {}", e)))],
            };
            let result = resolve_one(&nonce_cache.rpc_url, signer, contract, *req_id, *success, output, *time_ms, *instructions, base_nonce, block_hash);
            match &result {
                Ok(_) => return vec![(*req_id, result)],
                Err(e) if e.to_string().contains("InvalidNonce") => {
                    nonce_cache.invalidate();
                    if attempt < 4 { continue; }
                }
                Err(_) => return vec![(*req_id, result)],
            }
        }
        return vec![(*req_id, Err(anyhow::anyhow!("nonce retry exhausted")))];
    }

    let entries: Vec<serde_json::Value> = payloads.iter().map(|(req_id, success, output, time_ms, instructions)| {
        serde_json::json!([
            req_id,
            {
                "success": success,
                "output": {"Text": output},
                "error": if *success { serde_json::Value::Null } else { serde_json::Value::String("Execution failed".into()) },
                "resources_used": {"instructions": instructions, "time_ms": time_ms},
                "compilation_note": null,
                "refund_usd": null,
            }
        ])
    }).collect();

    let args = serde_json::json!({ "entries": entries });
    let rpc_url = &nonce_cache.rpc_url;

    let (base_nonce, block_hash) = match nonce_cache.reserve_batch(1) {
        Ok(r) => r,
        Err(e) => {
            nonce_cache.invalidate();
            return payloads.into_iter().map(|(id, _, _, _, _)| (id, Err(anyhow::anyhow!("nonce fetch failed: {}", e)))).collect();
        }
    };

    let result = (|| -> Result<String> {
        let client = JsonRpcClient::connect(rpc_url);
        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(async {
            let transaction = TransactionV0 {
                signer_id: signer.account_id.clone(),
                public_key: signer.public_key.clone(),
                nonce: base_nonce,
                receiver_id: contract.parse()?,
                block_hash,
                actions: vec![Action::FunctionCall(Box::new(FunctionCallAction {
                    method_name: "batch_resolve_execution".to_string(),
                    args: serde_json::to_vec(&args)?,
                    gas: 100_000_000_000_000 * payloads.len() as u64,
                    deposit: 0,
                }))],
            };
            let signed_tx = Transaction::V0(transaction).sign(&Signer::InMemory(signer.clone()));
            let tx_hash = format!("{:?}", signed_tx.get_hash());
            client.call(methods::broadcast_tx_commit::RpcBroadcastTxCommitRequest {
                signed_transaction: signed_tx,
            }).await.map_err(|e| anyhow::anyhow!("batch broadcast failed: {}", e))?;
            Ok(tx_hash)
        })
    })();

    match result {
        Ok(tx_hash) => payloads.into_iter().map(|(id, _, _, _, _)| (id, Ok(tx_hash.clone()))).collect(),
        Err(e) => {
            nonce_cache.invalidate();
            payloads.into_iter().map(|(id, _, _, _, _)| (id, Err(anyhow::anyhow!("batch resolve failed: {}", e)))).collect()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_for_test_creates_cache() {
        let cache = NonceCache::new_for_test();
        let inner = cache.inner.lock().unwrap();
        assert!(inner.nonce.is_none());
        assert!(inner.block_hash.is_none());
    }

    #[test]
    fn test_prefill_sets_nonce_when_empty() {
        let cache = NonceCache::new_for_test();
        let hash = CryptoHash::default();
        cache.prefill(42, hash);
        let inner = cache.inner.lock().unwrap();
        assert_eq!(inner.nonce, Some(42));
        assert_eq!(inner.block_hash, Some(hash));
    }

    #[test]
    fn test_prefill_does_not_overwrite() {
        let cache = NonceCache::new_for_test();
        let hash = CryptoHash::default();
        cache.prefill(10, hash);
        cache.prefill(99, hash); // should be ignored
        let inner = cache.inner.lock().unwrap();
        assert_eq!(inner.nonce, Some(10));
    }

    #[test]
    fn test_invalidate_clears_cache() {
        let cache = NonceCache::new_for_test();
        let hash = CryptoHash::default();
        cache.prefill(42, hash);
        cache.invalidate();
        let inner = cache.inner.lock().unwrap();
        assert!(inner.nonce.is_none());
        assert!(inner.block_hash.is_none());
    }

    #[test]
    fn test_invalidate_on_already_empty() {
        let cache = NonceCache::new_for_test();
        cache.invalidate(); // should not panic
        let inner = cache.inner.lock().unwrap();
        assert!(inner.nonce.is_none());
    }

    #[test]
    fn test_reserve_batch_increments() {
        let cache = NonceCache::new_for_test();
        let hash = CryptoHash::default();
        cache.prefill(100, hash);

        let (base1, _) = cache.reserve_batch(5).unwrap();
        assert_eq!(base1, 100);

        let inner = cache.inner.lock().unwrap();
        assert_eq!(inner.nonce, Some(105));
        drop(inner);

        let (base2, _) = cache.reserve_batch(3).unwrap();
        assert_eq!(base2, 105);

        let inner = cache.inner.lock().unwrap();
        assert_eq!(inner.nonce, Some(108));
    }

    #[test]
    fn test_reserve_batch_after_invalidate_then_prefill() {
        let cache = NonceCache::new_for_test();
        let hash = CryptoHash::default();
        cache.prefill(50, hash);
        cache.invalidate();
        cache.prefill(200, hash);

        let (base, _) = cache.reserve_batch(2).unwrap();
        assert_eq!(base, 200);
    }

    #[test]
    fn test_resolve_batch_empty_payload() {
        let cache = NonceCache::new_for_test();
        let signer = InMemorySigner::from_secret_key(
            "test.near".parse().unwrap(),
            near_crypto::SecretKey::from_random(near_crypto::KeyType::ED25519),
        );
        let result = resolve_batch(&cache, &signer, "contract.testnet", vec![]);
        assert!(result.is_empty());
    }
}
