//! Test WASM for near:rpc/api http-get and http-post host functions.
//!
//! Build:  cargo build --target wasm32-wasip2 --release
//! Run:    inlayer run target/wasm32-wasip2/release/http-test.wasm '{}'

wit_bindgen::generate!({
    world: "http-test",
    path: "wit",
});

fn check(name: &str, ok: bool, detail: &str) -> bool {
    if ok {
        eprintln!("[PASS] {} — {}", name, detail);
    } else {
        eprintln!("[FAIL] {} — {}", name, detail);
    }
    ok
}

fn main() {
    let mut passed = 0u32;
    let mut failed = 0u32;

    // Test 1: http-get to httpbin
    {
        let (body, err) = near::rpc::api::http_get("https://httpbin.org/get", None);
        if check("http-get httpbin", err.is_empty() && !body.is_empty(),
            &format!("{} bytes{}", body.len(), if !err.is_empty() { "" } else { ", url field present" }))
        {
            let v: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
            check("  url field", !v["url"].is_null(), &v["url"].to_string());
            passed += 1;
        } else { failed += 1; }
    }

    // Test 2: http-post to httpbin
    {
        let (body, err) = near::rpc::api::http_post(
            "https://httpbin.org/post",
            r#"{"hello":"world","from":"near:rpc/api http-post"}"#,
            None,
        );
        if check("http-post httpbin", err.is_empty() && !body.is_empty(),
            &format!("{} bytes", body.len()))
        {
            let v: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
            check("  json field echoed", v.get("json").is_some(), "");
            passed += 1;
        } else { failed += 1; }
    }

    // Test 3: http-get to Rhea price API (real-world use case)
    {
        let (body, err) = near::rpc::api::http_get(
            "https://api.rhea.finance/list-token-price",
            None,
        );
        if check("http-get rhea prices", err.is_empty() && body.len() > 1000,
            &format!("{} bytes", body.len()))
        {
            let v: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
            check("  is JSON object", v.is_object(), "");
            passed += 1;
        } else { failed += 1; }
    }

    // Test 4: http-get with custom headers
    {
        let (body, err) = near::rpc::api::http_get(
            "https://httpbin.org/headers",
            Some(r#"{"X-Custom-Header":"test-value","Accept":"application/json"}"#),
        );
        if check("http-get with headers", err.is_empty() && !body.is_empty(),
            &format!("{} bytes", body.len()))
        {
            let v: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
            let echoed = v["headers"]["X-Custom-Header"].to_string();
            check("  custom header echoed", !v["headers"]["X-Custom-Header"].is_null(),
                &echoed);
            passed += 1;
        } else { failed += 1; }
    }

    eprintln!("\n=== Results: {}/{} passed ===", passed, passed + failed);
    println!(r#"{{"passed":{},"failed":{}}}"#, passed, failed);
}
