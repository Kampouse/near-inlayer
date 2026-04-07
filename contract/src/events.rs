use crate::*;
use near_sdk::serde::Serialize;
use near_sdk::serde_json::json;

pub mod emit {
    use super::*;

    #[derive(Serialize)]
    #[serde(crate = "near_sdk::serde")]
    struct ExecutionRequestedEventData<'a> {
        pub request_data: &'a String,
        pub data_id: CryptoHash,
        pub timestamp: u64,
    }

    #[derive(Serialize)]
    #[serde(crate = "near_sdk::serde")]
    struct ExecutionCompletedEventData<'a> {
        pub sender_id: &'a AccountId,
        pub code_source: &'a CodeSource,
        pub resources_used: &'a ResourceMetrics,
        pub success: bool,
        pub error_message: Option<&'a str>,
        pub payment_charged: U128,
        pub payment_refunded: U128,
        pub compilation_note: Option<&'a str>,
        pub timestamp: u64,
    }

    fn log_event<T: Serialize>(standard: &str, version: &str, event: &str, data: T) {
        let event = json!({
            "standard": standard,
            "version": version,
            "event": event,
            "data": [data]
        });
        near_sdk::log!("EVENT_JSON:{}", event.to_string());
    }

    pub fn execution_requested(standard: &str, version: &str, request_data: &String, data_id: CryptoHash) {
        log_event(standard, version, "execution_requested", ExecutionRequestedEventData {
            request_data,
            data_id,
            timestamp: near_sdk::env::block_timestamp(),
        });
    }

    pub fn execution_completed(
        standard: &str, version: &str,
        sender_id: &AccountId, code_source: &CodeSource,
        resources_used: &ResourceMetrics, success: bool,
        error_message: Option<&str>, payment_charged: U128, payment_refunded: U128,
        compilation_note: Option<&str>,
    ) {
        log_event(standard, version, "execution_completed", ExecutionCompletedEventData {
            sender_id, code_source, resources_used, success, error_message,
            payment_charged, payment_refunded, compilation_note,
            timestamp: near_sdk::env::block_timestamp(),
        });
    }
}
