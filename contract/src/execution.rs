use crate::*;
use near_sdk::serde_json::json;

#[near_bindgen]
impl Contract {
    /// Request off-chain execution
    #[payable]
    pub fn request_execution(
        &mut self,
        source: ExecutionSource,
        resource_limits: Option<ResourceLimits>,
        input_data: Option<String>,
        response_format: Option<ResponseFormat>,
        params: Option<RequestParams>,
    ) {
        self.assert_not_paused();

        let (resolved_source, _project_uuid) = self.resolve_execution_source(&source);
        let limits = resource_limits.clone().unwrap_or_default();
        let request_params = params.unwrap_or_default();
        let compile_only = request_params.compile_only || resource_limits.is_none();

        // Validate resource limits
        if !compile_only {
            let max_instructions = limits.max_instructions.unwrap_or_default();
            let max_execution_seconds = limits.max_execution_seconds.unwrap_or_default();
            assert!(max_instructions <= MAX_INSTRUCTIONS, "max_instructions exceeds limit");
            assert!(max_execution_seconds <= MAX_EXECUTION_SECONDS, "max_execution_seconds exceeds limit");
        }

        let estimated_cost = if compile_only { self.base_fee } else { self.estimate_cost(&limits) };
        let payment = env::attached_deposit().as_yoctonear();
        assert!(payment >= estimated_cost, "Insufficient payment: required {} yoctoNEAR, got {}", estimated_cost, payment);

        let request_id = self.next_request_id;
        self.next_request_id += 1;

        let predecessor_id = env::predecessor_account_id();
        let signer_id = env::signer_account_id();
        let format = response_format.unwrap_or_default();

        // Handle large input data
        let input_data_in_state = input_data.as_ref().map(|d| d.len() >= INPUT_DATA_EVENT_THRESHOLD).unwrap_or(false);
        let input_data_for_event = if input_data_in_state { String::new() } else { input_data.as_ref().cloned().unwrap_or_default() };

        let request_data = json!({
            "request_id": request_id,
            "sender_id": signer_id,
            "predecessor_id": predecessor_id,
            "code_source": resolved_source,
            "resource_limits": limits,
            "input_data": input_data_for_event,
            "input_data_in_state": input_data_in_state,
            "response_format": format,
            "payment": U128::from(payment),
            "timestamp": env::block_timestamp(),
            "compile_only": compile_only,
        });

        let data_id: CryptoHash = CryptoHash::default();

        let execution_request = ExecutionRequest {
            request_id,
            data_id,
            sender_id: predecessor_id.clone(),
            execution_source: source,
            resolved_source: resolved_source.clone(),
            resource_limits: limits,
            payment,
            timestamp: env::block_timestamp(),
            response_format: format,
            input_data,
        };

        self.pending_requests.insert(&request_id, &execution_request);
        events::emit::execution_requested(&self.event_standard, &self.event_version, &request_data.to_string(), data_id);
        log!("Request #{} queued (payment: {} yoctoNEAR)", request_id, payment);
    }

    /// Worker calls this to resolve execution
    pub fn resolve_execution(&mut self, request_id: u64, response: ExecutionResponse) {
        self.assert_resolver();
        self.resolve_execution_internal(request_id, response);
    }

    /// Batch resolve multiple executions in a single transaction
    pub fn batch_resolve_execution(&mut self, entries: Vec<(u64, ExecutionResponse)>) -> u32 {
        self.assert_resolver();
        let mut resolved = 0u32;
        for (request_id, response) in entries {
            if self.pending_requests.contains_key(&request_id) {
                self.resolve_execution_internal(request_id, response);
                resolved += 1;
            } else {
                log!("Skipping unknown request_id: {}", request_id);
            }
        }
        resolved
    }

    /// Cancel stale execution request (10 min timeout)
    pub fn cancel_stale_execution(&mut self, request_id: u64) {
        let request = self.pending_requests.get(&request_id)
            .expect("Execution request not found");
        assert_eq!(env::predecessor_account_id(), request.sender_id, "Only the sender can cancel");
        assert!(env::block_timestamp() > request.timestamp + EXECUTION_TIMEOUT, "Not yet stale");

        if let Some(stale_request) = self.pending_requests.remove(&request_id) {
            near_sdk::Promise::new(stale_request.sender_id.clone())
                .transfer(NearToken::from_yoctonear(stale_request.payment));
            log!("Cancelled stale execution {} and refunded {}", request_id, stale_request.sender_id);
        }
    }
}

impl Contract {
    fn resolve_execution_internal(&mut self, request_id: u64, response: ExecutionResponse) {
        let request = self.pending_requests.get(&request_id)
            .expect("Execution request not found");

        self.total_executions += 1;

        if response.success {
            let cost = self.calculate_cost(&response.resources_used);
            let refund = request.payment.saturating_sub(cost);

            if refund > 0 {
                near_sdk::Promise::new(request.sender_id.clone())
                    .transfer(NearToken::from_yoctonear(refund));
            }
            self.total_fees_collected += cost;

            events::emit::execution_completed(
                &self.event_standard, &self.event_version,
                &request.sender_id, &request.resolved_source,
                &response.resources_used, true, None,
                U128(cost), U128(refund), response.compilation_note.as_deref(),
            );

            let output_preview = match &response.output {
                Some(ExecutionOutput::Text(t)) => format!("Text({} bytes)", t.len()),
                Some(ExecutionOutput::Bytes(b)) => format!("Bytes({} bytes)", b.len()),
                Some(ExecutionOutput::Json(v)) => format!("Json({} bytes)", serde_json::to_string(v).map(|s| s.len()).unwrap_or(0)),
                None => "None".to_string(),
            };
            log!("Request #{} resolved: {} | cost: {} yN | refund: {} yN", request_id, output_preview, cost, refund);
        } else {
            let refund = request.payment.saturating_sub(self.base_fee);
            if refund > 0 {
                near_sdk::Promise::new(request.sender_id.clone())
                    .transfer(NearToken::from_yoctonear(refund));
            }
            self.total_fees_collected += self.base_fee;

            let error_msg = response.error.as_deref().unwrap_or("Unknown error");
            events::emit::execution_completed(
                &self.event_standard, &self.event_version,
                &request.sender_id, &request.resolved_source,
                &response.resources_used, false, Some(error_msg),
                U128(self.base_fee), U128(refund), response.compilation_note.as_deref(),
            );
            log!("Request #{} failed: {} | base fee: {} yN", request_id, error_msg, self.base_fee);
        }

        self.pending_requests.remove(&request_id);
    }
}
