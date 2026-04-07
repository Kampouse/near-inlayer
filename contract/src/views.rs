use crate::*;

#[near_bindgen]
impl Contract {
    /// Get execution request by ID
    pub fn get_request(&self, request_id: u64) -> Option<ExecutionRequest> {
        self.pending_requests.get(&request_id)
    }

    /// Get IDs of pending execution requests with pagination
    pub fn get_pending_request_ids(&self, from_index: Option<u64>, limit: Option<u64>) -> Vec<u64> {
        let from = from_index.unwrap_or(0);
        let max_limit = limit.unwrap_or(100);
        let mut result = Vec::new();
        let mut skipped = 0u64;
        for request_id in 0..self.next_request_id {
            if self.pending_requests.contains_key(&request_id) {
                if skipped < from { skipped += 1; continue; }
                result.push(request_id);
                if result.len() as u64 >= max_limit { break; }
            }
        }
        result
    }

    /// Get contract statistics
    pub fn get_stats(&self) -> (u64, U128) {
        (self.total_executions, U128(self.total_fees_collected))
    }

    /// Get current NEAR pricing
    pub fn get_pricing(&self) -> (U128, U128, U128, U128) {
        (
            U128(self.base_fee),
            U128(self.per_million_instructions_fee),
            U128(self.per_ms_fee),
            U128(self.per_compile_ms_fee),
        )
    }

    /// Estimate cost for given resource limits
    pub fn estimate_execution_cost(&self, resource_limits: Option<ResourceLimits>) -> U128 {
        let limits = resource_limits.unwrap_or_default();
        U128(self.estimate_cost(&limits))
    }

    /// Get maximum resource limits
    pub fn get_max_limits(&self) -> (u64, u64, u64) {
        (MAX_INSTRUCTIONS, MAX_EXECUTION_SECONDS, MAX_COMPILATION_SECONDS)
    }

    /// Check if contract is paused
    pub fn is_paused(&self) -> bool {
        self.paused
    }

    /// Get owner and operator
    pub fn get_config(&self) -> (AccountId, AccountId, bool) {
        (self.owner_id.clone(), self.operator_id.clone(), self.open_resolution)
    }

    /// Get event metadata
    pub fn get_event_metadata(&self) -> (String, String) {
        (self.event_standard.clone(), self.event_version.clone())
    }
}
