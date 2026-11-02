use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// Shared struct for authentication status response.
/// Used by both backend (API) and frontend (client) code.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuthStatusResponse {
    pub authenticated: bool,
}

/// Tracks which of several overlapping async requests is the newest.
///
/// Responses can arrive out of order, so each request takes an id from
/// [`LatestRequest::begin`] and only applies its result while
/// [`LatestRequest::is_current`] still holds.
#[derive(Debug, Clone, Default)]
pub struct LatestRequest(Arc<AtomicU64>);

impl LatestRequest {
    /// Starts a request, superseding every earlier one.
    pub fn begin(&self) -> u64 {
        self.0.fetch_add(1, Ordering::SeqCst) + 1
    }

    /// True when no newer request has started since `id`.
    pub fn is_current(&self, id: u64) -> bool {
        self.0.load(Ordering::SeqCst) == id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_latest_request_supersedes_older_ids() {
        let latest = LatestRequest::default();
        let first = latest.begin();
        assert!(latest.is_current(first));

        let second = latest.begin();
        assert!(!latest.is_current(first));
        assert!(latest.is_current(second));
    }

    #[test]
    fn test_latest_request_is_shared_between_clones() {
        let latest = LatestRequest::default();
        let handle = latest.clone();
        let first = latest.begin();
        handle.begin();
        assert!(!latest.is_current(first));
    }
}
