use serde::{Deserialize, Serialize};

/// Shared struct for authentication status response.
/// Used by both backend (API) and frontend (client) code.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuthStatusResponse {
    pub authenticated: bool,
}
