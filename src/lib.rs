#![recursion_limit = "1024"]
pub mod app;
pub mod components;
pub mod pages;
pub mod shared;

#[cfg(feature = "ssr")]
pub mod api;
#[cfg(feature = "ssr")]
pub mod auth;
#[cfg(feature = "ssr")]
pub mod database;
#[cfg(feature = "ssr")]
pub mod file_server;
pub mod ip_subnet;
#[cfg(feature = "ssr")]
pub mod rate_limit;
#[cfg(feature = "ssr")]
pub mod security_headers;

pub use app::*;

/// Largest file the upload endpoint accepts, in bytes.
pub const MAX_UPLOAD_SIZE: usize = 250 * 1024 * 1024;

/// Headroom added on top of [`MAX_UPLOAD_SIZE`] for multipart framing.
pub const MULTIPART_OVERHEAD: usize = 1024 * 1024;

#[cfg(feature = "ssr")]
#[derive(Clone)]
pub struct AppState {
    pub database: sqlx::SqlitePool,
    pub data_dir: String,
    pub auth_key: String,
    /// Addresses allowed to log in. Empty means loopback only.
    pub whitelist_ips: std::sync::Arc<[ip_subnet::IPSubnet]>,
    /// Peers whose `X-Forwarded-For` header is believed. Empty means none.
    pub trusted_proxies: std::sync::Arc<[ip_subnet::IPSubnet]>,
    /// Failed login tracking, shared by every clone of the state.
    pub login_limiter: std::sync::Arc<rate_limit::LoginRateLimiter>,
    /// Random key that signs session tokens. Regenerated on every start, so a
    /// restart logs everyone out.
    pub signing_key: std::sync::Arc<[u8]>,
}

#[cfg(feature = "ssr")]
impl AppState {
    /// Builds state with an empty whitelist (loopback only) and no trusted proxies.
    pub fn new(
        database: sqlx::SqlitePool,
        data_dir: impl Into<String>,
        auth_key: impl Into<String>,
    ) -> Self {
        Self {
            database,
            data_dir: data_dir.into(),
            auth_key: auth_key.into(),
            whitelist_ips: Vec::new().into(),
            trusted_proxies: Vec::new().into(),
            login_limiter: Default::default(),
            signing_key: auth::generate_signing_key().into(),
        }
    }

    pub fn with_whitelist(mut self, whitelist: Vec<ip_subnet::IPSubnet>) -> Self {
        self.whitelist_ips = whitelist.into();
        self
    }

    pub fn with_trusted_proxies(mut self, proxies: Vec<ip_subnet::IPSubnet>) -> Self {
        self.trusted_proxies = proxies.into();
        self
    }
}

#[cfg(feature = "hydrate")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn hydrate() {
    use crate::app::*;
    console_error_panic_hook::set_once();
    leptos::mount::hydrate_body(App);
}
