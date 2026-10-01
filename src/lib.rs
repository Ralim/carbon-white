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
    pub whitelist_ips: Vec<ip_subnet::IPSubnet>,
}

#[cfg(feature = "hydrate")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn hydrate() {
    use crate::app::*;
    console_error_panic_hook::set_once();
    leptos::mount::hydrate_body(App);
}
