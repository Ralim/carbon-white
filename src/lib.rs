#![recursion_limit = "256"]
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

pub use app::*;

#[cfg(feature = "ssr")]
#[derive(Clone)]
pub struct AppState {
    pub database: sqlx::SqlitePool,
    pub data_dir: String,
    pub auth_key: String,
    pub whitelist_ips: Vec<std::net::IpAddr>,
}

#[cfg(feature = "hydrate")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn hydrate() {
    use crate::app::*;
    console_error_panic_hook::set_once();
    leptos::mount::hydrate_body(App);
}
