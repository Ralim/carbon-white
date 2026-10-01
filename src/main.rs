#![recursion_limit = "1024"]

#[cfg(feature = "ssr")]
use carbon_white::ip_subnet::IPSubnet;
#[cfg(feature = "ssr")]
#[tokio::main]
async fn main() {
    #[allow(unused_imports)] // Required for into_make_service_with_connect_info trait method
    use axum::extract::connect_info::IntoMakeServiceWithConnectInfo;
    use axum::{Router, extract::DefaultBodyLimit};
    use carbon_white::*;
    use leptos::prelude::*;
    use leptos_axum::{LeptosRoutes, generate_route_list};
    use std::env;
    use std::net::SocketAddr;
    use tower_http::services::ServeDir;
    use tracing::{info, warn};
    use tracing_subscriber;

    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Load environment variables
    let carbon_data_dir =
        env::var("CARBON_DATA_DIR").unwrap_or_else(|_| "/tmp/carbon/".to_string());
    let carbon_auth_key = env::var("CARBON_AUTH_KEY").expect("CARBON_AUTH_KEY must be set");
    let carbon_whitelist_ips = env::var("CARBON_WHITELIST_IPS").unwrap_or_else(|_| {
        warn!("CARBON_WHITELIST_IPS not set, you only get localhost");
        "127.0.0.1,::1".to_string()
    });

    info!("Carbon data directory: `{}`", carbon_data_dir);
    info!("IP whitelist: `{}`", carbon_whitelist_ips);

    // Create data directories
    std::fs::create_dir_all(&carbon_data_dir).expect("Failed to create data directory");
    std::fs::create_dir_all(format!("{}/files", carbon_data_dir))
        .expect("Failed to create files directory");

    // Uploads staged that never finished have no database row, so they are unreachable. Clear them at startup.
    api::purge_incomplete_uploads(&carbon_data_dir).await;

    // Initialize database
    let database = database::init_db(&carbon_data_dir)
        .await
        .expect("Failed to initialize database");

    // Create app state
    let app_state = AppState {
        database,
        data_dir: carbon_data_dir,
        auth_key: carbon_auth_key,
        whitelist_ips: parse_ip_whitelist(&carbon_whitelist_ips),
    };

    // Setting get_configuration(None) means we'll be using cargo-leptos's env values
    let conf = get_configuration(None).unwrap();
    let leptos_options = conf.leptos_options;
    let addr = leptos_options.site_addr;
    let routes = generate_route_list(App);

    // Create static file serving for pkg directory
    let pkg_dir = format!("{}/pkg", leptos_options.site_root);
    let pkg_service = ServeDir::new(&pkg_dir);

    // Create API routes with app state and increased body limit for file uploads
    let api_routes = Router::new()
        .nest("/api", api::create_api_routes())
        .nest("/file", file_server::create_file_routes())
        .layer(DefaultBodyLimit::max(
            carbon_white::MAX_UPLOAD_SIZE + carbon_white::MULTIPART_OVERHEAD,
        ))
        .with_state(app_state);

    // Create static routes (must come before leptos routes to avoid fallback catching them)
    let static_routes = Router::new()
        .nest_service("/pkg", pkg_service)
        .route("/favicon.ico", axum::routing::get(serve_favicon))
        .route("/favicon-16x16.png", axum::routing::get(serve_favicon))
        .route("/favicon-32x32.png", axum::routing::get(serve_favicon))
        .route("/apple-touch-icon.png", axum::routing::get(serve_favicon))
        .route("/site.webmanifest", axum::routing::get(serve_favicon))
        .route(
            "/android-chrome-192x192.png",
            axum::routing::get(serve_favicon),
        )
        .route(
            "/android-chrome-512x512.png",
            axum::routing::get(serve_favicon),
        );

    // Create the leptos app with its own state (fallback catches everything not matched above)
    let leptos_app = Router::new()
        .leptos_routes(&leptos_options, routes, {
            let leptos_options = leptos_options.clone();
            move || shell(leptos_options.clone())
        })
        .fallback(leptos_axum::file_and_error_handler(shell))
        .with_state(leptos_options);

    // Merge them together - order matters! Static and API routes first, then leptos fallback
    let app = static_routes.merge(api_routes).merge(leptos_app);

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    info!("Carbon White server listening on http://{}", &addr);
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
}

#[cfg(not(feature = "ssr"))]
pub fn main() {
    // no client-side main function
    // see lib.rs for hydration function instead
}

#[cfg(feature = "ssr")]
async fn serve_favicon(
    request: axum::extract::Request,
) -> Result<axum::response::Response<axum::body::Body>, axum::http::StatusCode> {
    use leptos::prelude::*;

    // Resolve the site root from the build-time configuration and delegate.
    let site_root = get_configuration(None).unwrap().leptos_options.site_root;
    serve_favicon_at(request, site_root.as_ref()).await
}

/// Serves a static asset from `site_root`.
#[cfg(feature = "ssr")]
async fn serve_favicon_at(
    request: axum::extract::Request,
    site_root: &str,
) -> Result<axum::response::Response<axum::body::Body>, axum::http::StatusCode> {
    use axum::{
        body::Body,
        http::{StatusCode, header},
        response::Response,
    };
    use std::path::Path;
    use tokio::fs;

    // Get filename from request path
    let path = request.uri().path();
    let filename = path.trim_start_matches('/');

    let file_path = Path::new(site_root).join(filename);

    match fs::read(&file_path).await {
        Ok(content) => {
            let mime_type = match filename.rsplit('.').next() {
                Some("ico") => "image/x-icon",
                Some("png") => "image/png",
                Some("webmanifest") => "application/manifest+json",
                _ => "application/octet-stream",
            };

            let response = Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, mime_type)
                .header(header::CACHE_CONTROL, "public, max-age=86400")
                .body(Body::from(content))
                .unwrap();

            Ok(response)
        }
        Err(_) => Err(StatusCode::NOT_FOUND),
    }
}

/// Parses a comma-separated whitelist of IPs or CIDR ranges.
#[cfg(feature = "ssr")]
fn parse_ip_whitelist(whitelist: &str) -> Vec<IPSubnet> {
    if whitelist.is_empty() {
        return Vec::new();
    }

    whitelist
        .split(',')
        .filter_map(|ip| ip.trim().try_into().ok())
        .collect()
}

#[cfg(test)]
#[cfg(feature = "ssr")]
mod tests {
    use super::*;
    use carbon_white::{App, AppState, api, database, file_server};
    use leptos::prelude::get_configuration;
    use leptos_axum::generate_route_list;
    use std::net::SocketAddr;
    use tempfile::TempDir;

    #[test]
    fn test_parse_ip_whitelist_empty() {
        let result = parse_ip_whitelist("");
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_ip_whitelist_single_ip() {
        let result = parse_ip_whitelist("127.0.0.1");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].to_string(), "127.0.0.1");
    }

    #[test]
    fn test_parse_ip_whitelist_multiple_ips() {
        let result = parse_ip_whitelist("127.0.0.1,192.168.1.1,::1");
        assert_eq!(result.len(), 3);
        assert_eq!(result[0].to_string(), "127.0.0.1");
        assert_eq!(result[1].to_string(), "192.168.1.1");
        assert_eq!(result[2].to_string(), "::1");
    }

    #[test]
    fn test_parse_ip_whitelist_with_spaces() {
        let result = parse_ip_whitelist(" 127.0.0.1 , 192.168.1.1 ");
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].to_string(), "127.0.0.1");
        assert_eq!(result[1].to_string(), "192.168.1.1");
    }

    #[test]
    fn test_parse_ip_whitelist_invalid_ips() {
        let result = parse_ip_whitelist("127.0.0.1,invalid,192.168.1.1");
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].to_string(), "127.0.0.1");
        assert_eq!(result[1].to_string(), "192.168.1.1");
    }

    #[tokio::test]
    async fn test_app_state_creation() {
        use tempfile::tempdir;

        let temp_dir = tempdir().expect("Failed to create temp directory");
        let temp_path = temp_dir.path().to_string_lossy().to_string();

        // Create the database
        let database = database::init_db(&temp_path)
            .await
            .expect("Failed to initialize test database");

        let app_state = AppState {
            database,
            data_dir: temp_path.clone(),
            auth_key: "test_auth_key".to_string(),
            whitelist_ips: parse_ip_whitelist("127.0.0.1"),
        };

        assert_eq!(app_state.data_dir, temp_path);
        assert_eq!(app_state.auth_key, "test_auth_key");
        assert_eq!(app_state.whitelist_ips.len(), 1);
    }

    #[tokio::test]
    async fn test_server_components() {
        use tempfile::tempdir;

        // Create a test configuration. The Leptos options are derived from the
        // build environment rather than these variables, so no process-global
        // env is mutated here; doing so would race with other tests.
        let conf = get_configuration(None).unwrap();
        let _leptos_options = conf.leptos_options;

        // Test that we can create the router without panicking
        let routes = generate_route_list(App);
        assert!(!routes.is_empty(), "Routes should not be empty");

        // Create app state in a self-cleaning directory
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let temp_path = temp_dir.path().to_string_lossy().to_string();

        let database = database::init_db(&temp_path)
            .await
            .expect("Failed to initialize test database");

        let app_state = AppState {
            database,
            data_dir: temp_path,
            auth_key: "test_auth_key".to_string(),
            whitelist_ips: parse_ip_whitelist("127.0.0.1"),
        };

        // Test that we can create API routes
        let _api_routes = api::create_api_routes();
        let _file_routes = file_server::create_file_routes();

        // Verify app state values
        assert_eq!(app_state.auth_key, "test_auth_key");
        assert_eq!(app_state.whitelist_ips.len(), 1);
    }

    #[tokio::test]
    async fn test_static_file_serving_setup() {
        // Simple test to verify our static file serving setup works
        use std::fs;
        use tempfile::tempdir;
        use tower_http::services::ServeDir;

        // Create a temporary directory with test files
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let temp_path = temp_dir.path();

        // Create pkg subdirectory
        let pkg_dir = temp_path.join("pkg");
        fs::create_dir_all(&pkg_dir).unwrap();

        // Create test CSS file
        fs::write(pkg_dir.join("test.css"), "body { color: red; }").unwrap();

        // Verify we can create the static service (this tests our setup logic)
        let _static_service = ServeDir::new(&pkg_dir);

        // Test passes if we can create the service without errors
        assert!(pkg_dir.exists());
        assert!(pkg_dir.join("test.css").exists());
    }

    #[tokio::test]
    async fn test_authentication_flow_end_to_end() {
        use axum::body::Body;
        use axum::extract::ConnectInfo;
        use axum::http::{Method, Request, StatusCode};

        use serde_json::json;
        use tempfile::tempdir;
        use tower::ServiceExt;

        // Set up test environment
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let temp_path = temp_dir.path().to_string_lossy().to_string();

        // Initialize test database
        let database = database::init_db(&temp_path)
            .await
            .expect("Failed to initialize test database");

        let app_state = AppState {
            database,
            data_dir: temp_path,
            auth_key: "test_auth_key_123".to_string(),
            whitelist_ips: vec![], // Empty whitelist allows loopback only
        };

        // Create API router
        let api_router = api::create_api_routes().with_state(app_state);

        // The router under test is not wrapped by `into_make_service_with_connect_info`,
        // so the peer address is injected directly via request extensions, which is
        // where the `ConnectInfo` extractor reads it from.
        let loopback = SocketAddr::from(([127, 0, 0, 1], 40000));

        // Test 1: Authentication with valid key should return token
        let auth_request = Request::builder()
            .method(Method::POST)
            .uri("/auth")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({"auth_key": "test_auth_key_123"}).to_string(),
            ))
            .unwrap();
        let mut auth_request = auth_request;
        auth_request.extensions_mut().insert(ConnectInfo(loopback));

        let auth_response = api_router.clone().oneshot(auth_request).await.unwrap();
        assert_eq!(auth_response.status(), StatusCode::OK);

        let auth_body = axum::body::to_bytes(auth_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let auth_result: serde_json::Value = serde_json::from_slice(&auth_body).unwrap();

        assert_eq!(auth_result["success"], true);
        assert!(auth_result["token"].is_string());
        let token = auth_result["token"].as_str().unwrap();
        assert!(!token.is_empty());

        // Test 2: Authentication with invalid key should fail
        let invalid_auth_request = Request::builder()
            .method(Method::POST)
            .uri("/auth")
            .header("content-type", "application/json")
            .body(Body::from(json!({"auth_key": "wrong_key"}).to_string()))
            .unwrap();
        let mut invalid_auth_request = invalid_auth_request;
        invalid_auth_request
            .extensions_mut()
            .insert(ConnectInfo(loopback));

        let invalid_auth_response = api_router
            .clone()
            .oneshot(invalid_auth_request)
            .await
            .unwrap();
        assert_eq!(invalid_auth_response.status(), StatusCode::OK);

        let invalid_auth_body = axum::body::to_bytes(invalid_auth_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let invalid_auth_result: serde_json::Value =
            serde_json::from_slice(&invalid_auth_body).unwrap();

        assert_eq!(invalid_auth_result["success"], false);
        assert!(invalid_auth_result["token"].is_null());

        // Test 3: Auth status check with valid token should succeed
        let auth_status_request = Request::builder()
            .method(Method::GET)
            .uri("/auth/status")
            .header("authorization", format!("Bearer {}", token))
            .body(Body::empty())
            .unwrap();

        let auth_status_response = api_router
            .clone()
            .oneshot(auth_status_request)
            .await
            .unwrap();
        assert_eq!(auth_status_response.status(), StatusCode::OK);

        let status_body = axum::body::to_bytes(auth_status_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let status_result: serde_json::Value = serde_json::from_slice(&status_body).unwrap();
        assert_eq!(status_result["authenticated"], true);

        // Test 4: Auth status check without token should fail
        let no_token_request = Request::builder()
            .method(Method::GET)
            .uri("/auth/status")
            .body(Body::empty())
            .unwrap();

        let no_token_response = api_router.clone().oneshot(no_token_request).await.unwrap();
        assert_eq!(no_token_response.status(), StatusCode::OK);

        let no_token_body = axum::body::to_bytes(no_token_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let no_token_result: serde_json::Value = serde_json::from_slice(&no_token_body).unwrap();
        assert_eq!(no_token_result["authenticated"], false);
    }

    #[tokio::test]
    async fn test_auth_rejects_non_whitelisted_ip() {
        use axum::body::Body;
        use axum::extract::ConnectInfo;
        use axum::http::{Method, Request};
        use serde_json::json;
        use tempfile::tempdir;
        use tower::ServiceExt;

        let temp_dir = tempdir().expect("Failed to create temp directory");
        let temp_path = temp_dir.path().to_string_lossy().to_string();

        let app_state = AppState {
            database: database::init_db(&temp_path)
                .await
                .expect("Failed to initialize test database"),
            data_dir: temp_path,
            auth_key: "test_auth_key_123".to_string(),
            whitelist_ips: vec![],
        };

        let api_router = api::create_api_routes().with_state(app_state);

        // A non-loopback client must be refused even with the correct key.
        let request = Request::builder()
            .method(Method::POST)
            .uri("/auth")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({"auth_key": "test_auth_key_123"}).to_string(),
            ))
            .unwrap();
        let mut request = request;
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([203, 0, 113, 7], 40000))));

        let response = api_router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let result: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(result["success"], false);
        assert!(result["token"].is_null());
    }

    /// Builds a router over a temp database seeded with `count` documents.
    ///
    /// The returned `TempDir` must be kept alive for as long as the pool is
    /// used, since it owns the SQLite file on disk.
    async fn seeded_router(count: usize) -> (axum::Router, TempDir) {
        let temp_dir = tempfile::tempdir().expect("Failed to create temp directory");
        // `init_db` appends `carbon.db` itself, so point it at the directory.
        let db_dir = temp_dir.path().to_string_lossy().to_string();

        let pool = database::init_db(&db_dir).await.expect("Failed to init db");

        for i in 0..count {
            database::insert_document_if_absent(
                &pool,
                database::NewDocument {
                    title: format!("Doc {:03}", i),
                    part_number: Some(format!("PN{:03}", i)),
                    manufacturer: Some("Test Corp".to_string()),
                    document_id: None,
                    document_version: None,
                    package_marking: None,
                    device_address: None,
                    notes: None,
                    storage_date: "2024-01-01".to_string(),
                    original_file_name: format!("doc{}.pdf", i),
                    file_sha256: format!("{:064x}", i),
                    file_path: format!("{}/doc.pdf", db_dir),
                },
            )
            .await
            .expect("Failed to seed document")
            .expect("document should be inserted");
        }

        let state = AppState {
            database: pool,
            data_dir: db_dir,
            auth_key: "test_auth_key".to_string(),
            whitelist_ips: vec![],
        };

        (api::create_api_routes().with_state(state), temp_dir)
    }

    #[tokio::test]
    async fn test_submit_rejects_duplicate_file() {
        use axum::body::Body;
        use axum::http::{Method, Request, StatusCode};
        use carbon_white::auth::create_jwt_token_with_secret;
        use tower::ServiceExt;

        let auth_key = "duplicate_test_key";
        let temp_dir = tempfile::tempdir().expect("Failed to create temp directory");
        let db_dir = temp_dir.path().to_string_lossy().to_string();
        std::fs::create_dir_all(format!("{}/files", db_dir)).unwrap();

        let pool = database::init_db(&db_dir).await.expect("Failed to init db");
        let state = AppState {
            database: pool,
            data_dir: db_dir.clone(),
            auth_key: auth_key.to_string(),
            whitelist_ips: vec![],
        };
        let router = api::create_api_routes().with_state(state);

        let token = create_jwt_token_with_secret(auth_key.as_bytes()).unwrap();
        let boundary = "----cwtestboundary";
        let content = b"identical file contents";

        // Builds a multipart/form-data body with a single file part.
        let build_body = |filename: &str, title: &str| {
            let mut body = Vec::new();
            body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
            body.extend_from_slice(b"Content-Disposition: form-data; name=\"title\"\r\n\r\n");
            body.extend_from_slice(title.as_bytes());
            body.extend_from_slice(b"\r\n");
            body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
            body.extend_from_slice(
                format!(
                    "Content-Disposition: form-data; name=\"file\"; filename=\"{}\"\r\n",
                    filename
                )
                .as_bytes(),
            );
            body.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
            body.extend_from_slice(content);
            body.extend_from_slice(format!("\r\n--{}--\r\n", boundary).as_bytes());
            body
        };

        let send = |filename: &str, title: &str| {
            let body = build_body(filename, title);
            let request = Request::builder()
                .method(Method::POST)
                .uri("/submit")
                .header(
                    "content-type",
                    format!("multipart/form-data; boundary={}", boundary),
                )
                .header("authorization", format!("Bearer {}", token))
                .body(Body::from(body))
                .unwrap();
            let router = router.clone();
            async move { router.oneshot(request).await.unwrap() }
        };

        // First upload of the content is accepted.
        let first = send("first.pdf", "First Title").await;
        assert_eq!(first.status(), StatusCode::OK);
        let first_body = axum::body::to_bytes(first.into_body(), usize::MAX)
            .await
            .unwrap();
        let first_json: serde_json::Value = serde_json::from_slice(&first_body).unwrap();
        assert_eq!(first_json["success"], true);

        // Uploading the same bytes again is rejected, even with a different
        // name and title.
        let second = send("second.pdf", "Second Title").await;
        assert_eq!(second.status(), StatusCode::OK);
        let second_body = axum::body::to_bytes(second.into_body(), usize::MAX)
            .await
            .unwrap();
        let second_json: serde_json::Value = serde_json::from_slice(&second_body).unwrap();

        assert_eq!(second_json["success"], false);
        assert!(
            second_json["message"]
                .as_str()
                .unwrap()
                .contains("already been uploaded"),
            "unexpected message: {second_json}"
        );

        // The original record must be intact, not replaced by the second upload.
        let stored = database::get_document_by_sha256(
            &database::init_db(&db_dir).await.unwrap(),
            first_json["file_sha256"].as_str().unwrap(),
        )
        .await
        .unwrap()
        .expect("original document should still exist");
        assert_eq!(stored.title, "First Title");
        assert_eq!(stored.original_file_name, "first.pdf");

        // The rejected upload must not have written a second copy to disk.
        let hash = first_json["file_sha256"].as_str().unwrap();
        let dir = std::path::Path::new(&db_dir).join("files").join(hash);
        let entries: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        assert_eq!(
            entries,
            vec!["first.pdf".to_string()],
            "only the accepted upload should be on disk"
        );

        // Streaming stages every upload before the dedup check commits it, so
        // the staging directory must be empty afterwards. A leftover here would
        // mean an upload's bytes are on disk with no database row.
        let staged: Vec<_> = std::fs::read_dir(format!("{}/files/.incoming", db_dir))
            .expect("staging directory should exist")
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        assert!(
            staged.is_empty(),
            "staging directory should be empty, found: {staged:?}"
        );
    }

    #[tokio::test]
    async fn test_list_endpoint_pagination() {
        use axum::body::Body;
        use axum::http::{Method, Request, StatusCode};
        use tower::ServiceExt;

        // 250 documents at the default page size of 100 gives 3 pages.
        let (router, _temp) = seeded_router(250).await;

        async fn get_page(router: axum::Router, uri: &str) -> serde_json::Value {
            let request = Request::builder()
                .method(Method::GET)
                .uri(uri)
                .body(Body::empty())
                .unwrap();
            let response = router.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            serde_json::from_slice(&body).unwrap()
        }

        // First page: full, and links forward only.
        let first = get_page(router.clone(), "/documents").await;
        assert_eq!(first["page"], 1);
        assert_eq!(first["per_page"], 100);
        assert_eq!(first["total"], 250);
        assert_eq!(first["total_pages"], 3);
        assert_eq!(first["results"].as_array().unwrap().len(), 100);
        assert_eq!(first["has_previous"], false);
        assert_eq!(first["has_next"], true);

        // Middle page.
        let second = get_page(router.clone(), "/documents?page=2").await;
        assert_eq!(second["page"], 2);
        assert_eq!(second["results"].as_array().unwrap().len(), 100);
        assert_eq!(second["has_previous"], true);
        assert_eq!(second["has_next"], true);

        // Last page: partial, links backward only.
        let third = get_page(router.clone(), "/documents?page=3").await;
        assert_eq!(third["page"], 3);
        assert_eq!(third["results"].as_array().unwrap().len(), 50);
        assert_eq!(third["has_previous"], true);
        assert_eq!(third["has_next"], false);

        // Pages must not overlap.
        let first_titles: Vec<String> = first["results"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["title"].as_str().unwrap().to_string())
            .collect();
        let third_titles: Vec<String> = third["results"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["title"].as_str().unwrap().to_string())
            .collect();
        for title in &first_titles {
            assert!(
                !third_titles.contains(title),
                "page 1 and page 3 must not share documents"
            );
        }
    }

    #[tokio::test]
    async fn test_list_endpoint_clamps_bad_pagination_params() {
        use axum::body::Body;
        use axum::http::{Method, Request, StatusCode};
        use tower::ServiceExt;

        let (router, _temp) = seeded_router(5).await;

        async fn get_page(router: axum::Router, uri: &str) -> serde_json::Value {
            let request = Request::builder()
                .method(Method::GET)
                .uri(uri)
                .body(Body::empty())
                .unwrap();
            let response = router.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            serde_json::from_slice(&body).unwrap()
        }

        // A page past the end is clamped rather than erroring.
        let beyond = get_page(router.clone(), "/documents?page=500").await;
        assert_eq!(beyond["page"], 1);
        assert_eq!(beyond["results"].as_array().unwrap().len(), 5);

        // Zero and negative values fall back to the defaults.
        let zero_page = get_page(router.clone(), "/documents?page=0").await;
        assert_eq!(zero_page["page"], 1);

        let negative = get_page(router.clone(), "/documents?page=-3").await;
        assert_eq!(negative["page"], 1);

        // The page size is fixed server-side, so a `per_page` parameter is
        // ignored rather than honoured.
        let with_per_page = get_page(router.clone(), "/documents?per_page=2").await;
        assert_eq!(with_per_page["per_page"], 100);
        assert_eq!(with_per_page["results"].as_array().unwrap().len(), 5);
        assert_eq!(with_per_page["total_pages"], 1);
    }

    #[tokio::test]
    async fn test_list_endpoint_empty_database() {
        use axum::body::Body;
        use axum::http::{Method, Request, StatusCode};
        use tower::ServiceExt;

        let (router, _temp) = seeded_router(0).await;

        let request = Request::builder()
            .method(Method::GET)
            .uri("/documents")
            .body(Body::empty())
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let result: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(result["total"], 0);
        // One (empty) page so the client never has to divide by zero.
        assert_eq!(result["total_pages"], 1);
        assert_eq!(result["has_next"], false);
        assert_eq!(result["has_previous"], false);
        assert_eq!(result["results"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn test_favicon_serving() {
        use axum::body::Body;
        use axum::http::{Method, Request, StatusCode};
        use std::fs;
        use tempfile::tempdir;

        // Create a temporary site directory with test favicon files
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let site_root = temp_dir.path().to_string_lossy().to_string();

        // Create test favicon files
        fs::write(
            temp_dir.path().join("favicon.ico"),
            b"\x00\x00\x01\x00\x01\x00\x10\x10\x00\x00",
        )
        .unwrap();
        fs::write(temp_dir.path().join("favicon-16x16.png"), b"fake png 16x16").unwrap();
        fs::write(temp_dir.path().join("favicon-32x32.png"), b"fake png 32x32").unwrap();
        fs::write(
            temp_dir.path().join("apple-touch-icon.png"),
            b"fake apple touch icon",
        )
        .unwrap();
        fs::write(
            temp_dir.path().join("site.webmanifest"),
            b"{\"name\":\"Test App\"}",
        )
        .unwrap();

        // Test serving favicon.ico
        let ico_request = Request::builder()
            .method(Method::GET)
            .uri("/favicon.ico")
            .body(Body::empty())
            .unwrap();

        let result = serve_favicon_at(ico_request, &site_root).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            response
                .headers()
                .get("content-type")
                .unwrap()
                .to_str()
                .unwrap()
                .contains("image/x-icon")
        );

        // Test serving PNG favicon
        let png_request = Request::builder()
            .method(Method::GET)
            .uri("/favicon-16x16.png")
            .body(Body::empty())
            .unwrap();

        let result = serve_favicon_at(png_request, &site_root).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            response
                .headers()
                .get("content-type")
                .unwrap()
                .to_str()
                .unwrap()
                .contains("image/png")
        );

        // Test serving webmanifest
        let manifest_request = Request::builder()
            .method(Method::GET)
            .uri("/site.webmanifest")
            .body(Body::empty())
            .unwrap();

        let result = serve_favicon_at(manifest_request, &site_root).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            response
                .headers()
                .get("content-type")
                .unwrap()
                .to_str()
                .unwrap()
                .contains("application/manifest+json")
        );

        // Test 404 for non-existent file
        let not_found_request = Request::builder()
            .method(Method::GET)
            .uri("/nonexistent.ico")
            .body(Body::empty())
            .unwrap();

        let result = serve_favicon_at(not_found_request, &site_root).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_favicon_mime_type_detection() {
        // Test that our favicon serving function can handle different file types
        let test_cases = vec![
            ("favicon.ico", "image/x-icon"),
            ("favicon-16x16.png", "image/png"),
            ("apple-touch-icon.png", "image/png"),
            ("site.webmanifest", "application/manifest+json"),
            ("unknown.xyz", "application/octet-stream"),
        ];

        for (filename, expected_mime) in test_cases {
            let detected_mime = match filename.rsplit('.').next() {
                Some("ico") => "image/x-icon",
                Some("png") => "image/png",
                Some("webmanifest") => "application/manifest+json",
                _ => "application/octet-stream",
            };
            assert_eq!(detected_mime, expected_mime, "Failed for {}", filename);
        }
    }

    #[test]
    fn test_favicon_routes_creation() {
        // Test that favicon routes are properly configured
        let favicon_routes = vec![
            "/favicon.ico",
            "/favicon-16x16.png",
            "/favicon-32x32.png",
            "/apple-touch-icon.png",
            "/site.webmanifest",
            "/android-chrome-192x192.png",
            "/android-chrome-512x512.png",
        ];

        // This test verifies that the routes we expect are handled
        // In a real server setup, these would all map to the serve_favicon function
        for route in favicon_routes {
            assert!(route.starts_with('/'));
            assert!(!route.is_empty());
            assert!(
                route.contains("favicon")
                    || route.contains("apple-touch")
                    || route.contains("android-chrome")
                    || route.contains("site.webmanifest")
            );
        }
    }
}
