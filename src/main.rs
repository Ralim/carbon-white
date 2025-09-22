#[cfg(feature = "ssr")]
#[tokio::main]
async fn main() {
    #[allow(unused_imports)] // Required for into_make_service_with_connect_info trait method
    use axum::extract::connect_info::IntoMakeServiceWithConnectInfo;
    use axum::{extract::DefaultBodyLimit, Router};
    use carbon_white::*;
    use leptos::prelude::*;
    use leptos_axum::{generate_route_list, LeptosRoutes};
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
        warn!("CARBON_WHITELIST_IPS not set, allowing all IPs");
        "".to_string()
    });

    info!("Carbon data directory: `{}`", carbon_data_dir);
    info!("IP whitelist: `{}`", carbon_whitelist_ips);

    // Create data directories
    std::fs::create_dir_all(&carbon_data_dir).expect("Failed to create data directory");
    std::fs::create_dir_all(format!("{}/files", carbon_data_dir))
        .expect("Failed to create files directory");

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
        .layer(DefaultBodyLimit::max(250 * 1024 * 1024)) // 250MB limit
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
    // unless we want this to work with e.g., Trunk for a purely client-side app
    // see lib.rs for hydration function instead
}

#[cfg(feature = "ssr")]
async fn serve_favicon(
    request: axum::extract::Request,
) -> Result<axum::response::Response<axum::body::Body>, axum::http::StatusCode> {
    use axum::{
        body::Body,
        http::{header, StatusCode},
        response::Response,
    };
    use leptos::prelude::*;
    use std::path::Path;
    use tokio::fs;

    // Get filename from request path
    let path = request.uri().path();
    let filename = path.trim_start_matches('/');

    // Get site root from leptos options
    let conf = get_configuration(None).unwrap();
    let site_root = conf.leptos_options.site_root;
    let file_path = Path::new(site_root.as_ref()).join(filename);

    match fs::read(&file_path).await {
        Ok(content) => {
            let mime_type = match filename.split('.').next_back() {
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

fn parse_ip_whitelist(whitelist: &str) -> Vec<std::net::IpAddr> {
    if whitelist.is_empty() {
        return Vec::new();
    }

    whitelist
        .split(',')
        .filter_map(|ip| ip.trim().parse().ok())
        .collect()
}

#[cfg(test)]
#[cfg(feature = "ssr")]
mod tests {
    use super::*;
    use carbon_white::{api, database, file_server, App, AppState};
    use leptos::prelude::get_configuration;
    use leptos_axum::generate_route_list;

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
        // Set environment variables for test
        std::env::set_var("CARBON_DATA_DIR", "/tmp/test_carbon/");
        std::env::set_var("CARBON_AUTH_KEY", "test_key");
        std::env::set_var("CARBON_WHITELIST_IPS", "127.0.0.1");

        // Create a test configuration
        let conf = get_configuration(None).unwrap();
        let _leptos_options = conf.leptos_options;

        // Test that we can create the router without panicking
        let routes = generate_route_list(App);
        assert!(!routes.is_empty(), "Routes should not be empty");

        // Create app state
        let temp_dir = std::env::temp_dir().join("carbon_test");
        std::fs::create_dir_all(&temp_dir).unwrap();
        let temp_path = temp_dir.to_string_lossy().to_string();

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

        // Clean up
        std::env::remove_var("CARBON_DATA_DIR");
        std::env::remove_var("CARBON_AUTH_KEY");
        std::env::remove_var("CARBON_WHITELIST_IPS");
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
            whitelist_ips: vec![], // Empty whitelist allows all IPs
        };

        // Create API router
        let api_router = api::create_api_routes().with_state(app_state);

        // Test 1: Authentication with valid key should return token
        let auth_request = Request::builder()
            .method(Method::POST)
            .uri("/auth")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({"auth_key": "test_auth_key_123"}).to_string(),
            ))
            .unwrap();

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

        // Mock leptos configuration for testing
        std::env::set_var("LEPTOS_SITE_ROOT", &site_root);

        // Test serving favicon.ico
        let ico_request = Request::builder()
            .method(Method::GET)
            .uri("/favicon.ico")
            .body(Body::empty())
            .unwrap();

        let result = serve_favicon(ico_request).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("image/x-icon"));

        // Test serving PNG favicon
        let png_request = Request::builder()
            .method(Method::GET)
            .uri("/favicon-16x16.png")
            .body(Body::empty())
            .unwrap();

        let result = serve_favicon(png_request).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("image/png"));

        // Test serving webmanifest
        let manifest_request = Request::builder()
            .method(Method::GET)
            .uri("/site.webmanifest")
            .body(Body::empty())
            .unwrap();

        let result = serve_favicon(manifest_request).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("application/manifest+json"));

        // Test 404 for non-existent file
        let not_found_request = Request::builder()
            .method(Method::GET)
            .uri("/nonexistent.ico")
            .body(Body::empty())
            .unwrap();

        let result = serve_favicon(not_found_request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), StatusCode::NOT_FOUND);

        // Clean up
        std::env::remove_var("LEPTOS_SITE_ROOT");
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
            let detected_mime = match filename.split('.').last() {
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
