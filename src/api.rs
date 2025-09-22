use axum::{
    extract::{ConnectInfo, Multipart, Query, State},
    http::{HeaderMap, StatusCode},
    response::Json,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

use once_cell::sync::Lazy;
use std::env;
use std::io::Write;
use std::path::Path;
use std::time::Instant;
use tracing::{error, info, warn};

use crate::{
    auth::{
        create_jwt_token, get_client_ip, is_ip_whitelisted, validate_auth_key, AuthRequest,
        AuthResponse,
    },
    database::{self, NewDocument},
    shared::AuthStatusResponse,
    AppState,
};

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    fn test_ip_whitelist_with_headers() {
        // Whitelist contains 192.168.1.1
        let whitelist = vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))];
        let connect_info = Some(SocketAddr::from(([127, 0, 0, 1], 12345)));

        // X-Forwarded-For header present
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("192.168.1.1"));
        let ip = get_client_ip(&headers, connect_info);
        assert_eq!(ip, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(is_ip_whitelisted(ip.unwrap(), &whitelist));

        // X-Real-IP header present
        let mut headers = HeaderMap::new();
        headers.insert("x-real-ip", HeaderValue::from_static("192.168.1.1"));
        let ip = get_client_ip(&headers, connect_info);
        assert_eq!(ip, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(is_ip_whitelisted(ip.unwrap(), &whitelist));

        // Not whitelisted
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("10.0.0.1"));
        let ip = get_client_ip(&headers, connect_info);
        assert_eq!(ip, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(!is_ip_whitelisted(ip.unwrap(), &whitelist));
    }

    #[test]
    fn test_ip_whitelist_with_connect_info_fallback() {
        // Simulate no headers, fallback to ConnectInfo
        let whitelist = vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))];
        let headers = HeaderMap::new();
        let connect_info = Some(SocketAddr::from(([127, 0, 0, 1], 12345)));
        let client_ip = get_client_ip(&headers, connect_info);
        assert_eq!(client_ip, Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(is_ip_whitelisted(client_ip.unwrap(), &whitelist));
    }

    #[test]
    fn test_ip_whitelist_empty_allows_any() {
        let whitelist = vec![];
        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        assert!(is_ip_whitelisted(ip, &whitelist));
    }

    #[test]
    fn test_search_result_creation() {
        let result = SearchResult {
            title: "Test Document".to_string(),
            part_number: "PN123".to_string(),
            manufacturer: "Test Corp".to_string(),
            document_id: "DOC001".to_string(),
            document_version: "1.0".to_string(),
            package_marking: "QFN32".to_string(),
            device_address: "0x48".to_string(),
            notes: "Test notes".to_string(),
            storage_date: "2024-01-01".to_string(),
            original_file_name: "test.pdf".to_string(),
            file_sha256: "abcd1234".to_string(),
        };

        assert_eq!(result.title, "Test Document");
        assert_eq!(result.part_number, "PN123");
        assert_eq!(result.manufacturer, "Test Corp");
    }

    #[test]
    fn test_search_response_creation() {
        let response = SearchResponse {
            results: vec![],
            duration_ms: 50,
        };

        assert_eq!(response.results.len(), 0);
        assert_eq!(response.duration_ms, 50);
    }

    #[test]
    fn test_submit_response_creation() {
        let response = SubmitResponse {
            success: true,
            message: "File uploaded successfully".to_string(),
            file_sha256: Some("abcd1234".to_string()),
        };

        assert!(response.success);
        assert_eq!(response.message, "File uploaded successfully");
        assert_eq!(response.file_sha256.unwrap(), "abcd1234");
    }

    #[test]
    fn test_auth_status_response() {
        let response = AuthStatusResponse {
            authenticated: true,
        };

        assert!(response.authenticated);
    }

    #[test]
    fn test_search_query_deserialization() {
        // This would typically be tested with actual JSON deserialization
        let query = SearchQuery {
            q: "test search".to_string(),
        };

        assert_eq!(query.q, "test search");
    }

    #[test]
    fn test_auth_request_creation() {
        let request = AuthRequest {
            auth_key: "test_key".to_string(),
        };

        assert_eq!(request.auth_key, "test_key");
    }

    #[test]
    fn test_auth_response_success() {
        let response = AuthResponse {
            success: true,
            message: "Authentication successful".to_string(),
            token: Some("test_token".to_string()),
        };

        assert!(response.success);
        assert_eq!(response.message, "Authentication successful");
        assert_eq!(response.token.unwrap(), "test_token");
    }

    #[test]
    fn test_auth_response_failure() {
        let response = AuthResponse {
            success: false,
            message: "Invalid auth key".to_string(),
            token: None,
        };

        assert!(!response.success);
        assert_eq!(response.message, "Invalid auth key");
        assert!(response.token.is_none());
    }

    #[test]
    fn test_file_size_limit_check() {
        // Test that our file size limit constant is reasonable
        const MAX_FILE_SIZE: usize = 100 * 1024 * 1024; // 100MB

        // Should accept reasonable file sizes
        let small_file_size = 1024; // 1KB
        let medium_file_size = 5 * 1024 * 1024; // 5MB
        let large_file_size = 50 * 1024 * 1024; // 50MB

        assert!(small_file_size <= MAX_FILE_SIZE);
        assert!(medium_file_size <= MAX_FILE_SIZE);
        assert!(large_file_size <= MAX_FILE_SIZE);

        // Should reject oversized files
        let oversized_file = 150 * 1024 * 1024; // 150MB
        assert!(oversized_file > MAX_FILE_SIZE);
    }

    #[test]
    fn test_submit_response_file_too_large() {
        let response = SubmitResponse {
            success: false,
            message: "File size exceeds 100MB limit".to_string(),
            file_sha256: None,
        };

        assert!(!response.success);
        assert_eq!(response.message, "File size exceeds 100MB limit");
        assert!(response.file_sha256.is_none());
    }

    #[test]
    fn test_search_query_empty_string() {
        let query = SearchQuery { q: "".to_string() };

        assert_eq!(query.q, "");
        assert!(query.q.trim().is_empty());
    }

    #[test]
    fn test_search_response_recent_files() {
        // Test response structure for recent files (same as search results)
        let recent_result = SearchResult {
            title: "Recent Document".to_string(),
            part_number: "RPN123".to_string(),
            manufacturer: "Recent Corp".to_string(),
            document_id: "RDOC001".to_string(),
            document_version: "1.0".to_string(),
            package_marking: "QFN64".to_string(),
            device_address: "0x50".to_string(),
            notes: "Recent file notes".to_string(),
            storage_date: "2024-01-15".to_string(),
            original_file_name: "recent.pdf".to_string(),
            file_sha256: "recent_hash_123".to_string(),
        };

        let response = SearchResponse {
            results: vec![recent_result],
            duration_ms: 25,
        };

        assert_eq!(response.results.len(), 1);
        assert_eq!(response.results[0].title, "Recent Document");
        assert_eq!(response.duration_ms, 25);
    }
}

#[derive(Debug, Deserialize)]
pub struct SearchQuery {
    pub q: String,
}

#[derive(Debug, Serialize)]
pub struct SearchResult {
    pub title: String,
    pub part_number: String,
    pub manufacturer: String,
    pub document_id: String,
    pub document_version: String,
    pub package_marking: String,
    pub device_address: String,
    pub notes: String,
    pub storage_date: String,
    pub original_file_name: String,
    pub file_sha256: String,
}

#[derive(Debug, Serialize)]
pub struct SearchResponse {
    pub results: Vec<SearchResult>,
    pub duration_ms: u128,
}

#[derive(Debug, Serialize)]
pub struct SubmitResponse {
    pub success: bool,
    pub message: String,
    pub file_sha256: Option<String>,
}

pub fn create_api_routes() -> Router<AppState> {
    Router::new()
        .route("/auth", post(handle_auth))
        .route("/auth/status", get(handle_auth_status))
        .route("/search", get(handle_search))
        .route("/submit", post(handle_submit))
}

pub async fn handle_auth(
    State(state): State<AppState>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    Json(request): Json<AuthRequest>,
) -> Result<Json<AuthResponse>, StatusCode> {
    let client_ip = get_client_ip(&headers, Some(addr));
    info!("Authentication attempt from {:?}", client_ip);

    // Check IP whitelist if configured
    if !state.whitelist_ips.is_empty() {
        // Get client IP from headers with fallback to connection info

        match client_ip {
            Some(ip) => {
                if !is_ip_whitelisted(ip, &state.whitelist_ips) {
                    warn!("Authentication attempt from non-whitelisted IP: {}", ip);
                    return Ok(Json(AuthResponse {
                        success: false,
                        message: "Access denied from this IP address".to_string(),
                        token: None,
                    }));
                }
                info!("IP {} is whitelisted", ip);
            }
            None => {
                warn!("Could not determine client IP for authentication (checked headers and connection info)");
                return Ok(Json(AuthResponse {
                    success: false,
                    message: "Could not verify IP address".to_string(),
                    token: None,
                }));
            }
        }
    }

    // Validate auth key
    if !validate_auth_key(&request.auth_key, &state.auth_key) {
        warn!("Invalid auth key provided");
        return Ok(Json(AuthResponse {
            success: false,
            message: "Invalid authentication key".to_string(),
            token: None,
        }));
    }

    // Generate JWT token
    match create_jwt_token() {
        Ok(token) => {
            info!("Authentication successful, token generated");

            Ok(Json(AuthResponse {
                success: true,
                message: "Authentication successful".to_string(),
                token: Some(token),
            }))
        }
        Err(e) => {
            error!("Failed to create JWT token: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

pub async fn handle_auth_status(
    headers: HeaderMap,
) -> Result<Json<AuthStatusResponse>, StatusCode> {
    use crate::auth::{extract_token_from_headers, verify_jwt_token};

    let token = extract_token_from_headers(&headers);
    let authenticated = match token {
        Some(token) => verify_jwt_token(&token).is_ok(),
        None => false,
    };

    Ok(Json(AuthStatusResponse { authenticated }))
}

pub async fn handle_search(
    State(state): State<AppState>,
    Query(query): Query<SearchQuery>,
) -> Result<Json<SearchResponse>, StatusCode> {
    let start_time = Instant::now();
    info!("Search request for query: '{}'", query.q);

    // If no search query provided, return latest N files (from env or default 10)
    static RECENT_FILE_COUNT: Lazy<u32> = Lazy::new(|| {
        env::var("RECENT_FILE_COUNT")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(10)
    });
    if query.q.trim().is_empty() {
        match database::get_latest_documents(&state.database, *RECENT_FILE_COUNT).await {
            Ok(documents) => {
                let results: Vec<SearchResult> = documents
                    .into_iter()
                    .map(|doc| SearchResult {
                        title: doc.title,
                        part_number: doc.part_number.unwrap_or_default(),
                        manufacturer: doc.manufacturer.unwrap_or_default(),
                        document_id: doc.document_id.unwrap_or_default(),
                        document_version: doc.document_version.unwrap_or_default(),
                        package_marking: doc.package_marking.unwrap_or_default(),
                        device_address: doc.device_address.unwrap_or_default(),
                        notes: doc.notes.unwrap_or_default(),
                        storage_date: doc.storage_date,
                        original_file_name: doc.original_file_name,
                        file_sha256: doc.file_sha256,
                    })
                    .collect();

                let duration = start_time.elapsed().as_millis();
                info!("Returned {} latest files in {}ms", results.len(), duration);

                return Ok(Json(SearchResponse {
                    results,
                    duration_ms: duration,
                }));
            }
            Err(e) => {
                error!("Database error getting latest documents: {}", e);
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        }
    }

    match database::search_documents(&state.database, &query.q).await {
        Ok(documents) => {
            let results: Vec<SearchResult> = documents
                .into_iter()
                .map(|doc| SearchResult {
                    title: doc.title,
                    part_number: doc.part_number.unwrap_or_default(),
                    manufacturer: doc.manufacturer.unwrap_or_default(),
                    document_id: doc.document_id.unwrap_or_default(),
                    document_version: doc.document_version.unwrap_or_default(),
                    package_marking: doc.package_marking.unwrap_or_default(),
                    device_address: doc.device_address.unwrap_or_default(),
                    notes: doc.notes.unwrap_or_default(),
                    storage_date: doc.storage_date,
                    original_file_name: doc.original_file_name,
                    file_sha256: doc.file_sha256,
                })
                .collect();

            let duration = start_time.elapsed().as_millis();
            info!(
                "Search completed in {}ms, found {} results",
                duration,
                results.len()
            );

            Ok(Json(SearchResponse {
                results,
                duration_ms: duration,
            }))
        }
        Err(e) => {
            error!("Database search error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

pub async fn handle_submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Result<Json<SubmitResponse>, StatusCode> {
    use crate::auth::{extract_token_from_headers, verify_jwt_token};

    info!("File submission request received");
    info!("Request headers: {:?}", headers);

    // Check Content-Type header specifically
    if let Some(content_type) = headers.get("content-type") {
        info!("Content-Type: {:?}", content_type);
    } else {
        warn!("No Content-Type header found");
    }

    // Check authentication
    let token = match extract_token_from_headers(&headers) {
        Some(token) => token,
        None => {
            warn!("No auth token provided for file submission");
            return Ok(Json(SubmitResponse {
                success: false,
                message: "Authentication required".to_string(),
                file_sha256: None,
            }));
        }
    };

    if let Err(e) = verify_jwt_token(&token) {
        warn!("Invalid token for file submission: {}", e);
        return Ok(Json(SubmitResponse {
            success: false,
            message: "Invalid or expired token".to_string(),
            file_sha256: None,
        }));
    }

    let mut form_data: HashMap<String, String> = HashMap::new();
    let mut file_data: Option<(String, Vec<u8>)> = None;

    // Process multipart form data with detailed error handling
    info!("Starting multipart field processing");
    while let Some(field) = multipart.next_field().await.map_err(|e| {
        error!("Error reading multipart field: {}", e);
        error!("Headers received: {:?}", headers);
        error!("Error details: {:?}", e);
        StatusCode::BAD_REQUEST
    })? {
        let name = field.name().unwrap_or("").to_string();
        info!("Processing field: '{}'", name);

        if name == "file" {
            let filename = field.file_name().unwrap_or("unknown").to_string();
            let content_type = field.content_type().map(|ct| ct.to_string());
            info!(
                "Processing file: '{}', content type: {:?}",
                filename, content_type
            );

            // Read file data in chunks to handle large files better
            let data = field.bytes().await.map_err(|e| {
                error!("Error reading file data: {}", e);
                error!("Field content type: {:?}", content_type);
                error!("Filename: {}", filename);
                StatusCode::BAD_REQUEST
            })?;

            if data.len() > 100 * 1024 * 1024 {
                // 100MB limit
                return Ok(Json(SubmitResponse {
                    success: false,
                    message: "File size exceeds 100MB limit".to_string(),
                    file_sha256: None,
                }));
            }

            info!("File data size: {} bytes", data.len());
            file_data = Some((filename, data.to_vec()));
        } else {
            let content_type = field.content_type().map(|ct| ct.to_string());
            let value = field.text().await.map_err(|e| {
                error!("Error reading form field {}: {}", name, e);
                error!("Field content type: {:?}", content_type);
                StatusCode::BAD_REQUEST
            })?;
            info!("Field '{}' = '{}'", name, value);
            form_data.insert(name, value);
        }
    }

    // Validate required fields
    let title = form_data.get("title").cloned().unwrap_or_default();
    if title.trim().is_empty() {
        return Ok(Json(SubmitResponse {
            success: false,
            message: "Title is required".to_string(),
            file_sha256: None,
        }));
    }

    let (original_filename, file_bytes) = match file_data {
        Some(data) => data,
        None => {
            return Ok(Json(SubmitResponse {
                success: false,
                message: "File is required".to_string(),
                file_sha256: None,
            }));
        }
    };

    // Calculate file SHA256
    let mut hasher = Sha256::new();
    hasher.update(&file_bytes);
    let file_hash = format!("{:x}", hasher.finalize());

    info!(
        "Processing file upload: {} (SHA256: {})",
        original_filename, file_hash
    );

    // Create file storage directory
    let file_dir = Path::new(&state.data_dir).join("files").join(&file_hash);

    if let Err(e) = std::fs::create_dir_all(&file_dir) {
        error!("Failed to create file directory: {}", e);
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    // Write file to disk
    let file_path = file_dir.join(&original_filename);
    let mut file = match std::fs::File::create(&file_path) {
        Ok(file) => file,
        Err(e) => {
            error!("Failed to create file: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    if let Err(e) = file.write_all(&file_bytes) {
        error!("Failed to write file data: {}", e);
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    // Create database record
    let storage_date = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let new_document = NewDocument {
        title: title.clone(),
        part_number: form_data.get("part_number").cloned(),
        manufacturer: form_data.get("manufacturer").cloned(),
        document_id: form_data.get("document_id").cloned(),
        document_version: form_data.get("document_version").cloned(),
        package_marking: form_data.get("package_marking").cloned(),
        device_address: form_data.get("device_address").cloned(),
        notes: form_data.get("notes").cloned(),
        storage_date,
        original_file_name: original_filename,
        file_sha256: file_hash.clone(),
        file_path: file_path.to_string_lossy().to_string(),
    };

    match database::insert_or_update_document(&state.database, new_document).await {
        Ok(id) => {
            info!("Document {} stored successfully with ID: {}", title, id);
            Ok(Json(SubmitResponse {
                success: true,
                message: "Document uploaded successfully".to_string(),
                file_sha256: Some(file_hash),
            }))
        }
        Err(e) => {
            error!("Failed to store document in database: {}", e);
            // Clean up the file if database insertion fails
            let _ = std::fs::remove_file(&file_path);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}
