use axum::{
    extract::{ConnectInfo, Multipart, Path as AxumPath, Query, State},
    http::{HeaderMap, StatusCode},
    response::Json,
    routing::{get, post, put},
    Router,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

use std::env;
use std::path::Path;
use std::sync::LazyLock;
use std::time::Instant;
use tracing::{error, info, warn};

use crate::{
    auth::{
        create_jwt_token_with_secret, extract_token_from_headers, get_client_ip, is_ip_whitelisted,
        validate_auth_key, verify_jwt_token_with_secret, AuthRequest, AuthResponse,
    },
    database::{self, NewDocument},
    shared::AuthStatusResponse,
    AppState,
};

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

/// Maximum accepted upload size, enforced after the multipart body is decoded.
const MAX_FILE_SIZE: usize = 100 * 1024 * 1024;

/// Upper bound on a stored filename. Leaves headroom under the common 255-byte
/// filesystem limit once the hash directory prefix is added.
const MAX_FILENAME_LEN: usize = 200;

/// Reduces a client-supplied upload filename to a single safe path component.
///
/// The filename arrives from a multipart `Content-Disposition` header and is
/// therefore fully attacker controlled. Stripping every directory component
/// prevents `../` traversal and absolute-path escapes, replacing characters that
/// are unsafe on common filesystems keeps the name portable, and the fallback
/// guarantees the result is never empty or a relative-directory marker.
///
/// The original name is still recorded in the database for display purposes; only
/// the on-disk path is derived from this value.
fn sanitize_upload_filename(raw: &str) -> String {
    // `rsplit` on both separators so that Windows-style paths are handled too.
    let basename = raw.rsplit(['/', '\\']).next().unwrap_or_default().trim();

    let mut cleaned: String = basename
        .chars()
        .map(|c| {
            if c.is_control()
                || matches!(
                    c,
                    '"' | '\'' | '<' | '>' | '|' | ':' | '*' | '?' | '\\' | '/'
                )
            {
                '_'
            } else {
                c
            }
        })
        .collect();

    // Leading dots would produce hidden files or the relative markers `.` / `..`.
    cleaned = cleaned.trim().trim_start_matches('.').trim().to_string();

    if cleaned.is_empty() {
        return "upload".to_string();
    }

    // Truncate on a char boundary so we never emit invalid UTF-8.
    if cleaned.len() > MAX_FILENAME_LEN {
        let mut end = MAX_FILENAME_LEN;
        while !cleaned.is_char_boundary(end) {
            end -= 1;
        }
        cleaned.truncate(end);
    }

    if cleaned.is_empty() {
        "upload".to_string()
    } else {
        cleaned
    }
}

impl From<database::Document> for SearchResult {
    fn from(doc: database::Document) -> Self {
        Self {
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
        }
    }
}

pub fn create_api_routes() -> Router<AppState> {
    Router::new()
        .route("/auth", post(handle_auth))
        .route("/auth/status", get(handle_auth_status))
        .route("/search", get(handle_search))
        .route("/documents", get(handle_list))
        .route("/submit", post(handle_submit))
        .route("/document/{sha256}", get(handle_get_document))
        .route("/document/{sha256}", put(handle_update_document))
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
    match create_jwt_token_with_secret(state.auth_key.as_bytes()) {
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
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<AuthStatusResponse>, StatusCode> {
    let authenticated = extract_token_from_headers(&headers)
        .map(|token| verify_jwt_token_with_secret(state.auth_key.as_bytes(), &token).is_ok())
        .unwrap_or(false);

    Ok(Json(AuthStatusResponse { authenticated }))
}

pub async fn handle_search(
    State(state): State<AppState>,
    Query(query): Query<SearchQuery>,
) -> Result<Json<SearchResponse>, StatusCode> {
    let start_time = Instant::now();
    info!("Search request for query: '{}'", query.q);

    // If no search query provided, return latest N files (from env or default 10)
    static RECENT_FILE_COUNT: LazyLock<u32> = LazyLock::new(|| {
        env::var("RECENT_FILE_COUNT")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(10)
    });
    if query.q.trim().is_empty() {
        return match database::get_latest_documents(&state.database, *RECENT_FILE_COUNT).await {
            Ok(documents) => {
                let results: Vec<SearchResult> =
                    documents.into_iter().map(SearchResult::from).collect();

                let duration = start_time.elapsed().as_millis();
                info!("Returned {} latest files in {}ms", results.len(), duration);

                Ok(Json(SearchResponse {
                    results,
                    duration_ms: duration,
                }))
            }
            Err(e) => {
                error!("Database error getting latest documents: {}", e);
                Err(StatusCode::INTERNAL_SERVER_ERROR)
            }
        };
    }

    match database::search_documents(&state.database, &query.q).await {
        Ok(documents) => {
            let results: Vec<SearchResult> =
                documents.into_iter().map(SearchResult::from).collect();

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

/// Query parameters for the paginated document listing.
#[derive(Debug, Deserialize)]
pub struct ListQuery {
    #[serde(default)]
    pub page: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct ListResponse {
    pub results: Vec<SearchResult>,
    pub page: i64,
    pub per_page: i64,
    pub total: i64,
    pub total_pages: i64,
    pub has_previous: bool,
    pub has_next: bool,
    duration_ms: u128,
}

pub async fn handle_list(
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
) -> Result<Json<ListResponse>, StatusCode> {
    let start_time = Instant::now();

    // An absent or nonsensical `page` starts at the first page; out-of-range
    // pages are clamped inside `get_documents_page`.
    let page = match query.page {
        Some(requested) if requested > 0 => requested,
        _ => 1,
    };

    match database::get_documents_page(&state.database, page, database::PAGE_SIZE).await {
        Ok(page_data) => {
            let duration = start_time.elapsed().as_millis();
            let total_pages = page_data.total_pages();
            let (page_number, per_page, total, has_previous, has_next) = (
                page_data.page,
                page_data.per_page,
                page_data.total,
                page_data.has_previous(),
                page_data.has_next(),
            );
            let result_count = page_data.documents.len();

            info!(
                "Listed page {} of {} ({} documents) in {}ms",
                page_number, total_pages, result_count, duration
            );

            Ok(Json(ListResponse {
                results: page_data
                    .documents
                    .into_iter()
                    .map(SearchResult::from)
                    .collect(),
                page: page_number,
                per_page,
                total,
                total_pages,
                has_previous,
                has_next,
                duration_ms: duration,
            }))
        }
        Err(e) => {
            error!("Database error listing documents: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

pub async fn handle_submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Result<Json<SubmitResponse>, StatusCode> {
    info!("File submission request received");

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

    if let Err(e) = verify_jwt_token_with_secret(state.auth_key.as_bytes(), &token) {
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
    while let Some(field) = multipart.next_field().await.map_err(|e| {
        error!("Error reading multipart field: {}", e);
        StatusCode::BAD_REQUEST
    })? {
        let name = field.name().unwrap_or("").to_string();

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
                error!("Filename: {}", filename);
                StatusCode::BAD_REQUEST
            })?;

            if data.len() > MAX_FILE_SIZE {
                return Ok(Json(SubmitResponse {
                    success: false,
                    message: format!(
                        "File size exceeds {}MB limit",
                        MAX_FILE_SIZE / (1024 * 1024)
                    ),
                    file_sha256: None,
                }));
            }

            info!("File data size: {} bytes", data.len());
            file_data = Some((filename, data.to_vec()));
        } else {
            let value = field.text().await.map_err(|e| {
                error!("Error reading form field {}: {}", name, e);
                StatusCode::BAD_REQUEST
            })?;
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
    let file_hash = hex::encode(hasher.finalize());

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

    // The uploaded name is attacker controlled, so only ever use the sanitized
    // basename for the on-disk path. The raw name is kept in the database for
    // display only.
    let stored_filename = sanitize_upload_filename(&original_filename);
    let file_path = file_dir.join(&stored_filename);
    let mut file = match tokio::fs::File::create(&file_path).await {
        Ok(file) => file,
        Err(e) => {
            error!("Failed to create file: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    if let Err(e) = tokio::io::AsyncWriteExt::write_all(&mut file, &file_bytes).await {
        error!("Failed to write file data: {}", e);
        let _ = tokio::fs::remove_file(&file_path).await;
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
            let _ = tokio::fs::remove_file(&file_path).await;
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateDocumentRequest {
    pub title: String,
    pub part_number: Option<String>,
    pub manufacturer: Option<String>,
    pub document_id: Option<String>,
    pub document_version: Option<String>,
    pub package_marking: Option<String>,
    pub device_address: Option<String>,
    pub notes: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DocumentResponse {
    pub id: i64,
    pub title: String,
    pub part_number: Option<String>,
    pub manufacturer: Option<String>,
    pub document_id: Option<String>,
    pub document_version: Option<String>,
    pub package_marking: Option<String>,
    pub device_address: Option<String>,
    pub notes: Option<String>,
    pub storage_date: String,
    pub original_file_name: String,
    pub file_sha256: String,
    pub file_path: String,
}

pub async fn handle_get_document(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(sha256): AxumPath<String>,
) -> Result<Json<DocumentResponse>, StatusCode> {
    // Authenticate the user
    if !authenticate_request(&headers, &state) {
        warn!(
            "Unauthorized document retrieval attempt for SHA256: {}",
            sha256
        );
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Validate SHA256 format
    if sha256.len() != 64 || !sha256.chars().all(|c| c.is_ascii_hexdigit()) {
        warn!("Invalid SHA256 format: {}", sha256);
        return Err(StatusCode::BAD_REQUEST);
    }

    match database::get_document_by_sha256(&state.database, &sha256).await {
        Ok(Some(document)) => {
            info!("Document retrieved successfully: {}", sha256);
            Ok(Json(DocumentResponse {
                id: document.id,
                title: document.title,
                part_number: document.part_number,
                manufacturer: document.manufacturer,
                document_id: document.document_id,
                document_version: document.document_version,
                package_marking: document.package_marking,
                device_address: document.device_address,
                notes: document.notes,
                storage_date: document.storage_date,
                original_file_name: document.original_file_name,
                file_sha256: document.file_sha256,
                file_path: document.file_path,
            }))
        }
        Ok(None) => {
            warn!("Document not found: {}", sha256);
            Err(StatusCode::NOT_FOUND)
        }
        Err(e) => {
            error!("Database error retrieving document {}: {}", sha256, e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

pub async fn handle_update_document(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(sha256): AxumPath<String>,
    Json(update_request): Json<UpdateDocumentRequest>,
) -> Result<Json<UpdateResponse>, StatusCode> {
    // Authenticate the user
    if !authenticate_request(&headers, &state) {
        warn!(
            "Unauthorized document update attempt for SHA256: {}",
            sha256
        );
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Validate SHA256 format
    if sha256.len() != 64 || !sha256.chars().all(|c| c.is_ascii_hexdigit()) {
        warn!("Invalid SHA256 format: {}", sha256);
        return Err(StatusCode::BAD_REQUEST);
    }

    // Validate required fields
    if update_request.title.trim().is_empty() {
        return Ok(Json(UpdateResponse {
            success: false,
            message: "Title is required".to_string(),
        }));
    }

    // Check if document exists
    match database::get_document_by_sha256(&state.database, &sha256).await {
        Ok(Some(_existing_doc)) => {
            // Update the document
            match database::update_document_metadata(
                &state.database,
                &sha256,
                &database::DocumentMetadataUpdate {
                    title: &update_request.title,
                    part_number: update_request.part_number.as_deref(),
                    manufacturer: update_request.manufacturer.as_deref(),
                    document_id: update_request.document_id.as_deref(),
                    document_version: update_request.document_version.as_deref(),
                    package_marking: update_request.package_marking.as_deref(),
                    device_address: update_request.device_address.as_deref(),
                    notes: update_request.notes.as_deref(),
                },
            )
            .await
            {
                Ok(_) => {
                    info!("Document {} updated successfully", sha256);
                    Ok(Json(UpdateResponse {
                        success: true,
                        message: "Document updated successfully".to_string(),
                    }))
                }
                Err(e) => {
                    error!("Database error updating document {}: {}", sha256, e);
                    Ok(Json(UpdateResponse {
                        success: false,
                        message: "Database error occurred".to_string(),
                    }))
                }
            }
        }
        Ok(None) => {
            warn!("Document not found for update: {}", sha256);
            Err(StatusCode::NOT_FOUND)
        }
        Err(e) => {
            error!("Database error checking document {}: {}", sha256, e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Checks the bearer token on a request against the configured auth key.
///
/// Returns `true` only when a well-formed `Authorization: Bearer <token>` header
/// carries a token that verifies and has not expired.
fn authenticate_request(headers: &HeaderMap, state: &AppState) -> bool {
    headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(|token| verify_jwt_token_with_secret(state.auth_key.as_bytes(), token).is_ok())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ip_subnet::IPSubnet;
    use axum::http::{HeaderMap, HeaderValue};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    fn test_ip_whitelist_with_headers() {
        // Whitelist contains 192.168.1.1
        let whitelist = vec![IPSubnet::try_from("192.168.1.1/32").unwrap()];
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
        let whitelist = vec![IPSubnet::try_from("127.0.0.1/32").unwrap()];
        let headers = HeaderMap::new();
        let connect_info = Some(SocketAddr::from(([127, 0, 0, 1], 12345)));
        let client_ip = get_client_ip(&headers, connect_info);
        assert_eq!(client_ip, Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(is_ip_whitelisted(client_ip.unwrap(), &whitelist));
    }

    #[test]
    fn test_ip_whitelist_empty_allows_localhost() {
        let whitelist = vec![];
        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let local = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        assert!(is_ip_whitelisted(local, &whitelist));
        assert!(!is_ip_whitelisted(ip, &whitelist));
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

    #[test]
    fn test_sanitize_upload_filename_preserves_normal_names() {
        assert_eq!(sanitize_upload_filename("normal.pdf"), "normal.pdf");
        assert_eq!(
            sanitize_upload_filename("file with spaces.doc"),
            "file with spaces.doc"
        );
        assert_eq!(sanitize_upload_filename("a.b.c.tar.gz"), "a.b.c.tar.gz");
    }

    #[test]
    fn test_sanitize_upload_filename_strips_path_traversal() {
        // The basename is all that should survive; the directory part is dropped.
        assert_eq!(sanitize_upload_filename("../../../../etc/passwd"), "passwd");
        assert_eq!(
            sanitize_upload_filename("..\\..\\windows\\system32"),
            "system32"
        );
        // An absolute path must not escape the storage directory.
        assert_eq!(sanitize_upload_filename("/etc/shadow"), "shadow");
        assert_eq!(
            sanitize_upload_filename("C:\\Windows\\evil.exe"),
            "evil.exe"
        );
        // Mixed separators.
        assert_eq!(sanitize_upload_filename("../foo/../../bar.txt"), "bar.txt");
    }

    #[test]
    fn test_sanitize_upload_filename_replaces_unsafe_characters() {
        assert_eq!(sanitize_upload_filename("a\0b.txt"), "a_b.txt");
        assert_eq!(sanitize_upload_filename("re:po|rt?.txt"), "re_po_rt_.txt");
        assert_eq!(sanitize_upload_filename("file\x01\x1f.txt"), "file__.txt");
    }

    #[test]
    fn test_sanitize_upload_filename_never_returns_empty_or_relative() {
        // Anything that would reduce to nothing falls back to a safe default.
        assert_eq!(sanitize_upload_filename(""), "upload");
        assert_eq!(sanitize_upload_filename("   "), "upload");
        assert_eq!(sanitize_upload_filename("."), "upload");
        assert_eq!(sanitize_upload_filename(".."), "upload");
        assert_eq!(sanitize_upload_filename("/"), "upload");
        assert_eq!(sanitize_upload_filename("..."), "upload");
    }

    #[test]
    fn test_sanitize_upload_filename_truncates_without_splitting_utf8() {
        // Long names are clamped, and the result stays valid UTF-8.
        let long = "ф".repeat(500);
        let result = sanitize_upload_filename(&long);
        assert!(result.len() <= MAX_FILENAME_LEN);
        assert!(result.is_char_boundary(result.len()));

        // A multi-byte char straddling the truncation boundary must not panic.
        let boundary = "a".repeat(MAX_FILENAME_LEN - 1) + "ф";
        let result = sanitize_upload_filename(&boundary);
        assert!(result.len() <= MAX_FILENAME_LEN);
        assert!(std::str::from_utf8(result.as_bytes()).is_ok());
    }
}
