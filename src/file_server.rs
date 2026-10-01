use axum::{
    Router,
    body::Body,
    extract::{Path, State},
    http::{HeaderValue, StatusCode, header},
    response::Response,
    routing::get,
};
use mime_guess::MimeGuess;
use tower::ServiceExt;
use tower_http::services::ServeFile;
use tracing::{error, info, warn};

use crate::{AppState, database};

pub fn create_file_routes() -> Router<AppState> {
    Router::new().route("/{sha256}", get(serve_file))
}

pub async fn serve_file(
    State(state): State<AppState>,
    Path(sha256): Path<String>,
) -> Result<Response<Body>, StatusCode> {
    info!("File request for SHA256: {}", sha256);

    // Validate SHA256 format (64 hex characters)
    if !is_valid_sha256(&sha256) {
        warn!("Invalid SHA256 format: {}", sha256);
        return Err(StatusCode::BAD_REQUEST);
    }

    // Look up document in database
    let document = match database::get_document_by_sha256(&state.database, &sha256).await {
        Ok(Some(doc)) => doc,
        Ok(None) => {
            warn!("Document not found for SHA256: {}", sha256);
            return Err(StatusCode::NOT_FOUND);
        }
        Err(e) => {
            error!("Database error while looking up document: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    // Stream the file from disk including resume
    let request = axum::http::Request::builder()
        .uri("/")
        .body(Body::empty())
        .map_err(|e| {
            error!("Failed to build file request: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let mut response = ServeFile::new(&document.file_path)
        .oneshot(request)
        .await
        .map_err(|e| {
            error!("Failed to serve file {}: {}", document.file_path, e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // Missing file
    if response.status() == StatusCode::NOT_FOUND {
        error!("File not found on disk: {}", document.file_path);
        return Err(StatusCode::NOT_FOUND);
    }

    // Determine MIME type. The recorded original name is preferred over the
    // stored one.
    let mime_type = MimeGuess::from_path(&document.original_file_name)
        .first_or_octet_stream()
        .to_string();
    if let Ok(value) = HeaderValue::from_str(&mime_type) {
        response.headers_mut().insert(header::CONTENT_TYPE, value);
    }

    // Set Content-Disposition to inline so files open in browser instead of
    // downloading.
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        content_disposition_header(&document.original_file_name),
    );

    // Add cache control headers. The on-disk path is derived from the content
    // hash, so a given URL always maps to the same bytes so crank to Firefox max.
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=86400"),
    );

    info!(
        "Serving file: {} ({})",
        document.original_file_name, document.file_path
    );

    Ok(response.map(Body::new))
}

/// Builds the `Content-Disposition` value for a filename.
///
/// Header values are restricted to visible ASCII, so a filename containing
/// non-ASCII characters cannot be placed in the header as written. Rather than
/// failing the response, fall back to a bare `inline`.
fn content_disposition_header(filename: &str) -> HeaderValue {
    let sanitized = sanitize_filename(filename);
    match HeaderValue::from_str(&format!("inline; filename=\"{sanitized}\"")) {
        Ok(value) if value.to_str().is_ok() => value,
        _ => HeaderValue::from_static("inline"),
    }
}

fn is_valid_sha256(input: &str) -> bool {
    input.len() == 64 && input.chars().all(|c| c.is_ascii_hexdigit())
}

fn sanitize_filename(filename: &str) -> String {
    // Remove or replace characters that could be problematic in HTTP headers
    filename
        .chars()
        .map(|c| match c {
            '"' => '_',
            '\\' => '_',
            '\n' => '_',
            '\r' => '_',
            '\t' => '_',
            c if c.is_control() => '_',
            c => c,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_content_disposition_header_plain_filename() {
        let value = content_disposition_header("datasheet.pdf");
        assert_eq!(
            value.to_str().unwrap(),
            "inline; filename=\"datasheet.pdf\""
        );
    }

    #[test]
    fn test_content_disposition_header_sanitizes_quotes() {
        // An embedded quote would otherwise terminate the filename early and
        // let a caller inject additional header parameters.
        let value = content_disposition_header("we\"ird.pdf");
        assert_eq!(value.to_str().unwrap(), "inline; filename=\"we_ird.pdf\"");
    }

    #[test]
    fn test_content_disposition_header_falls_back_for_non_ascii() {
        // Header values are visible-ASCII only. The previous implementation
        // called `.unwrap()` on the parse, so a filename like this panicked
        // the request handler instead of serving the file.
        let value = content_disposition_header("файл.pdf");
        assert_eq!(value.to_str().unwrap(), "inline");
    }

    #[tokio::test]
    async fn test_serve_file_returns_stored_contents() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let temp_dir = tempfile::tempdir().unwrap();
        let data_dir = temp_dir.path().to_str().unwrap();
        let pool = crate::database::init_db(data_dir).await.unwrap();

        // Write a file using the layout the submit handler creates and register
        // the document that points at it.
        let sha = "a".repeat(64);
        let file_dir = std::path::Path::new(data_dir).join("files").join(&sha);
        std::fs::create_dir_all(&file_dir).unwrap();
        let file_path = file_dir.join("datasheet.pdf");
        let contents = b"%PDF-1.4 pretend this is a pdf";
        std::fs::write(&file_path, contents).unwrap();

        crate::database::insert_document_if_absent(
            &pool,
            crate::database::NewDocument {
                title: "Datasheet".to_string(),
                part_number: None,
                manufacturer: None,
                document_id: None,
                document_version: None,
                package_marking: None,
                device_address: None,
                notes: None,
                storage_date: "2024-01-01".to_string(),
                original_file_name: "datasheet.pdf".to_string(),
                file_sha256: sha.clone(),
                file_path: file_path.to_string_lossy().to_string(),
            },
        )
        .await
        .unwrap()
        .expect("document should insert");

        let state = AppState {
            database: pool,
            data_dir: data_dir.to_string(),
            auth_key: "test-key".to_string(),
            whitelist_ips: vec![],
        };
        let router = create_file_routes().with_state(state);

        let request = Request::builder()
            .uri(format!("/{sha}"))
            .body(Body::empty())
            .unwrap();
        let response = router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CONTENT_TYPE], "application/pdf");
        assert_eq!(
            response.headers()[header::CONTENT_DISPOSITION],
            "inline; filename=\"datasheet.pdf\""
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(body.as_ref(), contents);
    }

    #[tokio::test]
    async fn test_serve_file_404s_for_unknown_hash() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let temp_dir = tempfile::tempdir().unwrap();
        let data_dir = temp_dir.path().to_str().unwrap();
        let state = AppState {
            database: crate::database::init_db(data_dir).await.unwrap(),
            data_dir: data_dir.to_string(),
            auth_key: "test-key".to_string(),
            whitelist_ips: vec![],
        };
        let router = create_file_routes().with_state(state);

        let request = Request::builder()
            .uri(format!("/{}", "b".repeat(64)))
            .body(Body::empty())
            .unwrap();
        let response = router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_is_valid_sha256() {
        // Valid SHA256
        assert!(is_valid_sha256(
            "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456"
        ));
        assert!(is_valid_sha256(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        ));

        // Invalid - wrong length
        assert!(!is_valid_sha256(
            "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef12345"
        ));
        assert!(!is_valid_sha256(
            "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef1234567"
        ));

        // Invalid - non-hex characters
        assert!(!is_valid_sha256(
            "g1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456"
        ));
        assert!(!is_valid_sha256(
            "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef12345!"
        ));

        // Invalid - empty
        assert!(!is_valid_sha256(""));
    }

    #[test]
    fn test_sanitize_filename() {
        assert_eq!(sanitize_filename("normal.pdf"), "normal.pdf");
        assert_eq!(
            sanitize_filename("file with spaces.doc"),
            "file with spaces.doc"
        );
        assert_eq!(
            sanitize_filename("file\"with\"quotes.txt"),
            "file_with_quotes.txt"
        );
        assert_eq!(
            sanitize_filename("file\\with\\backslash.pdf"),
            "file_with_backslash.pdf"
        );
        assert_eq!(
            sanitize_filename("file\nwith\nnewlines.txt"),
            "file_with_newlines.txt"
        );
        assert_eq!(
            sanitize_filename("file\rwith\rreturns.txt"),
            "file_with_returns.txt"
        );
        assert_eq!(
            sanitize_filename("file\twith\ttabs.txt"),
            "file_with_tabs.txt"
        );
    }

    #[test]
    fn test_sanitize_filename_control_characters() {
        // Test control characters (ASCII 0-31)
        let input = "file\x00\x01\x1f.txt";
        let result = sanitize_filename(input);
        assert_eq!(result, "file___.txt");
    }

    #[test]
    fn test_sanitize_filename_unicode() {
        // Unicode characters should be preserved
        assert_eq!(sanitize_filename("файл.pdf"), "файл.pdf");
        assert_eq!(sanitize_filename("文件.doc"), "文件.doc");
        assert_eq!(sanitize_filename("ファイル.txt"), "ファイル.txt");
    }

    #[test]
    fn test_sanitize_filename_empty() {
        assert_eq!(sanitize_filename(""), "");
    }

    #[test]
    fn test_sanitize_filename_only_problematic_chars() {
        assert_eq!(sanitize_filename("\"\\"), "__");
        assert_eq!(sanitize_filename("\n\r\t"), "___");
    }
}
