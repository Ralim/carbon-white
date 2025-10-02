use axum::{
    body::Body,
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::Response,
    routing::get,
    Router,
};
use mime_guess::MimeGuess;
use std::path::Path as StdPath;
use tokio::fs;
use tracing::{error, info, warn};

use crate::{database, AppState};

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

    // Check if file exists on disk
    let file_path = StdPath::new(&document.file_path);
    if !file_path.exists() {
        error!("File not found on disk: {}", document.file_path);
        return Err(StatusCode::NOT_FOUND);
    }

    // Read file content
    let file_content = match fs::read(&file_path).await {
        Ok(content) => content,
        Err(e) => {
            error!("Failed to read file {}: {}", document.file_path, e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    // Determine MIME type
    let mime_type = MimeGuess::from_path(&document.original_file_name)
        .first_or_octet_stream()
        .to_string();

    info!(
        "Serving file: {} ({} bytes, MIME: {})",
        document.original_file_name,
        file_content.len(),
        mime_type
    );

    // Build response headers
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, mime_type.parse().unwrap());
    headers.insert(
        header::CONTENT_LENGTH,
        file_content.len().to_string().parse().unwrap(),
    );

    // Set Content-Disposition to inline so files open in browser instead of downloading
    let content_disposition = format!(
        "inline; filename=\"{}\"",
        sanitize_filename(&document.original_file_name)
    );
    headers.insert(
        header::CONTENT_DISPOSITION,
        content_disposition.parse().unwrap(),
    );

    // Add cache control headers
    headers.insert(
        header::CACHE_CONTROL,
        "public, max-age=3600".parse().unwrap(),
    );

    // Build response
    let mut response = Response::builder()
        .status(StatusCode::OK)
        .body(Body::from(file_content))
        .unwrap();

    *response.headers_mut() = headers;

    Ok(response)
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
