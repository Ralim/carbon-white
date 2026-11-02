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

    // Uploads are attacker controlled and served from the app's origin, so
    // only types a browser renders passively are shown inline.
    let presentation = Presentation::for_filename(&document.original_file_name);
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, presentation.content_type);
    headers.insert(
        header::CONTENT_DISPOSITION,
        content_disposition_header(presentation.disposition, &document.original_file_name),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    if let Some(policy) = presentation.content_security_policy {
        headers.insert(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(policy),
        );
    }

    // Add cache control headers. The on-disk path is derived from the content
    // hash, so a given URL always maps to the same bytes so crank to Firefox max.
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=86400"),
    );

    info!(
        "Serving file: {} ({})",
        document.original_file_name, document.file_path
    );

    Ok(response.map(Body::new))
}

/// Whether the browser should display a file or download it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Disposition {
    Inline,
    Attachment,
}

impl Disposition {
    fn as_str(self) -> &'static str {
        match self {
            Self::Inline => "inline",
            Self::Attachment => "attachment",
        }
    }
}

/// Policy for passive inline content: no scripts, no plugins, no network
/// access beyond the file itself, and a unique opaque origin.
const SANDBOX_POLICY: &str =
    "default-src 'none'; img-src 'self'; style-src 'unsafe-inline'; sandbox";

/// How a stored file is presented to the browser.
#[derive(Debug)]
struct Presentation {
    content_type: HeaderValue,
    disposition: Disposition,
    content_security_policy: Option<&'static str>,
}

impl Presentation {
    /// Chooses headers from the uploader-supplied filename.
    ///
    /// The filename is untrusted, so this is an allowlist: anything that is not
    /// known to render passively (HTML, SVG, XML, scripts, unknown types) is
    /// downloaded as opaque bytes rather than rendered on the app origin.
    fn for_filename(filename: &str) -> Self {
        let mime = MimeGuess::from_path(filename).first_or_octet_stream();
        let inline_type = match mime.essence_str() {
            // Browser PDF viewers break under a sandbox CSP and isolate PDF
            // scripts from the embedding origin themselves.
            "application/pdf" => {
                return Self {
                    content_type: HeaderValue::from_static("application/pdf"),
                    disposition: Disposition::Inline,
                    content_security_policy: None,
                };
            }
            "image/png" => Some("image/png"),
            "image/jpeg" => Some("image/jpeg"),
            "image/gif" => Some("image/gif"),
            "image/webp" => Some("image/webp"),
            "image/bmp" => Some("image/bmp"),
            "image/avif" => Some("image/avif"),
            // Text formats are shown as plain text, never interpreted.
            "text/plain"
            | "text/markdown"
            | "text/x-markdown"
            | "text/csv"
            | "text/tab-separated-values" => Some("text/plain; charset=utf-8"),
            _ => None,
        };

        match inline_type {
            Some(content_type) => Self {
                content_type: HeaderValue::from_static(content_type),
                disposition: Disposition::Inline,
                content_security_policy: Some(SANDBOX_POLICY),
            },
            None => Self {
                content_type: HeaderValue::from_static("application/octet-stream"),
                disposition: Disposition::Attachment,
                content_security_policy: Some(SANDBOX_POLICY),
            },
        }
    }
}

/// Builds the `Content-Disposition` value for a filename.
///
/// Header values are restricted to visible ASCII, so the quoted `filename`
/// carries an ASCII approximation and `filename*` (RFC 6266) carries the exact
/// UTF-8 name for browsers that support it.
fn content_disposition_header(disposition: Disposition, filename: &str) -> HeaderValue {
    let sanitized = sanitize_filename(filename);
    let ascii: String = sanitized
        .chars()
        .map(|c| if c.is_ascii() { c } else { '_' })
        .collect();

    let value = if ascii == sanitized {
        format!("{}; filename=\"{ascii}\"", disposition.as_str())
    } else {
        format!(
            "{}; filename=\"{ascii}\"; filename*=UTF-8''{}",
            disposition.as_str(),
            urlencoding::encode(&sanitized)
        )
    };

    HeaderValue::from_str(&value).unwrap_or_else(|_| HeaderValue::from_static("attachment"))
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
        let value = content_disposition_header(Disposition::Inline, "datasheet.pdf");
        assert_eq!(
            value.to_str().unwrap(),
            "inline; filename=\"datasheet.pdf\""
        );
    }

    #[test]
    fn test_content_disposition_header_sanitizes_quotes() {
        // An embedded quote would otherwise terminate the filename early and
        // let a caller inject additional header parameters.
        let value = content_disposition_header(Disposition::Attachment, "we\"ird.pdf");
        assert_eq!(
            value.to_str().unwrap(),
            "attachment; filename=\"we_ird.pdf\""
        );
    }

    #[test]
    fn test_content_disposition_header_encodes_non_ascii() {
        // Header values are visible-ASCII only, so the exact name travels in
        // the percent-encoded `filename*` parameter.
        let value = content_disposition_header(Disposition::Inline, "файл.pdf");
        assert_eq!(
            value.to_str().unwrap(),
            "inline; filename=\"____.pdf\"; filename*=UTF-8''%D1%84%D0%B0%D0%B9%D0%BB.pdf"
        );
    }

    #[test]
    fn test_presentation_allows_passive_types_inline() {
        let pdf = Presentation::for_filename("datasheet.PDF");
        assert_eq!(pdf.content_type, "application/pdf");
        assert_eq!(pdf.disposition, Disposition::Inline);
        assert_eq!(pdf.content_security_policy, None);

        let png = Presentation::for_filename("pinout.png");
        assert_eq!(png.content_type, "image/png");
        assert_eq!(png.disposition, Disposition::Inline);
        assert_eq!(png.content_security_policy, Some(SANDBOX_POLICY));

        for name in ["notes.txt", "readme.md", "table.csv"] {
            let text = Presentation::for_filename(name);
            assert_eq!(text.content_type, "text/plain; charset=utf-8", "{name}");
            assert_eq!(text.disposition, Disposition::Inline, "{name}");
        }
    }

    #[test]
    fn test_presentation_downloads_active_and_unknown_types() {
        for name in [
            "evil.html",
            "evil.htm",
            "evil.xhtml",
            "evil.svg",
            "evil.xml",
            "evil.js",
            "firmware.bin",
            "archive.zip",
            "no_extension",
        ] {
            let presentation = Presentation::for_filename(name);
            assert_eq!(
                presentation.content_type, "application/octet-stream",
                "{name}"
            );
            assert_eq!(presentation.disposition, Disposition::Attachment, "{name}");
            assert_eq!(
                presentation.content_security_policy,
                Some(SANDBOX_POLICY),
                "{name}"
            );
        }
    }

    /// Stores `contents` as `name` and returns a router serving it plus its hash.
    async fn router_with_file(name: &str, contents: &[u8]) -> (Router, String, tempfile::TempDir) {
        let temp_dir = tempfile::tempdir().unwrap();
        let data_dir = temp_dir.path().to_str().unwrap().to_string();
        let pool = crate::database::init_db(&data_dir).await.unwrap();

        let sha = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(contents));
        let file_dir = std::path::Path::new(&data_dir).join("files").join(&sha);
        std::fs::create_dir_all(&file_dir).unwrap();
        let file_path = file_dir.join(name);
        std::fs::write(&file_path, contents).unwrap();

        crate::database::insert_document_if_absent(
            &pool,
            crate::database::NewDocument {
                title: name.to_string(),
                part_number: None,
                manufacturer: None,
                document_id: None,
                document_version: None,
                package_marking: None,
                device_address: None,
                notes: None,
                storage_date: "2024-01-01".to_string(),
                original_file_name: name.to_string(),
                file_sha256: sha.clone(),
                file_path: file_path.to_string_lossy().to_string(),
            },
        )
        .await
        .unwrap()
        .expect("document should insert");

        let state = AppState::new(pool, data_dir, "test-key");
        (create_file_routes().with_state(state), sha, temp_dir)
    }

    #[tokio::test]
    async fn test_serve_file_downloads_html_instead_of_rendering() {
        use axum::http::Request;

        let (router, sha, _temp) =
            router_with_file("evil.html", b"<script>alert(document.cookie)</script>").await;
        let response = router
            .oneshot(
                Request::builder()
                    .uri(format!("/{sha}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let headers = response.headers();
        assert_eq!(headers[header::CONTENT_TYPE], "application/octet-stream");
        assert_eq!(
            headers[header::CONTENT_DISPOSITION],
            "attachment; filename=\"evil.html\""
        );
        assert_eq!(headers[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
        assert_eq!(headers[header::CONTENT_SECURITY_POLICY], SANDBOX_POLICY);
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

        let state = AppState::new(pool, data_dir, "test-key");
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
        let state = AppState::new(
            crate::database::init_db(data_dir).await.unwrap(),
            data_dir,
            "test-key",
        );
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
