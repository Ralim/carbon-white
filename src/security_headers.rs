//! Response headers applied to every route.

use axum::{
    http::{HeaderValue, header},
    response::Response,
};

/// Policy for the app's own pages.
///
/// `script-src` is not restricted because Leptos hydration bootstraps through
/// an inline module script; the directives here still block framing,
/// plugins, `<base>` hijacking and cross-origin form posts.
pub const PAGE_POLICY: &str =
    "frame-ancestors 'none'; object-src 'none'; base-uri 'self'; form-action 'self'";

/// Adds baseline security headers, leaving any a handler already set.
pub async fn apply(mut response: Response) -> Response {
    let is_html = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("text/html"));

    let headers = response.headers_mut();
    let mut set_default = |name: header::HeaderName, value: &'static str| {
        headers
            .entry(name)
            .or_insert_with(|| HeaderValue::from_static(value));
    };

    set_default(header::X_CONTENT_TYPE_OPTIONS, "nosniff");
    set_default(header::X_FRAME_OPTIONS, "DENY");
    set_default(header::REFERRER_POLICY, "same-origin");
    if is_html {
        set_default(header::CONTENT_SECURITY_POLICY, PAGE_POLICY);
    }

    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;

    fn response_with_type(content_type: &str) -> Response {
        Response::builder()
            .header(header::CONTENT_TYPE, content_type)
            .body(Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn test_html_pages_get_full_policy() {
        let response = apply(response_with_type("text/html; charset=utf-8")).await;
        let headers = response.headers();
        assert_eq!(headers[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
        assert_eq!(headers[header::X_FRAME_OPTIONS], "DENY");
        assert_eq!(headers[header::REFERRER_POLICY], "same-origin");
        assert_eq!(headers[header::CONTENT_SECURITY_POLICY], PAGE_POLICY);
    }

    #[tokio::test]
    async fn test_non_html_skips_page_policy() {
        // A page CSP on a PDF would stop the browser's viewer from loading it.
        let response = apply(response_with_type("application/pdf")).await;
        let headers = response.headers();
        assert_eq!(headers[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
        assert!(headers.get(header::CONTENT_SECURITY_POLICY).is_none());
    }

    #[tokio::test]
    async fn test_handler_headers_are_kept() {
        let mut response = response_with_type("text/html");
        response.headers_mut().insert(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static("sandbox"),
        );
        let response = apply(response).await;
        assert_eq!(
            response.headers()[header::CONTENT_SECURITY_POLICY],
            "sandbox"
        );
    }
}
