use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::env;
use std::net::{IpAddr, SocketAddr};
use tracing::{error, info, warn};

use crate::AppState;

static JWT_SECRET: Lazy<Vec<u8>> = Lazy::new(|| {
    env::var("CARBON_AUTH_KEY")
        .expect("CARBON_AUTH_KEY must be set in environment")
        .into_bytes()
});

const JWT_EXPIRATION_HOURS: i64 = 24;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // Subject (typically user ID)
    pub exp: usize,  // Expiration timestamp
    pub iat: usize,  // Issued at timestamp
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthRequest {
    pub auth_key: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthResponse {
    pub success: bool,
    pub message: String,
    pub token: Option<String>,
}

pub fn create_jwt_token() -> Result<String, jsonwebtoken::errors::Error> {
    let now = chrono::Utc::now();
    let exp = now + chrono::Duration::hours(JWT_EXPIRATION_HOURS);

    let claims = Claims {
        sub: "carbon_white_user".to_string(),
        exp: exp.timestamp() as usize,
        iat: now.timestamp() as usize,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(&JWT_SECRET),
    )
}

pub fn verify_jwt_token(token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    let validation = Validation::new(Algorithm::HS256);

    decode::<Claims>(token, &DecodingKey::from_secret(&JWT_SECRET), &validation)
        .map(|token_data| token_data.claims)
}

pub fn extract_token_from_headers(headers: &HeaderMap) -> Option<String> {
    // Try to get token from Authorization header
    if let Some(auth_header) = headers.get("authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            if auth_str.starts_with("Bearer ") {
                return Some(auth_str.trim_start_matches("Bearer ").to_string());
            }
        }
    }

    // Try to get token from cookie
    if let Some(cookie_header) = headers.get("cookie") {
        if let Ok(cookie_str) = cookie_header.to_str() {
            for cookie in cookie_str.split(';') {
                let cookie = cookie.trim();
                if let Some((name, value)) = cookie.split_once('=') {
                    if name.trim() == "carbon_auth_token" {
                        return Some(value.trim().to_string());
                    }
                }
            }
        }
    }

    None
}

pub async fn auth_middleware(
    State(_state): State<AppState>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Skip auth for public endpoints
    let path = request.uri().path();
    if is_public_endpoint(path) {
        return Ok(next.run(request).await);
    }

    // Extract token from headers
    let token = match extract_token_from_headers(&headers) {
        Some(token) => token,
        None => {
            warn!("No auth token found for protected endpoint: {}", path);
            return Err(StatusCode::UNAUTHORIZED);
        }
    };

    // Verify token
    match verify_jwt_token(&token) {
        Ok(claims) => {
            info!("Valid token for user: {} accessing {}", claims.sub, path);
            Ok(next.run(request).await)
        }
        Err(e) => {
            error!("Invalid token for endpoint {}: {}", path, e);
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}

fn is_public_endpoint(path: &str) -> bool {
    // Public endpoints that don't require authentication
    let public_paths = [
        "/",
        "/login",
        "/api/search",
        "/api/auth",
        "/file/",
        "/pkg/",
        "/assets/",
    ];

    public_paths.iter().any(|&public_path| {
        if public_path == "/" {
            // Root path should only match exactly
            path == "/"
        } else if public_path.ends_with('/') {
            path.starts_with(public_path)
        } else {
            path == public_path
        }
    })
}

pub fn validate_auth_key(provided_key: &str, expected_key: &str) -> bool {
    if expected_key.is_empty() || provided_key.is_empty() {
        return false;
    }

    // Use constant-time comparison to prevent timing attacks

    if provided_key.len() != expected_key.len() {
        return false;
    }

    provided_key
        .bytes()
        .zip(expected_key.bytes())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

pub fn is_ip_whitelisted(client_ip: IpAddr, whitelist: &[IpAddr]) -> bool {
    // If whitelist is empty, allow all IPs
    if whitelist.is_empty() {
        return true;
    }

    whitelist.contains(&client_ip)
}

pub fn get_client_ip_from_headers(headers: &HeaderMap) -> Option<IpAddr> {
    // Try X-Forwarded-For header first (for reverse proxies)
    if let Some(xff_header) = headers.get("x-forwarded-for") {
        if let Ok(xff_str) = xff_header.to_str() {
            // Take the first IP in the comma-separated list
            if let Some(first_ip) = xff_str.split(',').next() {
                if let Ok(ip) = first_ip.trim().parse::<IpAddr>() {
                    return Some(ip);
                }
            }
        }
    }

    // Try X-Real-IP header
    if let Some(xri_header) = headers.get("x-real-ip") {
        if let Ok(xri_str) = xri_header.to_str() {
            if let Ok(ip) = xri_str.parse::<IpAddr>() {
                return Some(ip);
            }
        }
    }

    None
}

/// Get client IP address from headers with fallback to connection info
///
/// This function first tries to extract the client IP from headers (X-Forwarded-For, X-Real-IP)
/// and falls back to using the connection's remote address if no IP is found in headers.
///
/// # Arguments
///
/// * `headers` - HTTP headers that may contain forwarded IP information
/// * `connect_info` - Optional socket address from the connection
///
/// # Returns
///
/// The client's IP address if found, None otherwise
pub fn get_client_ip(headers: &HeaderMap, connect_info: Option<SocketAddr>) -> Option<IpAddr> {
    // First try to get IP from headers
    if let Some(ip) = get_client_ip_from_headers(headers) {
        return Some(ip);
    }

    // Fall back to connection info if available
    connect_info.map(|addr| addr.ip())
}

#[cfg(test)]
mod test_auth {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_create_and_verify_jwt_token() {
        let token = create_jwt_token().unwrap();
        assert!(!token.is_empty());

        let claims = verify_jwt_token(&token).unwrap();
        assert_eq!(claims.sub, "carbon_white_user");

        // Check that expiration is in the future
        let now = chrono::Utc::now().timestamp() as usize;
        assert!(claims.exp > now);
        assert!(claims.iat <= now);
    }

    #[test]
    fn test_verify_invalid_token() {
        let result = verify_jwt_token("invalid.token.here");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_auth_key() {
        let expected_key = "secret123";

        assert!(validate_auth_key("secret123", expected_key));
        assert!(!validate_auth_key("wrong_key", expected_key));
        assert!(!validate_auth_key("", expected_key));
        assert!(!validate_auth_key("secret123", ""));
        assert!(!validate_auth_key("secret12", expected_key)); // Different length
    }

    #[test]
    fn test_is_ip_whitelisted() {
        let whitelist = vec![
            IpAddr::from_str("192.168.1.1").unwrap(),
            IpAddr::from_str("::1").unwrap(),
        ];

        // Test whitelisted IPs
        assert!(is_ip_whitelisted(
            IpAddr::from_str("192.168.1.1").unwrap(),
            &whitelist
        ));
        assert!(is_ip_whitelisted(
            IpAddr::from_str("::1").unwrap(),
            &whitelist
        ));

        // Test non-whitelisted IP
        assert!(!is_ip_whitelisted(
            IpAddr::from_str("192.168.1.2").unwrap(),
            &whitelist
        ));

        // Test empty whitelist (should allow all)
        assert!(is_ip_whitelisted(
            IpAddr::from_str("192.168.1.2").unwrap(),
            &[]
        ));
    }

    #[test]
    fn test_is_public_endpoint() {
        // Test public endpoints
        assert!(is_public_endpoint("/"));
        assert!(is_public_endpoint("/login"));
        assert!(is_public_endpoint("/api/search"));
        assert!(is_public_endpoint("/api/auth"));
        assert!(is_public_endpoint("/file/abc123"));
        assert!(is_public_endpoint("/pkg/app.js"));
        assert!(is_public_endpoint("/assets/logo.png"));

        // Test protected endpoints
        assert!(!is_public_endpoint("/submit"));
        assert!(!is_public_endpoint("/api/submit"));
        assert!(!is_public_endpoint("/admin"));
    }

    #[test]
    fn test_extract_token_from_headers() {
        use axum::http::{HeaderMap, HeaderValue};

        let mut headers = HeaderMap::new();

        // Test Authorization header
        headers.insert(
            "authorization",
            HeaderValue::from_str("Bearer test_token").unwrap(),
        );
        assert_eq!(
            extract_token_from_headers(&headers),
            Some("test_token".to_string())
        );

        // Test cookie
        headers.clear();
        headers.insert(
            "cookie",
            HeaderValue::from_str("carbon_auth_token=cookie_token; other=value").unwrap(),
        );
        assert_eq!(
            extract_token_from_headers(&headers),
            Some("cookie_token".to_string())
        );

        // Test no token
        headers.clear();
        assert_eq!(extract_token_from_headers(&headers), None);
    }

    #[test]
    fn test_get_client_ip_from_headers() {
        use axum::http::{HeaderMap, HeaderValue};

        let mut headers = HeaderMap::new();

        // Test X-Forwarded-For header
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_str("192.168.1.1, 10.0.0.1").unwrap(),
        );
        assert_eq!(
            get_client_ip_from_headers(&headers),
            Some(IpAddr::from_str("192.168.1.1").unwrap())
        );

        // Test X-Real-IP header
        headers.clear();
        headers.insert("x-real-ip", HeaderValue::from_str("192.168.1.2").unwrap());
        assert_eq!(
            get_client_ip_from_headers(&headers),
            Some(IpAddr::from_str("192.168.1.2").unwrap())
        );

        // Test no IP headers
        headers.clear();
        assert_eq!(get_client_ip_from_headers(&headers), None);
    }

    #[test]
    fn test_get_client_ip_with_headers() {
        use axum::http::{HeaderMap, HeaderValue};

        let mut headers = HeaderMap::new();
        let connect_info = Some(SocketAddr::from(([127, 0, 0, 1], 12345)));

        // Test X-Forwarded-For header takes precedence
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_str("192.168.1.1").unwrap(),
        );
        assert_eq!(
            get_client_ip(&headers, connect_info),
            Some(IpAddr::from_str("192.168.1.1").unwrap())
        );

        // Test X-Real-IP header takes precedence
        headers.clear();
        headers.insert("x-real-ip", HeaderValue::from_str("10.0.0.1").unwrap());
        assert_eq!(
            get_client_ip(&headers, connect_info),
            Some(IpAddr::from_str("10.0.0.1").unwrap())
        );
    }

    #[test]
    fn test_get_client_ip_fallback_to_connection() {
        use axum::http::HeaderMap;

        let headers = HeaderMap::new();
        let connect_info = Some(SocketAddr::from(([192, 168, 1, 100], 54321)));

        // Test fallback to connection info when no headers
        assert_eq!(
            get_client_ip(&headers, connect_info),
            Some(IpAddr::from_str("192.168.1.100").unwrap())
        );

        // Test IPv6 connection
        let ipv6_connect_info = Some(SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 8080)));
        assert_eq!(
            get_client_ip(&headers, ipv6_connect_info),
            Some(IpAddr::from_str("::1").unwrap())
        );
    }

    #[test]
    fn test_get_client_ip_no_source() {
        use axum::http::HeaderMap;

        let headers = HeaderMap::new();
        let connect_info = None;

        // Test no IP source available
        assert_eq!(get_client_ip(&headers, connect_info), None);
    }

    #[test]
    fn test_get_client_ip_invalid_header_fallback() {
        use axum::http::{HeaderMap, HeaderValue};

        let mut headers = HeaderMap::new();
        let connect_info = Some(SocketAddr::from(([10, 0, 0, 1], 9000)));

        // Test invalid IP in header falls back to connection
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_str("invalid-ip").unwrap(),
        );
        assert_eq!(
            get_client_ip(&headers, connect_info),
            Some(IpAddr::from_str("10.0.0.1").unwrap())
        );

        // Test empty header value falls back to connection
        headers.clear();
        headers.insert("x-real-ip", HeaderValue::from_str("").unwrap());
        assert_eq!(
            get_client_ip(&headers, connect_info),
            Some(IpAddr::from_str("10.0.0.1").unwrap())
        );
    }
}
