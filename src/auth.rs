use crate::ip_subnet::IPSubnet;
use axum::http::HeaderMap;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};

const JWT_EXPIRATION_HOURS: i64 = 24;

/// Length of the session signing key, matching the HS256 block of SHA-256 output.
pub const SIGNING_KEY_LEN: usize = 32;

/// Draws a fresh session signing key from the OS RNG.
///
/// The login key is never used to sign tokens, so a leaked token cannot be
/// used to brute-force it offline.
pub fn generate_signing_key() -> [u8; SIGNING_KEY_LEN] {
    let mut key = [0u8; SIGNING_KEY_LEN];
    getrandom::fill(&mut key).expect("the OS random number generator is unavailable");
    key
}

#[derive(Debug, Serialize, Clone, Deserialize)]
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

pub fn create_jwt_token_with_secret(secret: &[u8]) -> Result<String, jsonwebtoken::errors::Error> {
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
        &EncodingKey::from_secret(secret),
    )
}

pub fn verify_jwt_token_with_secret(
    secret: &[u8],
    token: &str,
) -> Result<Claims, jsonwebtoken::errors::Error> {
    let validation = Validation::new(Algorithm::HS256);

    decode::<Claims>(token, &DecodingKey::from_secret(secret), &validation)
        .map(|token_data| token_data.claims)
}

/// Reads the session token from an `Authorization: Bearer` header.
///
/// Cookies are deliberately not accepted: the browser attaches them to
/// cross-site requests, which would open the API to request forgery.
pub fn extract_token_from_headers(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
}

/// True when the request carries a valid, unexpired session token.
pub fn is_request_authenticated(headers: &HeaderMap, signing_key: &[u8]) -> bool {
    extract_token_from_headers(headers)
        .is_some_and(|token| verify_jwt_token_with_secret(signing_key, token).is_ok())
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

pub fn is_ip_whitelisted(client_ip: IpAddr, whitelist: &[IPSubnet]) -> bool {
    // An empty whitelist allows loopback only.
    if whitelist.is_empty() {
        client_ip.to_canonical().is_loopback()
    } else {
        for ip_range in whitelist {
            if ip_range.contains(&client_ip) {
                return true;
            }
        }
        false
    }
}

fn is_trusted_proxy(ip: IpAddr, trusted_proxies: &[IPSubnet]) -> bool {
    trusted_proxies.iter().any(|proxy| proxy.contains(&ip))
}

/// Parses one forwarded address, tolerating the `ip:port` and `[ipv6]:port`
/// forms some proxies emit.
fn parse_forwarded_ip(value: &str) -> Option<IpAddr> {
    let value = value.trim();
    value
        .parse::<IpAddr>()
        .or_else(|_| value.parse::<SocketAddr>().map(|addr| addr.ip()))
        .ok()
        .map(|ip| ip.to_canonical())
}

/// Resolves the address of the client that originated a request.
///
/// The socket peer is the client unless it is listed in `trusted_proxies`.
/// Only then are forwarding headers consulted: `X-Forwarded-For` is walked
/// right to left, skipping trusted hops, because proxies append to it and
/// everything left of the first untrusted hop is client supplied. `X-Real-IP` is
/// used when no `X-Forwarded-For` is present.
///
/// Returns `None` when a trusted proxy forwarded an address that cannot be
/// parsed, so callers fail closed rather than guessing.
pub fn resolve_client_ip(
    headers: &HeaderMap,
    peer: IpAddr,
    trusted_proxies: &[IPSubnet],
) -> Option<IpAddr> {
    let peer = peer.to_canonical();
    if !is_trusted_proxy(peer, trusted_proxies) {
        return Some(peer);
    }

    // Repeated header lines are equivalent to a single comma-joined list.
    let mut hops = Vec::new();
    for value in headers.get_all("x-forwarded-for") {
        hops.extend(
            value
                .to_str()
                .ok()?
                .split(',')
                .map(str::trim)
                .filter(|hop| !hop.is_empty()),
        );
    }

    if !hops.is_empty() {
        let mut client = peer;
        for hop in hops.iter().rev() {
            client = parse_forwarded_ip(hop)?;
            if !is_trusted_proxy(client, trusted_proxies) {
                return Some(client);
            }
        }
        // Every hop is a trusted proxy, so the left-most one originated the request.
        return Some(client);
    }

    match headers.get("x-real-ip") {
        Some(value) => value.to_str().ok().and_then(parse_forwarded_ip),
        None => Some(peer),
    }
}

#[cfg(test)]
mod test_auth {
    use super::*;
    use jsonwebtoken::{EncodingKey, Header, encode};
    use std::str::FromStr;

    #[test]
    fn test_create_and_verify_jwt_token() {
        let secret = b"test-secret-for-unit-tests";
        let token = create_jwt_token_with_secret(secret).unwrap();
        assert!(!token.is_empty());

        let claims = verify_jwt_token_with_secret(secret, &token).unwrap();
        assert_eq!(claims.sub, "carbon_white_user");

        // Check that expiration is in the future
        let now = chrono::Utc::now().timestamp() as usize;
        assert!(claims.exp > now);
        assert!(claims.iat <= now);
    }

    #[test]
    fn test_verify_invalid_token() {
        let secret = b"test-secret-for-unit-tests";
        assert!(verify_jwt_token_with_secret(secret, "invalid.token.here").is_err());
    }

    #[test]
    fn test_token_signed_with_other_secret_is_rejected() {
        let token = create_jwt_token_with_secret(b"secret-a").unwrap();
        assert!(verify_jwt_token_with_secret(b"secret-b", &token).is_err());
    }

    #[test]
    fn test_expired_token_is_rejected() {
        // A token whose `exp` is already in the past must fail verification,
        // otherwise a leaked token would be valid forever.
        let secret = b"test-secret-for-unit-tests";
        let claims = Claims {
            sub: "carbon_white_user".to_string(),
            exp: (chrono::Utc::now() - chrono::Duration::hours(1)).timestamp() as usize,
            iat: (chrono::Utc::now() - chrono::Duration::hours(2)).timestamp() as usize,
        };
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(secret),
        )
        .unwrap();

        assert!(verify_jwt_token_with_secret(secret, &token).is_err());
    }

    #[test]
    fn test_tampered_token_is_rejected() {
        let secret = b"test-secret-for-unit-tests";
        let token = create_jwt_token_with_secret(secret).unwrap();

        // Flip a character in the signature segment.
        let mut parts: Vec<String> = token.split('.').map(str::to_string).collect();
        let replacement = if parts[2].starts_with('a') { "b" } else { "a" };
        parts[2].replace_range(0..1, replacement);
        let tampered = parts.join(".");

        assert!(verify_jwt_token_with_secret(secret, &tampered).is_err());
    }

    #[test]
    fn test_token_lifetime_is_bounded() {
        let secret = b"test-secret-for-unit-tests";
        let token = create_jwt_token_with_secret(secret).unwrap();
        let claims = verify_jwt_token_with_secret(secret, &token).unwrap();

        let lifetime = claims.exp - claims.iat;
        assert_eq!(
            lifetime as i64,
            JWT_EXPIRATION_HOURS * 3600,
            "token should live for exactly JWT_EXPIRATION_HOURS"
        );
    }

    #[test]
    fn test_generate_signing_key_is_random() {
        let first = generate_signing_key();
        let second = generate_signing_key();
        assert_ne!(first, second);
        assert_ne!(first, [0u8; SIGNING_KEY_LEN]);
    }

    #[test]
    fn test_token_from_previous_key_is_rejected() {
        // A restart draws a new key, which must invalidate earlier tokens.
        let before_restart = generate_signing_key();
        let after_restart = generate_signing_key();
        let token = create_jwt_token_with_secret(&before_restart).unwrap();
        assert!(verify_jwt_token_with_secret(&after_restart, &token).is_err());
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
    fn test_validate_auth_key_rejects_mismatch_at_any_position() {
        let expected = "abcdefgh";
        for i in 0..expected.len() {
            let mut provided = expected.to_string();
            provided.replace_range(i..=i, "X");
            assert!(
                !validate_auth_key(&provided, expected),
                "key differing at byte {i} must not validate"
            );
        }
    }

    #[test]
    fn test_is_ip_whitelisted() {
        let whitelist: Vec<IPSubnet> = vec![
            IPSubnet::try_from("192.168.1.1/32").unwrap(),
            IPSubnet::try_from("::1/128").unwrap(),
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

        // Test empty whitelist (should allow only localhost)
        assert!(is_ip_whitelisted(
            IpAddr::from_str("127.0.0.1").unwrap(),
            &[]
        ));
        assert!(!is_ip_whitelisted(
            IpAddr::from_str("192.168.1.2").unwrap(),
            &[]
        ));

        // A dual-stack socket reports IPv4 loopback as a mapped address.
        assert!(is_ip_whitelisted(
            IpAddr::from_str("::ffff:127.0.0.1").unwrap(),
            &[]
        ));
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
        assert_eq!(extract_token_from_headers(&headers), Some("test_token"));

        // Cookies are ignored, so a cross-site request cannot authenticate.
        headers.clear();
        headers.insert(
            "cookie",
            HeaderValue::from_str("carbon_auth_token=cookie_token; other=value").unwrap(),
        );
        assert_eq!(extract_token_from_headers(&headers), None);

        // Other schemes are not bearer tokens.
        headers.clear();
        headers.insert("authorization", HeaderValue::from_static("Basic abc"));
        assert_eq!(extract_token_from_headers(&headers), None);

        // Test no token
        headers.clear();
        assert_eq!(extract_token_from_headers(&headers), None);
    }

    #[test]
    fn test_is_request_authenticated() {
        use axum::http::{HeaderMap, HeaderValue};

        let key = generate_signing_key();
        let token = create_jwt_token_with_secret(&key).unwrap();

        let mut headers = HeaderMap::new();
        assert!(!is_request_authenticated(&headers, &key));

        headers.insert(
            "authorization",
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );
        assert!(is_request_authenticated(&headers, &key));
        assert!(!is_request_authenticated(&headers, &generate_signing_key()));

        headers.clear();
        headers.insert(
            "cookie",
            HeaderValue::from_str(&format!("carbon_auth_token={token}")).unwrap(),
        );
        assert!(!is_request_authenticated(&headers, &key));
    }

    #[test]
    fn test_resolve_client_ip_ignores_headers_from_untrusted_peer() {
        use axum::http::{HeaderMap, HeaderValue};

        // Without a trusted proxy the headers are client controlled, so a
        // spoofed loopback address must not be believed.
        let peer = IpAddr::from_str("203.0.113.7").unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("127.0.0.1"));
        headers.insert("x-real-ip", HeaderValue::from_static("127.0.0.1"));

        assert_eq!(resolve_client_ip(&headers, peer, &[]), Some(peer));

        let unrelated_proxy = vec![IPSubnet::try_from("10.0.0.1").unwrap()];
        assert_eq!(
            resolve_client_ip(&headers, peer, &unrelated_proxy),
            Some(peer)
        );
    }

    #[test]
    fn test_resolve_client_ip_uses_right_most_untrusted_hop() {
        use axum::http::{HeaderMap, HeaderValue};

        let proxy = IpAddr::from_str("10.0.0.1").unwrap();
        let trusted = vec![IPSubnet::try_from("10.0.0.1").unwrap()];

        // The client prepended a spoofed hop; the proxy appended the real one.
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("127.0.0.1, 198.51.100.4"),
        );
        assert_eq!(
            resolve_client_ip(&headers, proxy, &trusted),
            Some(IpAddr::from_str("198.51.100.4").unwrap())
        );
    }

    #[test]
    fn test_resolve_client_ip_skips_chained_trusted_proxies() {
        use axum::http::{HeaderMap, HeaderValue};

        let peer = IpAddr::from_str("10.0.0.1").unwrap();
        let trusted = vec![IPSubnet::try_from("10.0.0.0/8").unwrap()];

        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("198.51.100.4, 10.0.0.2"),
        );
        assert_eq!(
            resolve_client_ip(&headers, peer, &trusted),
            Some(IpAddr::from_str("198.51.100.4").unwrap())
        );

        // When every hop is trusted, the left-most one is the origin.
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("10.0.0.3, 10.0.0.2"),
        );
        assert_eq!(
            resolve_client_ip(&headers, peer, &trusted),
            Some(IpAddr::from_str("10.0.0.3").unwrap())
        );
    }

    #[test]
    fn test_resolve_client_ip_combines_repeated_headers() {
        use axum::http::{HeaderMap, HeaderValue};

        let peer = IpAddr::from_str("10.0.0.1").unwrap();
        let trusted = vec![IPSubnet::try_from("10.0.0.1").unwrap()];

        let mut headers = HeaderMap::new();
        headers.append("x-forwarded-for", HeaderValue::from_static("127.0.0.1"));
        headers.append("x-forwarded-for", HeaderValue::from_static("198.51.100.4"));
        assert_eq!(
            resolve_client_ip(&headers, peer, &trusted),
            Some(IpAddr::from_str("198.51.100.4").unwrap())
        );
    }

    #[test]
    fn test_resolve_client_ip_fails_closed_on_garbage() {
        use axum::http::{HeaderMap, HeaderValue};

        let peer = IpAddr::from_str("10.0.0.1").unwrap();
        let trusted = vec![IPSubnet::try_from("10.0.0.1").unwrap()];

        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("not-an-ip"));
        assert_eq!(resolve_client_ip(&headers, peer, &trusted), None);

        headers.clear();
        headers.insert("x-real-ip", HeaderValue::from_static(""));
        assert_eq!(resolve_client_ip(&headers, peer, &trusted), None);
    }

    #[test]
    fn test_resolve_client_ip_from_trusted_proxy() {
        use axum::http::{HeaderMap, HeaderValue};

        let peer = IpAddr::from_str("::1").unwrap();
        let trusted = vec![IPSubnet::try_from("::1").unwrap()];
        let mut headers = HeaderMap::new();

        // No forwarding headers: the proxy itself is the client.
        assert_eq!(resolve_client_ip(&headers, peer, &trusted), Some(peer));

        headers.insert("x-real-ip", HeaderValue::from_static("192.168.1.2"));
        assert_eq!(
            resolve_client_ip(&headers, peer, &trusted),
            Some(IpAddr::from_str("192.168.1.2").unwrap())
        );

        // Port suffixes are tolerated.
        headers.clear();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("192.168.1.3:5000, [2001:db8::1]:443"),
        );
        assert_eq!(
            resolve_client_ip(&headers, peer, &trusted),
            Some(IpAddr::from_str("2001:db8::1").unwrap())
        );
    }

    #[test]
    fn test_resolve_client_ip_canonicalises_mapped_peer() {
        let headers = HeaderMap::new();
        let mapped = IpAddr::from_str("::ffff:192.168.1.5").unwrap();
        assert_eq!(
            resolve_client_ip(&headers, mapped, &[]),
            Some(IpAddr::from_str("192.168.1.5").unwrap())
        );
    }
}
